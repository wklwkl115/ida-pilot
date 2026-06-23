package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func isAutoNamed(name string) bool {
	return strings.HasPrefix(name, "sub_") ||
		strings.HasPrefix(name, "nullsub_") ||
		strings.HasPrefix(name, "j_") ||
		strings.HasPrefix(name, "unknown_libname_")
}

func (s *Server) getDisasm(ctx context.Context, req *mcp.CallToolRequest, args GetDisasmRequest) (*mcp.CallToolResult, any, error) {
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_disasm")
	if err != nil {
		return nil, err, nil
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}
	s.logToolInvocation("get_disasm", sess.ID, map[string]any{"address": addr, "whole_function": args.WholeFunction})

	if args.WholeFunction {
		resp, err := (*client.Analysis).GetFunctionDisasm(ctx, connect.NewRequest(&pb.GetFunctionDisasmRequest{Address: addr}))
		if err != nil {
			return nil, s.logAndReturnError("get_disasm RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("get_disasm", errors.New(e)), nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: resp.Msg.GetDisassembly()}}}, nil, nil
	}

	resp, err := (*client.Analysis).GetDisasm(ctx, connect.NewRequest(&pb.GetDisasmRequest{Address: addr}))
	if err != nil {
		return nil, s.logAndReturnError("get_disasm RPC", err), nil
	}
	if resp.Msg.Error != "" {
		return nil, s.logAndReturnError("get_disasm", errors.New(resp.Msg.Error)), nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: resp.Msg.Disasm}}}, nil, nil
}

func (s *Server) getFunctions(ctx context.Context, req *mcp.CallToolRequest, args GetFunctionsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_functions", args.SessionID, map[string]any{
		"offset": args.Offset,
		"limit":  args.Limit,
		"regex":  args.Regex,
	})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_functions")
	if err != nil {
		return nil, err, nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_functions")
	cache := s.getSessionCache(sess.ID)
	functionsData, hit, err := cache.loadFunctions(sess.ID, s.logger, func() ([]*pb.Function, error) {
		return s.fetchAllFunctions(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndReturnError("get_functions cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_functions", "Functions served from cache", 1, 1)
	}

	filtered := functionsData
	if args.NamedOnly {
		tmp := make([]*pb.Function, 0, len(filtered)/4)
		for _, fn := range filtered {
			if !isAutoNamed(fn.Name) {
				tmp = append(tmp, fn)
			}
		}
		filtered = tmp
	}
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.Function, 0, len(filtered))
		for _, fn := range filtered {
			if regex.MatchString(fn.Name) {
				tmp = append(tmp, fn)
			}
		}
		filtered = tmp
	}

	totalFunctions := len(filtered)
	offset, end, err := clampPage(args.Offset, args.Limit, totalFunctions)
	if err != nil {
		return nil, err, nil
	}

	text := formatFunctionsText(filtered[offset:end], totalFunctions, offset)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) getImports(ctx context.Context, req *mcp.CallToolRequest, args GetImportsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_imports", args.SessionID, map[string]any{
		"offset": args.Offset,
		"limit":  args.Limit,
		"module": args.Module,
		"regex":  args.Regex,
	})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_imports")
	if err != nil {
		return nil, err, nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_imports")
	cache := s.getSessionCache(sess.ID)
	importsData, hit, err := cache.loadImports(sess.ID, s.logger, func() ([]*pb.Import, error) {
		return s.fetchAllImports(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndReturnError("get_imports cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_imports", "Imports served from cache", 1, 1)
	}

	filtered := importsData
	if args.Module != "" {
		tmp := make([]*pb.Import, 0, len(filtered))
		for _, imp := range filtered {
			if matchModule(imp.Module, args.Module, args.CaseSens) {
				tmp = append(tmp, imp)
			}
		}
		filtered = tmp
	}
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.Import, 0, len(filtered))
		for _, imp := range filtered {
			if regex.MatchString(imp.Name) {
				tmp = append(tmp, imp)
			}
		}
		filtered = tmp
	}

	totalImports := len(filtered)
	offset, end, err := clampPage(args.Offset, args.Limit, totalImports)
	if err != nil {
		return nil, err, nil
	}

	text := formatImportsText(filtered[offset:end], totalImports, offset)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) getExports(ctx context.Context, req *mcp.CallToolRequest, args GetExportsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_exports", args.SessionID, map[string]any{
		"offset": args.Offset,
		"limit":  args.Limit,
		"regex":  args.Regex,
	})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_exports")
	if err != nil {
		return nil, err, nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_exports")
	cache := s.getSessionCache(sess.ID)
	exportsData, hit, err := cache.loadExports(sess.ID, s.logger, func() ([]*pb.Export, error) {
		return s.fetchAllExports(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndReturnError("get_exports cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_exports", "Exports served from cache", 1, 1)
	}

	filtered := exportsData
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.Export, 0, len(filtered))
		for _, exp := range filtered {
			if regex.MatchString(exp.Name) {
				tmp = append(tmp, exp)
			}
		}
		filtered = tmp
	}

	totalExports := len(filtered)
	offset, end, err := clampPage(args.Offset, args.Limit, totalExports)
	if err != nil {
		return nil, err, nil
	}

	text := formatExportsText(filtered[offset:end], totalExports, offset)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) getStrings(ctx context.Context, req *mcp.CallToolRequest, args GetStringsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_strings", args.SessionID, map[string]any{
		"offset": args.Offset,
		"limit":  args.Limit,
		"regex":  args.Regex,
	})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_strings")
	if err != nil {
		return nil, err, nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_strings")
	cache := s.getSessionCache(sess.ID)
	stringsData, hit, err := cache.loadStrings(sess.ID, s.logger, func() ([]*pb.StringItem, error) {
		return s.fetchAllStrings(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndReturnError("get_strings cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_strings", "Strings served from cache", 1, 1)
	}

	filtered := stringsData
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.StringItem, 0, len(filtered))
		for _, item := range filtered {
			if regex.MatchString(item.Value) {
				tmp = append(tmp, item)
			}
		}
		filtered = tmp
	}

	totalStrings := len(filtered)
	offset, end, err := clampPage(args.Offset, args.Limit, totalStrings)
	if err != nil {
		return nil, err, nil
	}
	text := formatStringsText(filtered[offset:end], totalStrings, offset)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) getXRefs(ctx context.Context, req *mcp.CallToolRequest, args GetXRefsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_xrefs", args.SessionID, map[string]any{"address": args.Address, "direction": args.Direction})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_xrefs")
	if err != nil {
		return nil, err, nil
	}

	dir := args.Direction
	if dir == "" {
		dir = "both"
	}

	cache := s.getSessionCache(sess.ID)
	if dir == "both" {
		if entry, ok := cache.getXRefs(args.Address); ok {
			text := formatXRefsText(args.Address, entry.to, entry.from)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
		}
	}

	var toEntries, fromEntries [][]any

	fetchTo := dir == "to" || dir == "both"
	fetchFrom := dir == "from" || dir == "both"

	if fetchTo && fetchFrom {
		type xrefResult struct {
			key     string
			entries [][]any
			err     error
		}
		ch := make(chan xrefResult, 2)

		go func() {
			resp, err := (*client.Analysis).GetXRefsTo(ctx, connect.NewRequest(&pb.GetXRefsToRequest{Address: args.Address}))
			if err != nil {
				ch <- xrefResult{"to", nil, err}
				return
			}
			if e := resp.Msg.GetError(); e != "" {
				ch <- xrefResult{"to", nil, errors.New(e)}
				return
			}
			entries := make([][]any, 0, len(resp.Msg.GetXrefs()))
			for _, x := range resp.Msg.GetXrefs() {
				entries = append(entries, []any{x.GetFrom(), x.GetType()})
			}
			ch <- xrefResult{"to", entries, nil}
		}()

		go func() {
			resp, err := (*client.Analysis).GetXRefsFrom(ctx, connect.NewRequest(&pb.GetXRefsFromRequest{Address: args.Address}))
			if err != nil {
				ch <- xrefResult{"from", nil, err}
				return
			}
			if e := resp.Msg.GetError(); e != "" {
				ch <- xrefResult{"from", nil, errors.New(e)}
				return
			}
			entries := make([][]any, 0, len(resp.Msg.GetXrefs()))
			for _, x := range resp.Msg.GetXrefs() {
				entries = append(entries, []any{x.GetTo(), x.GetType()})
			}
			ch <- xrefResult{"from", entries, nil}
		}()

		cacheEntry := &xrefsEntry{}
		for i := 0; i < 2; i++ {
			r := <-ch
			if r.err != nil {
				return nil, s.logAndReturnError("get_xrefs "+r.key+" RPC", r.err), nil
			}
			if r.key == "to" {
				toEntries = r.entries
				cacheEntry.to = r.entries
			} else {
				fromEntries = r.entries
				cacheEntry.from = r.entries
			}
		}
		cache.setXRefs(args.Address, cacheEntry)
	} else if fetchTo {
		resp, err := (*client.Analysis).GetXRefsTo(ctx, connect.NewRequest(&pb.GetXRefsToRequest{Address: args.Address}))
		if err != nil {
			return nil, s.logAndReturnError("get_xrefs to RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("get_xrefs to", errors.New(e)), nil
		}
		entries := make([][]any, 0, len(resp.Msg.GetXrefs()))
		for _, x := range resp.Msg.GetXrefs() {
			entries = append(entries, []any{x.GetFrom(), x.GetType()})
		}
		toEntries = entries
	} else {
		resp, err := (*client.Analysis).GetXRefsFrom(ctx, connect.NewRequest(&pb.GetXRefsFromRequest{Address: args.Address}))
		if err != nil {
			return nil, s.logAndReturnError("get_xrefs from RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("get_xrefs from", errors.New(e)), nil
		}
		entries := make([][]any, 0, len(resp.Msg.GetXrefs()))
		for _, x := range resp.Msg.GetXrefs() {
			entries = append(entries, []any{x.GetTo(), x.GetType()})
		}
		fromEntries = entries
	}

	text := formatXRefsText(args.Address, toEntries, fromEntries)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) getDataRefs(ctx context.Context, req *mcp.CallToolRequest, args DataRefRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_data_refs", args.SessionID, map[string]any{"address": args.Address})
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_data_refs")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).GetDataRefs(ctx, connect.NewRequest(&pb.GetDataRefsRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndReturnError("get_data_refs RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("get_data_refs IDA operation", errors.New(msgErr)), nil
	}
	refs := resp.Msg.GetRefs()
	if len(refs) == 0 {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "no data refs"}}}, nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d refs:\n", len(refs))
	for _, ref := range refs {
		fmt.Fprintf(&b, "  0x%x %d\n", ref.GetFrom(), ref.GetType())
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: textResult(b.String())}}}, nil, nil
}

func (s *Server) getStringXRefs(ctx context.Context, req *mcp.CallToolRequest, args StringXRefRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_string_xrefs", args.SessionID, map[string]any{"address": args.Address})
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_string_xrefs")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).GetStringXRefs(ctx, connect.NewRequest(&pb.GetStringXRefsRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndReturnError("get_string_xrefs RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("get_string_xrefs IDA operation", errors.New(msgErr)), nil
	}
	refs := resp.Msg.GetRefs()
	if len(refs) == 0 {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "no string xrefs"}}}, nil, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d refs:\n", len(refs))
	for _, ref := range refs {
		fmt.Fprintf(&b, "  0x%x %s @ 0x%x\n", ref.GetAddress(), ref.GetFunctionName(), ref.GetFunctionAddress())
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: textResult(b.String())}}}, nil, nil
}

func (s *Server) getSegments(ctx context.Context, req *mcp.CallToolRequest, args GetSegmentsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_segments", args.SessionID, nil)
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_segments")
	if err != nil {
		return nil, err, nil
	}

	cache := s.getSessionCache(sess.ID)
	segs, _, err := cache.loadSegments(sess.ID, s.logger, func() ([]*pb.Segment, error) {
		resp, err := (*client.Analysis).GetSegments(ctx, connect.NewRequest(&pb.GetSegmentsRequest{}))
		if err != nil {
			return nil, err
		}
		if msgErr := resp.Msg.GetError(); msgErr != "" {
			return nil, errors.New(msgErr)
		}
		return resp.Msg.GetSegments(), nil
	})
	if err != nil {
		return nil, s.logAndReturnError("get_segments", err), nil
	}

	text := formatSegmentsText(segs)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) getEntryPoint(ctx context.Context, req *mcp.CallToolRequest, args GetEntryPointRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_entry_point", args.SessionID, nil)
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_entry_point")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).GetEntryPoint(ctx, connect.NewRequest(&pb.GetEntryPointRequest{}))
	if err != nil {
		return nil, s.logAndReturnError("get_entry_point RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("get_entry_point IDA operation", errors.New(msgErr)), nil
	}
	result, _ := json.Marshal(map[string]any{"address": hexAddr(resp.Msg.GetAddress())})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) readMemory(ctx context.Context, req *mcp.CallToolRequest, args ReadMemoryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("read_memory", args.SessionID, map[string]any{"address": args.Address, "format": args.Format})
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "read_memory")
	if err != nil {
		return nil, err, nil
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}

	format := args.Format
	if format == "" {
		format = "bytes"
	}

	// Each fetcher returns the envelope key, the value to wrap, and any IDA-side
	// error string. The 5 cases previously copy-pasted the same 8-line RPC +
	// error-check + marshal envelope; the dispatch table collapses them while
	// keeping the typed RPC requests/responses inline (no runtime type
	// assertions).
	type memoryResult struct {
		envelopeKey string
		value       any
		ideErr      string
	}
	fetchers := map[string]func() (memoryResult, error){
		"string": func() (memoryResult, error) {
			maxLen := int(args.Size)
			if maxLen <= 0 {
				maxLen = 256
			}
			resp, err := (*client.Analysis).DataReadString(ctx, connect.NewRequest(&pb.DataReadStringRequest{Address: addr, MaxLength: uint32(maxLen)}))
			if err != nil {
				return memoryResult{}, err
			}
			return memoryResult{"value", resp.Msg.GetValue(), resp.Msg.GetError()}, nil
		},
		"dword": func() (memoryResult, error) {
			resp, err := (*client.Analysis).GetDwordAt(ctx, connect.NewRequest(&pb.GetDwordAtRequest{Address: addr}))
			if err != nil {
				return memoryResult{}, err
			}
			return memoryResult{"value", resp.Msg.GetValue(), resp.Msg.GetError()}, nil
		},
		"qword": func() (memoryResult, error) {
			resp, err := (*client.Analysis).GetQwordAt(ctx, connect.NewRequest(&pb.GetQwordAtRequest{Address: addr}))
			if err != nil {
				return memoryResult{}, err
			}
			return memoryResult{"value", resp.Msg.GetValue(), resp.Msg.GetError()}, nil
		},
		"byte": func() (memoryResult, error) {
			resp, err := (*client.Analysis).DataReadByte(ctx, connect.NewRequest(&pb.DataReadByteRequest{Address: addr}))
			if err != nil {
				return memoryResult{}, err
			}
			return memoryResult{"value", resp.Msg.GetValue(), resp.Msg.GetError()}, nil
		},
		"bytes": func() (memoryResult, error) {
			size := args.Size
			if size == 0 {
				size = 16
			}
			resp, err := (*client.Analysis).GetBytes(ctx, connect.NewRequest(&pb.GetBytesRequest{Address: addr, Size: size}))
			if err != nil {
				return memoryResult{}, err
			}
			return memoryResult{"data", resp.Msg.Data, resp.Msg.GetError()}, nil
		},
	}

	fetch, ok := fetchers[format]
	if !ok {
		return nil, fmt.Errorf("invalid format %q: use bytes, dword, qword, byte, or string", format), nil
	}
	res, err := fetch()
	if err != nil {
		return nil, s.logAndReturnError("read_memory "+format+" RPC", err), nil
	}
	if res.ideErr != "" {
		return nil, s.logAndReturnError("read_memory "+format, errors.New(res.ideErr)), nil
	}
	body, _ := json.Marshal(map[string]any{res.envelopeKey: res.value})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}
