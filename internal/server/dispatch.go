package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) query(ctx context.Context, req *mcp.CallToolRequest, args QueryRequest) (*mcp.CallToolResult, any, error) {
	switch args.Category {
	case "functions":
		return s.getFunctions(ctx, req, GetFunctionsRequest{
			SessionID: args.SessionID, Offset: args.Offset, Limit: args.Limit,
			Regex: args.Regex, CaseSens: args.CaseSensitive, NamedOnly: args.NamedOnly,
		})
	case "imports":
		return s.getImports(ctx, req, GetImportsRequest{
			SessionID: args.SessionID, Offset: args.Offset, Limit: args.Limit,
			Module: args.Module, Regex: args.Regex, CaseSens: args.CaseSensitive,
		})
	case "exports":
		return s.getExports(ctx, req, GetExportsRequest{
			SessionID: args.SessionID, Offset: args.Offset, Limit: args.Limit,
			Regex: args.Regex, CaseSens: args.CaseSensitive,
		})
	case "strings":
		return s.getStrings(ctx, req, GetStringsRequest{
			SessionID: args.SessionID, Offset: args.Offset, Limit: args.Limit,
			Regex: args.Regex, CaseSens: args.CaseSensitive,
		})
	case "globals":
		return s.getGlobals(ctx, req, GetGlobalsRequest{
			SessionID: args.SessionID, Regex: args.Regex, CaseSensitive: args.CaseSensitive,
			Offset: args.Offset, Limit: args.Limit,
		})
	case "segments":
		return s.getSegments(ctx, req, GetSegmentsRequest{SessionID: args.SessionID})
	case "structs":
		return s.getStructs(ctx, req, GetStructsRequest{
			SessionID: args.SessionID, Name: args.Name,
			Regex: args.Regex, CaseSensitive: args.CaseSensitive,
		})
	case "enums":
		return s.getEnums(ctx, req, GetEnumsRequest{
			SessionID: args.SessionID, Name: args.Name,
			Regex: args.Regex, CaseSensitive: args.CaseSensitive,
		})
	case "entry_point":
		return s.getEntryPoint(ctx, req, GetEntryPointRequest{SessionID: args.SessionID})
	default:
		return nil, fmt.Errorf("invalid category %q: use functions, imports, exports, strings, globals, segments, structs, enums, or entry_point", args.Category), nil
	}
}

func (s *Server) getReferences(ctx context.Context, req *mcp.CallToolRequest, args GetReferencesRequest) (*mcp.CallToolResult, any, error) {
	mode := args.Mode
	if mode == "" {
		mode = "code"
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}
	switch mode {
	case "code":
		switch args.Direction {
		case "", "to", "from", "both":
		default:
			return nil, fmt.Errorf("invalid direction %q: use to, from, or both", args.Direction), nil
		}
		return s.getXRefs(ctx, req, GetXRefsRequest{
			SessionID: args.SessionID, Address: addr, Direction: args.Direction,
		})
	case "data":
		if args.Direction != "" {
			return nil, errors.New("direction is only valid for mode=code (data references have no direction)"), nil
		}
		return s.getDataRefs(ctx, req, DataRefRequest{
			SessionID: args.SessionID, Address: addr,
		})
	case "string":
		if args.Direction != "" {
			return nil, errors.New("direction is only valid for mode=code (string references have no direction)"), nil
		}
		return s.getStringXRefs(ctx, req, StringXRefRequest{
			SessionID: args.SessionID, Address: addr,
		})
	default:
		return nil, fmt.Errorf("invalid mode %q: use code, data, or string", mode), nil
	}
}

func (s *Server) search(ctx context.Context, req *mcp.CallToolRequest, args SearchRequest) (*mcp.CallToolResult, any, error) {
	start, err := parseAddrDefault(args.Start, 0)
	if err != nil {
		return nil, err, nil
	}
	end, err := parseAddrDefault(args.End, 0)
	if err != nil {
		return nil, err, nil
	}
	switch args.Mode {
	case "text":
		return s.findText(ctx, req, FindTextRequest{
			SessionID: args.SessionID, Start: start, End: end,
			Needle: args.Needle, CaseSensitive: args.CaseSensitive, Unicode: args.Unicode,
		})
	case "binary":
		return s.findBinary(ctx, req, FindBinaryRequest{
			SessionID: args.SessionID, Start: start, End: end,
			Pattern: args.Pattern, SearchUp: args.SearchUp,
		})
	default:
		return nil, fmt.Errorf("invalid mode %q: use text or binary", args.Mode), nil
	}
}

func (s *Server) inspect(ctx context.Context, req *mcp.CallToolRequest, args InspectRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("inspect", args.SessionID, map[string]any{"address": args.Address})
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "inspect")
	if err != nil {
		return nil, err, nil
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}

	results, errs := runLabeled(map[string]func() (any, error){
		"name": func() (any, error) {
			resp, err := (*client.Analysis).GetName(ctx, connect.NewRequest(&pb.GetNameRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			return resp.Msg.GetName(), nil
		},
		"type": func() (any, error) {
			resp, err := (*client.Analysis).GetTypeAt(ctx, connect.NewRequest(&pb.GetTypeAtRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			return resp.Msg, nil
		},
		"comment": func() (any, error) {
			resp, err := (*client.Analysis).GetComment(ctx, connect.NewRequest(&pb.GetCommentRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			return resp.Msg.GetComment(), nil
		},
		"func_info": func() (any, error) {
			resp, err := (*client.Analysis).GetFunctionInfo(ctx, connect.NewRequest(&pb.GetFunctionInfoRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			return resp.Msg, nil
		},
		"insn_len": func() (any, error) {
			resp, err := (*client.Analysis).GetInstructionLength(ctx, connect.NewRequest(&pb.GetInstructionLengthRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			return resp.Msg.GetLength(), nil
		},
	})
	// Robust to adding/removing inspect sub-RPCs above: trigger only when
	// every task errored, not on a hardcoded count.
	if len(results) == 0 {
		return nil, errors.New("all inspect RPCs failed — worker may be unhealthy"), nil
	}

	// Preserve the downstream formatting's data/failed contract: results holds
	// the successful values; failed marks keys whose RPC errored.
	data := results
	failed := make(map[string]bool, len(errs))
	for k := range errs {
		failed[k] = true
	}

	var b strings.Builder
	fmt.Fprintf(&b, "0x%x\n", addr)

	// A failed sub-RPC is surfaced explicitly ("(lookup failed)") so it is not
	// confused with a successful-but-empty result, which stays omitted.
	if name, ok := data["name"].(string); ok && name != "" {
		fmt.Fprintf(&b, "name: %s\n", name)
	} else if failed["name"] {
		b.WriteString("name: (lookup failed)\n")
	}

	if typeResp, ok := data["type"].(*pb.GetTypeAtResponse); ok && typeResp.GetHasType() {
		fmt.Fprintf(&b, "type: %s  [%s, %d bytes]\n",
			typeResp.GetType(), typeKindStr(typeResp), typeResp.GetSize())
	} else if failed["type"] {
		b.WriteString("type: (lookup failed)\n")
	}

	if comment, ok := data["comment"].(string); ok && comment != "" {
		fmt.Fprintf(&b, "comment: %s\n", comment)
	} else if failed["comment"] {
		b.WriteString("comment: (lookup failed)\n")
	}

	if info, ok := data["func_info"].(*pb.GetFunctionInfoResponse); ok {
		fmt.Fprintf(&b, "bounds: 0x%x..0x%x  (%d bytes)\n",
			info.GetStart(), info.GetEnd(), info.GetSize())
		var details []string
		if cc := info.GetCallingConvention(); cc != "" {
			details = append(details, "cc: "+cc)
		}
		if rt := info.GetReturnType(); rt != "" {
			details = append(details, "ret: "+rt)
		}
		if na := info.GetNumArgs(); na > 0 {
			details = append(details, fmt.Sprintf("args: %d", na))
		}
		if fs := info.GetFrameSize(); fs > 0 {
			details = append(details, fmt.Sprintf("frame: %d", fs))
		}
		if len(details) > 0 {
			b.WriteString(strings.Join(details, "  ") + "\n")
		}
	} else if failed["func_info"] {
		b.WriteString("func_info: (lookup failed)\n")
	}

	if length, ok := data["insn_len"].(uint32); ok && length > 0 {
		fmt.Fprintf(&b, "insn: %d bytes\n", length)
	} else if failed["insn_len"] {
		b.WriteString("insn: (lookup failed)\n")
	}

	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: textResult(b.String())}}}, nil, nil
}

func (s *Server) setMetadata(ctx context.Context, req *mcp.CallToolRequest, args SetMetadataRequest) (*mcp.CallToolResult, any, error) {
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}
	switch args.Action {
	case "set_name":
		if strings.TrimSpace(args.Name) == "" {
			return nil, errors.New("name is required for action set_name"), nil
		}
		return s.setName(ctx, req, SetNameRequest{
			SessionID: args.SessionID, Address: addr, Name: args.Name,
		})
	case "delete_name":
		return s.deleteName(ctx, req, DeleteNameRequest{
			SessionID: args.SessionID, Address: addr,
		})
	case "set_comment":
		funcAddr, err := parseAddrDefault(args.FunctionAddress, 0)
		if err != nil {
			return nil, err, nil
		}
		return s.setComment(ctx, req, SetCommentRequest{
			SessionID: args.SessionID, Address: addr,
			Comment: args.Comment, Scope: args.Scope,
			Repeatable: args.Repeatable, FunctionAddress: funcAddr,
		})
	default:
		return nil, fmt.Errorf("invalid action %q: use set_name, delete_name, or set_comment", args.Action), nil
	}
}

func (s *Server) setType(ctx context.Context, req *mcp.CallToolRequest, args SetTypeRequest) (*mcp.CallToolResult, any, error) {
	switch args.Target {
	case "function":
		addr, err := parseAddr(args.Address)
		if err != nil {
			return nil, fmt.Errorf("address is required for target function: %v", err), nil
		}
		if strings.TrimSpace(args.Prototype) == "" {
			return nil, errors.New("prototype is required for target function (e.g. \"int __fastcall foo(int a)\")"), nil
		}
		return s.setFunctionType(ctx, req, SetFunctionTypeRequest{
			SessionID: args.SessionID, Address: addr, Prototype: args.Prototype,
		})
	case "global":
		addr, err := parseAddr(args.Address)
		if err != nil {
			return nil, fmt.Errorf("address is required for target global: %v", err), nil
		}
		if strings.TrimSpace(args.Type) == "" {
			return nil, errors.New("type is required for target global (C-style type, e.g. \"int\")"), nil
		}
		return s.setGlobalType(ctx, req, SetGlobalTypeRequest{
			SessionID: args.SessionID, Address: addr, Type: args.Type,
		})
	case "lvar":
		faddr, err := parseAddr(args.FunctionAddress)
		if err != nil {
			return nil, fmt.Errorf("function_address is required for target lvar: %v", err), nil
		}
		if strings.TrimSpace(args.LvarName) == "" {
			return nil, errors.New("lvar_name is required for target lvar"), nil
		}
		if strings.TrimSpace(args.Type) == "" {
			return nil, errors.New("type is required for target lvar (C-style type, e.g. \"int\")"), nil
		}
		return s.setLvarType(ctx, req, SetLvarTypeRequest{
			SessionID: args.SessionID, FunctionAddress: faddr,
			LvarName: args.LvarName, LvarType: args.Type,
		})
	default:
		return nil, fmt.Errorf("invalid target %q: use function, global, or lvar", args.Target), nil
	}
}

func (s *Server) importMetadata(ctx context.Context, req *mcp.CallToolRequest, args ImportMetadataRequest) (*mcp.CallToolResult, any, error) {
	switch args.Format {
	case "il2cpp":
		return s.importIl2cpp(ctx, req, ImportIl2cppRequest{
			SessionID: args.SessionID, ScriptPath: args.ScriptPath,
			Il2cppPath: args.Il2cppPath, Fields: args.Fields,
		})
	case "flutter":
		return s.importFlutter(ctx, req, ImportFlutterRequest{
			SessionID: args.SessionID, MetaJsonPath: args.MetaJsonPath,
		})
	default:
		return nil, fmt.Errorf("invalid format %q: use il2cpp or flutter", args.Format), nil
	}
}
