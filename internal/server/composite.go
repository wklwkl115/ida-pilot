package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/internal/session"
	"github.com/wklwkl115/ida-pilot/internal/worker"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const surveyTopN = 20

func (s *Server) surveyBinary(ctx context.Context, req *mcp.CallToolRequest, args SurveyBinaryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("survey_binary", args.SessionID, nil)

	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "survey_binary")
	if err != nil {
		return nil, err, nil
	}

	cache := s.getSessionCache(sess.ID)

	// Each survey sub-RPC gets the same bounded timeout; withTimeout adapts a
	// context-taking fetch into the bare func() the parallel runner expects.
	const surveyFetchTimeout = 30 * time.Second
	withTimeout := func(fn func(context.Context) (any, error)) func() (any, error) {
		return func() (any, error) {
			fctx, cancel := context.WithTimeout(ctx, surveyFetchTimeout)
			defer cancel()
			return fn(fctx)
		}
	}

	data, errs := runLabeled(map[string]func() (any, error){
		"segments": withTimeout(func(fctx context.Context) (any, error) {
			segs, _, err := cache.loadSegments(sess.ID, s.logger, func() ([]*pb.Segment, error) {
				resp, err := (*client.Analysis).GetSegments(fctx, connect.NewRequest(&pb.GetSegmentsRequest{}))
				if err != nil {
					return nil, err
				}
				if e := resp.Msg.GetError(); e != "" {
					return nil, errors.New(e)
				}
				return resp.Msg.GetSegments(), nil
			})
			return segs, err
		}),
		"functions": withTimeout(func(fctx context.Context) (any, error) {
			d, _, e := cache.loadFunctions(sess.ID, s.logger, func() ([]*pb.Function, error) {
				return s.fetchAllFunctions(fctx, client, nil)
			})
			return d, e
		}),
		"imports": withTimeout(func(fctx context.Context) (any, error) {
			d, _, e := cache.loadImports(sess.ID, s.logger, func() ([]*pb.Import, error) {
				return s.fetchAllImports(fctx, client, nil)
			})
			return d, e
		}),
		"exports": withTimeout(func(fctx context.Context) (any, error) {
			d, _, e := cache.loadExports(sess.ID, s.logger, func() ([]*pb.Export, error) {
				return s.fetchAllExports(fctx, client, nil)
			})
			return d, e
		}),
		"strings": withTimeout(func(fctx context.Context) (any, error) {
			resp, err := (*client.Analysis).GetStrings(fctx, connect.NewRequest(&pb.GetStringsRequest{
				Offset: 0,
				Limit:  int32(surveyTopN),
			}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			total := resp.Msg.GetTotal()
			items := resp.Msg.GetStrings()
			if total == 0 && len(items) > 0 {
				total = int32(len(items))
			}
			return map[string]any{"count": total, "top": mapStringItems(items)}, nil
		}),
		"entry_point": withTimeout(func(fctx context.Context) (any, error) {
			resp, err := (*client.Analysis).GetEntryPoint(fctx, connect.NewRequest(&pb.GetEntryPointRequest{}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			return resp.Msg.GetAddress(), nil
		}),
		"info": withTimeout(func(fctx context.Context) (any, error) {
			resp, err := (*client.SessionCtrl).GetSessionInfo(fctx, connect.NewRequest(&pb.GetSessionInfoRequest{}))
			if err != nil {
				return nil, err
			}
			return resp.Msg, nil
		}),
	})

	var failed []string
	for k, e := range errs {
		s.debugf("survey_binary: %s: %v", k, e)
		failed = append(failed, k)
	}
	sort.Strings(failed)

	survey := map[string]any{
		"binary_path": sess.BinaryPath,
	}

	// Surface sub-RPCs that failed so a missing section is distinguishable from
	// a section that genuinely has no entries (both omit their key otherwise).
	if len(failed) > 0 {
		survey["failed_sections"] = failed
	}

	if ep, ok := data["entry_point"]; ok {
		survey["entry_point"] = hexAddr(anyToUint64(ep))
	}
	if info, ok := data["info"].(*pb.GetSessionInfoResponse); ok {
		survey["has_decompiler"] = info.GetHasDecompiler()
		survey["auto_state"] = info.GetAutoState()
		survey["auto_running"] = info.GetAutoRunning()
	}
	if segs, ok := data["segments"].([]*pb.Segment); ok {
		out := make([]map[string]any, 0, len(segs))
		for _, seg := range segs {
			out = append(out, map[string]any{
				"name": seg.GetName(), "start": hexAddr(seg.GetStart()), "end": hexAddr(seg.GetEnd()),
				"permissions": seg.GetPermissions(), "class": seg.GetSegClass(),
			})
		}
		survey["segments"] = out
	}
	if funcs, ok := data["functions"].([]*pb.Function); ok {
		var named []*pb.Function
		for _, fn := range funcs {
			if !isAutoNamed(fn.Name) {
				named = append(named, fn)
			}
		}
		top := named
		if len(top) > surveyTopN {
			top = top[:surveyTopN]
		}
		survey["functions"] = map[string]any{
			"total":     len(funcs),
			"named":     len(named),
			"top_named": mapFunctionItems(top),
		}
	}
	if imps, ok := data["imports"].([]*pb.Import); ok {
		top := imps
		if len(top) > surveyTopN {
			top = top[:surveyTopN]
		}
		survey["imports"] = map[string]any{"count": len(imps), "top": mapImportItems(top)}
	}
	if exps, ok := data["exports"].([]*pb.Export); ok {
		top := exps
		if len(top) > surveyTopN {
			top = top[:surveyTopN]
		}
		survey["exports"] = map[string]any{"count": len(exps), "top": mapExportItems(top)}
	}
	if strs, ok := data["strings"].(map[string]any); ok {
		survey["strings"] = strs
	}

	// Point the agent at the natural next action with a concrete address. The
	// recommended path lives in the data (which agents read) rather than only in
	// the tool description (which they skim).
	if ep, ok := survey["entry_point"].(string); ok {
		survey["next_step"] = fmt.Sprintf("call analyze_function(address=%s) on the entry point, or analyze_functions for several named functions", ep)
	} else {
		survey["next_step"] = "call analyze_function on an address of interest, or analyze_functions for several"
	}

	s.promoteToTier(2)

	body, _ := json.Marshal(survey)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) analyzeSingleFunction(ctx context.Context, sess *session.Session, client *worker.WorkerClient, addr uint64) map[string]any {
	cache := s.getSessionCache(sess.ID)

	data, errs := runLabeled(map[string]func() (any, error){
		"decompiled": func() (any, error) {
			if code, ok := cache.getDecomp(addr); ok {
				return code, nil
			}
			resp, err := (*client.Analysis).GetDecompiled(ctx, connect.NewRequest(&pb.GetDecompiledRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			code := resp.Msg.GetCode()
			cache.setDecomp(addr, code)
			return code, nil
		},
		"info": func() (any, error) {
			resp, err := (*client.Analysis).GetFunctionInfo(ctx, connect.NewRequest(&pb.GetFunctionInfoRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			if e := resp.Msg.GetError(); e != "" {
				return nil, errors.New(e)
			}
			return resp.Msg, nil
		},
		"xrefs": func() (any, error) {
			if entry, ok := cache.getXRefs(addr); ok {
				return entry, nil
			}
			xres, xerrs := runLabeled(map[string]func() (any, error){
				"to": func() (any, error) {
					resp, err := (*client.Analysis).GetXRefsTo(ctx, connect.NewRequest(&pb.GetXRefsToRequest{Address: addr}))
					if err != nil {
						return nil, err
					}
					if e := resp.Msg.GetError(); e != "" {
						return nil, errors.New(e)
					}
					return resp.Msg.GetXrefs(), nil
				},
				"from": func() (any, error) {
					resp, err := (*client.Analysis).GetXRefsFrom(ctx, connect.NewRequest(&pb.GetXRefsFromRequest{Address: addr}))
					if err != nil {
						return nil, err
					}
					if e := resp.Msg.GetError(); e != "" {
						return nil, errors.New(e)
					}
					return resp.Msg.GetXrefs(), nil
				},
			})
			// Match the prior all-or-nothing xref semantics: either direction's
			// failure aborts the xref load (and surfaces as analyze_function's
			// xrefs_error), so xrefsEntry is never cached half-populated.
			// errors.Join is deterministic and surfaces both directions when
			// both failed; ranging over the map was order-dependent.
			if xerr := errors.Join(xerrs["to"], xerrs["from"]); xerr != nil {
				return nil, xerr
			}
			entry := &xrefsEntry{}
			if to, ok := xres["to"].([]*pb.XRef); ok {
				tuples := make([][]any, 0, len(to))
				for _, x := range to {
					tuples = append(tuples, []any{x.GetFrom(), x.GetType()})
				}
				entry.to = tuples
			}
			if from, ok := xres["from"].([]*pb.XRef); ok {
				tuples := make([][]any, 0, len(from))
				for _, x := range from {
					tuples = append(tuples, []any{x.GetTo(), x.GetType()})
				}
				entry.from = tuples
			}
			cache.setXRefs(addr, entry)
			return entry, nil
		},
		"comment": func() (any, error) {
			resp, err := (*client.Analysis).GetFuncComment(ctx, connect.NewRequest(&pb.GetFuncCommentRequest{Address: addr}))
			if err != nil {
				return nil, err
			}
			return resp.Msg.GetComment(), nil
		},
	})

	for k, e := range errs {
		s.debugf("analyze_function: %s: %v", k, e)
	}

	result := map[string]any{}

	if code, ok := data["decompiled"].(string); ok {
		result["decompilation"] = code
	} else if e, ok := errs["decompiled"]; ok {
		result["decompilation_error"] = e.Error()
	}

	if info, ok := data["info"].(*pb.GetFunctionInfoResponse); ok {
		result["name"] = info.GetName()
		result["start"] = hexAddr(info.GetStart())
		result["end"] = hexAddr(info.GetEnd())
		result["size"] = info.GetSize()
		if cc := info.GetCallingConvention(); cc != "" {
			result["calling_convention"] = cc
		}
		if rt := info.GetReturnType(); rt != "" {
			result["return_type"] = rt
		}
		if na := info.GetNumArgs(); na > 0 {
			result["num_args"] = na
		}
		flags := info.GetFlags()
		fmap := map[string]any{}
		if flags.GetIsLibrary() {
			fmap["is_library"] = true
		}
		if flags.GetIsThunk() {
			fmap["is_thunk"] = true
		}
		if flags.GetNoReturn() {
			fmap["no_return"] = true
		}
		if len(fmap) > 0 {
			result["flags"] = fmap
		}
	}

	if entry, ok := data["xrefs"].(*xrefsEntry); ok {
		if len(entry.to) > 0 {
			result["xrefs_to"] = hexAddrTuples(entry.to)
		}
		if len(entry.from) > 0 {
			result["xrefs_from"] = hexAddrTuples(entry.from)
		}
	} else if e, ok := errs["xrefs"]; ok {
		result["xrefs_error"] = e.Error()
	}

	if comment, ok := data["comment"].(string); ok && comment != "" {
		result["comment"] = comment
	}

	cache.markVisited(addr, time.Now().Unix(), "")
	return result
}

func (s *Server) analyzeFunction(ctx context.Context, req *mcp.CallToolRequest, args AnalyzeFunctionRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("analyze_function", args.SessionID, map[string]any{"address": args.Address})

	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "analyze_function")
	if err != nil {
		return nil, err, nil
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}

	result := s.analyzeSingleFunction(ctx, sess, client, addr)
	s.promoteToTier(2)
	body, _ := json.Marshal(result)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

const maxBatchAnalyze = 10

func (s *Server) analyzeFunctions(ctx context.Context, req *mcp.CallToolRequest, args AnalyzeFunctionsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("analyze_functions", args.SessionID, map[string]any{"count": len(args.Addresses)})

	if len(args.Addresses) == 0 {
		return nil, errors.New("addresses required"), nil
	}
	if len(args.Addresses) > maxBatchAnalyze {
		return nil, fmt.Errorf("max %d functions per batch", maxBatchAnalyze), nil
	}

	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "analyze_functions")
	if err != nil {
		return nil, err, nil
	}

	// Per-item degradation: a malformed address yields a targeted error in its
	// own slot rather than sinking the batch. Parsing runs inside the parallel
	// fn; parallelMap preserves input order.
	results := parallelMap(args.Addresses, func(a string) map[string]any {
		addr, perr := parseAddr(a)
		if perr != nil {
			return map[string]any{"address": a, "error": perr.Error()}
		}
		return s.analyzeSingleFunction(ctx, sess, client, addr)
	})

	body, _ := json.Marshal(map[string]any{"functions": results})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) annotateFunction(ctx context.Context, req *mcp.CallToolRequest, args AnnotateFunctionRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("annotate_function", args.SessionID, map[string]any{"address": args.Address})

	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "annotate_function")
	if err != nil {
		return nil, err, nil
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}

	// Build batch request — single HTTP call replaces N sequential RPCs
	batchReq := map[string]any{"address": addr}
	if len(args.Retypes) > 0 {
		retypes := make([]map[string]string, len(args.Retypes))
		for i, rt := range args.Retypes {
			retypes[i] = map[string]string{"name": rt.Name, "type": rt.Type}
		}
		batchReq["retypes"] = retypes
	}
	if len(args.Renames) > 0 {
		renames := make([]map[string]string, len(args.Renames))
		for i, rn := range args.Renames {
			renames[i] = map[string]string{"current": rn.Current, "new": rn.New}
		}
		batchReq["renames"] = renames
	}
	if args.Name != "" {
		batchReq["name"] = args.Name
	}
	if args.Comment != "" {
		batchReq["comment"] = args.Comment
	}
	if len(args.DecompComments) > 0 {
		dcs := make([]map[string]any, len(args.DecompComments))
		for i, dc := range args.DecompComments {
			dcAddr, err := parseAddr(dc.Address)
			if err != nil {
				return nil, err, nil
			}
			dcs[i] = map[string]any{"address": dcAddr, "comment": dc.Comment}
		}
		batchReq["decompiler_comments"] = dcs
	}

	payload, _ := json.Marshal(batchReq)
	respBody, err := s.workerPOST(ctx, client, "/batch_annotate", payload, "annotate_function")
	if err != nil {
		return nil, err, nil
	}

	// Invalidate caches: decompilation always changes after annotation.
	sessionCache := s.getSessionCache(sess.ID)
	if args.Name != "" {
		// Renaming the function invalidates its own decomp and the function
		// list. Callers' decomp is still valid because Hex-Rays resolves
		// names dynamically from the database on each text conversion.
		sessionCache.invalidateFunctions()
		sessionCache.invalidateDecomp(addr)
	} else {
		// Lvar/comment edits only affect this function's pseudocode.
		sessionCache.invalidateDecomp(addr)
	}

	// Parse and re-marshal to ensure consistent format with address field
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, s.logAndReturnError("annotate_function parse response", err), nil
	}
	result["address"] = hexAddr(addr)

	body, _ := json.Marshal(result)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) setAnalysisNote(ctx context.Context, req *mcp.CallToolRequest, args SetAnalysisNoteRequest) (*mcp.CallToolResult, any, error) {
	sess, err := s.resolveSession(args.SessionID)
	if err != nil {
		return nil, err, nil
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}
	sess.Touch()
	cache := s.getSessionCache(sess.ID)
	cache.setNote(addr, time.Now().Unix(), args.Note)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil, nil
}

func (s *Server) getAnalysisContext(ctx context.Context, req *mcp.CallToolRequest, args GetAnalysisContextRequest) (*mcp.CallToolResult, any, error) {
	sess, err := s.resolveSession(args.SessionID)
	if err != nil {
		return nil, err, nil
	}
	sess.Touch()
	cache := s.getSessionCache(sess.ID)
	visited := cache.getVisited()

	entries := make([]map[string]any, 0, len(visited))
	for addr, note := range visited {
		entry := map[string]any{"address": hexAddr(addr), "t": note.Timestamp}
		if note.Note != "" {
			entry["note"] = note.Note
		}
		entries = append(entries, entry)
	}

	body, _ := json.Marshal(map[string]any{"visited": entries})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) pruneContext(ctx context.Context, req *mcp.CallToolRequest, args PruneContextRequest) (*mcp.CallToolResult, any, error) {
	sess, err := s.resolveSession(args.SessionID)
	if err != nil {
		return nil, err, nil
	}
	sess.Touch()

	outputsCleared := s.outputs.clear()
	cache := s.getSessionCache(sess.ID)
	cachesPruned := cache.pruneNotedFunctions()

	text := fmt.Sprintf("Pruned %d cached outputs, %d noted function caches", outputsCleared, cachesPruned)
	s.logger.Printf("[PruneContext] session=%s %s", sess.ID, text)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) pyEval(ctx context.Context, req *mcp.CallToolRequest, args PyEvalRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("py_eval", args.SessionID, map[string]any{"code_len": len(args.Code)})

	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "py_eval")
	if err != nil {
		return nil, err, nil
	}

	payload, _ := json.Marshal(map[string]any{
		"code": args.Code,
	})
	respBody, err := s.workerPOST(ctx, client, "/py_eval", payload, "py_eval")
	if err != nil {
		return nil, err, nil
	}

	// py_eval can rename/retype/patch the database directly, bypassing the
	// explicit invalidation that the typed write tools perform. Conservatively
	// drop the mutable caches so later reads reflect any edits; the agent opts
	// out with read_only=true when the code only inspects state.
	if !args.ReadOnly {
		cache := s.getSessionCache(sess.ID)
		cache.invalidateFunctions()
		cache.invalidateAllDecomp()
		cache.invalidateAllXRefs()
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(respBody)}},
	}, nil, nil
}
