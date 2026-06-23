package server

import (
	"context"
	"fmt"
	"regexp"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Cross-session analysis tools ──

func (s *Server) crossReference(ctx context.Context, req *mcp.CallToolRequest, args CrossReferenceRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("cross_reference", "", map[string]any{
		"source": args.SourceSessionID,
		"target": args.TargetSessionID,
		"addr":   args.Address,
	})

	// Resolve both sessions independently
	srcSess, srcClient, err := s.resolveClientWait(ctx, req, args.SourceSessionID, "cross_reference")
	if err != nil {
		return nil, err, nil
	}
	tgtSess, tgtClient, err := s.resolveClientWait(ctx, req, args.TargetSessionID, "cross_reference")
	if err != nil {
		return nil, err, nil
	}

	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}

	// Step 1: Get the name at the address in the source binary.
	nameResp, err := (*srcClient.Analysis).GetName(ctx, connect.NewRequest(&pb.GetNameRequest{Address: addr}))
	if err != nil {
		return nil, s.logAndReturnError("cross_reference source GetName", err), nil
	}
	symbolName := nameResp.Msg.GetName()
	if symbolName == "" {
		// Try function name if regular name is empty.
		fnResp, fnErr := (*srcClient.Analysis).GetFunctionName(ctx, connect.NewRequest(&pb.GetFunctionNameRequest{Address: addr}))
		if fnErr == nil && fnResp.Msg != nil {
			symbolName = fnResp.Msg.GetName()
		}
	}
	if symbolName == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("no name found at 0x%x in source session %s", addr, srcSess.ID)},
			},
		}, nil, nil
	}

	// Step 2: Search for that name in the target binary across imports, exports,
	// function names, and strings.
	var matches []crossMatch

	if importsResp, err := (*tgtClient.Analysis).GetImports(ctx, connect.NewRequest(&pb.GetImportsRequest{})); err == nil && importsResp.Msg != nil {
		for _, imp := range importsResp.Msg.GetImports() {
			if imp.GetName() == symbolName {
				matches = append(matches, crossMatch{Category: "import", Address: imp.GetAddress(), Name: imp.GetName(), Module: imp.GetModule()})
			}
		}
	}

	if exportsResp, err := (*tgtClient.Analysis).GetExports(ctx, connect.NewRequest(&pb.GetExportsRequest{})); err == nil && exportsResp.Msg != nil {
		for _, exp := range exportsResp.Msg.GetExports() {
			if exp.GetName() == symbolName {
				matches = append(matches, crossMatch{Category: "export", Address: exp.GetAddress(), Name: exp.GetName()})
			}
		}
	}

	// Function-name matches catch non-imported functions sharing the name.
	if funcsResp, err := (*tgtClient.Analysis).GetFunctions(ctx, connect.NewRequest(&pb.GetFunctionsRequest{})); err == nil && funcsResp.Msg != nil {
		for _, fn := range funcsResp.Msg.GetFunctions() {
			if fn.GetName() == symbolName {
				matches = append(matches, crossMatch{Category: "function", Address: fn.GetAddress(), Name: fn.GetName()})
			}
		}
	}

	// fetchAllStrings paginates internally — single GetStrings calls silently
	// cap at maxPageLimit, missing matches past the first page.
	if allStrings, err := s.fetchAllStrings(ctx, tgtClient, nil); err == nil {
		for _, str := range allStrings {
			if str.GetValue() == symbolName {
				matches = append(matches, crossMatch{Category: "string", Address: str.GetAddress(), Name: str.GetValue()})
			}
		}
	}

	text := formatCrossReference(symbolName, srcSess.ID, tgtSess.ID, addr, matches)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) crossSearch(ctx context.Context, req *mcp.CallToolRequest, args CrossSearchRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("cross_search", "", map[string]any{
		"mode":   args.Mode,
		"regex":  args.Regex,
		"needle": args.Needle,
	})

	if args.Mode == "" {
		return nil, fmt.Errorf("mode is required: functions, imports, exports, or strings"), nil
	}

	// Determine which sessions to search.
	var sessionIDs []string
	if len(args.SessionIDs) > 0 {
		sessionIDs = args.SessionIDs
	} else {
		for _, sess := range s.registry.List() {
			sessionIDs = append(sessionIDs, sess.ID)
		}
	}
	if len(sessionIDs) == 0 {
		return nil, fmt.Errorf("no active sessions"), nil
	}

	// Compile the regex once before the per-session loop, surfacing a bad
	// pattern as a single error rather than once per session.
	pattern, err := compileRegex(args.Regex, true)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %v", err), nil
	}

	limit := args.Limit
	if limit <= 0 || limit > int32(maxPageLimit) {
		limit = 100
	}

	var results []crossSearchResult
	for _, sid := range sessionIDs {
		sess, client, err := s.resolveClientWait(ctx, req, sid, "cross_search")
		if err != nil {
			results = append(results, crossSearchResult{SessionID: sid, Error: err.Error()})
			continue
		}

		var items []crossMatch
		switch args.Mode {
		case "functions":
			if resp, rpcErr := (*client.Analysis).GetFunctions(ctx, connect.NewRequest(&pb.GetFunctionsRequest{})); rpcErr == nil && resp.Msg != nil {
				for _, fn := range resp.Msg.GetFunctions() {
					if matchFilter(fn.GetName(), pattern, args.Needle) {
						items = append(items, crossMatch{Address: fn.GetAddress(), Name: fn.GetName()})
					}
				}
			}
		case "imports":
			if resp, rpcErr := (*client.Analysis).GetImports(ctx, connect.NewRequest(&pb.GetImportsRequest{})); rpcErr == nil && resp.Msg != nil {
				for _, imp := range resp.Msg.GetImports() {
					if matchFilter(imp.GetName(), pattern, args.Needle) {
						items = append(items, crossMatch{Address: imp.GetAddress(), Name: imp.GetName(), Module: imp.GetModule()})
					}
				}
			}
		case "exports":
			if resp, rpcErr := (*client.Analysis).GetExports(ctx, connect.NewRequest(&pb.GetExportsRequest{})); rpcErr == nil && resp.Msg != nil {
				for _, exp := range resp.Msg.GetExports() {
					if matchFilter(exp.GetName(), pattern, args.Needle) {
						items = append(items, crossMatch{Address: exp.GetAddress(), Name: exp.GetName()})
					}
				}
			}
		case "strings":
			if allStrings, rpcErr := s.fetchAllStrings(ctx, client, nil); rpcErr == nil {
				for _, str := range allStrings {
					if matchFilter(str.GetValue(), pattern, args.Needle) {
						items = append(items, crossMatch{Address: str.GetAddress(), Value: str.GetValue()})
					}
				}
			}
		default:
			return nil, fmt.Errorf("invalid mode %q: use functions, imports, exports, or strings", args.Mode), nil
		}

		if len(items) > int(limit) {
			items = items[:limit]
		}
		results = append(results, crossSearchResult{
			SessionID:  sess.ID,
			BinaryPath: sess.BinaryPath,
			Items:      items,
		})
	}

	totalMatches := 0
	for _, r := range results {
		totalMatches += len(r.Items)
	}

	text := formatCrossSearch(args.Mode, totalMatches, results)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

// matchFilter returns true when name matches the filter criteria.
// needle is an exact-match override; pattern (when non-nil) is a precompiled regex.
func matchFilter(name string, pattern *regexp.Regexp, needle string) bool {
	if needle != "" {
		return name == needle
	}
	if pattern != nil {
		return pattern.MatchString(name)
	}
	return true
}
