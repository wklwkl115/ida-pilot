package server

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/internal/worker"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var okResult = &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}

func (s *Server) setComment(ctx context.Context, req *mcp.CallToolRequest, args SetCommentRequest) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.Comment) == "" {
		return nil, errors.New("comment is required"), nil
	}
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "set_comment")
	if err != nil {
		return nil, err, nil
	}
	scope := args.Scope
	if scope == "" {
		scope = "address"
	}
	s.logToolInvocation("set_comment", sess.ID, map[string]any{"address": args.Address, "scope": scope})

	var success bool
	switch scope {
	case "function":
		resp, err := (*client.Analysis).SetFuncComment(ctx, connect.NewRequest(&pb.SetFuncCommentRequest{
			Address: args.Address, Comment: args.Comment,
		}))
		if err != nil {
			return nil, s.logAndReturnError("set_comment RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("set_comment", errors.New(e)), nil
		}
		success = resp.Msg.GetSuccess()

	case "decompiler":
		if args.FunctionAddress == 0 {
			return nil, errors.New("function_address required for decompiler scope"), nil
		}
		resp, err := (*client.Analysis).SetDecompilerComment(ctx, connect.NewRequest(&pb.SetDecompilerCommentRequest{
			FunctionAddress: args.FunctionAddress, Address: args.Address, Comment: args.Comment,
		}))
		if err != nil {
			return nil, s.logAndReturnError("set_comment RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("set_comment", errors.New(e)), nil
		}
		success = resp.Msg.GetSuccess()

	default: // "address"
		resp, err := (*client.Analysis).SetComment(ctx, connect.NewRequest(&pb.SetCommentRequest{
			Address: args.Address, Comment: args.Comment, Repeatable: args.Repeatable,
		}))
		if err != nil {
			return nil, s.logAndReturnError("set_comment RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("set_comment", errors.New(e)), nil
		}
		success = resp.Msg.GetSuccess()
	}

	if !success {
		return nil, errors.New("operation failed"), nil
	}
	// Comments shown in pseudocode invalidate that function's cached decomp.
	// Function-scope comments (idc.set_func_cmt) appear in the listing, not
	// pseudocode, so they don't require invalidation.
	if scope == "decompiler" {
		cache := s.getSessionCache(sess.ID)
		cache.invalidateDecomp(args.FunctionAddress)
	}
	return okResult, nil, nil
}

func (s *Server) setName(ctx context.Context, req *mcp.CallToolRequest, args SetNameRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_name", args.SessionID, map[string]any{"address": args.Address, "name": args.Name})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "set_name")
	if err != nil {
		return nil, err, nil
	}

	// Capture the old name before renaming so we can do targeted decomp cache
	// invalidation: only cached pseudocode that contains the old name is stale.
	oldName := s.fetchName(ctx, client, args.Address)

	resp, err := (*client.Analysis).SetName(ctx, connect.NewRequest(&pb.SetNameRequest{
		Address: args.Address, Name: args.Name,
	}))
	if err != nil {
		return nil, s.logAndReturnError("set_name RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("set_name", errors.New(msgErr)), nil
	}
	if !resp.Msg.GetSuccess() {
		return nil, errors.New("operation failed"), nil
	}
	cache := s.getSessionCache(sess.ID)

	// Invalidate decomp cache surgically. A function rename only makes that
	// function's cached pseudocode stale (its header line changes). A data
	// label rename can render differently inside any cached decomp that
	// references it, so we search and evict only the entries containing the
	// old name. Check isCachedFunction BEFORE invalidateFunctions since the
	// latter clears the function list.
	isFunc := cache.isCachedFunction(args.Address)
	cache.invalidateFunctions()

	if isFunc {
		cache.invalidateDecomp(args.Address)
	} else if oldName != "" {
		n := cache.invalidateDecompByOldName(oldName)
		if n > 0 {
			s.debugf("[Cache] rename at 0x%x (old=%q): invalidated %d decomp entries", args.Address, oldName, n)
		}
	}
	return okResult, nil, nil
}

// fetchName gets the current name at an address from the worker (best-effort).
func (s *Server) fetchName(ctx context.Context, client *worker.WorkerClient, addr uint64) string {
	resp, err := (*client.Analysis).GetName(ctx, connect.NewRequest(&pb.GetNameRequest{Address: addr}))
	if err != nil || resp.Msg == nil {
		if err != nil {
			s.debugf("[Cache] fetchName failed for 0x%x: %v", addr, err)
		}
		return ""
	}
	return resp.Msg.GetName()
}

func (s *Server) deleteName(ctx context.Context, req *mcp.CallToolRequest, args DeleteNameRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("delete_name", args.SessionID, map[string]any{"address": args.Address})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "delete_name")
	if err != nil {
		return nil, err, nil
	}

	oldName := s.fetchName(ctx, client, args.Address)

	resp, err := (*client.Analysis).DeleteName(ctx, connect.NewRequest(&pb.DeleteNameRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndReturnError("delete_name RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("delete_name", errors.New(msgErr)), nil
	}
	if !resp.Msg.GetSuccess() {
		return nil, errors.New("operation failed"), nil
	}
	cache := s.getSessionCache(sess.ID)

	isFunc := cache.isCachedFunction(args.Address)
	cache.invalidateFunctions()

	if isFunc {
		cache.invalidateDecomp(args.Address)
	} else if oldName != "" {
		n := cache.invalidateDecompByOldName(oldName)
		if n > 0 {
			s.debugf("[Cache] delete_name at 0x%x (old=%q): invalidated %d decomp entries", args.Address, oldName, n)
		}
	}
	return okResult, nil, nil
}

func (s *Server) setLvarType(ctx context.Context, req *mcp.CallToolRequest, args SetLvarTypeRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_lvar_type", args.SessionID, map[string]any{"function_address": args.FunctionAddress, "lvar": args.LvarName})
	if strings.TrimSpace(args.LvarType) == "" {
		return nil, errors.New("lvar_type is required"), nil
	}
	if args.FunctionAddress == 0 {
		return nil, errors.New("function_address is required"), nil
	}
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "set_lvar_type")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).SetLvarType(ctx, connect.NewRequest(&pb.SetLvarTypeRequest{
		FunctionAddress: args.FunctionAddress, LvarName: args.LvarName, LvarType: args.LvarType,
	}))
	if err != nil {
		return nil, s.logAndReturnError("set_lvar_type RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("set_lvar_type", errors.New(msgErr)), nil
	}
	if !resp.Msg.GetSuccess() {
		return nil, errors.New("operation failed"), nil
	}
	s.getSessionCache(sess.ID).invalidateDecomp(args.FunctionAddress)
	return okResult, nil, nil
}

func (s *Server) setGlobalType(ctx context.Context, req *mcp.CallToolRequest, args SetGlobalTypeRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_global_type", args.SessionID, map[string]any{"address": args.Address})
	if strings.TrimSpace(args.Type) == "" {
		return nil, errors.New("type is required"), nil
	}
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "set_global_type")
	if err != nil {
		return nil, err, nil
	}

	oldName := s.fetchName(ctx, client, args.Address)

	resp, err := (*client.Analysis).SetGlobalType(ctx, connect.NewRequest(&pb.SetGlobalTypeRequest{
		Address: args.Address, Type: args.Type,
	}))
	if err != nil {
		return nil, s.logAndReturnError("set_global_type RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("set_global_type", errors.New(msgErr)), nil
	}
	if !resp.Msg.GetSuccess() {
		return nil, errors.New("operation failed"), nil
	}
	if oldName != "" {
		cache := s.getSessionCache(sess.ID)
		n := cache.invalidateDecompByOldName(oldName)
		if n > 0 {
			s.debugf("[Cache] set_global_type at 0x%x: invalidated %d decomp entries containing %q", args.Address, n, oldName)
		}
	}
	return okResult, nil, nil
}

func (s *Server) setFunctionType(ctx context.Context, req *mcp.CallToolRequest, args SetFunctionTypeRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_function_type", args.SessionID, map[string]any{"address": args.Address})
	if strings.TrimSpace(args.Prototype) == "" {
		return nil, errors.New("prototype is required"), nil
	}
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "set_function_type")
	if err != nil {
		return nil, err, nil
	}

	oldName := s.fetchName(ctx, client, args.Address)

	resp, err := (*client.Analysis).SetFunctionType(ctx, connect.NewRequest(&pb.SetFunctionTypeRequest{
		Address: args.Address, Prototype: args.Prototype,
	}))
	if err != nil {
		return nil, s.logAndReturnError("set_function_type RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("set_function_type", errors.New(msgErr)), nil
	}
	if !resp.Msg.GetSuccess() {
		return nil, errors.New("operation failed"), nil
	}
	// Prototype changes affect this function's decomp and callers that
	// reference it by name. Invalidate the function and do an old-name
	// search to evict cached callers.
	cache := s.getSessionCache(sess.ID)
	cache.invalidateDecomp(args.Address)
	if oldName != "" {
		n := cache.invalidateDecompByOldName(oldName)
		if n > 0 {
			s.debugf("[Cache] set_function_type at 0x%x: invalidated %d decomp entries", args.Address, n)
		}
	}
	return okResult, nil, nil
}

func (s *Server) makeFunction(ctx context.Context, req *mcp.CallToolRequest, args MakeFunctionRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("make_function", args.SessionID, map[string]any{"address": args.Address})
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "make_function")
	if err != nil {
		return nil, err, nil
	}
	addr, err := parseAddr(args.Address)
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).MakeFunction(ctx, connect.NewRequest(&pb.MakeFunctionRequest{
		Address: addr,
	}))
	if err != nil {
		return nil, s.logAndReturnError("make_function RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("make_function", errors.New(msgErr)), nil
	}
	if !resp.Msg.GetSuccess() {
		return nil, errors.New("operation failed"), nil
	}
	// Creating a function adds it to the function list and may alter xrefs
	// pointing at that address. Existing decomp, imports, exports, strings,
	// and segments are unaffected.
	cache := s.getSessionCache(sess.ID)
	cache.invalidateFunctions()
	cache.invalidateAllXRefs()
	return okResult, nil, nil
}
