package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) findBinary(ctx context.Context, req *mcp.CallToolRequest, args FindBinaryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("find_binary", args.SessionID, map[string]any{"pattern": args.Pattern})
	if strings.TrimSpace(args.Pattern) == "" {
		return nil, errors.New("pattern is required"), nil
	}
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "find_binary")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).FindBinary(ctx, connect.NewRequest(&pb.FindBinaryRequest{
		Start: args.Start, End: args.End, Pattern: args.Pattern, SearchUp: args.SearchUp,
	}))
	if err != nil {
		return nil, s.logAndReturnError("find_binary RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("find_binary", errors.New(msgErr)), nil
	}
	result, _ := json.Marshal(map[string]any{"addresses": resp.Msg.GetAddresses()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) findText(ctx context.Context, req *mcp.CallToolRequest, args FindTextRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("find_text", args.SessionID, map[string]any{"needle": args.Needle})
	if strings.TrimSpace(args.Needle) == "" {
		return nil, errors.New("needle is required"), nil
	}
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "find_text")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).FindText(ctx, connect.NewRequest(&pb.FindTextRequest{
		Start: args.Start, End: args.End, Needle: args.Needle,
		CaseSensitive: args.CaseSensitive, Unicode: args.Unicode,
	}))
	if err != nil {
		return nil, s.logAndReturnError("find_text RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("find_text", errors.New(msgErr)), nil
	}
	result, _ := json.Marshal(map[string]any{"addresses": resp.Msg.GetAddresses()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}
