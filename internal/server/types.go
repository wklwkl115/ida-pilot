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

func (s *Server) getGlobals(ctx context.Context, req *mcp.CallToolRequest, args GetGlobalsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_globals", args.SessionID, map[string]any{"regex": args.Regex})
	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_globals")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).GetGlobals(ctx, connect.NewRequest(&pb.GetGlobalsRequest{Regex: args.Regex, CaseSensitive: args.CaseSensitive}))
	if err != nil {
		return nil, s.logAndReturnError("get_globals RPC", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndReturnError("get_globals", errors.New(msgErr)), nil
	}
	globals := resp.Msg.GetGlobals()
	total := len(globals)
	offset := args.Offset
	if offset > total {
		offset = total
	}
	globals = globals[offset:]
	limit := args.Limit
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if limit > len(globals) {
		limit = len(globals)
	}
	globals = globals[:limit]
	var b strings.Builder
	b.WriteString(formatListHeader(total, offset, len(globals)) + "\n")
	for _, g := range globals {
		if t := g.GetType(); t != "" {
			fmt.Fprintf(&b, "0x%x\t%s\t%s\n", g.GetAddress(), g.GetName(), t)
		} else {
			fmt.Fprintf(&b, "0x%x\t%s\n", g.GetAddress(), g.GetName())
		}
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: textResult(b.String())}}}, nil, nil
}

func (s *Server) getStructs(ctx context.Context, req *mcp.CallToolRequest, args GetStructsRequest) (*mcp.CallToolResult, any, error) {
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_structs")
	if err != nil {
		return nil, err, nil
	}
	s.logToolInvocation("get_structs", sess.ID, map[string]any{"name": args.Name})

	if args.Name != "" {
		resp, err := (*client.Analysis).GetStruct(ctx, connect.NewRequest(&pb.GetStructRequest{Name: args.Name}))
		if err != nil {
			return nil, s.logAndReturnError("get_structs RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("get_structs", errors.New(e)), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "struct %s {  // %d bytes\n", resp.Msg.GetName(), resp.Msg.GetSize())
		for _, m := range resp.Msg.GetMembers() {
			fmt.Fprintf(&b, "  +0x%02x  %s %s;  // %d bytes\n", m.GetOffset(), m.GetType(), m.GetName(), m.GetSize())
		}
		b.WriteString("};")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, nil, nil
	}

	resp, err := (*client.Analysis).ListStructs(ctx, connect.NewRequest(&pb.ListStructsRequest{Regex: args.Regex, CaseSensitive: args.CaseSensitive}))
	if err != nil {
		return nil, s.logAndReturnError("get_structs RPC", err), nil
	}
	if e := resp.Msg.GetError(); e != "" {
		return nil, s.logAndReturnError("get_structs", errors.New(e)), nil
	}
	var b strings.Builder
	for _, st := range resp.Msg.GetStructs() {
		fmt.Fprintf(&b, "%s  (%d bytes)\n", st.GetName(), st.GetSize())
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: textResult(b.String())}}}, nil, nil
}

func (s *Server) getEnums(ctx context.Context, req *mcp.CallToolRequest, args GetEnumsRequest) (*mcp.CallToolResult, any, error) {
	sess, client, err := s.resolveClientWait(ctx, req, args.SessionID, "get_enums")
	if err != nil {
		return nil, err, nil
	}
	s.logToolInvocation("get_enums", sess.ID, map[string]any{"name": args.Name})

	if args.Name != "" {
		resp, err := (*client.Analysis).GetEnum(ctx, connect.NewRequest(&pb.GetEnumRequest{Name: args.Name}))
		if err != nil {
			return nil, s.logAndReturnError("get_enums RPC", err), nil
		}
		if e := resp.Msg.GetError(); e != "" {
			return nil, s.logAndReturnError("get_enums", errors.New(e)), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "enum %s {\n", resp.Msg.GetName())
		for _, m := range resp.Msg.GetMembers() {
			fmt.Fprintf(&b, "  %s = %d,\n", m.GetName(), m.GetValue())
		}
		b.WriteString("};")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, nil, nil
	}

	resp, err := (*client.Analysis).ListEnums(ctx, connect.NewRequest(&pb.ListEnumsRequest{Regex: args.Regex, CaseSensitive: args.CaseSensitive}))
	if err != nil {
		return nil, s.logAndReturnError("get_enums RPC", err), nil
	}
	if e := resp.Msg.GetError(); e != "" {
		return nil, s.logAndReturnError("get_enums", errors.New(e)), nil
	}
	var b strings.Builder
	for _, en := range resp.Msg.GetEnums() {
		fmt.Fprintf(&b, "%s\n", en.GetName())
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: textResult(b.String())}}}, nil, nil
}
