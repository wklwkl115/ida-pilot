package server

import (
	"context"
	"encoding/json"
	"errors"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
)

func (s *Server) importFlutter(ctx context.Context, req *mcp.CallToolRequest, args ImportFlutterRequest) (*mcp.CallToolResult, any, error) {
	payloadInfo := map[string]any{
		"meta_json_path": args.MetaJsonPath,
	}
	s.logToolInvocation("import_flutter", args.SessionID, payloadInfo)
	if args.MetaJsonPath == "" {
		return nil, errors.New("meta_json_path is required"), nil
	}
	metaPath, perr := s.validatePath("meta_json_path", args.MetaJsonPath)
	if perr != nil {
		return nil, s.logAndReturnError("import_flutter path validation", perr), nil
	}
	args.MetaJsonPath = metaPath

	_, client, err := s.resolveClientWait(ctx, req, args.SessionID, "import_flutter")
	if err != nil {
		return nil, err, nil
	}
	resp, err := (*client.Analysis).ImportFlutter(ctx, connect.NewRequest(&pb.ImportFlutterRequest{
		MetaJsonPath: args.MetaJsonPath,
	}))
	if err != nil {
		return nil, s.logAndReturnError("import_flutter RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" && !resp.Msg.GetSuccess() {
		return nil, s.logAndReturnError("import_flutter IDA operation", errors.New(msgErr)), nil
	}
	result := map[string]any{
		"success":            resp.Msg.GetSuccess(),
		"duration_seconds":   resp.Msg.GetDurationSeconds(),
		"functions_created":  resp.Msg.GetFunctionsCreated(),
		"functions_named":    resp.Msg.GetFunctionsNamed(),
		"structs_created":    resp.Msg.GetStructsCreated(),
		"signatures_applied": resp.Msg.GetSignaturesApplied(),
		"comments_set":       resp.Msg.GetCommentsSet(),
		"analysis_tip":       "Run run_auto_analysis after import to refresh cross references and caches.",
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		result["warning"] = msgErr
	}
	jsonResult, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}
