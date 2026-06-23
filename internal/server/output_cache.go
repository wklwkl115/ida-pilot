package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultMaxOutputChars = 8000
	maxCacheEntries       = 200
	cacheEntryTTL         = 1 * time.Hour

	// truncationHint tells the agent how to retrieve the full output when a
	// response was truncated, so the next step is self-evident from the payload.
	truncationHint = "output truncated — call get_cached_output with this _cache_id (use offset/limit, or limit=0 for all) to read the full result"
)

var cacheIDFallbackCounter atomic.Uint64

type outputEntry struct {
	ID        string
	Tool      string
	Content   string
	CreatedAt time.Time
}

type outputStore struct {
	mu      sync.RWMutex
	entries map[string]*outputEntry
	order   []string // FIFO eviction
}

func newOutputStore() *outputStore {
	return &outputStore{
		entries: make(map[string]*outputEntry),
	}
}

func (c *outputStore) put(tool, content string) string {
	id := genCacheID()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict expired
	now := time.Now()
	for len(c.order) > 0 {
		oldest := c.order[0]
		if e, ok := c.entries[oldest]; ok && now.Sub(e.CreatedAt) > cacheEntryTTL {
			delete(c.entries, oldest)
			c.order = c.order[1:]
			continue
		}
		break
	}

	// Evict if over limit
	for len(c.order) >= maxCacheEntries {
		evict := c.order[0]
		delete(c.entries, evict)
		c.order = c.order[1:]
	}

	c.entries[id] = &outputEntry{
		ID:        id,
		Tool:      tool,
		Content:   content,
		CreatedAt: now,
	}
	c.order = append(c.order, id)
	return id
}

func (c *outputStore) get(id string) (*outputEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[id]
	if ok && time.Since(e.CreatedAt) > cacheEntryTTL {
		return nil, false
	}
	return e, ok
}

func (c *outputStore) clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = make(map[string]*outputEntry)
	c.order = c.order[:0]
	return n
}

func genCacheID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x%016x", uint64(time.Now().UnixNano()), cacheIDFallbackCounter.Add(1))
	}
	return hex.EncodeToString(b)
}

// maybeCacheResult checks if a tool result exceeds the size threshold.
// If so, caches the full output and returns a truncated version with cache_id.
func (s *Server) maybeCacheResult(toolName string, result *mcp.CallToolResult) *mcp.CallToolResult {
	if result == nil || len(result.Content) == 0 {
		return result
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok || len(tc.Text) <= defaultMaxOutputChars {
		return result
	}

	fullText := tc.Text
	cacheID := s.outputs.put(toolName, fullText)

	// Try to parse as JSON object and produce a smart truncation
	var parsed map[string]any
	if json.Unmarshal([]byte(fullText), &parsed) == nil {
		return s.truncateJSON(parsed, cacheID, toolName, len(fullText))
	}

	// Raw text (e.g., decompiled pseudocode) — simple truncation
	preview := fullText[:defaultMaxOutputChars]
	wrapper := map[string]any{
		"_truncated":   true,
		"_cache_id":    cacheID,
		"_total_chars": len(fullText),
		"_next_offset": defaultMaxOutputChars,
		"_hint":        truncationHint,
		"preview":      preview,
	}
	body, _ := json.Marshal(wrapper)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}
}

// truncateJSON preserves JSON structure but truncates large string values and arrays.
func (s *Server) truncateJSON(parsed map[string]any, cacheID, toolName string, totalChars int) *mcp.CallToolResult {
	out := map[string]any{
		"_truncated":   true,
		"_cache_id":    cacheID,
		"_total_chars": totalChars,
		"_hint":        truncationHint,
	}

	for k, v := range parsed {
		switch val := v.(type) {
		case string:
			if len(val) > 2000 {
				out[k] = val[:2000] + fmt.Sprintf("... [truncated, %d chars total]", len(val))
			} else {
				out[k] = val
			}
		case []any:
			if b, _ := json.Marshal(val); len(b) > 3000 {
				limit := 10
				if len(val) < limit {
					limit = len(val)
				}
				out[k] = map[string]any{
					"count":   len(val),
					"preview": val[:limit],
				}
			} else {
				out[k] = val
			}
		case map[string]any:
			// Nested objects — check for count+top pattern (survey_binary style)
			if _, hasCount := val["count"]; hasCount {
				out[k] = val // already summarized
			} else {
				b, _ := json.Marshal(val)
				if len(b) > 2000 {
					out[k] = fmt.Sprintf("[object, %d bytes]", len(b))
				} else {
					out[k] = val
				}
			}
		default:
			out[k] = val
		}
	}

	body, _ := json.Marshal(out)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}
}

// toolEnums constrains discriminator / closed-set fields to their valid values
// at the schema level. jsonschema-go cannot express enums via struct tags, so we
// inject them onto the generated input schema here — the single place every tool
// registers — which lets the MCP framework reject out-of-set values during
// argument validation instead of letting them reach the handler's "invalid X"
// fallback. Keyed by tool name, then by JSON field name.
var toolEnums = map[string]map[string][]string{
	"query":           {"category": {"functions", "imports", "exports", "strings", "globals", "segments", "structs", "enums", "entry_point"}},
	"get_references":  {"mode": {"code", "data", "string"}, "direction": {"to", "from", "both"}},
	"search":          {"mode": {"text", "binary"}},
	"read_memory":     {"format": {"bytes", "dword", "qword", "byte", "string"}},
	"set_metadata":    {"action": {"set_name", "delete_name", "set_comment"}, "scope": {"address", "function", "decompiler"}},
	"set_type":        {"target": {"function", "global", "lvar"}},
	"import_metadata": {"format": {"il2cpp", "flutter"}},
}

// applyEnumConstraints pre-generates the tool's input schema (the same inference
// the MCP SDK runs) and stamps JSON-Schema enum constraints onto the registered
// discriminator fields. No-op for tools without enum fields or when a schema was
// already set explicitly; on any inference error it leaves InputSchema nil so the
// SDK falls back to its own inference.
func applyEnumConstraints[T any](tool *mcp.Tool) {
	enums, ok := toolEnums[tool.Name]
	if !ok || tool.InputSchema != nil {
		return
	}
	schema, err := jsonschema.For[T](nil)
	if err != nil || schema == nil {
		return
	}
	for field, values := range enums {
		prop, ok := schema.Properties[field]
		if !ok || prop == nil {
			continue
		}
		vals := make([]any, len(values))
		for i, v := range values {
			vals[i] = v
		}
		prop.Enum = vals
	}
	tool.InputSchema = schema
}

// addToolWithCache registers an MCP tool with automatic output caching.
// Handlers return user-facing errors as the second value (any). This wrapper
// detects error values there and converts them to the third return so the
// MCP SDK sets IsError=true and puts the message in Content. Without this,
// json.Marshal(error) produces "{}" and the client sees an empty object.
func addToolWithCache[T any](s *Server, mcpServer *mcp.Server, tool *mcp.Tool, handler func(context.Context, *mcp.CallToolRequest, T) (*mcp.CallToolResult, any, error)) {
	applyEnumConstraints[T](tool)
	mcp.AddTool(mcpServer, tool, func(ctx context.Context, req *mcp.CallToolRequest, args T) (*mcp.CallToolResult, any, error) {
		result, meta, err := handler(ctx, req, args)
		if userErr, ok := meta.(error); ok {
			return nil, nil, userErr
		}
		if err != nil || result == nil || meta != nil {
			return result, meta, err
		}
		return s.maybeCacheResult(tool.Name, result), meta, nil
	})
}

// getCachedOutput retrieves cached output with pagination.
func (s *Server) getCachedOutput(ctx context.Context, req *mcp.CallToolRequest, args GetCachedOutputRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_cached_output", "", map[string]any{"cache_id": args.CacheID, "offset": args.Offset, "limit": args.Limit})

	entry, ok := s.outputs.get(args.CacheID)
	if !ok {
		return nil, nil, fmt.Errorf("cache entry not found or expired: %s", args.CacheID)
	}

	content := entry.Content
	total := len(content)

	offset := args.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}

	limit := args.Limit
	if limit <= 0 {
		limit = defaultMaxOutputChars
	}

	end := offset + limit
	if end > total {
		end = total
	}

	chunk := content[offset:end]
	hasMore := end < total

	result := map[string]any{
		"cache_id":    args.CacheID,
		"tool":        entry.Tool,
		"content":     chunk,
		"offset":      offset,
		"limit":       limit,
		"total_chars": total,
		"has_more":    hasMore,
	}
	if hasMore {
		result["next_offset"] = end
	}

	body, _ := json.Marshal(result)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}
