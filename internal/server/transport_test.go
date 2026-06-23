package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/jsonschema-go/jsonschema"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/ida/worker/v1/workerconnect"
	"github.com/wklwkl115/ida-pilot/internal/session"
	"github.com/wklwkl115/ida-pilot/internal/worker"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestApplyEnumConstraints verifies discriminator fields get JSON-Schema enum
// constraints injected onto the generated input schema, and that tools without
// enum config are left for the SDK's own inference. Pure function call — no
// server/session, so it is deterministic regardless of suite ordering.
func TestApplyEnumConstraints(t *testing.T) {
	t.Parallel()

	tool := &mcp.Tool{Name: "query"}
	applyEnumConstraints[QueryRequest](tool)
	schema, ok := tool.InputSchema.(*jsonschema.Schema)
	if !ok || schema == nil {
		t.Fatalf("query: expected InputSchema to be *jsonschema.Schema, got %T", tool.InputSchema)
	}
	cat, ok := schema.Properties["category"]
	if !ok || cat == nil {
		t.Fatal("query: category property missing from schema")
	}
	if len(cat.Enum) != 9 {
		t.Fatalf("query.category: expected 9 enum values, got %d: %v", len(cat.Enum), cat.Enum)
	}

	// Two-discriminator tool: both fields constrained.
	st := &mcp.Tool{Name: "set_metadata"}
	applyEnumConstraints[SetMetadataRequest](st)
	sm := st.InputSchema.(*jsonschema.Schema)
	if len(sm.Properties["action"].Enum) != 3 || len(sm.Properties["scope"].Enum) != 3 {
		t.Fatalf("set_metadata: expected action+scope enums of 3 each, got action=%v scope=%v",
			sm.Properties["action"].Enum, sm.Properties["scope"].Enum)
	}

	// Tool with no enum config: schema left nil for the SDK to infer.
	plain := &mcp.Tool{Name: "open_binary"}
	applyEnumConstraints[OpenBinaryRequest](plain)
	if plain.InputSchema != nil {
		t.Fatalf("open_binary: expected InputSchema to stay nil, got %#v", plain.InputSchema)
	}
}

func TestFormatListHeader(t *testing.T) {
	t.Parallel()
	// Truncated page: must surface that more exist and the next offset.
	got := formatListHeader(133, 0, 10)
	for _, want := range []string{"Total: 133", "123 more", "offset=10"} {
		if !strings.Contains(got, want) {
			t.Errorf("truncated header %q missing %q", got, want)
		}
	}
	// Complete page keeps the original compact form (no "more"), so complete
	// outputs stay byte-identical to pre-change goldens.
	if got := formatListHeader(5, 0, 5); got != "Total: 5 (offset 0)" {
		t.Errorf("complete header = %q, want %q", got, "Total: 5 (offset 0)")
	}
	// Final page of a paginated walk (offset>0, exhausts the remainder).
	if got := formatListHeader(12, 10, 2); got != "Total: 12 (offset 10)" {
		t.Errorf("final page header = %q, want %q", got, "Total: 12 (offset 10)")
	}
}

func TestReadinessGate(t *testing.T) {
	t.Parallel()
	s := &Server{}

	// No progress snapshot (restored/reused session) → treated as ready.
	if err := s.readinessError("unknown"); err != nil {
		t.Fatalf("expected nil for session without progress, got %v", err)
	}

	// In-progress stages must be gated with a self-correcting message.
	for _, stage := range []string{"starting", "opening", "analyzing"} {
		s.recordProgress("s1", stage, "loading", 2, 3)
		err := s.readinessError("s1")
		if err == nil || !strings.Contains(err.Error(), "not ready") || !strings.Contains(err.Error(), "get_session_progress") {
			t.Fatalf("stage %q: expected not-ready error mentioning the poll, got %v", stage, err)
		}
		if !strings.Contains(err.Error(), stage) {
			t.Fatalf("stage %q: error should report the current stage, got %v", stage, err)
		}
	}

	// Ready and auto_analysis (manual analysis settled) must pass.
	for _, stage := range []string{"ready", "auto_analysis", "open_binary"} {
		s.recordProgress("s1", stage, "done", 3, 3)
		if err := s.readinessError("s1"); err != nil {
			t.Fatalf("stage %q: expected ready (nil), got %v", stage, err)
		}
	}

	// Failed load gets a distinct, actionable error.
	s.recordProgress("s2", "failed", "no such file", 0, 3)
	if err := s.readinessError("s2"); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("expected failed-load error, got %v", err)
	}
}

func TestStreamableHTTPTransportLifecycle(t *testing.T) {
	t.Parallel()
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	runLifecycleScenario(t, transport)
}

func TestSSETransportLifecycle(t *testing.T) {
	t.Parallel()
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	transport := &mcp.SSEClientTransport{Endpoint: httpServer.URL + "/sse"}
	runLifecycleScenario(t, transport)
}

// TestTierDemotionRemovesAllTools guards against registration/removal-list drift:
// every tool registered on promotion must be named in the tierNToolNames removal
// lists, so demotion leaves exactly the 3 boot tools. cross_reference/cross_search
// regressed this once — they were registered in registerTier1 but missing from
// tier1ToolNames, so they leaked into tier 0 after the last session closed.
func TestTierDemotionRemovesAllTools(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "tier-test", Version: "0.0.1"}, nil)
	conn, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	toolNames := func() map[string]bool {
		list, err := conn.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		names := make(map[string]bool, len(list.Tools))
		for _, tool := range list.Tools {
			names[tool.Name] = true
		}
		return names
	}

	bootTools := []string{"open_binary", "list_sessions", "get_cached_output"}

	// Boot: exactly the 3 tier-0 tools.
	if got := toolNames(); len(got) != len(bootTools) {
		t.Fatalf("boot tier: expected %d tools, got %d: %v", len(bootTools), len(got), got)
	}

	// Open + analyze → full surface (tier 2): 3 boot + 20 read + 5 write = 28.
	binaryPath := filepath.Join(t.TempDir(), "tiers.bin")
	open, err := conn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": binaryPath},
	})
	if err != nil {
		t.Fatalf("open_binary: %v", err)
	}
	sessionID, _ := decodeContent(t, open)["session_id"].(string)
	waitForSessionReady(t, conn, sessionID)
	promoteToTier2ForTest(t, ctx, conn, sessionID)

	if got := toolNames(); len(got) != 28 {
		t.Fatalf("full tier: expected 28 tools, got %d: %v", len(got), got)
	}

	// Close the only session → demote. Nothing may leak past the 3 boot tools.
	if _, err := conn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "close_binary",
		Arguments: map[string]any{"session_id": sessionID},
	}); err != nil {
		t.Fatalf("close_binary: %v", err)
	}

	got := toolNames()
	if len(got) != len(bootTools) {
		t.Fatalf("after demotion: expected exactly %d boot tools, got %d: %v", len(bootTools), len(got), got)
	}
	for _, name := range bootTools {
		if !got[name] {
			t.Errorf("after demotion: boot tool %q missing", name)
		}
	}
}

func TestOpenBinaryReusesActiveSession(t *testing.T) {
	t.Parallel()
	httpServer, workers := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "reuse-test.bin")
	sessionConn, sessionID1 := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	result2, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": testBinary},
	})
	if err != nil {
		t.Fatalf("open_binary (2): %v", err)
	}
	payload2 := decodeContent(t, result2)
	sessionID2, _ := payload2["session_id"].(string)
	if sessionID2 != sessionID1 {
		t.Fatalf("expected same session id, got %s and %s", sessionID1, sessionID2)
	}
	if reused, _ := payload2["reused"].(bool); !reused {
		t.Fatalf("expected reused flag to be true: %v", payload2)
	}
	if workers.StartCount(testBinary) != 1 {
		t.Fatalf("expected worker to start once for binary, got %d", workers.StartCount(testBinary))
	}
}

func TestBackgroundOpenTracksInFlightUntilReady(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	registry := session.NewRegistry(4)
	workers := newFakeWorkerManager(t)
	workers.planAndWaitStarted = make(chan struct{}, 1)
	workers.planAndWaitBlock = make(chan struct{})
	srv := &Server{
		registry:       registry,
		workers:        workers,
		logger:         logger,
		sessionTimeout: time.Minute,
	}

	binaryPath := filepath.Join(t.TempDir(), "slow-open.bin")
	sess, err := registry.Create(binaryPath, time.Minute)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sess.LastActivity = time.Now().Add(-time.Hour)
	if err := workers.Start(context.Background(), sess, binaryPath); err != nil {
		t.Fatalf("start worker: %v", err)
	}
	client, err := workers.GetClient(sess.ID)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.backgroundOpen(sess, client, binaryPath, true, nil, context.Background())
	}()

	select {
	case <-workers.planAndWaitStarted:
	case <-time.After(time.Second):
		t.Fatal("backgroundOpen did not reach PlanAndWait")
	}
	if !sess.HasInFlight() {
		t.Fatal("backgroundOpen should hold an in-flight lease while worker RPCs are active")
	}

	close(workers.planAndWaitBlock)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("backgroundOpen did not finish after releasing PlanAndWait")
	}
	if sess.HasInFlight() {
		t.Fatal("backgroundOpen should release its in-flight lease when ready")
	}
	if sess.IsExpired() {
		t.Fatal("backgroundOpen release should refresh idle time")
	}
}

func TestCleanupExpiredSessionsRechecksAfterInFlightRelease(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	registry := session.NewRegistry(4)
	workers := newFakeWorkerManager(t)
	srv := &Server{
		registry:       registry,
		workers:        workers,
		logger:         logger,
		sessionTimeout: time.Minute,
	}

	binaryPath := filepath.Join(t.TempDir(), "stale-expired-snapshot.bin")
	sess, err := registry.Create(binaryPath, time.Minute)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sess.LastActivity = time.Now().Add(-time.Hour)
	sess.AcquireInFlight()
	if err := workers.Start(context.Background(), sess, binaryPath); err != nil {
		t.Fatalf("start worker: %v", err)
	}

	expired := registry.Expired()
	if len(expired) != 1 || expired[0] != sess {
		t.Fatalf("expected stale snapshot to include session, got %v", expired)
	}

	sess.ReleaseInFlight()
	if cleaned := srv.cleanupExpiredSessions(expired); cleaned != 0 {
		t.Fatalf("expected stale snapshot to be ignored after release refreshed idle time, cleaned %d", cleaned)
	}
	if _, ok := registry.Get(sess.ID); !ok {
		t.Fatal("session should remain registered after stale snapshot cleanup")
	}
	if _, err := workers.GetClient(sess.ID); err != nil {
		t.Fatalf("worker should remain active after stale snapshot cleanup: %v", err)
	}
}

// TestReusedSessionReportsReady guards the readiness/gate consistency fix:
// reopening an already-open binary stamps stage "open_binary", which must still
// report ready=true (the gate already admits it) so the agent doesn't poll
// get_session_progress forever after a reuse.
func TestReusedSessionReportsReady(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	testBinary := filepath.Join(t.TempDir(), "reuse-ready.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	// Reopen the same path → reuse the active session (stamps stage open_binary).
	reopen, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": testBinary},
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reused, _ := decodeContent(t, reopen)["reused"].(bool); !reused {
		t.Fatalf("expected reused=true on second open")
	}

	prog, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_session_progress",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("get_session_progress: %v", err)
	}
	payload := decodeContent(t, prog)
	if ready, _ := payload["ready"].(bool); !ready {
		t.Fatalf("reused session must report ready=true, got %v", payload)
	}
	if ns, _ := payload["next_step"].(string); !strings.Contains(ns, "survey_binary") {
		t.Errorf("reused-session next_step = %q, want it to point at survey_binary", ns)
	}
}

func TestGetStringsRegexFiltering(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "strings.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"session_id":     sessionID,
			"category":       "strings",
			"regex":          "alpha",
			"limit":          10,
			"case_sensitive": false,
		},
	})
	if err != nil {
		t.Fatalf("get_strings: %v", err)
	}
	assertTextContains(t, resp, "Total: 1")
}

func TestGetImportsFilters(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "imports.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"session_id":     sessionID,
			"category":       "imports",
			"module":         "libalpha",
			"regex":          "Helper",
			"case_sensitive": false,
		},
	})
	if err != nil {
		t.Fatalf("get_imports: %v", err)
	}
	assertTextContains(t, resp, "Total: 1")
}

func TestGetFunctionsRegexFiltering(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "functions.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"session_id":     sessionID,
			"category":       "functions",
			"regex":          "helper",
			"case_sensitive": false,
		},
	})
	if err != nil {
		t.Fatalf("query functions regex: %v", err)
	}
	assertTextContains(t, resp, "Total: 1")
}

func TestCrossReferenceTools(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	samplePath := filepath.Join("..", "samples", "test_xrefs_arm64")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, samplePath)
	ctx := context.Background()

	if _, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "run_auto_analysis",
		Arguments: map[string]any{"session_id": sessionID},
	}); err != nil {
		t.Fatalf("run_auto_analysis: %v", err)
	}

	callTool := func(name string, args map[string]any) *mcp.CallToolResult {
		args["session_id"] = sessionID
		resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return resp
	}

	assertTextContains(t, callTool("get_references", map[string]any{"address": "0x1000", "mode": "code", "direction": "to"}), "xrefs_to")
	assertTextContains(t, callTool("get_references", map[string]any{"address": "0x1000", "mode": "code", "direction": "from"}), "xrefs_from")
	assertTextContains(t, callTool("get_references", map[string]any{"address": "0x1000", "mode": "data"}), "refs:")
	assertTextContains(t, callTool("get_references", map[string]any{"address": "0x2000", "mode": "string"}), "refs:")
}

func TestRunAutoAnalysisInvalidatesFunctionCache(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "cache.bin")
	sessionConn, sessionID := openTestSessionWithArgs(t, httpServer.URL, map[string]any{
		"path":          testBinary,
		"skip_analysis": true,
	})
	ctx := context.Background()

	// Initial call before analysis should return the small function set.
	beforeResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"session_id": sessionID,
			"category":   "functions",
			"limit":      10,
		},
	})
	if err != nil {
		t.Fatalf("query functions before analysis: %v", err)
	}
	assertTextContains(t, beforeResp, "Total: 2")

	// Run auto analysis (plan_and_wait) which should invalidate caches.
	if _, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "run_auto_analysis",
		Arguments: map[string]any{
			"session_id": sessionID,
		},
	}); err != nil {
		t.Fatalf("run_auto_analysis: %v", err)
	}

	// Subsequent call should see the expanded function set.
	afterResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"session_id": sessionID,
			"category":   "functions",
			"limit":      10,
		},
	})
	if err != nil {
		t.Fatalf("query functions after analysis: %v", err)
	}
	assertTextContains(t, afterResp, "Total: 4")
}

// newCacheTestServer builds a Server wired to a fake worker with one ready
// session, for exercising handler cache-invalidation directly (no HTTP layer).
func newCacheTestServer(t *testing.T) (*Server, *session.Session) {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	registry := session.NewRegistry(4)
	workers := newFakeWorkerManager(t)
	srv := &Server{registry: registry, workers: workers, logger: logger, sessionTimeout: time.Minute}

	binaryPath := filepath.Join(t.TempDir(), "cachetest.bin")
	sess, err := registry.Create(binaryPath, time.Minute)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := workers.Start(context.Background(), sess, binaryPath); err != nil {
		t.Fatalf("start worker: %v", err)
	}
	return srv, sess
}

// TestPyEvalInvalidatesCaches guards the py_eval staleness footgun: arbitrary
// Python can rename/retype/patch the database, so by default py_eval drops the
// mutable caches. read_only=true opts out to keep them warm.
func TestPyEvalInvalidatesCaches(t *testing.T) {
	srv, sess := newCacheTestServer(t)
	ctx := context.Background()

	seed := func() *sessionCache {
		c := srv.getSessionCache(sess.ID)
		c.functions = []*pb.Function{{}}
		c.setDecomp(0x1000, "int sub_1000() { return 0; }")
		c.setXRefs(0x1000, &xrefsEntry{to: [][]any{{uint64(0x2000), "call"}}})
		return c
	}

	// Default (writes): the mutable caches must be dropped.
	c := seed()
	if _, _, err := srv.pyEval(ctx, nil, PyEvalRequest{SessionID: sess.ID, Code: "idc.set_name(0x1000, 'foo')"}); err != nil {
		t.Fatalf("py_eval (writes): %v", err)
	}
	if c.functions != nil {
		t.Error("functions cache should be cleared after a writing py_eval")
	}
	if _, ok := c.getDecomp(0x1000); ok {
		t.Error("decomp cache should be cleared after a writing py_eval")
	}
	if _, ok := c.getXRefs(0x1000); ok {
		t.Error("xrefs cache should be cleared after a writing py_eval")
	}

	// read_only=true: caches must be preserved to stay warm.
	c = seed()
	if _, _, err := srv.pyEval(ctx, nil, PyEvalRequest{SessionID: sess.ID, Code: "print(idc.get_name(0x1000))", ReadOnly: true}); err != nil {
		t.Fatalf("py_eval (read_only): %v", err)
	}
	if c.functions == nil {
		t.Error("functions cache should be preserved when read_only=true")
	}
	if _, ok := c.getDecomp(0x1000); !ok {
		t.Error("decomp cache should be preserved when read_only=true")
	}
	if _, ok := c.getXRefs(0x1000); !ok {
		t.Error("xrefs cache should be preserved when read_only=true")
	}
}

// TestSetNameTargetedDecompInvalidation verifies that renaming a symbol only
// invalidates decomp entries that contain the old name (found via text search).
// Function renames invalidate just that function; data renames invalidate only
// cached decomp that references the old name.
func TestSetNameTargetedDecompInvalidation(t *testing.T) {
	srv, sess := newCacheTestServer(t)
	cache := srv.getSessionCache(sess.ID)

	// name_5000 is the fake GetName return for address 0x5000
	cache.setDecomp(0x1000, "int sub_1000() { return name_5000; }")
	cache.setDecomp(0x2000, "void sub_2000() { sub_1000(); }")

	if _, _, err := srv.setName(context.Background(), nil, SetNameRequest{
		SessionID: sess.ID, Address: 0x5000, Name: "g_counter",
	}); err != nil {
		t.Fatalf("set_name: %v", err)
	}

	// 0x1000's decomp contained the old name "name_5000" — must be invalidated.
	if _, ok := cache.getDecomp(0x1000); ok {
		t.Fatal("rename must invalidate decomp entries containing the old name (0x1000 survived)")
	}
	// 0x2000 did NOT contain "name_5000" — must survive.
	if _, ok := cache.getDecomp(0x2000); !ok {
		t.Fatal("rename must not invalidate decomp entries that don't contain the old name (0x2000 lost)")
	}
}

// TestSetNameFunctionInvalidatesOwnDecomp verifies that renaming a function
// invalidates only that function's decomp, not unrelated entries.
func TestSetNameFunctionInvalidatesOwnDecomp(t *testing.T) {
	srv, sess := newCacheTestServer(t)
	cache := srv.getSessionCache(sess.ID)

	// Put functions in the cache so isCachedFunction detects 0x1000 as a function.
	cache.functions = []*pb.Function{{Address: 0x1000}, {Address: 0x2000}}
	cache.setDecomp(0x1000, "int sub_1000() { return 0; }")
	cache.setDecomp(0x2000, "void sub_2000() { sub_1000(); }")

	if _, _, err := srv.setName(context.Background(), nil, SetNameRequest{
		SessionID: sess.ID, Address: 0x1000, Name: "main",
	}); err != nil {
		t.Fatalf("set_name: %v", err)
	}

	// 0x1000 IS the renamed function — its decomp must be invalidated.
	if _, ok := cache.getDecomp(0x1000); ok {
		t.Fatal("renamed function's decomp must be invalidated (0x1000 survived)")
	}
	// 0x2000 is NOT the renamed function — must survive.
	if _, ok := cache.getDecomp(0x2000); !ok {
		t.Fatal("unrelated function's decomp must survive (0x2000 lost)")
	}
}

// TestSetCommentDecompilerScopeInvalidatesOwnDecomp verifies decompiler-scope
// comments invalidate exactly the commented function's decomp, and nothing else.
func TestSetCommentDecompilerScopeInvalidatesOwnDecomp(t *testing.T) {
	srv, sess := newCacheTestServer(t)
	cache := srv.getSessionCache(sess.ID)
	cache.setDecomp(0x1000, "target")
	cache.setDecomp(0x2000, "unrelated")

	if _, _, err := srv.setComment(context.Background(), nil, SetCommentRequest{
		SessionID: sess.ID, Scope: "decompiler", FunctionAddress: 0x1000, Address: 0x1010, Comment: "note",
	}); err != nil {
		t.Fatalf("set_comment: %v", err)
	}

	if _, ok := cache.getDecomp(0x1000); ok {
		t.Fatal("decompiler comment must invalidate that function's decomp")
	}
	if _, ok := cache.getDecomp(0x2000); !ok {
		t.Fatal("decompiler comment must not invalidate unrelated functions")
	}
}

func TestSetTypeFunctionTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "prototype.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	promoteToTier2ForTest(t, ctx, sessionConn, sessionID)
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "set_type",
		Arguments: map[string]any{
			"session_id": sessionID,
			"target":     "function",
			"address":    "0x1234",
			"prototype":  "int __fastcall foo(int a, int b)",
		},
	})
	if err != nil {
		t.Fatalf("set_type function: %v", err)
	}
	assertTextContent(t, resp, "ok")
}

func TestSetTypeLvarTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "lvar.bin"))
	ctx := context.Background()
	promoteToTier2ForTest(t, ctx, sessionConn, sessionID)
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "set_type",
		Arguments: map[string]any{
			"session_id":       sessionID,
			"target":           "lvar",
			"function_address": "0x2000",
			"lvar_name":        "v1",
			"type":             "int",
		},
	})
	if err != nil {
		t.Fatalf("set_type lvar: %v", err)
	}
	assertTextContent(t, resp, "ok")
}

func TestSetMetadataCommentTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "decomp.bin"))
	ctx := context.Background()
	promoteToTier2ForTest(t, ctx, sessionConn, sessionID)
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "set_metadata",
		Arguments: map[string]any{
			"session_id":       sessionID,
			"action":           "set_comment",
			"scope":            "decompiler",
			"function_address": "0x3000",
			"address":          "0x3004",
			"comment":          "TODO: check bounds",
		},
	})
	if err != nil {
		t.Fatalf("set_metadata comment: %v", err)
	}
	assertTextContent(t, resp, "ok")
}

func TestQueryGlobalsTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "globals.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"session_id": sessionID, "category": "globals"},
	})
	if err != nil {
		t.Fatalf("query globals: %v", err)
	}
	assertTextContains(t, resp, "Total: 2")
	assertTextContains(t, resp, "gAlpha")
	assertTextContains(t, resp, "gBeta")
}

func TestSetTypeGlobalTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "gtype.bin"))
	ctx := context.Background()
	promoteToTier2ForTest(t, ctx, sessionConn, sessionID)
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "set_type",
		Arguments: map[string]any{"session_id": sessionID, "target": "global", "address": "0x6000", "type": "int"},
	})
	if err != nil {
		t.Fatalf("set_type global: %v", err)
	}
	assertTextContent(t, resp, "ok")
}

func TestSetMetadataNameTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "gname.bin"))
	ctx := context.Background()
	promoteToTier2ForTest(t, ctx, sessionConn, sessionID)
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "set_metadata",
		Arguments: map[string]any{"session_id": sessionID, "action": "set_name", "address": "0x6000", "name": "gScore"},
	})
	if err != nil {
		t.Fatalf("set_metadata set_name: %v", err)
	}
	assertTextContent(t, resp, "ok")
}

// TestAnalyzeFunctionsBatchDegradesOnBadAddress guards per-item degradation: a
// single malformed address must not abort the whole batch.
func TestAnalyzeFunctionsBatchDegradesOnBadAddress(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "batch.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "analyze_functions",
		Arguments: map[string]any{
			"session_id": sessionID,
			"addresses":  []any{"0x1000", "not-an-address"},
		},
	})
	if err != nil {
		t.Fatalf("analyze_functions: %v", err)
	}
	payload := decodeContent(t, resp)
	funcs, ok := payload["functions"].([]any)
	if !ok || len(funcs) != 2 {
		t.Fatalf("expected 2 result entries (batch not aborted), got %v", payload)
	}
	bad, _ := funcs[1].(map[string]any)
	errMsg, _ := bad["error"].(string)
	if !strings.Contains(errMsg, "invalid address") {
		t.Fatalf("expected per-item parse error for bad address, got %v", funcs[1])
	}
}

// TestNextStepGuidance checks that the recommended next action is embedded in
// tool output (which agents read) rather than only in tool descriptions.
func TestNextStepGuidance(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "guide.bin"))
	ctx := context.Background()

	prog, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_session_progress",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("get_session_progress: %v", err)
	}
	if ns, _ := decodeContent(t, prog)["next_step"].(string); !strings.Contains(ns, "survey_binary") {
		t.Errorf("ready progress next_step = %q, want it to point at survey_binary", ns)
	}

	survey, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "survey_binary",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("survey_binary: %v", err)
	}
	if ns, _ := decodeContent(t, survey)["next_step"].(string); !strings.Contains(ns, "analyze_function") {
		t.Errorf("survey next_step = %q, want it to point at analyze_function", ns)
	}
}

func TestReadMemoryStringTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "str.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "read_memory",
		Arguments: map[string]any{"session_id": sessionID, "address": "0x7000", "format": "string", "size": 32},
	})
	if err != nil {
		t.Fatalf("read_memory string: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["value"].(string) == "" {
		t.Fatalf("expected string value, got %v", payload)
	}
}

func TestDataReadByteTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "byte.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "read_memory",
		Arguments: map[string]any{
			"session_id": sessionID,
			"address":    "0x8000",
			"format":     "byte",
		},
	})
	if err != nil {
		t.Fatalf("read_memory byte: %v", err)
	}
	payload := decodeContent(t, resp)
	if _, ok := payload["value"].(float64); !ok {
		t.Fatalf("expected numeric value, got %v", payload)
	}
}

func TestQueryStructsTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "structs.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"session_id": sessionID, "category": "structs"},
	})
	if err != nil {
		t.Fatalf("query structs: %v", err)
	}
	assertTextContains(t, resp, "Vector3")
	assertTextContains(t, resp, "InventoryItem")
}

func TestQueryStructDetailTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "struct-detail.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"session_id": sessionID,
			"category":   "structs",
			"name":       "Vector3",
		},
	})
	if err != nil {
		t.Fatalf("query struct detail: %v", err)
	}
	assertTextContains(t, resp, "struct Vector3 {")
	assertTextContains(t, resp, "double x;")
	assertTextContains(t, resp, "};")
}

func TestSearchBinaryTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "findbin.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "search",
		Arguments: map[string]any{"session_id": sessionID, "mode": "binary", "start": "0x1000", "end": "0", "pattern": "90 90"},
	})
	if err != nil {
		t.Fatalf("search binary: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["addresses"] == nil {
		t.Fatalf("expected addresses array, got %v", payload)
	}
}

func TestSearchTextTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "findtext.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "search",
		Arguments: map[string]any{"session_id": sessionID, "mode": "text", "start": "0x1000", "end": "0", "needle": "HTTP"},
	})
	if err != nil {
		t.Fatalf("search text: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["addresses"] == nil {
		t.Fatalf("expected addresses array, got %v", payload)
	}
}

func TestGetFunctionDisasmTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "funcdis.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_disasm",
		Arguments: map[string]any{
			"session_id":     sessionID,
			"address":        "0xdeadbeef",
			"whole_function": true,
		},
	})
	if err != nil {
		t.Fatalf("get_disasm whole_function: %v", err)
	}
	assertTextContent(t, resp, "deadbeef: mov x0, x0")
}

func TestImportMetadataIl2cppTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "il2cpp.bin"))
	ctx := context.Background()
	promoteToTier2ForTest(t, ctx, sessionConn, sessionID)
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "script.json")
	if err := os.WriteFile(scriptPath, []byte(`{"ScriptMethod":[]}`), 0o600); err != nil {
		t.Fatalf("write script.json: %v", err)
	}
	headerPath := filepath.Join(tmpDir, "il2cpp.h")
	if err := os.WriteFile(headerPath, []byte("struct Foo { int a; };"), 0o600); err != nil {
		t.Fatalf("write il2cpp.h: %v", err)
	}
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "import_metadata",
		Arguments: map[string]any{
			"session_id":  sessionID,
			"format":      "il2cpp",
			"script_path": scriptPath,
			"il2cpp_path": headerPath,
			"fields":      []string{"ScriptMethod"},
		},
	})
	if err != nil {
		t.Fatalf("import_metadata il2cpp: %v", err)
	}
	payload := decodeContent(t, resp)
	if success, _ := payload["success"].(bool); !success {
		t.Fatalf("expected success response, got %v", payload)
	}
	if _, ok := payload["functions_named"]; !ok {
		t.Fatalf("expected functions_named field, got %v", payload)
	}
}

func TestQuerySegments(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "segments.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"session_id": sessionID, "category": "segments"},
	})
	if err != nil {
		t.Fatalf("query segments: %v", err)
	}

	assertTextContains(t, resp, ".text")
	assertTextContains(t, resp, ".data")
}

func TestInspectAddress(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "inspect.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "inspect",
		Arguments: map[string]any{"session_id": sessionID, "address": "0x1234"},
	})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}

	assertTextContains(t, resp, "0x1234")
	assertTextContains(t, resp, "name: name_1234")
}

func TestQueryEntryPoint(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "entrypoint.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"session_id": sessionID, "category": "entry_point"},
	})
	if err != nil {
		t.Fatalf("query entry_point: %v", err)
	}

	payload := decodeContent(t, resp)
	address, ok := payload["address"].(string)
	if !ok || address != "0x100000" {
		t.Fatalf("expected address 0x100000, got %v", payload)
	}
}

func TestMakeFunction(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "makefunc.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	promoteToTier2ForTest(t, ctx, sessionConn, sessionID)

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "make_function",
		Arguments: map[string]any{"session_id": sessionID, "address": "0x1000"},
	})
	if err != nil {
		t.Fatalf("make_function: %v", err)
	}
	assertTextContent(t, resp, "ok")
}

func setupTestMCPServer(t *testing.T) (*httptest.Server, *fakeWorkerManager) {
	t.Helper()

	logger := log.New(io.Discard, "", 0)
	registry := session.NewRegistry(4)
	workers := newFakeWorkerManager(t)
	store, err := session.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session store: %v", err)
	}

	srv := &Server{
		registry:       registry,
		workers:        workers,
		logger:         logger,
		sessionTimeout: time.Minute,
		debug:          true,
		store:          store,
		// Tests exercise the full surface (including py_eval) so the
		// production gate doesn't hide regressions in tier registration /
		// removal lists.
		enablePyEval: true,
		bind:         "127.0.0.1",
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "ida-pilot-test",
		Version: "0.0.1",
	}, nil)

	srv.RegisterTools(mcpServer)
	handler := srv.HTTPMux(mcpServer)
	return newIPv4HTTPServer(t, handler), workers
}

func runLifecycleScenario(t *testing.T, transport mcp.Transport) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "integration-client",
		Version: "0.0.1",
	}, nil)

	sessionConn, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sessionConn.Close()

	listResp, err := sessionConn.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(listResp.Tools) == 0 {
		t.Fatal("expected at least one tool registered")
	}

	binaryPath := filepath.Join(t.TempDir(), "lifecycle.bin")
	open, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": binaryPath},
	})
	if err != nil {
		t.Fatalf("open_binary: %v", err)
	}
	openPayload := decodeContent(t, open)
	sessionID, ok := openPayload["session_id"].(string)
	if !ok || sessionID == "" {
		t.Fatalf("expected session_id in open_binary result, got %v", openPayload)
	}
	waitForSessionReady(t, sessionConn, sessionID)

	funcs, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"session_id": sessionID, "category": "functions"},
	})
	if err != nil {
		t.Fatalf("query functions: %v", err)
	}
	funcText := assertTextContains(t, funcs, "Total:")
	if !strings.Contains(funcText, "_start") {
		t.Fatalf("expected function names in output, got:\n%s", funcText)
	}

	paged, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"session_id": sessionID, "category": "functions", "limit": 1},
	})
	if err != nil {
		t.Fatalf("get_functions pagination: %v", err)
	}
	pagedText := getTextContent(t, paged)
	// With limit=1, the text output should contain "Total:" header and exactly one entry line.
	lines := strings.Split(strings.TrimSpace(pagedText), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + 1 entry) with limit=1, got %d:\n%s", len(lines), pagedText)
	}

	sessionsResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("list_sessions: %v", err)
	}
	sessionsPayload := decodeContent(t, sessionsResp)
	if count := lenPayloadArray(t, sessionsPayload, "sessions"); count != 1 {
		t.Fatalf("expected 1 active session, got %v", sessionsPayload)
	}

	closeResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "close_binary",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("close_binary: %v", err)
	}
	assertTextContent(t, closeResp, "ok")
}

func decodeContent(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("missing content in response")
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", result.Content[0])
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &payload); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	return payload
}

func assertTextContent(t *testing.T, result *mcp.CallToolResult, want string) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("missing content in response")
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", result.Content[0])
	}
	if textContent.Text != want {
		t.Fatalf("expected text %q, got %q", want, textContent.Text)
	}
}

func assertTextContains(t *testing.T, result *mcp.CallToolResult, substr string) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("missing content in response")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", result.Content[0])
	}
	if !strings.Contains(tc.Text, substr) {
		t.Fatalf("expected text to contain %q, got:\n%s", substr, tc.Text)
	}
	return tc.Text
}

func getTextContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("missing content in response")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", result.Content[0])
	}
	return tc.Text
}

func lenPayloadArray(t *testing.T, payload map[string]any, key string) int {
	t.Helper()
	items, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected %s array, got %v", key, payload)
	}
	return len(items)
}

func promoteToTier2ForTest(t *testing.T, ctx context.Context, sessionConn *mcp.ClientSession, sessionID string) {
	t.Helper()
	if _, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "analyze_function",
		Arguments: map[string]any{"session_id": sessionID, "address": "0x1000"},
	}); err != nil {
		t.Fatalf("promote to tier 2: %v", err)
	}
}

func openTestSession(t *testing.T, endpoint, binaryPath string) (*mcp.ClientSession, string) {
	return openTestSessionWithArgs(t, endpoint, map[string]any{"path": binaryPath})
}

func openTestSessionWithArgs(t *testing.T, endpoint string, args map[string]any) (*mcp.ClientSession, string) {
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	sessionConn, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { sessionConn.Close() })
	openResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("open_binary: %v", err)
	}
	payload := decodeContent(t, openResp)
	sessionID, _ := payload["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("missing session id in response: %v", payload)
	}
	waitForSessionReady(t, sessionConn, sessionID)
	return sessionConn, sessionID
}

// waitForSessionReady polls get_session_progress until ready=true, mirroring the
// readiness contract real agents must follow now that resolveClient gates on it.
func waitForSessionReady(t *testing.T, conn *mcp.ClientSession, sessionID string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := conn.CallTool(ctx, &mcp.CallToolParams{
			Name:      "get_session_progress",
			Arguments: map[string]any{"session_id": sessionID},
		})
		if err == nil {
			payload := decodeContent(t, resp)
			if ready, _ := payload["ready"].(bool); ready {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %s not ready within timeout", sessionID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newIPv4HTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp4 listen not permitted: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = ln
	server.Start()
	return server
}

type fakeWorkerManager struct {
	t        *testing.T
	mu       sync.Mutex
	sessions map[string]*fakeWorker
	starts   map[string]int

	planAndWaitStarted chan struct{}
	planAndWaitBlock   chan struct{}
}

func newFakeWorkerManager(t *testing.T) *fakeWorkerManager {
	return &fakeWorkerManager{
		t:        t,
		sessions: make(map[string]*fakeWorker),
		starts:   make(map[string]int),
	}
}

type fakeWorker struct {
	sessionID string
	server    *httptest.Server
	client    *worker.WorkerClient

	mu         sync.Mutex
	binaryPath string
	closed     bool
	analyzed   bool

	planAndWaitStarted chan struct{}
	planAndWaitBlock   chan struct{}
}

func (f *fakeWorkerManager) Start(_ context.Context, sess *session.Session, binaryPath string) error {
	f.mu.Lock()
	planAndWaitStarted := f.planAndWaitStarted
	planAndWaitBlock := f.planAndWaitBlock
	f.mu.Unlock()

	fake := &fakeWorker{
		sessionID:          sess.ID,
		binaryPath:         binaryPath,
		planAndWaitStarted: planAndWaitStarted,
		planAndWaitBlock:   planAndWaitBlock,
	}

	sessionSvc := &fakeSessionControlServer{worker: fake}
	analysisSvc := &fakeAnalysisServer{worker: fake}
	healthSvc := &fakeHealthServer{}

	// Create Connect RPC handlers without options. Do not pass nil as the
	// second argument - when nil is passed to a variadic parameter and
	// unpacked with ..., it causes a nil pointer dereference.
	mux := http.NewServeMux()
	mux.Handle(workerconnect.NewSessionControlHandler(sessionSvc))
	mux.Handle(workerconnect.NewAnalysisToolsHandler(analysisSvc))
	mux.Handle(workerconnect.NewHealthcheckHandler(healthSvc))
	// Custom (non-Connect) routes the Go server posts to directly.
	mux.HandleFunc("/py_eval", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result": null}`))
	})

	server := newIPv4HTTPServer(f.t, mux)

	httpClient := server.Client()
	baseURL := server.URL
	sessionClient := workerconnect.NewSessionControlClient(httpClient, baseURL)
	analysisClient := workerconnect.NewAnalysisToolsClient(httpClient, baseURL)
	healthClient := workerconnect.NewHealthcheckClient(httpClient, baseURL)

	fake.server = server
	fake.client = &worker.WorkerClient{
		SessionCtrl: &sessionClient,
		Analysis:    &analysisClient,
		Health:      &healthClient,
		HTTPClient:  httpClient,
		BaseURL:     baseURL,
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[sess.ID] = fake
	f.starts[binaryPath]++
	return nil
}

func (f *fakeWorkerManager) Stop(sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fake, ok := f.sessions[sessionID]
	if !ok {
		return fmt.Errorf("no worker for session %s", sessionID)
	}
	fake.server.Close()
	delete(f.sessions, sessionID)
	return nil
}

func (f *fakeWorkerManager) GetClient(sessionID string) (*worker.WorkerClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fake, ok := f.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("no worker for session %s", sessionID)
	}
	return fake.client, nil
}

func (f *fakeWorkerManager) StartCount(binaryPath string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts[binaryPath]
}

type fakeSessionControlServer struct {
	worker *fakeWorker
}

func (f *fakeSessionControlServer) OpenBinary(_ context.Context, req *connect.Request[pb.OpenBinaryRequest]) (*connect.Response[pb.OpenBinaryResponse], error) {
	f.worker.mu.Lock()
	f.worker.binaryPath = req.Msg.GetBinaryPath()
	f.worker.closed = false
	f.worker.mu.Unlock()
	return connect.NewResponse(&pb.OpenBinaryResponse{
		Success:       true,
		HasDecompiler: true,
		BinaryPath:    req.Msg.GetBinaryPath(),
	}), nil
}

func (f *fakeSessionControlServer) CloseSession(_ context.Context, _ *connect.Request[pb.CloseSessionRequest]) (*connect.Response[pb.CloseSessionResponse], error) {
	f.worker.mu.Lock()
	f.worker.closed = true
	f.worker.mu.Unlock()
	return connect.NewResponse(&pb.CloseSessionResponse{Success: true}), nil
}

func (f *fakeSessionControlServer) PlanAndWait(ctx context.Context, _ *connect.Request[pb.PlanAndWaitRequest]) (*connect.Response[pb.PlanAndWaitResponse], error) {
	if f.worker.planAndWaitStarted != nil {
		select {
		case f.worker.planAndWaitStarted <- struct{}{}:
		default:
		}
	}
	if f.worker.planAndWaitBlock != nil {
		select {
		case <-f.worker.planAndWaitBlock:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.worker.mu.Lock()
	f.worker.analyzed = true
	f.worker.mu.Unlock()
	return connect.NewResponse(&pb.PlanAndWaitResponse{
		Success:         true,
		DurationSeconds: 0.1,
	}), nil
}

func (f *fakeSessionControlServer) SaveDatabase(_ context.Context, _ *connect.Request[pb.SaveDatabaseRequest]) (*connect.Response[pb.SaveDatabaseResponse], error) {
	return connect.NewResponse(&pb.SaveDatabaseResponse{
		Success:   true,
		Timestamp: time.Now().Unix(),
		Dirty:     false,
	}), nil
}

func (f *fakeSessionControlServer) GetSessionInfo(_ context.Context, _ *connect.Request[pb.GetSessionInfoRequest]) (*connect.Response[pb.GetSessionInfoResponse], error) {
	f.worker.mu.Lock()
	defer f.worker.mu.Unlock()
	return connect.NewResponse(&pb.GetSessionInfoResponse{
		BinaryPath:    f.worker.binaryPath,
		OpenedAt:      time.Now().Add(-time.Minute).Unix(),
		LastActivity:  time.Now().Unix(),
		HasDecompiler: true,
	}), nil
}

type fakeAnalysisServer struct {
	workerconnect.UnimplementedAnalysisToolsHandler
	worker *fakeWorker
}

func (f *fakeAnalysisServer) GetFunctions(_ context.Context, _ *connect.Request[pb.GetFunctionsRequest]) (*connect.Response[pb.GetFunctionsResponse], error) {
	f.worker.mu.Lock()
	defer f.worker.mu.Unlock()

	functions := []*pb.Function{
		{Address: 0x1000, Name: fmt.Sprintf("%s_start", f.worker.sessionID)},
		{Address: 0x2000, Name: fmt.Sprintf("%s_helper", f.worker.sessionID)},
	}
	if f.worker.analyzed {
		functions = append(functions,
			&pb.Function{Address: 0x3000, Name: fmt.Sprintf("%s_alpha", f.worker.sessionID)},
			&pb.Function{Address: 0x4000, Name: fmt.Sprintf("%s_beta", f.worker.sessionID)},
		)
	}

	return connect.NewResponse(&pb.GetFunctionsResponse{
		Functions: functions,
	}), nil
}

func (f *fakeAnalysisServer) GetBytes(context.Context, *connect.Request[pb.GetBytesRequest]) (*connect.Response[pb.GetBytesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetDisasm(context.Context, *connect.Request[pb.GetDisasmRequest]) (*connect.Response[pb.GetDisasmResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetFunctionDisasm(context.Context, *connect.Request[pb.GetFunctionDisasmRequest]) (*connect.Response[pb.GetFunctionDisasmResponse], error) {
	return connect.NewResponse(&pb.GetFunctionDisasmResponse{Disassembly: "deadbeef: mov x0, x0"}), nil
}

func (f *fakeAnalysisServer) GetDecompiled(context.Context, *connect.Request[pb.GetDecompiledRequest]) (*connect.Response[pb.GetDecompiledResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) SetName(context.Context, *connect.Request[pb.SetNameRequest]) (*connect.Response[pb.SetNameResponse], error) {
	resp := &pb.SetNameResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetFunctionType(context.Context, *connect.Request[pb.SetFunctionTypeRequest]) (*connect.Response[pb.SetFunctionTypeResponse], error) {
	resp := &pb.SetFunctionTypeResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetLvarType(context.Context, *connect.Request[pb.SetLvarTypeRequest]) (*connect.Response[pb.SetLvarTypeResponse], error) {
	resp := &pb.SetLvarTypeResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) RenameLvar(context.Context, *connect.Request[pb.RenameLvarRequest]) (*connect.Response[pb.RenameLvarResponse], error) {
	resp := &pb.RenameLvarResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetDecompilerComment(context.Context, *connect.Request[pb.SetDecompilerCommentRequest]) (*connect.Response[pb.SetDecompilerCommentResponse], error) {
	resp := &pb.SetDecompilerCommentResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetFunctionName(_ context.Context, req *connect.Request[pb.GetFunctionNameRequest]) (*connect.Response[pb.GetFunctionNameResponse], error) {
	name := fmt.Sprintf("func_%x", req.Msg.GetAddress())
	return connect.NewResponse(&pb.GetFunctionNameResponse{Name: name}), nil
}

func (f *fakeAnalysisServer) GetName(_ context.Context, req *connect.Request[pb.GetNameRequest]) (*connect.Response[pb.GetNameResponse], error) {
	name := fmt.Sprintf("name_%x", req.Msg.GetAddress())
	return connect.NewResponse(&pb.GetNameResponse{Name: name}), nil
}

func (f *fakeAnalysisServer) GetSegments(context.Context, *connect.Request[pb.GetSegmentsRequest]) (*connect.Response[pb.GetSegmentsResponse], error) {
	segments := []*pb.Segment{
		{Start: 0x100000, End: 0x101000, Name: ".text", SegClass: "CODE", Permissions: 5, Bitness: 64},
		{Start: 0x101000, End: 0x102000, Name: ".data", SegClass: "DATA", Permissions: 6, Bitness: 64},
	}
	return connect.NewResponse(&pb.GetSegmentsResponse{Segments: segments}), nil
}

func (f *fakeAnalysisServer) GetXRefsTo(_ context.Context, req *connect.Request[pb.GetXRefsToRequest]) (*connect.Response[pb.GetXRefsToResponse], error) {
	resp := &pb.GetXRefsToResponse{
		Xrefs: []*pb.XRef{{From: 0x1000, To: req.Msg.GetAddress(), Type: 1}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetXRefsFrom(_ context.Context, req *connect.Request[pb.GetXRefsFromRequest]) (*connect.Response[pb.GetXRefsFromResponse], error) {
	resp := &pb.GetXRefsFromResponse{
		Xrefs: []*pb.XRef{{From: req.Msg.GetAddress(), To: 0x2000, Type: 2}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetDataRefs(context.Context, *connect.Request[pb.GetDataRefsRequest]) (*connect.Response[pb.GetDataRefsResponse], error) {
	resp := &pb.GetDataRefsResponse{
		Refs: []*pb.DataRef{{From: 0x3000, Type: 3}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetStringXRefs(context.Context, *connect.Request[pb.GetStringXRefsRequest]) (*connect.Response[pb.GetStringXRefsResponse], error) {
	resp := &pb.GetStringXRefsResponse{
		Refs: []*pb.StringXRef{{Address: 0x4000, FunctionAddress: 0x5000, FunctionName: "string_user"}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) ImportIl2Cpp(context.Context, *connect.Request[pb.ImportIl2CppRequest]) (*connect.Response[pb.ImportIl2CppResponse], error) {
	resp := &pb.ImportIl2CppResponse{
		Success:           true,
		DurationSeconds:   1.0,
		FunctionsDefined:  2,
		FunctionsNamed:    3,
		StringsNamed:      4,
		MetadataNamed:     5,
		MetadataMethods:   6,
		SignaturesApplied: 7,
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetGlobals(context.Context, *connect.Request[pb.GetGlobalsRequest]) (*connect.Response[pb.GetGlobalsResponse], error) {
	resp := &pb.GetGlobalsResponse{Globals: []*pb.GlobalVariable{
		{Address: 0x6000, Name: "gAlpha", Type: "int"},
		{Address: 0x6008, Name: "gBeta", Type: "char *"},
	}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetGlobalType(context.Context, *connect.Request[pb.SetGlobalTypeRequest]) (*connect.Response[pb.SetGlobalTypeResponse], error) {
	resp := &pb.SetGlobalTypeResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) RenameGlobal(context.Context, *connect.Request[pb.RenameGlobalRequest]) (*connect.Response[pb.RenameGlobalResponse], error) {
	resp := &pb.RenameGlobalResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) DataReadString(context.Context, *connect.Request[pb.DataReadStringRequest]) (*connect.Response[pb.DataReadStringResponse], error) {
	resp := &pb.DataReadStringResponse{Value: "global_name"}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) DataReadByte(context.Context, *connect.Request[pb.DataReadByteRequest]) (*connect.Response[pb.DataReadByteResponse], error) {
	resp := &pb.DataReadByteResponse{Value: 42}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) FindBinary(context.Context, *connect.Request[pb.FindBinaryRequest]) (*connect.Response[pb.FindBinaryResponse], error) {
	resp := &pb.FindBinaryResponse{Addresses: []uint64{0xdeadbeef, 0xdeadbabe}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) FindText(context.Context, *connect.Request[pb.FindTextRequest]) (*connect.Response[pb.FindTextResponse], error) {
	resp := &pb.FindTextResponse{Addresses: []uint64{0xfeedface}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) ListStructs(context.Context, *connect.Request[pb.ListStructsRequest]) (*connect.Response[pb.ListStructsResponse], error) {
	resp := &pb.ListStructsResponse{Structs: []*pb.StructSummary{
		{Name: "Vector3", Id: 1, Size: 12},
		{Name: "InventoryItem", Id: 2, Size: 48},
	}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetStruct(_ context.Context, req *connect.Request[pb.GetStructRequest]) (*connect.Response[pb.GetStructResponse], error) {
	name := req.Msg.GetName()
	if name == "" {
		name = "Unnamed"
	}
	resp := &pb.GetStructResponse{
		Name: name,
		Id:   0x1234,
		Size: 48,
		Members: []*pb.StructMember{
			{Name: "x", Offset: 0, Size: 8, Type: "double"},
			{Name: "y", Offset: 8, Size: 8, Type: "double"},
			{Name: "z", Offset: 16, Size: 8, Type: "double"},
		},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetImports(context.Context, *connect.Request[pb.GetImportsRequest]) (*connect.Response[pb.GetImportsResponse], error) {
	imports := []*pb.Import{
		{Module: "libalpha", Address: 0x4010, Name: "AlphaInit", Ordinal: 1},
		{Module: "libbeta", Address: 0x4020, Name: "BetaLoop", Ordinal: 2},
		{Module: "libalpha", Address: 0x4030, Name: "AlphaHelper", Ordinal: 3},
	}
	return connect.NewResponse(&pb.GetImportsResponse{Imports: imports}), nil
}

func (f *fakeAnalysisServer) GetExports(context.Context, *connect.Request[pb.GetExportsRequest]) (*connect.Response[pb.GetExportsResponse], error) {
	exports := []*pb.Export{
		{Index: 1, Ordinal: 10, Address: 0x5000, Name: "ExportAlpha"},
		{Index: 2, Ordinal: 11, Address: 0x6000, Name: "ExportBeta"},
	}
	return connect.NewResponse(&pb.GetExportsResponse{Exports: exports}), nil
}

func (f *fakeAnalysisServer) GetEntryPoint(context.Context, *connect.Request[pb.GetEntryPointRequest]) (*connect.Response[pb.GetEntryPointResponse], error) {
	return connect.NewResponse(&pb.GetEntryPointResponse{Address: 0x100000}), nil
}

func (f *fakeAnalysisServer) GetStrings(_ context.Context, req *connect.Request[pb.GetStringsRequest]) (*connect.Response[pb.GetStringsResponse], error) {
	data := []*pb.StringItem{
		{Address: 0x100, Value: "alpha_http"},
		{Address: 0x200, Value: "beta"},
		{Address: 0x300, Value: "gamma"},
	}
	total := len(data)
	start := int(req.Msg.GetOffset())
	if start > total {
		start = total
	}
	limit := int(req.Msg.GetLimit())
	if limit <= 0 || start+limit > total {
		limit = total - start
	}
	if limit < 0 {
		limit = 0
	}
	selection := data[start : start+limit]
	resp := &pb.GetStringsResponse{
		Strings: selection,
		Total:   int32(total),
		Offset:  int32(start),
		Count:   int32(len(selection)),
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) MakeFunction(_ context.Context, req *connect.Request[pb.MakeFunctionRequest]) (*connect.Response[pb.MakeFunctionResponse], error) {
	// Simulate successful function creation
	return connect.NewResponse(&pb.MakeFunctionResponse{Success: true}), nil
}

func (f *fakeAnalysisServer) GetDwordAt(context.Context, *connect.Request[pb.GetDwordAtRequest]) (*connect.Response[pb.GetDwordAtResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetQwordAt(context.Context, *connect.Request[pb.GetQwordAtRequest]) (*connect.Response[pb.GetQwordAtResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetInstructionLength(context.Context, *connect.Request[pb.GetInstructionLengthRequest]) (*connect.Response[pb.GetInstructionLengthResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) DeleteName(context.Context, *connect.Request[pb.DeleteNameRequest]) (*connect.Response[pb.DeleteNameResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

type fakeHealthServer struct{}

func (f *fakeHealthServer) Ping(context.Context, *connect.Request[pb.PingRequest]) (*connect.Response[pb.PingResponse], error) {
	return connect.NewResponse(&pb.PingResponse{Alive: true}), nil
}

func (f *fakeHealthServer) StatusStream(_ context.Context, _ *connect.Request[pb.StatusStreamRequest], stream *connect.ServerStream[pb.WorkerStatus]) error {
	return stream.Send(&pb.WorkerStatus{
		Timestamp:       time.Now().Unix(),
		MemoryBytes:     42,
		Dirty:           false,
		LastActivity:    time.Now().Unix(),
		PendingRequests: 0,
	})
}
