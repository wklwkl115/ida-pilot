# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

`go build`, `go test`, and `go vet` work on any platform (Windows PowerShell included). Shell scripts (`make`, `./scripts/*.sh`) require Git Bash or WSL on Windows.

```bash
go build -o bin/ida-pilot ./cmd/ida-pilot   # Build server binary
go vet ./...                                  # Static analysis
go test ./internal/... ./ida/...              # Fast unit tests (no IDA required)
go test -v -run TestSetTypeLvarTool ./internal/server/   # Single test
make proto                                    # Regenerate protobuf stubs (requires protoc)
./scripts/consistency.sh                      # Verify cross-file constant consistency
```

**Local gates (`mise.toml`)** — the canonical developer suites; the Go/Python toolchain versions are pinned here (`go 1.25.0`, `python 3.12.10`). `.github/workflows/verify.yml` runs `mise run verify`, and `scripts/ci-parity.sh` asserts the workflow stays in sync with these tasks.

```bash
mise run dev-check    # Fast loop: go test ./internal/... ./ida/... (skips TestMCPToolGoldens)
mise run verify       # Release gate: go vet + go test -count=1 (no cache) + consistency.sh
mise run affected     # Picks dev-check vs verify based on changed paths (scripts/affected-check.sh)
mise run ci-parity    # Verify the local gate matches the GitHub workflow
```

**Test categories:**
- **Transport tests** (`TestStreamableHTTPTransportLifecycle`, `TestSSETransportLifecycle`): Use mock workers — no IDA required. Test full MCP lifecycle over HTTP and SSE transports.
- **Unit tests**: Everything else in `./internal/...` and `./ida/...` runs without IDA.

Useful make targets: `make build`, `make test` (unit + consistency), `make inspector` (launches MCP Inspector at localhost:5173).

**Python tests** (no IDA required): `python3 -m pytest python/tests/test_ida_wrapper.py python/tests/test_connect_server.py -v`. Install deps first: `python3 -m pip install protobuf pytest pytest-timeout`.

## Architecture

**Go server** (`cmd/ida-pilot`) manages sessions, caching, and MCP tool dispatch. **Python workers** (one per open binary) wrap IDA's idalib via Connect RPC. The Go server never touches IDA directly — all analysis goes through `(*client.Analysis).SomeRPC()` calls.

Worker communication uses Unix domain sockets (Linux/macOS) or TCP on localhost (Windows). The Go `Manager` delegates process startup to the direct launcher (`launcher_direct.go`), which spawns Python as a subprocess, waits for its port/socket readiness, and returns a `LaunchResult` (PID, BaseURL, stop/wait funcs) that the manager wraps into Connect RPC clients.

### Package layout

| Package | Role |
|---------|------|
| `internal/server/` | MCP tool handlers, caching, tiers, HTTP transport |
| `internal/session/` | `Registry` (in-memory session map with max-sessions cap) and `Store` (JSON-on-disk persistence for restart recovery) |
| `internal/worker/` | `Manager` (lifecycle), `Launcher` interface (`launcher.go`), direct subprocess launcher (`launcher_direct.go`), platform helpers (`launcher_wait.go`, `process_alive_*.go`), `Controller` interface to server |
| `python/worker/` | idalib wrapper (`ida_wrapper.py`), Connect RPC server (`connect_server.py`, `server.py`) |
| `python/tests/` | Python-side pytest suite: `test_ida_wrapper.py` (wrapper unit tests with mock IDA modules), `test_connect_server.py` (RPC routing tests) |
| `python/tests/mocks/` | Mock IDA modules (`mock_idapro`, `mock_ida_modules`) for testing without a real IDA Pro installation |

### Server file organization (`internal/server/`)

| File | Role |
|------|------|
| `server.go` | Tool registration, tier promotion/demotion, config |
| `dispatch.go` | Intent-based dispatchers (`query`, `get_references`, `search`, `inspect`, `set_metadata`, `set_type`, `import_metadata`) |
| `composite.go` | High-level aggregators (`surveyBinary`, `analyzeFunction`, `analyzeFunctions`, `annotateFunction`, `pruneContext`), analysis-context tools (`setAnalysisNote`, `getAnalysisContext`), and the `pyEval` escape hatch |
| `read.go` | Read handlers (disasm, memory, functions, imports, exports, strings, xrefs) |
| `write.go` | Write handlers (setName, setComment, setType, makeFunction) |
| `types.go` | Type-system handlers (globals, structs, enums) |
| `search.go` | Search handlers (findBinary, findText, dataRead) |
| `cross.go` | Cross-session tools (`cross_reference`, `cross_search`) for multi-binary analysis |
| `parallel.go` | Concurrency helpers (`runLabeled` for named fan-out, `parallelMap` for ordered batches) used by composite/dispatch handlers |
| `il2cpp.go` | Unity Il2Cpp metadata import handler |
| `flutter.go` | Flutter/Dart metadata import handler |
| `params.go` | All request structs with `mcp:` tags for schema generation |
| `format.go` | Text formatting helpers for compact output |
| `session.go` | Session lifecycle (open/close/restore) + Watchdog (expires idle sessions) |
| `cache.go` | Per-session cache (functions, decomp, xrefs, segments) with background warming on open; also holds the analysis context (visited functions + notes) |
| `output_cache.go` | Global output store — truncates responses over 8KB, assigns `_cache_id` for pagination |
| `progress.go` | Progress reporting for long-running operations (cache warming, auto-analysis) |
| `http.go` | HTTP mux: Streamable HTTP at `/` and SSE fallback at `/sse` |
| `util.go` | `resolveClient`, `resolveClientWait`, `resolveSession`, `logAndReturnError`, `waitForReady`, `readinessError` |

### Key patterns

**Tool handler signature:** Every handler follows `func (s *Server) handlerName(ctx context.Context, req *mcp.CallToolRequest, args SomeRequest) (*mcp.CallToolResult, any, error)`. The third return value (`error`) is how errors reach the MCP client — the SDK sets `IsError=true` and puts the message in `Content`. Return `nil, nil, err` for errors. The second return value (`any`) is metadata for middleware — `addToolWithCache` converts errors found there into the third return automatically. Never return `(nil, err, nil)` directly, as `json.Marshal(error)` produces `"{}"`.

**`resolveClient` / `resolveClientWait` / `resolveSession`:** All handlers call `resolveClient(sessionID, toolName)` or `resolveClientWait(ctx, req, sessionID, toolName)` to get the session + worker RPC client. When `session_id` is empty and exactly one session exists, it auto-resolves; with multiple, the error lists the active IDs so the agent can pick without a `list_sessions` round-trip. `resolveClientWait` is the preferred variant for user-facing tools: when the client provides an MCP progress token and the session is not ready, it blocks and streams `notifications/progress` via SSE until ready instead of returning an error.

**Readiness gate:** `resolveClient` rejects calls made before the binary finishes loading/auto-analysis/cache-warming (`readinessError` reads the in-memory progress stage — `starting`/`opening`/`analyzing`/`warming` → "not ready" with stage+percent, `failed` → distinct error). `resolveClientWait` (used by composite tools, dispatchers, and key read tools) turns the gate into a wait-with-progress: when a progress token is present, it blocks and streams `notifications/progress` via SSE until ready, eliminating the polling loop. Sessions with no progress snapshot (restored/reused) are treated as ready. Lifecycle tools that must run *during* loading (`run_auto_analysis`, `watch_auto_analysis`) call `resolveClientDuringLoad` to bypass the gate.

**`logAndReturnError`:** Standard error protocol — logs server-side and returns sanitized error to client. Use for all RPC and business errors.

**`addToolWithCache`:** Middleware wrapping `mcp.AddTool` that intercepts responses, stores large outputs (>8KB) in the output cache, and returns truncated previews with a `_cache_id` for pagination via `get_cached_output`.

**Progress streaming:** `open_binary` and `run_auto_analysis` never block on loading/analysis: the work runs on a detached `context.Background()` goroutine (see `backgroundOpen` / `beginBackgroundAnalysis`) that survives the tool call returning and any client-side per-call timeout — critical for large binaries whose analysis outlasts the MCP client's deadline. The agent polls `get_session_progress`, which a heartbeat refreshes every few seconds during the otherwise-opaque `plan_and_wait` so liveness is visible. Read/analysis tools still stream wait-progress: when a `progressToken` is present and the session isn't ready, `resolveClientWait` blocks and streams `notifications/progress` via SSE until ready. `progressReporter.Emit()` drops notifications silently when no token is present. (Mid-call streaming from `open_binary` itself is intentionally not used — the Streamable HTTP transport runs in JSON-response mode.)

**Dispatch pattern:** Consolidated tools (e.g., `query`) accept a discriminator field (`category`, `mode`, `action`, `target`, `format`), validate it, construct the appropriate inner request struct, and delegate to the existing handler. The inner handlers remain unchanged.

**Parallel RPC aggregation:** Used in `inspect`, `surveyBinary`, and `analyzeSingleFunction`. Use the helpers in `parallel.go` rather than hand-rolling goroutines: `runLabeled(map[string]func() (any, error))` for named fan-out with per-task errors, and `parallelMap[T,R]([]T, func(T) R) []R` for ordered batch operations where `fn` folds per-item errors into the return value.

**Analysis context tracking:** `set_analysis_note` / `get_analysis_context` persist per-address notes and a visited-function set in the session cache (`markVisited` / `setNote` in `cache.go`), letting an agent recover state after context loss. `prune_context` clears cached outputs and noted-function decomp to free memory.

**`py_eval` escape hatch:** Runs arbitrary Python inside the IDA worker (`_handle_py_eval` in `connect_server.py`); assign to `result` to return data. All `ida_*` modules are available — the fallback when no dedicated tool exists.

### Tiered tool loading

Tools register in three tiers: Tier 0 (boot: `open_binary`, `list_sessions`, `get_cached_output`), Tier 1 (read/analysis, promoted on first `open_binary`), Tier 2 (write/annotate, promoted on first analysis). Demotion back to Tier 0 happens when the last session closes. See `promoteToTier()` / `demoteToTier0()` in `server.go`.

### Session lifecycle

1. `open_binary` → spawns Python worker, creates session in Registry, saves metadata to Store, promotes to Tier 1. Returns immediately; loading + auto-analysis + cache warming run on a detached background goroutine (agent polls `get_session_progress` until `ready=true`). The detached context means a large binary whose load/analysis outlasts the client's tool-call timeout still completes.
2. `RestoreSessions()` on startup → reloads persisted sessions from Store, reconnects to running workers
3. `Watchdog()` goroutine → periodically checks for expired sessions and closes them
4. `close_binary` → stops worker, removes from Registry/Store, demotes to Tier 0 if no sessions remain

### Proto & RPC

Protobuf definitions: `proto/ida/worker/v1/service.proto`. Generated Go stubs: `ida/worker/v1/`. Generated Python stubs: `python/worker/gen/`. Three services: `SessionControl`, `AnalysisTools`, `Healthcheck`. Communication uses Connect RPC (HTTP-based, not raw gRPC).

### Cross-file constants

`consistency.yaml` + `scripts/consistency.sh` enforce that constants (port 17300, timeout 240min, page limits 1000/10000) stay in sync across `server.go`, `README.md`, and scripts. This runs as part of `make test`.

## Conventions

- Error returns use `logAndReturnError` — never return raw RPC errors to the MCP client. All handlers are wrapped by `addToolWithCache`, which converts error values in the second return into the third return so the SDK sets `IsError=true`.
- Request structs live in `params.go` with both `mcp:"..."` and `jsonschema:"..."` tags. The `jsonschema:` tag drives schema description generation for the MCP SDK.
- Compact text output is preferred over JSON for read tools (functions, imports, xrefs, etc.). JSON is used only for structured data (bytes, dword values).
- Write operations return `okResult` (the string `"ok"`) on success.
- Cache invalidation is explicit and targeted: `setName`/`deleteName` check `isCachedFunction()` before clearing the function list, then invalidate only that function's decomp (or do old-name text search for data labels). `setFunctionType`/`setGlobalType` use old-name search. `makeFunction` only invalidates the function list and xrefs. `annotateFunction` invalidates only the annotated function. `invalidateAllDecomp()` is reserved for `py_eval` (escape hatch).
- The `SessionID` field on request structs uses `json:"session_id,omitempty"` — the MCP framework auto-resolves it when omitted.

## Notes

- Python mock tests (`test_ida_wrapper.py`, `test_connect_server.py`) run without IDA Pro — they inject `python/tests/mocks/` into `sys.modules` to simulate idapro/ida_* APIs. Add new mock functions to `mock_ida_modules.py` when testing wrapper methods that use new IDA APIs.
- The project's own MCP client config is at `.mcp.json` (connects to `http://127.0.0.1:17300/mcp`).
- Python dependencies are in `python/requirements.txt`; test deps in `python/requirements-test.txt`.
- `consistency.sh` is bash — on Windows run it from Git Bash or WSL.
