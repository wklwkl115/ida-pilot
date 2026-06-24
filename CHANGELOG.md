# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims for
[Semantic Versioning](https://semver.org/) — while pre-1.0, minor versions may
include breaking changes.

## [Unreleased]

## [0.1.0] - 2026-06-24

First public release: a headless IDA Pro analysis server that exposes the
decompiler and disassembler as MCP tools for AI agents.

### Added
- MCP server with **tiered tool loading** — agents boot with 3 tools; read/analysis
  and write tools promote in as the workflow advances, keeping the per-turn schema small.
- **Composite tools** for one-call analysis: `survey_binary`, `analyze_function`,
  `analyze_functions` (batch up to 10), `annotate_function`.
- **Dispatchers**: `query`, `get_references`, `search`, `inspect`, `set_metadata`,
  `set_type`, `import_metadata`.
- **Cross-session** tools for multi-binary work: `cross_reference`, `cross_search`.
- **Multi-layer caching** (function list, decompilation LRU, xrefs, segments) with
  background warming, plus an output cache with pagination for large responses.
- **Streamable HTTP** (`/`) and **SSE** (`/sse`) transports.
- Metadata import for **Unity Il2Cpp** and **Flutter**.
- `py_eval` escape hatch for arbitrary Python in the IDA worker (opt-in).
- Session persistence and restore across server restarts.

### Security
- **Loopback-only bind** by default; `--bind` / `IDA_PILOT_BIND` to expose (behind your own auth).
- **`Origin` / `Host` guard** on loopback binds — blocks DNS-rebinding and browser cross-origin attacks.
- **`py_eval` off by default** — enable with `--enable-py-eval`; treated as an RCE primitive.
- **Optional filesystem allowlist** (`--allowed-roots`) confining agent-supplied paths, symlink-resolved.
- 128-bit output-cache IDs.
- Worker repair path purges IDA sidecars by exact name (no glob, no symlink-follow).

### Reliability
- Loading and auto-analysis run **detached**, surviving client tool-call timeouts; a
  live progress heartbeat keeps `get_session_progress` responsive even while idalib
  holds the GIL through `auto_wait()` — large binaries no longer look hung.
- **Worker lifetime bound to the server** (Windows Job Object `KILL_ON_JOB_CLOSE` /
  Linux `Pdeathsig`) so a crashed server leaves no orphaned workers holding databases open.
- **Session restore reopens the database**, so restored sessions are immediately usable.
- `close_binary` teardown hardened (kill-first to avoid a Windows access-denied race;
  session record removed unconditionally).

### Tooling
- CI (`verify` workflow): Windows release gate via `mise`, plus a cross-platform
  (ubuntu/macOS) unit + race job. Local gates mirrored in `mise.toml`.

[Unreleased]: https://github.com/wklwkl115/ida-pilot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wklwkl115/ida-pilot/releases/tag/v0.1.0
