package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/internal/session"
	"github.com/wklwkl115/ida-pilot/internal/worker"
)

const (
	DefaultPort              = 17300
	defaultSessionTimeoutMin = 240
	defaultMaxSessions       = 0
	defaultWorkerPath        = "python/worker/server.py"
	defaultPageLimit         = 1000
	maxPageLimit             = 10000
)

type Config struct {
	// Bind is the interface address the HTTP server listens on. Defaults to
	// "127.0.0.1" so a fresh run is reachable only by local clients. Set to
	// "0.0.0.0" (and pair with an upstream auth proxy) to expose externally.
	Bind                 string `json:"bind"`
	Port                 int    `json:"port"`
	SessionTimeoutMin    int    `json:"session_timeout_minutes"`
	MaxConcurrentSession int    `json:"max_concurrent_sessions"`
	DatabaseDirectory    string `json:"database_directory"`
	PythonWorkerPath     string `json:"python_worker_path"`
	Debug                bool   `json:"debug"`
	// EnablePyEval gates the py_eval tool. Off by default — py_eval runs
	// arbitrary Python inside the IDA worker (full filesystem / network
	// access) and is an RCE primitive in the hands of any client that can
	// reach the HTTP port.
	EnablePyEval bool `json:"enable_py_eval"`
	// AllowedRoots, when non-empty, restricts every agent-supplied filesystem
	// path (open_binary, import_metadata) to descendants of these directories,
	// after symlink resolution. Empty (the default) means no restriction — the
	// posture for a single trusted local client. Set it when exposing the port.
	AllowedRoots []string `json:"allowed_roots"`
}

// DefaultBind is the loopback address used when no Bind value is configured.
const DefaultBind = "127.0.0.1"

type Server struct {
	registry       *session.Registry
	workers        worker.Controller
	logger         *log.Logger
	sessionTimeout time.Duration
	debug          bool
	enablePyEval   bool // gates registration of the py_eval tool
	bind           string
	allowedRoots   []string // normalized filesystem allowlist; empty = unrestricted
	store          *session.Store
	cacheMu        sync.Mutex
	cache          map[string]*sessionCache
	progressMu     sync.Mutex
	progress       map[string]*sessionProgress
	outputs        *outputStore
	mcpServer      *mcp.Server
	tierMu         sync.Mutex
	tier           int // 0=boot, 1=read, 2=full
}

func New(registry *session.Registry, workers worker.Controller, logger *log.Logger, sessionTimeout time.Duration, debug bool, store *session.Store) *Server {
	return &Server{
		registry:       registry,
		workers:        workers,
		logger:         logger,
		sessionTimeout: sessionTimeout,
		debug:          debug,
		store:          store,
		cache:          make(map[string]*sessionCache),
		progress:       make(map[string]*sessionProgress),
		outputs:        newOutputStore(),
	}
}

// SetSecurity configures the bind address (used by the Origin/Host middleware),
// the py_eval enablement flag, and the filesystem path allowlist. Call before
// RegisterTools so the tier registration sees the final flag value. allowedRoots
// is normalized (absolute + symlink-resolved) here so the per-request check is a
// cheap prefix test.
func (s *Server) SetSecurity(bind string, enablePyEval bool, allowedRoots []string) {
	s.bind = bind
	s.enablePyEval = enablePyEval
	s.allowedRoots = normalizeRoots(allowedRoots)
}

func GetDefaultDBDir() string {
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "ida-pilot", "sessions")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".local", "share", "ida-pilot", "sessions")
	}
	return "/tmp/ida_sessions"
}

func LoadConfig(path string) (Config, error) {
	cfg := Config{
		Bind:                 DefaultBind,
		Port:                 DefaultPort,
		SessionTimeoutMin:    defaultSessionTimeoutMin,
		MaxConcurrentSession: defaultMaxSessions,
		DatabaseDirectory:    GetDefaultDBDir(),
		PythonWorkerPath:     defaultWorkerPath,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	ensureConfigDefaults(&cfg)
	return cfg, nil
}

func ensureConfigDefaults(cfg *Config) {
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Bind == "" {
		cfg.Bind = DefaultBind
	}
	if cfg.SessionTimeoutMin == 0 {
		cfg.SessionTimeoutMin = defaultSessionTimeoutMin
	}
	if cfg.PythonWorkerPath == "" {
		cfg.PythonWorkerPath = defaultWorkerPath
	}
	if cfg.DatabaseDirectory == "" {
		cfg.DatabaseDirectory = GetDefaultDBDir()
	}
}

func ApplyEnvOverrides(cfg *Config) {
	if val := os.Getenv("IDA_PILOT_BIND"); val != "" {
		cfg.Bind = val
	}
	if val := os.Getenv("IDA_PILOT_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Port = p
		}
	}
	if val := os.Getenv("IDA_PILOT_SESSION_TIMEOUT_MIN"); val != "" {
		if mins, err := strconv.Atoi(val); err == nil {
			cfg.SessionTimeoutMin = mins
		}
	}
	if val := os.Getenv("IDA_PILOT_MAX_SESSIONS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			cfg.MaxConcurrentSession = n
		}
	}
	if val := os.Getenv("IDA_PILOT_WORKER"); val != "" {
		cfg.PythonWorkerPath = val
	}
	if val := os.Getenv("IDA_PILOT_DEBUG"); val != "" {
		if parsed, ok := parseBool(val); ok {
			cfg.Debug = parsed
		}
	}
	if val := os.Getenv("IDA_PILOT_ENABLE_PY_EVAL"); val != "" {
		if parsed, ok := parseBool(val); ok {
			cfg.EnablePyEval = parsed
		}
	}
	if val := os.Getenv("IDA_PILOT_ALLOWED_ROOTS"); val != "" {
		// OS path-list separator (':' on Unix, ';' on Windows), matching $PATH.
		cfg.AllowedRoots = filepath.SplitList(val)
	}
}

// Tool tier names for RemoveTools on demotion. py_eval is appended at runtime
// only when EnablePyEval is set; the SDK no-ops removal of an unregistered
// tool either way, but keeping the slice honest avoids confusing the operator
// when they read the codebase.
var tier1ToolNames = []string{
	"close_binary", "save_database",
	"survey_binary", "analyze_function", "analyze_functions",
	"set_analysis_note", "get_analysis_context", "prune_context",
	"read_memory", "get_disasm",
	"query", "get_references", "search", "inspect",
	"cross_reference", "cross_search",
	"run_auto_analysis", "watch_auto_analysis", "get_session_progress",
}

// tier1Tools returns the Tier-1 tool names, optionally including py_eval.
func (s *Server) tier1Tools() []string {
	if s.enablePyEval {
		return append(append([]string{}, tier1ToolNames...), "py_eval")
	}
	return tier1ToolNames
}

var tier2ToolNames = []string{
	"annotate_function",
	"set_metadata", "set_type",
	"make_function",
	"import_metadata",
}

// RegisterTools registers Tier 0 (boot) tools only.
// Tier 1 (read) and Tier 2 (write) tools are registered dynamically
// when the agent's workflow phase advances, reducing schema overhead.
// 28 tools total across 3 tiers (3 boot + 20 read + 5 write).
func (s *Server) RegisterTools(mcpServer *mcp.Server) {
	s.mcpServer = mcpServer
	s.registerTier0()
}

// PromoteIfSessions checks for existing sessions and promotes tiers accordingly.
// Call after RestoreSessions.
func (s *Server) PromoteIfSessions() {
	if len(s.registry.List()) > 0 {
		s.promoteToTier(1)
	}
}

func (s *Server) promoteToTier(target int) {
	s.tierMu.Lock()
	defer s.tierMu.Unlock()
	if s.tier >= target {
		return
	}
	if target >= 1 && s.tier < 1 {
		s.registerTier1()
		s.logger.Printf("[Tools] promoted to tier 1 (read): %d tools", len(s.tier1Tools())+3)
	}
	if target >= 2 && s.tier < 2 {
		s.registerTier2()
		s.logger.Printf("[Tools] promoted to tier 2 (full): +%d write tools", len(tier2ToolNames))
	}
	s.tier = target
}

func (s *Server) demoteToTier0() {
	s.tierMu.Lock()
	defer s.tierMu.Unlock()
	if s.tier == 0 {
		return
	}
	if s.tier >= 2 {
		s.mcpServer.RemoveTools(tier2ToolNames...)
	}
	if s.tier >= 1 {
		s.mcpServer.RemoveTools(s.tier1Tools()...)
	}
	s.tier = 0
	s.logger.Printf("[Tools] demoted to tier 0 (boot): 3 tools")
}

func (s *Server) registerTier0() {
	m := s.mcpServer

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "open_binary",
		Description: "Open binary for analysis. Returns immediately; loading and auto-analysis run in the background — poll get_session_progress until ready=true before analyzing (large binaries take minutes). Set skip_analysis=true for import workflows.",
	}, s.openBinary)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "list_sessions",
		Description: "List active sessions",
	}, s.listSessions)

	mcp.AddTool(m, &mcp.Tool{
		Name:        "get_cached_output",
		Description: "Retrieve truncated response. Use _cache_id from any truncated output.",
	}, s.getCachedOutput)
}

func (s *Server) registerTier1() {
	m := s.mcpServer

	// ── Session lifecycle ──
	addToolWithCache(s, m, &mcp.Tool{
		Name:        "close_binary",
		Description: "Close analysis session",
	}, s.closeBinary)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "save_database",
		Description: "Save IDA database",
	}, s.saveDatabase)

	// ── Composite tools (preferred for agents) ──
	addToolWithCache(s, m, &mcp.Tool{
		Name:        "survey_binary",
		Description: "One-call binary overview: segments, functions, imports, exports, strings (counts + top entries), entry point, decompiler status. Use as first call after open.",
	}, s.surveyBinary)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "analyze_function",
		Description: "One-call function analysis: pseudocode + metadata + xrefs + comments.",
	}, s.analyzeFunction)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "analyze_functions",
		Description: "Batch-analyze up to 10 functions in parallel: pseudocode + metadata + xrefs for each. Use for call-graph traversal.",
	}, s.analyzeFunctions)

	// ── Context tools ──
	addToolWithCache(s, m, &mcp.Tool{
		Name:        "set_analysis_note",
		Description: "Store a note on an address. Persists server-side for context recovery.",
	}, s.setAnalysisNote)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "get_analysis_context",
		Description: "Get all visited functions and notes. Use after context loss to resume work.",
	}, s.getAnalysisContext)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "prune_context",
		Description: "Clear cached tool outputs and noted function caches. Call after taking summary notes to free memory.",
	}, s.pruneContext)

	// ── Intent-based read tools ──
	addToolWithCache(s, m, &mcp.Tool{
		Name:        "read_memory",
		Description: "Read memory at address. format: bytes|dword|qword|byte|string (default bytes). size: byte count for bytes, max length for string.",
	}, s.readMemory)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "get_disasm",
		Description: "Disassembly at address. Set whole_function=true for entire function.",
	}, s.getDisasm)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "query",
		Description: "Browse binary data by category: functions, imports, exports, strings, globals, segments, structs, enums, entry_point. Supports regex, pagination, and category-specific filters.",
	}, s.query)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "get_references",
		Description: "Cross-references. Requires address (hex 0x... or decimal). mode: code (default, direction: to/from/both), data, or string.",
	}, s.getReferences)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "search",
		Description: "Search binary. mode: text (needle + case_sensitive) or binary (IDA pattern). Specify start/end address range.",
	}, s.search)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "inspect",
		Description: "Metadata at address in one call: name, type, comment, function bounds, instruction length. For decompilation use analyze_function.",
	}, s.inspect)

	// ── Cross-session tools ──
	addToolWithCache(s, m, &mcp.Tool{
		Name:        "cross_reference",
		Description: "Look up a symbol in one binary and find where it appears in another. Provide source_session_id (where the address lives), target_session_id (where to search), and address. Searches imports, exports, function names, and strings in the target.",
	}, s.crossReference)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "cross_search",
		Description: "Search across multiple sessions simultaneously. mode: functions, imports, exports, or strings. Supports regex and exact needle. Omit session_ids to search all active sessions.",
	}, s.crossSearch)

	// ── Analysis control ──
	addToolWithCache(s, m, &mcp.Tool{
		Name:        "run_auto_analysis",
		Description: "Force auto-analysis. Not needed if open_binary ran with analysis.",
	}, s.runAutoAnalysis)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "watch_auto_analysis",
		Description: "Stream auto-analysis progress",
	}, s.watchAutoAnalysis)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "get_session_progress",
		Description: "Session load/analysis progress and readiness (stage, ready, auto_running). Poll after open_binary until ready=true.",
	}, s.getSessionProgress)

	// ── Escape hatches (opt-in, RCE primitive) ──
	// py_eval runs arbitrary Python in the IDA worker — full host filesystem
	// and network access. Registered only when the operator passes
	// --enable-py-eval / IDA_PILOT_ENABLE_PY_EVAL=1; otherwise it stays off
	// the tool list entirely.
	if s.enablePyEval {
		addToolWithCache(s, m, &mcp.Tool{
			Name:        "py_eval",
			Description: "Execute Python in IDA. All ida_* modules available. Assign to 'result' to return data. Caches are invalidated after each call so later reads reflect any edits; set read_only=true for pure reads to keep caches warm.",
		}, s.pyEval)
	}
}

func (s *Server) registerTier2() {
	m := s.mcpServer

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "annotate_function",
		Description: "Batch-annotate a function: rename/retype variables, rename function, set comments — returns updated pseudocode. Prefer over individual set_metadata/set_type for function-scoped changes.",
	}, s.annotateFunction)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "set_metadata",
		Description: "Set or delete names and comments. action: set_name, delete_name, or set_comment (scope: address/function/decompiler).",
	}, s.setMetadata)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "set_type",
		Description: "Apply type information. target: function (prototype), global (C-type), or lvar (C-type + function_address + lvar_name).",
	}, s.setType)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "make_function",
		Description: "Create function at address",
	}, s.makeFunction)

	addToolWithCache(s, m, &mcp.Tool{
		Name:        "import_metadata",
		Description: "Import external metadata. format: il2cpp (script.json + il2cpp.h) or flutter (flutter_meta.json).",
	}, s.importMetadata)
}

func normalizePagination(offset, limit int) (int, int, error) {
	if offset < 0 {
		return 0, 0, fmt.Errorf("offset must be >= 0")
	}
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if limit > maxPageLimit {
		return 0, 0, fmt.Errorf("limit must be <= %d", maxPageLimit)
	}
	return offset, limit, nil
}

// clampPage normalizes the requested offset/limit and clamps them against
// total to yield slice indices, so callers can write `xs[offset:end]` without
// re-implementing the bounds checks.
func clampPage(rawOffset, rawLimit, total int) (offset, end int, err error) {
	offset, limit, err := normalizePagination(rawOffset, rawLimit)
	if err != nil {
		return 0, 0, err
	}
	if offset > total {
		offset = total
	}
	end = offset + limit
	if end > total {
		end = total
	}
	return offset, end, nil
}

func compileRegex(expr string, caseSensitive bool) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	if caseSensitive {
		return regexp.Compile(expr)
	}
	return regexp.Compile("(?i)" + expr)
}

func mapStringItems(items []*pb.StringItem) []map[string]any {
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]any{
			"address": hexAddr(item.Address),
			"value":   item.Value,
		})
	}
	return result
}

func mapFunctionItems(items []*pb.Function) []map[string]any {
	result := make([]map[string]any, 0, len(items))
	for _, fn := range items {
		result = append(result, map[string]any{
			"address": hexAddr(fn.Address),
			"name":    fn.Name,
		})
	}
	return result
}

func mapImportItems(items []*pb.Import) []map[string]any {
	result := make([]map[string]any, 0, len(items))
	for _, imp := range items {
		entry := map[string]any{
			"module":  imp.Module,
			"address": hexAddr(imp.Address),
			"name":    imp.Name,
		}
		if imp.Ordinal != 0 {
			entry["ordinal"] = imp.Ordinal
		}
		result = append(result, entry)
	}
	return result
}

func mapExportItems(items []*pb.Export) []map[string]any {
	result := make([]map[string]any, 0, len(items))
	for _, exp := range items {
		entry := map[string]any{
			"address": hexAddr(exp.Address),
			"name":    exp.Name,
		}
		if exp.Ordinal != 0 {
			entry["ordinal"] = exp.Ordinal
		}
		result = append(result, entry)
	}
	return result
}

func matchModule(module, filter string, caseSensitive bool) bool {
	if filter == "" {
		return true
	}
	if caseSensitive {
		return strings.Contains(module, filter)
	}
	return strings.Contains(strings.ToLower(module), strings.ToLower(filter))
}

func parseBool(val string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "t", "yes", "y", "on":
		return true, true
	case "0", "false", "f", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}
