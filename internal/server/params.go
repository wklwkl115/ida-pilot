package server

// Parameter types for all MCP tool implementations.
// session_id is optional everywhere — auto-detected when only one session is active.

type OpenBinaryRequest struct {
	Path         string `json:"path" jsonschema:"path to binary file"`
	SkipAnalysis bool   `json:"skip_analysis,omitempty" jsonschema:"skip auto-analysis — use for large binaries, then call run_auto_analysis separately"`
}

type CloseBinaryRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type ListSessionsRequest struct{}

type SaveDatabaseRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type GetSessionProgressRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type RunAutoAnalysisRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type WatchAutoAnalysisRequest struct {
	SessionID   string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	IntervalMs  int    `json:"interval_ms,omitempty" jsonschema:"poll interval in milliseconds (default 1000)"`
	TimeoutSecs int    `json:"timeout_seconds,omitempty" jsonschema:"timeout in seconds"`
}

type GetDisasmRequest struct {
	SessionID     string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address       string `json:"address" jsonschema:"address as hex (0x...) or decimal"`
	WholeFunction bool   `json:"whole_function,omitempty" jsonschema:"disassemble entire function (default false)"`
}

type GetFunctionsRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size (default 1000, max 10000)"`
	Regex     string `json:"regex,omitempty" jsonschema:"regex filter on function name"`
	CaseSens  bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
	NamedOnly bool   `json:"named_only,omitempty" jsonschema:"exclude auto-named functions (sub_*/j_*)"`
}

type GetImportsRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size (default 1000, max 10000)"`
	Module    string `json:"module,omitempty" jsonschema:"filter by module name"`
	Regex     string `json:"regex,omitempty" jsonschema:"regex filter on import name"`
	CaseSens  bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
}

type GetExportsRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size (default 1000, max 10000)"`
	Regex     string `json:"regex,omitempty" jsonschema:"regex filter on export name"`
	CaseSens  bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
}

type GetStringsRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size (default 1000, max 10000)"`
	Regex     string `json:"regex,omitempty" jsonschema:"regex filter on string value"`
	CaseSens  bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
}

type ReadMemoryRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   string `json:"address" jsonschema:"memory address as hex (0x...) or decimal"`
	Format    string `json:"format,omitempty" jsonschema:"output format: bytes, dword, qword, byte, or string (default bytes)"`
	Size      uint32 `json:"size,omitempty" jsonschema:"byte count for bytes format, or max length for string format"`
}

type GetSegmentsRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type GetEntryPointRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

// SetCommentRequest is the unified comment setter (address, function, and decompiler comments).
type SetCommentRequest struct {
	SessionID       string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address         uint64 `json:"address" jsonschema:"target address as decimal integer (for decompiler scope: pseudocode address)"`
	Comment         string `json:"comment" jsonschema:"comment text to set"`
	Scope           string `json:"scope,omitempty" jsonschema:"comment scope: address (default), function, or decompiler"`
	Repeatable      bool   `json:"repeatable,omitempty" jsonschema:"repeatable comment (address scope only)"`
	FunctionAddress uint64 `json:"function_address,omitempty" jsonschema:"function address as decimal integer (decompiler scope only)"`
}

type SetNameRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   uint64 `json:"address" jsonschema:"address as decimal integer"`
	Name      string `json:"name" jsonschema:"new name to assign"`
}

type DeleteNameRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   uint64 `json:"address" jsonschema:"address as decimal integer"`
}

type SetLvarTypeRequest struct {
	SessionID       string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	FunctionAddress uint64 `json:"function_address" jsonschema:"function address as decimal integer"`
	LvarName        string `json:"lvar_name" jsonschema:"local variable name"`
	LvarType        string `json:"lvar_type" jsonschema:"C-style type declaration"`
}

type SetGlobalTypeRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   uint64 `json:"address" jsonschema:"global address as decimal integer"`
	Type      string `json:"type" jsonschema:"C-style type declaration"`
}

type SetFunctionTypeRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   uint64 `json:"address" jsonschema:"function address as decimal integer"`
	Prototype string `json:"prototype" jsonschema:"C-style function prototype"`
}

type MakeFunctionRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   string `json:"address" jsonschema:"start address as hex (0x...) or decimal"`
}

type GetGlobalsRequest struct {
	SessionID     string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Regex         string `json:"regex,omitempty" jsonschema:"regex filter on global name"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
	Offset        int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Limit         int    `json:"limit,omitempty" jsonschema:"max results (default 1000, max 10000)"`
}

// GetStructsRequest handles both listing and detail retrieval.
type GetStructsRequest struct {
	SessionID     string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Name          string `json:"name,omitempty" jsonschema:"struct name for detail view (omit to list all)"`
	Regex         string `json:"regex,omitempty" jsonschema:"regex filter on struct name (list mode)"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
}

// GetEnumsRequest handles both listing and detail retrieval.
type GetEnumsRequest struct {
	SessionID     string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Name          string `json:"name,omitempty" jsonschema:"enum name for detail view (omit to list all)"`
	Regex         string `json:"regex,omitempty" jsonschema:"regex filter on enum name (list mode)"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
}

type FindBinaryRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Start     uint64 `json:"start" jsonschema:"start address as decimal integer (0 for image base)"`
	End       uint64 `json:"end" jsonschema:"end address as decimal integer (0 for BADADDR)"`
	Pattern   string `json:"pattern" jsonschema:"IDA binary search pattern"`
	SearchUp  bool   `json:"search_up,omitempty" jsonschema:"search upward from start"`
}

type FindTextRequest struct {
	SessionID     string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Start         uint64 `json:"start" jsonschema:"start address as decimal integer (0 for image base)"`
	End           uint64 `json:"end" jsonschema:"end address as decimal integer (0 for BADADDR)"`
	Needle        string `json:"needle" jsonschema:"text string to search for"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive search"`
	Unicode       bool   `json:"unicode,omitempty" jsonschema:"search for unicode strings"`
}

type ImportIl2cppRequest struct {
	SessionID  string   `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	ScriptPath string   `json:"script_path" jsonschema:"path to Il2Cpp script.json metadata file"`
	Il2cppPath string   `json:"il2cpp_path" jsonschema:"path to il2cpp.h header file"`
	Fields     []string `json:"fields,omitempty" jsonschema:"sections to import (default all)"`
}

type ImportFlutterRequest struct {
	SessionID    string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	MetaJsonPath string `json:"meta_json_path" jsonschema:"path to flutter_meta.json file"`
}

type SurveyBinaryRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type AnalyzeFunctionRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   string `json:"address" jsonschema:"function address as hex (0x...) or decimal"`
}

type AnalyzeFunctionsRequest struct {
	SessionID string   `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Addresses []string `json:"addresses" jsonschema:"list of function addresses as hex (0x...) or decimal (max 10)"`
}

type SetAnalysisNoteRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   string `json:"address" jsonschema:"function or address as hex (0x...) or decimal"`
	Note      string `json:"note" jsonschema:"analysis note text to attach"`
}

type GetAnalysisContextRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type PruneContextRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
}

type PyEvalRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Code      string `json:"code" jsonschema:"Python code to execute in IDA (assign to 'result' variable to return data)"`
	ReadOnly  bool   `json:"read_only,omitempty" jsonschema:"set true only when the code does not modify the database; by default caches are invalidated after the call to stay consistent with edits"`
}

type LvarRename struct {
	Current string `json:"current" jsonschema:"current variable name"`
	New     string `json:"new" jsonschema:"new variable name"`
}

type LvarRetype struct {
	Name string `json:"name" jsonschema:"variable name (use current name, before any renames)"`
	Type string `json:"type" jsonschema:"C-style type declaration"`
}

type DecompComment struct {
	Address string `json:"address" jsonschema:"pseudocode address as hex (0x...) or decimal"`
	Comment string `json:"comment" jsonschema:"comment text"`
}

type AnnotateFunctionRequest struct {
	SessionID      string          `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address        string          `json:"address" jsonschema:"function address as hex (0x...) or decimal"`
	Name           string          `json:"name,omitempty" jsonschema:"new function name"`
	Comment        string          `json:"comment,omitempty" jsonschema:"function comment text"`
	Renames        []LvarRename    `json:"renames,omitempty" jsonschema:"local variable renames (applied after retypes)"`
	Retypes        []LvarRetype    `json:"retypes,omitempty" jsonschema:"local variable type changes (use current names, before renames)"`
	DecompComments []DecompComment `json:"decompiler_comments,omitempty" jsonschema:"pseudocode line comments"`
}

// Unified dispatch request types

type QueryRequest struct {
	SessionID     string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Category      string `json:"category" jsonschema:"data category: functions, imports, exports, strings, globals, segments, structs, enums, or entry_point"`
	Regex         string `json:"regex,omitempty" jsonschema:"regex filter"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive regex"`
	Offset        int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit         int    `json:"limit,omitempty" jsonschema:"page size (default 1000, max 10000)"`
	NamedOnly     bool   `json:"named_only,omitempty" jsonschema:"exclude auto-named functions like sub_*/j_* (functions category only)"`
	Module        string `json:"module,omitempty" jsonschema:"filter by module name (imports category only)"`
	Name          string `json:"name,omitempty" jsonschema:"item name for detail view (structs/enums categories only)"`
}

type GetReferencesRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   string `json:"address" jsonschema:"target address as hex (0x...) or decimal — required"`
	Mode      string `json:"mode,omitempty" jsonschema:"reference mode: code (default), data, or string"`
	Direction string `json:"direction,omitempty" jsonschema:"reference direction: to, from, or both (code mode only, default both)"`
}

type SearchRequest struct {
	SessionID     string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Mode          string `json:"mode" jsonschema:"search mode: text or binary"`
	Needle        string `json:"needle,omitempty" jsonschema:"text to search for (text mode)"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" jsonschema:"case sensitive search (text mode)"`
	Unicode       bool   `json:"unicode,omitempty" jsonschema:"search for unicode strings (text mode)"`
	Pattern       string `json:"pattern,omitempty" jsonschema:"IDA binary search pattern (binary mode)"`
	SearchUp      bool   `json:"search_up,omitempty" jsonschema:"search upward (binary mode)"`
	Start         string `json:"start,omitempty" jsonschema:"start address as hex (0x...) or decimal (empty for image base)"`
	End           string `json:"end,omitempty" jsonschema:"end address as hex (0x...) or decimal (empty for BADADDR)"`
}

type InspectRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   string `json:"address" jsonschema:"address to inspect as hex (0x...) or decimal"`
}

// ── Cross-session tools ──

type CrossReferenceRequest struct {
	SourceSessionID string `json:"source_session_id" jsonschema:"session ID of the source binary (where the address lives)"`
	TargetSessionID string `json:"target_session_id" jsonschema:"session ID of the target binary (where to search for references)"`
	Address         string `json:"address" jsonschema:"address in source binary as hex (0x...) or decimal"`
}

type CrossSearchRequest struct {
	SessionIDs []string `json:"session_ids" jsonschema:"session IDs to search across (omit to use all active sessions)"`
	Mode       string   `json:"mode" jsonschema:"what to search: functions, imports, exports, or strings"`
	Regex      string   `json:"regex,omitempty" jsonschema:"regex filter on name"`
	Needle     string   `json:"needle,omitempty" jsonschema:"exact name to search for"`
	Limit      int32    `json:"limit,omitempty" jsonschema:"max results per session (default 100, max 1000)"`
}

type SetMetadataRequest struct {
	SessionID       string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address         string `json:"address" jsonschema:"target address as hex (0x...) or decimal"`
	Action          string `json:"action" jsonschema:"action: set_name, delete_name, or set_comment"`
	Name            string `json:"name,omitempty" jsonschema:"new name (set_name action)"`
	Comment         string `json:"comment,omitempty" jsonschema:"comment text (set_comment action)"`
	Scope           string `json:"scope,omitempty" jsonschema:"comment scope: address (default), function, or decompiler (set_comment action)"`
	Repeatable      bool   `json:"repeatable,omitempty" jsonschema:"repeatable comment (address scope only)"`
	FunctionAddress string `json:"function_address,omitempty" jsonschema:"function address as hex (0x...) or decimal (decompiler scope only)"`
}

type SetTypeRequest struct {
	SessionID       string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address         string `json:"address,omitempty" jsonschema:"address as hex (0x...) or decimal (function/global targets)"`
	Target          string `json:"target" jsonschema:"target type: function, global, or lvar"`
	Type            string `json:"type,omitempty" jsonschema:"C-style type declaration (global/lvar targets)"`
	Prototype       string `json:"prototype,omitempty" jsonschema:"C-style function prototype (function target)"`
	FunctionAddress string `json:"function_address,omitempty" jsonschema:"function address as hex (0x...) or decimal (lvar target only)"`
	LvarName        string `json:"lvar_name,omitempty" jsonschema:"local variable name (lvar target only)"`
}

type ImportMetadataRequest struct {
	SessionID    string   `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Format       string   `json:"format" jsonschema:"metadata format: il2cpp or flutter"`
	ScriptPath   string   `json:"script_path,omitempty" jsonschema:"path to script.json (il2cpp format)"`
	Il2cppPath   string   `json:"il2cpp_path,omitempty" jsonschema:"path to il2cpp.h (il2cpp format)"`
	Fields       []string `json:"fields,omitempty" jsonschema:"sections to import (il2cpp format, default all)"`
	MetaJsonPath string   `json:"meta_json_path,omitempty" jsonschema:"path to flutter_meta.json (flutter format)"`
}

type GetCachedOutputRequest struct {
	CacheID string `json:"cache_id" jsonschema:"cache ID from a truncated response (_cache_id field)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"character offset to start reading from (default 0)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"max characters to return (default 8000, use 0 for all remaining)"`
}

type GetXRefsRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   uint64 `json:"address" jsonschema:"address as decimal integer"`
	Direction string `json:"direction,omitempty" jsonschema:"reference direction: to, from, or both (default both)"`
}

// Invoked internally via dispatchers, not registered as separate tools.

type DataRefRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   uint64 `json:"address" jsonschema:"address as decimal integer"`
}

type StringXRefRequest struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID (auto-detected when only one session exists)"`
	Address   uint64 `json:"address" jsonschema:"string address as decimal integer"`
}
