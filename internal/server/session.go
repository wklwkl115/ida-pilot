package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/internal/session"
	"github.com/wklwkl115/ida-pilot/internal/worker"
)

// Session lifecycle management functions

func (s *Server) RestoreSessions() {
	if s.store == nil {
		return
	}
	metas, err := s.store.Load()
	if err != nil {
		s.logger.Printf("Failed to load persisted sessions: %v", err)
		return
	}
	if len(metas) == 0 {
		return
	}

	s.logger.Printf("Restoring %d session(s) from disk", len(metas))
	for _, meta := range metas {
		// Probe the binary path before paying the worker-startup cost.
		// A binary moved or deleted between server runs leaves a stale
		// metadata entry that would otherwise produce a confusing
		// idapro.open_database failure mid-restart. Corruption of the
		// sidecar .i64/.idb is handled lower down by the worker's own
		// _try_open_with_repair path; we don't probe lockfiles here
		// because IDA's lockfile naming varies across versions.
		if _, err := os.Stat(meta.BinaryPath); err != nil {
			s.logger.Printf("Skipping session %s: binary path %q no longer accessible: %v", meta.ID, meta.BinaryPath, err)
			if delErr := s.store.Delete(meta.ID); delErr != nil {
				s.logger.Printf("Warning: failed to remove stale session record %s: %v", meta.ID, delErr)
			}
			continue
		}
		sess, err := s.registry.Restore(meta)
		if err != nil {
			s.logger.Printf("Skipping session %s: %v", meta.ID, err)
			continue
		}
		if err := s.workers.Start(context.Background(), sess, meta.BinaryPath); err != nil {
			s.logger.Printf("Failed to restart worker for session %s: %v", sess.ID, err)
			s.registry.Delete(sess.ID)
			s.deleteSessionState(sess.ID)
			s.deleteSessionCache(sess.ID)
			continue
		}
		s.logger.Printf("Session %s restored for binary %s", sess.ID, meta.BinaryPath)
	}
}

func (s *Server) persistSession(sess *session.Session) {
	if s.store == nil {
		return
	}
	if err := s.store.Save(sess); err != nil {
		s.logger.Printf("Warning: failed to persist session %s: %v", sess.ID, err)
	}
}

func (s *Server) deleteSessionState(sessionID string) {
	if s.store == nil {
		return
	}
	if err := s.store.Delete(sessionID); err != nil {
		s.logger.Printf("Warning: failed to delete session %s: %v", sessionID, err)
	}
}

// Watchdog cleans up expired sessions
func (s *Server) Watchdog() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cleaned := s.cleanupExpiredSessions(s.registry.Expired())
		if cleaned > 0 && len(s.registry.List()) == 0 {
			s.logger.Printf("[Watchdog] All sessions expired — demoting to tier 0")
			s.demoteToTier0()
		}
	}
}

func (s *Server) cleanupExpiredSessions(expired []*session.Session) int {
	cleaned := 0
	for _, sess := range expired {
		// A session is "expired" the moment time-since-Touch exceeds the
		// timeout, but a long-running worker operation may still be active.
		// Skip those and re-evaluate on the next tick.
		if sess.HasInFlight() {
			s.debugf("[Watchdog] Session %s expired but has in-flight worker operations; deferring", sess.ID)
			continue
		}
		// The expired slice is a snapshot. A long operation can finish between
		// Registry.Expired and this point, refreshing LastActivity as it releases
		// the in-flight lease, so re-check before deleting.
		if !sess.IsExpired() {
			continue
		}
		s.debugf("[Watchdog] Session %s expired, cleaning up", sess.ID)
		s.workers.Stop(sess.ID)
		s.registry.Delete(sess.ID)
		s.deleteSessionState(sess.ID)
		s.deleteSessionCache(sess.ID)
		s.clearProgress(sess.ID)
		cleaned++
	}
	return cleaned
}

// MCP tool implementations for session management

func (s *Server) openBinary(ctx context.Context, req *mcp.CallToolRequest, args OpenBinaryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("open_binary", "", map[string]any{"path": args.Path, "skip_analysis": args.SkipAnalysis})
	validPath, perr := s.validatePath("path", args.Path)
	if perr != nil {
		return nil, s.logAndReturnError("open_binary path validation", perr), nil
	}
	args.Path = validPath
	if existing, ok := s.registry.FindByBinaryPath(args.Path); ok {
		// Do NOT overwrite the session's progress here. The existing session
		// already carries its true stage (opening/analyzing/warming/ready); a
		// "reused" stamp would clobber an in-progress analysis and make the
		// session look ready when it isn't.
		result := map[string]any{
			"session_id":  existing.ID,
			"binary_path": existing.BinaryPath,
			"created_at":  existing.CreatedAt.Unix(),
			"reused":      true,
		}
		s.enrichSessionResult(ctx, existing.ID, result)
		s.promoteToTier(1)
		jsonResult, _ := json.Marshal(result)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(jsonResult)},
			},
		}, nil, nil
	}

	sess, err := s.registry.Create(args.Path, s.sessionTimeout)
	if err != nil {
		return nil, s.logAndReturnError("open_binary session creation", err), nil
	}

	s.recordProgress(sess.ID, "starting", "Starting worker", 0, 4)
	if err := s.workers.Start(ctx, sess, args.Path); err != nil {
		s.registry.Delete(sess.ID)
		s.deleteSessionCache(sess.ID)
		s.clearProgress(sess.ID)
		return nil, s.logAndReturnError("open_binary worker start", err), nil
	}

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		s.workers.Stop(sess.ID)
		s.registry.Delete(sess.ID)
		s.deleteSessionCache(sess.ID)
		s.clearProgress(sess.ID)
		return nil, s.logAndReturnError("open_binary worker client", err), nil
	}

	s.persistSession(sess)
	s.promoteToTier(1)

	autoAnalyze := !args.SkipAnalysis

	// Loading + auto-analysis + cache warming run on a DETACHED context so they
	// survive this tool call returning AND any client-side per-call timeout: a
	// 200MB binary can take far longer to load+analyze than the MCP client's
	// tool-call deadline, and the worker's IDA thread can't be interrupted
	// mid-analysis anyway. The agent polls get_session_progress until
	// ready=true. Mid-call progress streaming is intentionally not attempted:
	// the Streamable HTTP transport runs in JSON-response mode, so interim
	// notifications wouldn't reach the client during the call regardless.
	s.recordProgress(sess.ID, "opening", "Loading binary into IDA", 1, 4)
	go s.backgroundOpen(sess, client, args.Path, autoAnalyze, nil, context.Background())

	message := "Binary is loading in the background. Poll get_session_progress until ready=true before analyzing"
	if autoAnalyze {
		message += " (large binaries may take minutes)."
	} else {
		message += ". Auto-analysis skipped — call run_auto_analysis when ready."
	}
	result := map[string]any{
		"session_id":       sess.ID,
		"binary_path":      args.Path,
		"created_at":       sess.CreatedAt.Unix(),
		"status":           "opening",
		"analysis_pending": autoAnalyze,
		"auto_running":     true,
		"message":          message,
	}
	s.enrichSessionResult(ctx, sess.ID, result)
	jsonResult, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}

// enrichSessionResult fetches live session info from the worker and adds
// has_decompiler, auto_state, and auto_running to the result map (best-effort).
// Bounded by workerStatusTimeout: when open_binary reuses a session whose worker
// is mid-analysis, the worker's IDA thread holds the GIL and GetSessionInfo can't
// answer — without the timeout this would hang the open_binary call for the whole
// analysis. On timeout we just skip the enrichment.
func (s *Server) enrichSessionResult(ctx context.Context, sessionID string, result map[string]any) {
	client, err := s.workers.GetClient(sessionID)
	if err != nil {
		return
	}
	infoCtx, cancel := context.WithTimeout(ctx, workerStatusTimeout)
	defer cancel()
	infoResp, err := (*client.SessionCtrl).GetSessionInfo(infoCtx, connect.NewRequest(&pb.GetSessionInfoRequest{}))
	if err != nil || infoResp.Msg == nil {
		return
	}
	result["has_decompiler"] = infoResp.Msg.GetHasDecompiler()
	result["auto_state"] = infoResp.Msg.GetAutoState()
	result["auto_running"] = infoResp.Msg.GetAutoRunning()
}

// backgroundOpen loads the binary and runs auto-analysis off the request path.
// It uses a detached context so it survives the open_binary tool call returning,
// and reports phases via the server-side progress store (read by get_session_progress).
// When progress is non-nil it also streams progress notifications to the MCP client.
// The bgCtx is used for worker RPC calls — pass context.Background() for fire-and-forget
// or the request context when blocking inline.
func (s *Server) backgroundOpen(sess *session.Session, client *worker.WorkerClient, path string, autoAnalyze bool, progress *progressReporter, bgCtx context.Context) {
	sess.AcquireInFlight()
	defer sess.ReleaseInFlight()

	// Loading a large binary is itself a long GIL-holding worker call, so drive
	// it under a heartbeat too (not just analysis).
	var resp *connect.Response[pb.OpenBinaryResponse]
	var err error
	s.withHeartbeat(sess.ID, "opening", "Loading binary into IDA", 1, 4, func() {
		resp, err = (*client.SessionCtrl).OpenBinary(bgCtx, connect.NewRequest(&pb.OpenBinaryRequest{
			BinaryPath:  path,
			AutoAnalyze: false,
		}))
	})
	if err != nil {
		s.recordProgress(sess.ID, "failed", fmt.Sprintf("Failed to open binary: %v", err), 0, 4)
		s.logger.Printf("[open_binary] session=%s open failed: %v", sess.ID, err)
		return
	}
	if !resp.Msg.GetSuccess() {
		s.recordProgress(sess.ID, "failed", fmt.Sprintf("IDA failed to open binary: %s", resp.Msg.GetError()), 0, 4)
		s.logger.Printf("[open_binary] session=%s IDA open error: %s", sess.ID, resp.Msg.GetError())
		return
	}

	var warning string
	if autoAnalyze {
		// Guard so a concurrent run_auto_analysis can't launch a second pass.
		// A fresh open always wins the claim; the rare loser just skips (someone
		// else is already analyzing this session).
		if sess.TryBeginAnalysis() {
			ok, msg, _ := s.executeAnalysisWithHeartbeat(sess, client)
			sess.EndAnalysis()
			if !ok {
				warning = msg
				s.logger.Printf("[open_binary] session=%s %s", sess.ID, msg)
			}
		}
		s.warmSessionCache(sess.ID, progress)
	}

	// Emit "ready" only after cache warming completes. "warming" is a not-ready
	// stage (see inProgressStages), so emitting "ready" before warming made the
	// session flap ready → warming → ready, racing readiness checks that had
	// already observed the premature "ready".
	readyMsg := "Session ready"
	if autoAnalyze {
		readyMsg = "Session ready (cache warm)"
	}
	if warning != "" {
		readyMsg += " (" + warning + ")"
	}
	s.emitProgress(progress, sess.ID, "ready", readyMsg, 4, 4)
}

// analysisHeartbeatInterval is how often a heartbeat refreshes the progress
// snapshot while a long worker call (open_database, auto_wait) holds the Python
// GIL on the worker's single IDA thread. Those calls are opaque blocking C calls
// with no sub-progress and — critically — they starve the worker's "lightweight"
// status endpoint (it can't run Python to answer while the GIL is held). The
// heartbeat is the server-side liveness signal that survives that: it refreshes
// last_updated_ago so get_session_progress shows movement, and keeps a streaming
// client's timeout alive, even though the worker itself is momentarily mute.
const analysisHeartbeatInterval = 5 * time.Second

// workerStatusTimeout bounds the best-effort GetSessionInfo call in
// get_session_progress so a momentarily GIL-bound worker can never stall the
// poll. On timeout we fall back to the Go-side progress snapshot.
const workerStatusTimeout = 3 * time.Second

// analysisResult is the outcome of a background auto-analysis pass.
type analysisResult struct {
	success  bool
	duration float64
	errMsg   string
}

// withHeartbeat runs fn while a heartbeat keeps the given progress stage fresh
// (elapsed time + updated timestamp) every analysisHeartbeatInterval. Use it
// around long worker RPCs (load / analysis) so pollers see liveness even while
// the worker's IDA thread holds the GIL. The progress fraction stays fixed; the
// message carries elapsed time. It waits for the heartbeat goroutine to exit
// before returning, so no stale write lands after the caller records the next
// stage.
func (s *Server) withHeartbeat(sessionID, stage, message string, prog, total float64, fn func()) {
	start := time.Now()
	s.recordProgress(sessionID, stage, message, prog, total)

	stop := make(chan struct{})
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		ticker := time.NewTicker(analysisHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				elapsed := time.Since(start).Round(time.Second)
				s.recordProgress(sessionID, stage,
					fmt.Sprintf("%s (%s elapsed)", message, elapsed), prog, total)
			}
		}
	}()

	fn()

	close(stop)
	<-hbDone
}

// executeAnalysisWithHeartbeat runs plan_and_wait on a DETACHED context under a
// heartbeat. It blocks until analysis finishes and returns (success, errMsg,
// durationSeconds). It deliberately uses context.Background() rather than any
// request context: a client tool-call timeout must never abort an analysis the
// worker can't interrupt anyway. The caller owns cache invalidation and the
// terminal stage.
func (s *Server) executeAnalysisWithHeartbeat(sess *session.Session, client *worker.WorkerClient) (bool, string, float64) {
	var resp *connect.Response[pb.PlanAndWaitResponse]
	var err error
	s.withHeartbeat(sess.ID, "analyzing", "Running auto-analysis", 2, 4, func() {
		resp, err = (*client.SessionCtrl).PlanAndWait(context.Background(), connect.NewRequest(&pb.PlanAndWaitRequest{}))
	})

	if err != nil {
		return false, fmt.Sprintf("auto-analysis failed: %v", err), 0
	}
	if resp.Msg != nil && !resp.Msg.GetSuccess() {
		return false, fmt.Sprintf("auto-analysis error: %s", resp.Msg.GetError()), 0
	}
	var duration float64
	if resp.Msg != nil {
		duration = resp.Msg.GetDurationSeconds()
	}
	return true, "", duration
}

// beginBackgroundAnalysis starts an auto-analysis pass on a detached goroutine
// if one isn't already running for this session, returning a buffered completion
// channel and true. If analysis is already in flight it returns (nil, false).
//
// The analysis — and the post-analysis cache invalidation + progress
// bookkeeping — always runs to completion regardless of any request context, so
// a client tool-call timeout can't abort it. Callers that want the result race
// the returned channel against their own ctx; abandoning the channel is safe
// because it is buffered.
func (s *Server) beginBackgroundAnalysis(sess *session.Session, client *worker.WorkerClient) (<-chan analysisResult, bool) {
	if !sess.TryBeginAnalysis() {
		return nil, false
	}
	done := make(chan analysisResult, 1)
	// A dedicated in-flight lease keeps the watchdog off this session until the
	// analysis goroutine finishes — independent of the request's own lease,
	// which is released as soon as the tool call returns.
	sess.AcquireInFlight()
	go func() {
		defer sess.ReleaseInFlight()
		success, errMsg, duration := s.executeAnalysisWithHeartbeat(sess, client)
		if success {
			// Auto-analysis rewrites the function set, xrefs, etc. Invalidate the
			// cache BEFORE signaling so a caller that observes `done` (and any
			// read it issues next) sees fresh data.
			s.deleteSessionCache(sess.ID)
			s.recordProgress(sess.ID, "ready", "Session ready (analysis complete)", 4, 4)
		} else {
			msg := errMsg
			if msg == "" {
				msg = "auto-analysis failed"
			}
			s.recordProgress(sess.ID, "failed", msg, 0, 4)
		}
		// Clear the guard BEFORE signaling completion (not via defer, which would
		// run after the send): a get_session_progress poll racing the handler's
		// return must not still see AnalysisActive()=true once the terminal stage
		// is set.
		sess.EndAnalysis()
		done <- analysisResult{success: success, duration: duration, errMsg: errMsg}
	}()
	return done, true
}

func (s *Server) closeBinary(ctx context.Context, req *mcp.CallToolRequest, args CloseBinaryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("close_binary", args.SessionID, nil)
	sess, err := s.resolveSession(args.SessionID)
	if err != nil {
		return nil, err, nil
	}

	// Tear down the session record unconditionally. A worker-stop failure must
	// not leave the session persisted in the store, or RestoreSessions would try
	// to respawn a worker for it on the next start. Surface the stop error as a
	// warning instead of aborting the cleanup.
	stopErr := s.workers.Stop(sess.ID)

	s.registry.Delete(sess.ID)
	s.deleteSessionState(sess.ID)
	s.deleteSessionCache(sess.ID)
	s.clearProgress(sess.ID)

	if len(s.registry.List()) == 0 {
		s.demoteToTier0()
	}

	if stopErr != nil {
		s.logger.Printf("[close_binary] session=%s worker stop reported %v; session record removed anyway", sess.ID, stopErr)
		body, _ := json.Marshal(map[string]any{
			"status":  "closed",
			"warning": fmt.Sprintf("worker stop: %v", stopErr),
		})
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(body)},
			},
		}, nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "ok"},
		},
	}, nil, nil
}

func (s *Server) listSessions(ctx context.Context, req *mcp.CallToolRequest, args ListSessionsRequest) (*mcp.CallToolResult, any, error) {
	sessions := s.registry.List()

	result := make([]map[string]any, 0, len(sessions))
	for _, sess := range sessions {
		// Snapshot under the session lock — LastActivity is written concurrently
		// by ReleaseInFlight (background opens/analysis releasing their leases),
		// so reading the fields directly here is a data race.
		meta := sess.Metadata()
		result = append(result, map[string]any{
			"session_id":    meta.ID,
			"binary_path":   meta.BinaryPath,
			"created_at":    meta.CreatedAt.Unix(),
			"last_activity": meta.LastActivity.Unix(),
			"age_seconds":   time.Since(meta.CreatedAt).Seconds(),
			"idle_seconds":  time.Since(meta.LastActivity).Seconds(),
		})
	}

	jsonResult, _ := json.Marshal(map[string]any{
		"sessions": result,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}

func (s *Server) saveDatabase(ctx context.Context, req *mcp.CallToolRequest, args SaveDatabaseRequest) (*mcp.CallToolResult, any, error) {
	_, client, err := s.resolveClient(ctx, args.SessionID, "save_database")
	if err != nil {
		return nil, err, nil
	}

	resp, err := (*client.SessionCtrl).SaveDatabase(ctx, connect.NewRequest(&pb.SaveDatabaseRequest{}))
	if err != nil {
		return nil, s.logAndReturnError("save_database RPC call", err), nil
	}

	result, _ := json.Marshal(map[string]any{
		"timestamp": resp.Msg.Timestamp,
		"dirty":     resp.Msg.Dirty,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}

func (s *Server) getSessionProgress(ctx context.Context, req *mcp.CallToolRequest, args GetSessionProgressRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_session_progress", args.SessionID, nil)

	sess, err := s.resolveSession(args.SessionID)
	if err != nil {
		return nil, err, nil
	}
	sess.Touch()

	progressSnapshot, hasProgress := s.getProgress(sess.ID)
	stage := "idle"
	message := "No active operation"
	var progressValue, totalValue float64
	var updatedAt time.Time
	if hasProgress && progressSnapshot != nil {
		stage = progressSnapshot.Stage
		message = progressSnapshot.Message
		progressValue = progressSnapshot.Progress
		totalValue = progressSnapshot.Total
		updatedAt = progressSnapshot.UpdatedAt
	}

	var percent float64
	if totalValue > 0 {
		percent = (progressValue / totalValue) * 100.0
	}

	// Readiness is decided from Go-side signals — the progress stage (kept fresh
	// by the heartbeat) and the analysis guard — NOT a synchronous worker
	// round-trip. During a long load/analysis the worker's IDA thread holds the
	// Python GIL through an opaque C call (open_database / auto_wait), which
	// starves its own "lightweight" GetSessionInfo endpoint; querying it then
	// would block this poll for the entire phase (observed: a single poll hung
	// 64s mid-analysis). So we only consult the worker — briefly, best-effort —
	// when nothing IDA-bound is in flight, purely to enrich auto_state.
	analysisRunning := sess.AnalysisActive()
	autoState := "unknown"
	autoRunning := analysisRunning
	switch {
	case analysisRunning:
		autoState = "analyzing"
	case inProgressStages[stage]:
		autoState = stage
	default:
		if client, err := s.workers.GetClient(sess.ID); err == nil {
			infoCtx, cancel := context.WithTimeout(ctx, workerStatusTimeout)
			if infoResp, err := (*client.SessionCtrl).GetSessionInfo(infoCtx, connect.NewRequest(&pb.GetSessionInfoRequest{})); err == nil {
				autoState = infoResp.Msg.GetAutoState()
				autoRunning = infoResp.Msg.GetAutoRunning()
			}
			cancel()
		}
	}

	var lastUpdatedUnix int64
	var lastUpdatedAgo float64 = -1
	if !updatedAt.IsZero() {
		lastUpdatedUnix = updatedAt.Unix()
		lastUpdatedAgo = time.Since(updatedAt).Seconds()
	}

	now := time.Now().UTC()

	// Keep readiness consistent with the resolveClient gate (readinessError):
	// ready exactly when analysis tools would be accepted — not in a load/analysis
	// stage, not failed, and no analysis pass in flight. analysisRunning (the
	// Go-side guard) is authoritative; autoRunning only carries the best-effort
	// worker value for the idle/restored case where we actually queried it.
	ready := !analysisRunning && !autoRunning && stage != "failed" && !inProgressStages[stage]
	var nextStep string
	switch {
	case ready:
		nextStep = "call survey_binary for a one-call overview"
	case stage == "failed":
		nextStep = "re-open with open_binary or check the path"
	default:
		nextStep = "poll get_session_progress again until ready=true"
	}

	result := map[string]any{
		"session_id":        sess.ID,
		"stage":             stage,
		"message":           message,
		"progress":          progressValue,
		"total":             totalValue,
		"percent":           percent,
		"has_progress":      hasProgress,
		"auto_state":        autoState,
		"auto_running":      autoRunning,
		"ready":             ready,
		"next_step":         nextStep,
		"last_updated_at":   lastUpdatedUnix,
		"last_updated_ago":  lastUpdatedAgo,
		"server_timestamp":  now.Unix(),
		"server_time_iso":   now.Format(time.RFC3339),
		"analysis_required": autoRunning,
	}

	jsonResult, _ := json.Marshal(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}

func (s *Server) runAutoAnalysis(ctx context.Context, req *mcp.CallToolRequest, args RunAutoAnalysisRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("run_auto_analysis", args.SessionID, nil)

	sess, client, err := s.resolveClientDuringLoad(ctx, args.SessionID, "run_auto_analysis")
	if err != nil {
		return nil, err, nil
	}

	done, started := s.beginBackgroundAnalysis(sess, client)
	if !started {
		// Analysis is already running (open_binary's auto pass, or a prior
		// run_auto_analysis). Don't start a second pass or block — point the
		// agent at polling.
		return autoAnalysisResult(map[string]any{
			"session_id": sess.ID,
			"status":     "analyzing",
			"started":    false,
			"running":    true,
			"message":    "Auto-analysis already running — poll get_session_progress until ready=true",
		}), nil, nil
	}

	// Wait for completion, but only as long as THIS request is alive. The
	// analysis runs on a detached context, so a client-side tool-call timeout
	// (which cancels ctx) no longer aborts it — we just hand back a "still
	// running" result and the work continues, observable via
	// get_session_progress with a live heartbeat.
	select {
	case res := <-done:
		payload := map[string]any{
			"session_id":       sess.ID,
			"status":           "ready",
			"started":          true,
			"success":          res.success,
			"duration_seconds": res.duration,
			"message":          "Auto-analysis complete",
		}
		if !res.success {
			payload["status"] = "failed"
			payload["message"] = res.errMsg
			if res.errMsg == "" {
				payload["message"] = "auto-analysis failed"
			}
		}
		return autoAnalysisResult(payload), nil, nil
	case <-ctx.Done():
		return autoAnalysisResult(map[string]any{
			"session_id": sess.ID,
			"status":     "analyzing",
			"started":    true,
			"running":    true,
			"message":    "Auto-analysis still running in the background — poll get_session_progress until ready=true",
		}), nil, nil
	}
}

// autoAnalysisResult marshals a run_auto_analysis payload into a tool result.
func autoAnalysisResult(payload map[string]any) *mcp.CallToolResult {
	body, _ := json.Marshal(payload)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(body)},
		},
	}
}

func (s *Server) watchAutoAnalysis(ctx context.Context, req *mcp.CallToolRequest, args WatchAutoAnalysisRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("watch_auto_analysis", args.SessionID, map[string]any{
		"interval_ms":  args.IntervalMs,
		"timeout_secs": args.TimeoutSecs,
	})

	sess, client, err := s.resolveClientDuringLoad(ctx, args.SessionID, "watch_auto_analysis")
	if err != nil {
		return nil, err, nil
	}

	interval := time.Duration(args.IntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = time.Second
	}
	if interval < 200*time.Millisecond {
		interval = 200 * time.Millisecond
	}

	watchCtx := ctx
	cancel := func() {}
	if args.TimeoutSecs > 0 {
		watchCtx, cancel = context.WithTimeout(ctx, time.Duration(args.TimeoutSecs)*time.Second)
	}
	defer cancel()

	progress := s.progressReporter(ctx, req, sess.ID, "auto_analysis")
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	start := time.Now()
	updates := make([]map[string]any, 0, 32)
	var lastState string
	var lastRunning bool

	for {
		infoResp, err := (*client.SessionCtrl).GetSessionInfo(watchCtx, connect.NewRequest(&pb.GetSessionInfoRequest{}))
		if err != nil {
			return nil, s.logAndReturnError("watch_auto_analysis GetSessionInfo", err), nil
		}
		info := infoResp.Msg
		lastState = info.GetAutoState()
		lastRunning = info.GetAutoRunning()

		entry := map[string]any{
			"timestamp":       time.Now().Unix(),
			"auto_state":      lastState,
			"auto_running":    lastRunning,
			"session_id":      sess.ID,
			"elapsed_seconds": time.Since(start).Seconds(),
		}
		updates = append(updates, entry)
		s.emitProgress(progress, sess.ID, "auto_analysis", fmt.Sprintf("auto_state=%s running=%t", lastState, lastRunning), 0, 0)

		if !lastRunning {
			break
		}

		select {
		case <-watchCtx.Done():
			result, _ := json.Marshal(map[string]any{
				"auto_running": true,
				"auto_state":   lastState,
				"updates":      updates,
				"update_count": len(updates),
				"message":      fmt.Sprintf("Stopped waiting: %v", watchCtx.Err()),
			})
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: string(result)},
				},
			}, nil, nil
		case <-ticker.C:
		}
	}

	duration := time.Since(start).Seconds()
	result, _ := json.Marshal(map[string]any{
		"auto_running":     false,
		"auto_state":       lastState,
		"updates":          updates,
		"update_count":     len(updates),
		"duration_seconds": duration,
	})

	s.emitProgress(progress, sess.ID, "auto_analysis", "Auto-analysis complete", 1, 1)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}
