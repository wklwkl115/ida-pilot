package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wklwkl115/ida-pilot/internal/session"
	"github.com/wklwkl115/ida-pilot/internal/worker"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// parseAddr parses an address supplied by the agent as either hex ("0x1000")
// or decimal ("4096"). Addresses are strings at the MCP boundary so agents can
// paste the hex they see in disassembly/listings directly, without converting.
func parseAddr(s string) (uint64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, errors.New("address is required (hex like 0x1000 or decimal)")
	}
	base := 10
	if len(t) >= 2 && (t[0:2] == "0x" || t[0:2] == "0X") {
		t, base = t[2:], 16
	}
	v, err := strconv.ParseUint(t, base, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid address %q: want hex (0x...) or decimal", s)
	}
	return v, nil
}

// parseAddrDefault is parseAddr for optional fields: empty input yields def.
func parseAddrDefault(s string, def uint64) (uint64, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return parseAddr(s)
}

// hexAddr formats an address as a 0x-prefixed hex string for JSON output, so
// outputs match the hex the agent passes back in.
func hexAddr(a uint64) string {
	return fmt.Sprintf("0x%x", a)
}

// hexAddrTuples converts cached [addr(uint64), type] xref tuples into
// [hexAddr(string), type] for JSON output without mutating the cache.
func hexAddrTuples(tuples [][]any) [][]any {
	out := make([][]any, 0, len(tuples))
	for _, t := range tuples {
		if len(t) == 2 {
			out = append(out, []any{hexAddr(anyToUint64(t[0])), t[1]})
		}
	}
	return out
}

// logAndReturnError logs the full error server-side and returns it for the MCP client.
func (s *Server) logAndReturnError(context string, err error) error {
	s.logger.Printf("[Error] %s: %v", context, err)
	return fmt.Errorf("%s: %v", context, err)
}

// resolveSession auto-detects the session when session_id is omitted.
func (s *Server) resolveSession(sessionID string) (*session.Session, error) {
	if sessionID != "" {
		sess, ok := s.registry.Get(sessionID)
		if !ok {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return sess, nil
	}
	sessions := s.registry.List()
	switch len(sessions) {
	case 1:
		return sessions[0], nil
	case 0:
		return nil, fmt.Errorf("no active sessions — call open_binary first")
	default:
		// List the active IDs so the agent can pick one without a separate
		// list_sessions round-trip.
		ids := make([]string, 0, len(sessions))
		for _, sess := range sessions {
			ids = append(ids, sess.ID)
		}
		return nil, fmt.Errorf("multiple sessions active — specify session_id (active: %s)", strings.Join(ids, ", "))
	}
}

// inProgressStages are the background load/analysis phases reported through
// get_session_progress. While a session is in one of these the worker is still
// bringing the database up, so analysis/read/write tools cannot return
// meaningful results yet.
var inProgressStages = map[string]bool{
	"starting":  true,
	"opening":   true,
	"analyzing": true,
	"warming":   true,
}

// readinessError reports why a session is not ready for analysis, or nil when
// it is ready. It reads only the in-memory progress snapshot (no worker RPC),
// so it is cheap enough to run on every resolveClient call. Sessions with no
// snapshot (e.g. restored on startup, or reused) are treated as ready.
func (s *Server) readinessError(sessionID string) error {
	p, ok := s.getProgress(sessionID)
	if !ok {
		return nil
	}
	switch {
	case p.Stage == "failed":
		return fmt.Errorf("binary failed to load: %s — re-open with open_binary or check the path", p.Message)
	case inProgressStages[p.Stage]:
		pct := 0.0
		if p.Total > 0 {
			pct = (p.Progress / p.Total) * 100.0
		}
		return fmt.Errorf("binary not ready (stage=%s, %.0f%%) — poll get_session_progress until ready=true before analyzing", p.Stage, pct)
	default:
		return nil
	}
}

// resolveClient resolves session + worker client and gates on readiness: a call
// made before the binary has finished loading/auto-analysis is rejected with a
// self-correcting error instead of silently blocking on the worker thread or
// returning partial data. Lifecycle tools that legitimately run during loading
// (run_auto_analysis, watch_auto_analysis) use resolveClientDuringLoad instead.
func (s *Server) resolveClient(ctx context.Context, sessionID, tool string) (*session.Session, *worker.WorkerClient, error) {
	sess, client, err := s.resolveClientDuringLoad(ctx, sessionID, tool)
	if err != nil {
		return nil, nil, err
	}
	if err := s.readinessError(sess.ID); err != nil {
		return nil, nil, err
	}
	return sess, client, nil
}

// resolveClientWait is like resolveClient but when the client provides a
// progress token and the session is not ready, it blocks and streams progress
// notifications via MCP SSE until the session becomes ready. Falls back to
// the standard error behavior when no progress token is present.
func (s *Server) resolveClientWait(ctx context.Context, req *mcp.CallToolRequest, sessionID, tool string) (*session.Session, *worker.WorkerClient, error) {
	sess, client, err := s.resolveClientDuringLoad(ctx, sessionID, tool)
	if err != nil {
		return nil, nil, err
	}
	if readyErr := s.readinessError(sess.ID); readyErr != nil {
		if req == nil || req.Params.GetProgressToken() == nil {
			return nil, nil, readyErr
		}
		progress := s.progressReporter(ctx, req, sess.ID, "loading")
		if waitErr := s.waitForReady(ctx, sess.ID, progress); waitErr != nil {
			return nil, nil, fmt.Errorf("session not ready (waited: %w; original: %v)", waitErr, readyErr)
		}
	}
	return sess, client, nil
}

// waitForReady blocks until the session is ready for analysis, streaming
// progress notifications while polling the in-memory progress store.
func (s *Server) waitForReady(ctx context.Context, sessionID string, progress *progressReporter) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if err := s.readinessError(sessionID); err == nil {
			return nil
		}
		p, _ := s.getProgress(sessionID)
		if p != nil {
			pct := 0.0
			if p.Total > 0 {
				pct = (p.Progress / p.Total) * 100.0
			}
			progress.Emit(p.Stage, fmt.Sprintf("%s (%.0f%%)", p.Message, pct), p.Progress, p.Total)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// resolveClientDuringLoad resolves session + worker client without the
// readiness gate. Use only for tools that must operate while the binary is
// still loading or analyzing.
//
// Acquires the session's in-flight RPC counter and registers a context.AfterFunc
// to release it when the handler's ctx is cancelled (i.e. when the SDK returns
// to the client). The watchdog consults HasInFlight() before stopping a worker,
// so a long-running call is never torn down mid-flight.
func (s *Server) resolveClientDuringLoad(ctx context.Context, sessionID, tool string) (*session.Session, *worker.WorkerClient, error) {
	sess, err := s.resolveSession(sessionID)
	if err != nil {
		return nil, nil, err
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, nil, s.logAndReturnError(tool+" worker client", err)
	}
	sess.AcquireInFlight()
	context.AfterFunc(ctx, sess.ReleaseInFlight)
	return sess, client, nil
}

// workerPOST issues a JSON POST against the Python worker's non-protobuf
// endpoints (currently /batch_annotate and /py_eval). It folds the
// build/Do/read/status-check ladder that every caller would otherwise
// duplicate, routing each failure mode through logAndReturnError with a
// label-prefixed context.
func (s *Server) workerPOST(ctx context.Context, client *worker.WorkerClient, path string, payload []byte, label string) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", client.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, s.logAndReturnError(label+" request build", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, s.logAndReturnError(label+" HTTP call", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, s.logAndReturnError(label+" read response", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, s.logAndReturnError(label+" worker error", fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody)))
	}
	return respBody, nil
}

func (s *Server) logToolInvocation(tool, sessionID string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	if sessionID != "" {
		details["session"] = sessionID
	}
	s.logger.Printf("[Tool] %s %v", tool, details)
}

func (s *Server) debugf(format string, args ...any) {
	if s.debug {
		s.logger.Printf("[DEBUG] "+format, args...)
	}
}
