package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLocalhostGuardRejectsNonLoopbackHost covers the DNS-rebinding defense.
// A browser visiting evil.example pointing at 127.0.0.1 sends
// Host: evil.example, which must be rejected.
func TestLocalhostGuardRejectsNonLoopbackHost(t *testing.T) {
	t.Parallel()

	srv := &Server{logger: log.New(io.Discard, "", 0), bind: "127.0.0.1"}
	handler := srv.localhostGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name    string
		host    string
		wantStatus int
	}{
		{"loopback v4", "127.0.0.1:17300", http.StatusOK},
		{"loopback name", "localhost:17300", http.StatusOK},
		{"loopback v6", "[::1]:17300", http.StatusOK},
		{"rebinding attack", "evil.example", http.StatusForbidden},
		{"public IP", "203.0.113.5:17300", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
			req.Host = tc.host
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("Host=%q: status=%d, want %d (body=%q)", tc.host, rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestLocalhostGuardRejectsNonLoopbackOrigin covers browser cross-origin POSTs
// where the page on evil.com tries to talk to http://127.0.0.1:17300.
func TestLocalhostGuardRejectsNonLoopbackOrigin(t *testing.T) {
	t.Parallel()

	srv := &Server{logger: log.New(io.Discard, "", 0), bind: "127.0.0.1"}
	handler := srv.localhostGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name       string
		origin     string
		wantStatus int
	}{
		{"no origin", "", http.StatusOK},
		{"loopback origin", "http://127.0.0.1:17300", http.StatusOK},
		{"localhost origin", "http://localhost", http.StatusOK},
		{"loopback v6 origin", "http://[::1]:17300", http.StatusOK},
		{"cross-origin attack", "http://evil.example", http.StatusForbidden},
		{"https public", "https://attacker.com", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
			req.Host = "127.0.0.1:17300"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("Origin=%q: status=%d, want %d", tc.origin, rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestLocalhostGuardPermissiveWhenNotLoopback confirms the operator's
// explicit opt-in to a non-loopback bind disables the guard (the assumption is
// that they're putting an auth proxy in front).
func TestLocalhostGuardPermissiveWhenNotLoopback(t *testing.T) {
	t.Parallel()

	srv := &Server{logger: log.New(io.Discard, "", 0), bind: "0.0.0.0"}
	handler := srv.localhostGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	req.Host = "ida.example.com"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("non-loopback bind must skip the guard: got status=%d", rec.Code)
	}
}

// TestTier1ToolsRespectsPyEvalGate confirms py_eval enters/leaves the tier-1
// tool list based on the EnablePyEval flag — the registration site and the
// demotion site must agree to avoid orphaned tools after the last session
// closes.
func TestTier1ToolsRespectsPyEvalGate(t *testing.T) {
	t.Parallel()

	off := &Server{}
	on := &Server{enablePyEval: true}

	if got := off.tier1Tools(); containsName(got, "py_eval") {
		t.Errorf("default: py_eval must NOT appear in tier1 list, got %v", got)
	}
	if got := on.tier1Tools(); !containsName(got, "py_eval") {
		t.Errorf("enabled: py_eval must appear in tier1 list, got %v", got)
	}
}

func containsName(xs []string, needle string) bool {
	for _, s := range xs {
		if s == needle {
			return true
		}
	}
	return false
}
