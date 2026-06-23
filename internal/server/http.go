package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) HTTPMux(mcpServer *mcp.Server) http.Handler {
	sseHandler := mcp.NewSSEHandler(func(r *http.Request) *mcp.Server {
		if s.debug {
			s.logger.Printf("[DEBUG] SSE connection from %s: %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		}
		return mcpServer
	}, nil)

	streamHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, &mcp.StreamableHTTPOptions{
		JSONResponse:   true,
		SessionTimeout: s.sessionTimeout,
		Stateless:      true,
	})

	mux := http.NewServeMux()
	mux.Handle("/sse", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.debug {
			s.logger.Printf("[SSE] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}
		sseHandler.ServeHTTP(w, r)
	}))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.debug {
			s.logger.Printf("[HTTP] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}
		streamHandler.ServeHTTP(w, r)
	}))
	return s.localhostGuard(mux)
}

// localhostGuard wraps the MCP mux with Origin and Host checks.
//
// When the server is bound to a loopback address (the default), it rejects:
//   - Requests whose Host header is not a loopback name. Blocks DNS rebinding:
//     a browser visiting evil.example pointing at 127.0.0.1 sends Host: evil.example
//     so the check kills it before any tool runs.
//   - Requests whose Origin header is set and not loopback. Blocks browser
//     cross-origin POSTs from non-allowlisted pages.
//
// When the operator explicitly binds to a non-loopback interface the guard
// becomes permissive (assumed: an upstream auth/CORS proxy in front). Operators
// are expected to know what they signed up for and add their own controls.
func (s *Server) localhostGuard(next http.Handler) http.Handler {
	loopback := s.bind == "" || isLoopbackHost(s.bind)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopback {
			next.ServeHTTP(w, r)
			return
		}
		if hostHeader := r.Host; hostHeader != "" && !isLoopbackHost(hostHeader) {
			s.logger.Printf("[Security] reject non-loopback Host=%q from %s %s", hostHeader, r.RemoteAddr, r.URL.Path)
			http.Error(w, "Host header not allowed; server is loopback-only", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !isLoopbackOrigin(origin) {
			s.logger.Printf("[Security] reject non-loopback Origin=%q from %s %s", origin, r.RemoteAddr, r.URL.Path)
			http.Error(w, "Origin not allowed; server is loopback-only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isLoopbackHost reports whether hostHeader (e.g. "127.0.0.1:17300" or
// "localhost") names a loopback endpoint. It tolerates an optional :port suffix
// and the [::1] form, and falls back to net.IP.IsLoopback for raw addresses.
func isLoopbackHost(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isLoopbackOrigin parses an Origin header value (a full URL) and checks
// whether its host is loopback.
func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return isLoopbackHost(u.Host)
}
