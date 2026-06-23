package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/wklwkl115/ida-pilot/internal/server"
	"github.com/wklwkl115/ida-pilot/internal/session"
	"github.com/wklwkl115/ida-pilot/internal/worker"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	configPath      = flag.String("config", "config.json", "Path to server config")
	bindFlag        = flag.String("bind", "", "Bind interface (default 127.0.0.1; use 0.0.0.0 to expose externally)")
	portFlag        = flag.Int("port", 0, "HTTP port (overrides config)")
	pythonWorker    = flag.String("worker", "", "Python worker script (overrides config)")
	maxSessions     = flag.Int("max-sessions", 0, "Max concurrent sessions (overrides config)")
	timeoutFlag     = flag.Duration("session-timeout", 0, "Session idle timeout (overrides config)")
	debugFlag       = flag.Bool("debug", false, "Enable verbose debug logging")
	enablePyEvalFlg = flag.Bool("enable-py-eval", false, "Register the py_eval tool (arbitrary Python execution in the IDA worker — RCE primitive, off by default)")
)

func main() {
	flag.Parse()

	logger := log.New(os.Stdout, "[MCP] ", log.LstdFlags)
	logger.Printf("Starting IDA Pilot Server")
	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

	server.ApplyEnvOverrides(&cfg)

	if *bindFlag != "" {
		cfg.Bind = *bindFlag
	}
	if *portFlag > 0 {
		cfg.Port = *portFlag
	}
	if *pythonWorker != "" {
		cfg.PythonWorkerPath = *pythonWorker
	}
	if *maxSessions > 0 {
		cfg.MaxConcurrentSession = *maxSessions
	}

	sessionTimeout := time.Duration(cfg.SessionTimeoutMin) * time.Minute
	if *timeoutFlag > 0 {
		sessionTimeout = *timeoutFlag
	}

	if *debugFlag {
		cfg.Debug = true
	}
	if *enablePyEvalFlg {
		cfg.EnablePyEval = true
	}

	// Validate configuration before starting server
	if err := validateConfig(&cfg); err != nil {
		logger.Fatalf("invalid configuration: %v", err)
	}

	registry := session.NewRegistry(cfg.MaxConcurrentSession)
	workers := worker.NewManager(cfg.PythonWorkerPath, logger)
	stateDir := filepath.Join(cfg.DatabaseDirectory, "sessions")
	store, err := session.NewStore(stateDir)
	if err != nil {
		logger.Fatalf("failed to initialize session store: %v", err)
	}

	srv := server.New(registry, workers, logger, sessionTimeout, cfg.Debug, store)
	srv.SetSecurity(cfg.Bind, cfg.EnablePyEval)

	srv.RestoreSessions()

	go srv.Watchdog()

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "ida-pilot",
		Version: "0.1.0",
	}, nil)

	srv.RegisterTools(mcpServer)
	srv.PromoteIfSessions()

	addr := fmt.Sprintf("%s:%d", cfg.Bind, cfg.Port)
	mux := srv.HTTPMux(mcpServer)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	logger.Printf("Listening on %s", addr)
	logger.Printf("HTTP transport at http://%s:%d/", cfg.Bind, cfg.Port)
	logger.Printf("SSE transport at http://%s:%d/sse", cfg.Bind, cfg.Port)
	if !isLoopbackBind(cfg.Bind) {
		logger.Printf("⚠️  SECURITY: bound to non-loopback %q — server has no built-in auth. Put an authenticated reverse proxy in front, or revert to 127.0.0.1.", cfg.Bind)
	}
	if cfg.EnablePyEval {
		logger.Printf("⚠️  SECURITY: py_eval is ENABLED — any client that can reach this port can execute arbitrary Python on the host (RCE primitive).")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Println("Shutting down gracefully...")

		// Give HTTP server 10 seconds to finish in-flight requests
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("HTTP server shutdown error: %v", err)
		}

		// Stop all workers and log any errors
		for _, sess := range registry.List() {
			if err := workers.Stop(sess.ID); err != nil {
				logger.Printf("Failed to stop worker %s: %v", sess.ID, err)
			}
		}

		logger.Println("Shutdown complete")
		os.Exit(0)
	}()

	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal(err)
	}
}

// isLoopbackBind reports whether the configured Bind address is a loopback
// interface (127.0.0.0/8 or ::1). Used only to gate a security warning at
// startup; the runtime check lives in internal/server/http.go.
func isLoopbackBind(bind string) bool {
	if bind == "" {
		return true
	}
	ip := net.ParseIP(bind)
	if ip != nil {
		return ip.IsLoopback()
	}
	return bind == "localhost"
}

func validateConfig(cfg *server.Config) error {
	// Validate MaxConcurrentSession (0 = unlimited, negative is invalid)
	if cfg.MaxConcurrentSession < 0 {
		return fmt.Errorf("max_concurrent_sessions must be non-negative, got %d (use 0 for unlimited)", cfg.MaxConcurrentSession)
	}

	// Validate PythonWorkerPath exists and is executable
	if cfg.PythonWorkerPath == "" {
		return fmt.Errorf("python_worker_path is required")
	}

	// Make path absolute for clarity in error messages
	absPath, err := filepath.Abs(cfg.PythonWorkerPath)
	if err != nil {
		return fmt.Errorf("invalid python_worker_path %q: %w", cfg.PythonWorkerPath, err)
	}
	cfg.PythonWorkerPath = absPath

	// Check file exists
	info, err := os.Stat(cfg.PythonWorkerPath)
	if err != nil {
		return fmt.Errorf("python_worker_path %q not found: %w", cfg.PythonWorkerPath, err)
	}

	// Check it's a file, not a directory
	if info.IsDir() {
		return fmt.Errorf("python_worker_path %q is a directory, expected a Python script", cfg.PythonWorkerPath)
	}

	// Check it's executable (Unix-like systems; skip on Windows where mode bits are not meaningful)
	if runtime.GOOS != "windows" && info.Mode()&0111 == 0 {
		return fmt.Errorf("python_worker_path %q is not executable (try: chmod +x %s)", cfg.PythonWorkerPath, cfg.PythonWorkerPath)
	}

	return nil
}
