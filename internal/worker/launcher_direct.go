package worker

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/wklwkl115/ida-pilot/internal/session"
)

func newDirectLauncher(pythonScript string, logger *log.Logger) Launcher {
	return func(_ context.Context, sess *session.Session, binaryPath string) (LaunchResult, error) {
		workerCtx, cancel := context.WithCancel(context.Background())
		cmd, ready, err := startPythonWorker(workerCtx, pythonScript, sess, binaryPath)
		if err != nil {
			cancel()
			return LaunchResult{}, err
		}
		logger.Printf("[Worker] Started PID %d for session %s", cmd.Process.Pid, sess.ID)
		return LaunchResult{
			PID:        cmd.Process.Pid,
			BaseURL:    ready.baseURL,
			HTTPClient: ready.httpClient,
			Stop:       func() error { return stopDirectWorker(cancel, cmd, logger) },
			Wait:       cmd.Wait,
		}, nil
	}
}

type readyEndpoint struct {
	baseURL    string
	httpClient *http.Client
}

func startPythonWorker(workerCtx context.Context, script string, sess *session.Session, binaryPath string) (*exec.Cmd, readyEndpoint, error) {
	cmd, portFile, err := buildPythonCommand(workerCtx, script, sess, binaryPath)
	if err != nil {
		return nil, readyEndpoint{}, err
	}
	attachLogs(cmd)
	if err := cmd.Start(); err != nil {
		return nil, readyEndpoint{}, fmt.Errorf("failed to start worker: %w", err)
	}
	ready, err := waitForReadyEndpoint(cmd, sess, portFile)
	if err != nil {
		_ = stopDirectWorker(func() {}, cmd, log.New(io.Discard, "", 0))
		return nil, readyEndpoint{}, err
	}
	return cmd, ready, nil
}

func buildPythonCommand(ctx context.Context, script string, sess *session.Session, binaryPath string) (*exec.Cmd, string, error) {
	pythonBin := "python3"
	if runtime.GOOS == "windows" {
		pythonBin = "python"
		portFile := sess.SocketPath + ".port"
		_ = os.Remove(portFile)
		cmd := exec.CommandContext(ctx, pythonBin, script, "--port", "0", "--port-file", portFile, "--binary", binaryPath, "--session-id", sess.ID)
		return cmd, portFile, nil
	}
	if err := os.RemoveAll(sess.SocketPath); err != nil {
		return nil, "", fmt.Errorf("failed to remove old socket: %w", err)
	}
	cmd := exec.CommandContext(ctx, pythonBin, script, "--socket", sess.SocketPath, "--binary", binaryPath, "--session-id", sess.ID)
	return cmd, "", nil
}

func attachLogs(cmd *exec.Cmd) {
	if flag.Lookup("test.v") != nil {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
}

func waitForReadyEndpoint(cmd *exec.Cmd, sess *session.Session, portFile string) (readyEndpoint, error) {
	if runtime.GOOS == "windows" {
		return waitForTCPReady(cmd, portFile)
	}
	if err := waitForSocket(sess.SocketPath, 10*time.Second); err != nil {
		return readyEndpoint{}, fmt.Errorf("worker socket not ready: %w", err)
	}
	return readyEndpoint{baseURL: "http://unix", httpClient: unixHTTPClient(sess.SocketPath)}, nil
}

func waitForTCPReady(cmd *exec.Cmd, portFile string) (readyEndpoint, error) {
	if err := waitForPortFile(portFile, 30*time.Second); err != nil {
		return readyEndpoint{}, fmt.Errorf("worker TCP not ready: %w", err)
	}
	portBytes, err := os.ReadFile(portFile)
	if err != nil {
		return readyEndpoint{}, err
	}
	addr := "127.0.0.1:" + string(portBytes)
	if err := waitForTCP(addr, 10*time.Second); err != nil {
		return readyEndpoint{}, fmt.Errorf("worker TCP not connectable: %w", err)
	}
	return readyEndpoint{baseURL: "http://" + addr, httpClient: tcpHTTPClient()}, nil
}

func stopDirectWorker(cancel context.CancelFunc, cmd *exec.Cmd, logger *log.Logger) error {
	// Kill explicitly FIRST, then cancel the context. The reverse order races:
	// cancel() makes exec's own watcher call Process.Kill() asynchronously, and a
	// second Kill() landing on an already-terminating process returns
	// ERROR_ACCESS_DENIED on Windows (not os.ErrProcessDone), surfacing a
	// spurious "TerminateProcess: Access is denied" from close_binary even though
	// the worker did die. Killing a live process first avoids that; the
	// subsequent cancel() only releases context resources (its redundant kill
	// hits an already-dead process, which exec ignores).
	var killErr error
	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			killErr = err
			logger.Printf("[Worker] Failed to kill PID %d: %v", cmd.Process.Pid, err)
		}
	}
	cancel()
	return killErr
}

func tcpHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 90 * time.Second}}
}

func unixHTTPClient(socketPath string) *http.Client {
	transport := &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) { return net.Dial("unix", socketPath) }}
	return &http.Client{Transport: transport}
}

func waitForSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			if conn, err := net.Dial("unix", socketPath); err == nil {
				_ = conn.Close()
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket %s", socketPath)
}
