package worker

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/ida/worker/v1/workerconnect"
	"github.com/wklwkl115/ida-pilot/internal/session"
)

func TestManagerUsesInjectedLauncherEndpoint(t *testing.T) {
	t.Parallel()
	server := newHealthServer()
	defer server.Close()

	mgr := NewManagerWithLauncher("unused", testLogger(), readyLauncher(server.URL, server.Client()))
	sess := testSession(t, "launcher-ready.sock")

	if err := mgr.Start(context.Background(), sess, "sample.bin"); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop(sess.ID) })

	client, err := mgr.GetClient(sess.ID)
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}
	resp, err := (*client.Health).Ping(context.Background(), connect.NewRequest(&pb.PingRequest{}))
	if err != nil || !resp.Msg.Alive {
		t.Fatalf("Ping failed: resp=%v err=%v", resp, err)
	}
}

func TestManagerStartReturnsLauncherError(t *testing.T) {
	t.Parallel()
	want := "timeout waiting for ready endpoint"
	mgr := NewManagerWithLauncher("unused", testLogger(), failingLauncher(want))

	err := mgr.Start(context.Background(), testSession(t, "launcher-fail.sock"), "sample.bin")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Start error = %v, want substring %q", err, want)
	}
}

func testLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func testSession(t *testing.T, name string) *session.Session {
	t.Helper()
	return &session.Session{ID: name, SocketPath: filepath.Join(t.TempDir(), name)}
}

func readyLauncher(url string, client *http.Client) Launcher {
	return func(context.Context, *session.Session, string) (LaunchResult, error) {
		return LaunchResult{PID: 7, BaseURL: url, HTTPClient: client}, nil
	}
}

func failingLauncher(msg string) Launcher {
	return func(context.Context, *session.Session, string) (LaunchResult, error) {
		return LaunchResult{}, errors.New(msg)
	}
}

func newHealthServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle(workerconnect.NewHealthcheckHandler(fakeHealthServer{}))
	return httptest.NewServer(mux)
}

type fakeHealthServer struct {
	workerconnect.UnimplementedHealthcheckHandler
}

func (fakeHealthServer) Ping(context.Context, *connect.Request[pb.PingRequest]) (*connect.Response[pb.PingResponse], error) {
	return connect.NewResponse(&pb.PingResponse{Alive: true}), nil
}
