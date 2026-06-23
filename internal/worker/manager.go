package worker

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	pb "github.com/wklwkl115/ida-pilot/ida/worker/v1"
	"github.com/wklwkl115/ida-pilot/ida/worker/v1/workerconnect"
	"github.com/wklwkl115/ida-pilot/internal/session"
)

// Manager handles worker processes.
type Manager struct {
	launcher Launcher
	sessions map[string]*WorkerClient
	logger   *log.Logger
	mu       sync.RWMutex
}

// WorkerClient wraps Connect clients for a session.
type WorkerClient struct {
	SessionCtrl *workerconnect.SessionControlClient
	Analysis    *workerconnect.AnalysisToolsClient
	Health      *workerconnect.HealthcheckClient
	HTTPClient  *http.Client
	BaseURL     string
	stop        func() error
	wait        func() error
	done        chan struct{}
	session     *session.Session
	binaryPath  string
}

// Controller captures the worker operations required by the server.
type Controller interface {
	Start(ctx context.Context, sess *session.Session, binaryPath string) error
	Stop(sessionID string) error
	GetClient(sessionID string) (*WorkerClient, error)
}

// NewManager creates a manager with the default launcher.
func NewManager(pythonScript string, logger *log.Logger) *Manager {
	return NewManagerWithLauncher(pythonScript, logger, newDefaultLauncher(pythonScript, logger))
}

// NewManagerWithLauncher creates a manager with an injected launcher capability.
func NewManagerWithLauncher(_ string, logger *log.Logger, launcher Launcher) *Manager {
	return &Manager{launcher: launcher, sessions: map[string]*WorkerClient{}, logger: logger}
}

// Start spawns a worker with an independent lifecycle.
func (m *Manager) Start(_ context.Context, sess *session.Session, binaryPath string) error {
	result, err := m.launcher(context.Background(), sess, binaryPath)
	if err != nil {
		return err
	}
	sess.WorkerPID = result.PID
	worker := newWorkerClient(sess, binaryPath, result)
	m.mu.Lock()
	m.sessions[sess.ID] = worker
	m.mu.Unlock()
	if worker.wait != nil {
		go m.monitorWorker(sess.ID, worker)
	}
	return nil
}

func newWorkerClient(sess *session.Session, binaryPath string, result LaunchResult) *WorkerClient {
	sessionClient := workerconnect.NewSessionControlClient(result.HTTPClient, result.BaseURL)
	analysisClient := workerconnect.NewAnalysisToolsClient(result.HTTPClient, result.BaseURL)
	healthClient := workerconnect.NewHealthcheckClient(result.HTTPClient, result.BaseURL)
	return &WorkerClient{
		SessionCtrl: &sessionClient,
		Analysis:    &analysisClient,
		Health:      &healthClient,
		HTTPClient:  result.HTTPClient,
		BaseURL:     result.BaseURL,
		stop:        result.Stop,
		wait:        result.Wait,
		done:        make(chan struct{}),
		session:     sess,
		binaryPath:  binaryPath,
	}
}

func (m *Manager) monitorWorker(sessionID string, worker *WorkerClient) {
	defer close(worker.done)
	if err := worker.wait(); err != nil {
		m.logger.Printf("[Worker] Process %d exited with error for session %s: %v", worker.session.WorkerPID, sessionID, err)
	} else {
		m.logger.Printf("[Worker] Process %d exited for session %s", worker.session.WorkerPID, sessionID)
	}
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

// Stop terminates the worker for a session.
func (m *Manager) Stop(sessionID string) error {
	worker, err := m.GetClient(sessionID)
	if err != nil {
		return err
	}
	m.logger.Printf("[Worker] Stopping session %s PID %d", sessionID, worker.session.WorkerPID)
	closeSession(worker)
	if err := stopWorker(worker); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	return nil
}

func closeSession(worker *WorkerClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if worker.SessionCtrl != nil {
		_, _ = (*worker.SessionCtrl).CloseSession(ctx, connect.NewRequest(&pb.CloseSessionRequest{Save: true}))
	}
}

func stopWorker(worker *WorkerClient) error {
	if worker.stop == nil {
		return nil
	}
	if err := worker.stop(); err != nil {
		return fmt.Errorf("failed to stop worker: %w", err)
	}
	if worker.wait == nil {
		return nil
	}
	select {
	case <-worker.done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// GetClient returns the worker client for a session.
func (m *Manager) GetClient(sessionID string) (*WorkerClient, error) {
	m.mu.RLock()
	worker, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no worker for session %s", sessionID)
	}
	return worker, nil
}
