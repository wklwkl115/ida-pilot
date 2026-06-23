package worker

import (
	"context"
	"log"
	"net/http"

	"github.com/wklwkl115/ida-pilot/internal/session"
)

// Launcher starts a worker and returns a ready endpoint.
type Launcher func(context.Context, *session.Session, string) (LaunchResult, error)

// LaunchResult is the externally supplied worker capability.
type LaunchResult struct {
	PID        int
	BaseURL    string
	HTTPClient *http.Client
	Stop       func() error
	Wait       func() error
}

func newDefaultLauncher(pythonScript string, logger *log.Logger) Launcher {
	return newDirectLauncher(pythonScript, logger)
}
