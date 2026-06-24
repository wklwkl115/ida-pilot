//go:build !windows && !linux

package worker

import (
	"log"
	"os/exec"
)

// prepareWorkerCmd / superviseWorkerProcess are no-ops on platforms without a
// clean "die with parent" primitive (macOS/BSD have neither a Job Object nor
// Pdeathsig). Graceful shutdown still stops workers via Manager.Stop; only a
// hard crash of the server can orphan a worker here.
func prepareWorkerCmd(_ *exec.Cmd) {}

func superviseWorkerProcess(_ *exec.Cmd, _ *log.Logger) {}
