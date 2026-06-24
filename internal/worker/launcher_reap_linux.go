//go:build linux

package worker

import (
	"log"
	"os/exec"
	"syscall"
)

// prepareWorkerCmd asks the kernel to SIGKILL the worker if this (server)
// process dies, so a crashed server leaves no orphaned IDA worker. Set before
// Start. (Pdeathsig is Linux-only; see launcher_reap_other.go for the no-op
// platforms.)
func prepareWorkerCmd(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

// superviseWorkerProcess is a no-op on Linux; the binding is set pre-start via
// Pdeathsig.
func superviseWorkerProcess(_ *exec.Cmd, _ *log.Logger) {}
