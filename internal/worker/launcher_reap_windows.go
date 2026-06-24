//go:build windows

package worker

import (
	"log"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Worker lifetime is bound to the server via a Job Object configured to kill
// every assigned process when the job's last handle closes. The only handle is
// held by this (server) process, so the workers die the instant the server
// exits — gracefully OR via crash/taskkill — and a dead server never leaves
// orphaned IDA workers holding databases open. The job is created lazily on the
// first worker launch and held open for the server's lifetime.
var (
	jobOnce   sync.Once
	jobHandle windows.Handle
	jobErr    error
)

func ensureKillOnCloseJob() (windows.Handle, error) {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			jobErr = err
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
			BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
				LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			},
		}
		if _, err := windows.SetInformationJobObject(
			h,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		); err != nil {
			windows.CloseHandle(h)
			jobErr = err
			return
		}
		jobHandle = h
	})
	return jobHandle, jobErr
}

// prepareWorkerCmd is a no-op on Windows; lifetime binding happens after start
// via the Job Object (see superviseWorkerProcess).
func prepareWorkerCmd(_ *exec.Cmd) {}

// superviseWorkerProcess assigns the freshly-started worker to the kill-on-close
// job so it cannot outlive the server. Best-effort: on failure the worker still
// runs, we just lose the crash-cleanup guarantee, so we log and carry on.
func superviseWorkerProcess(cmd *exec.Cmd, logger *log.Logger) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	job, err := ensureKillOnCloseJob()
	if err != nil {
		logger.Printf("[Worker] kill-on-close job unavailable: %v (worker may orphan on crash)", err)
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		logger.Printf("[Worker] OpenProcess for job assignment failed: %v (worker may orphan on crash)", err)
		return
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		logger.Printf("[Worker] AssignProcessToJobObject failed: %v (worker may orphan on crash)", err)
	}
}
