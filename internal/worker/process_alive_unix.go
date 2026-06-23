//go:build !windows

package worker

import "syscall"

func processAlive(pid int) bool {
	if pid == 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
