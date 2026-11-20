package store

import (
	"os/exec"
	"syscall"
	"time"
)

// waitDelay bounds how long Wait waits for git's output pipes after the
// context ends. A child of git (ssh, a credential helper) can keep them open.
const waitDelay = 5 * time.Second

// killGroup runs cmd in its own process group and, when the context ends,
// kills the whole group. Killing only git leaves its ssh child running, and
// Wait would block on the pipes that child still holds, so a stalled network
// call would outlive its deadline and keep the sync lock.
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = waitDelay
}
