//go:build unix

package extexec

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup starts the command in its own process group, so a timeout
// can kill every process it spawned.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup sends SIGKILL to the command's whole process group.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// passSignals are the signals the tool catches while a passthrough
// command runs.
var passSignals = []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTERM}

// forwarded reports whether a caught signal goes on to the command. The
// terminal already sends interrupt and quit to the whole foreground group.
func forwarded(s os.Signal) bool { return s == syscall.SIGHUP || s == syscall.SIGTERM }

// exitStatus is the command's exit code, or 128 plus the signal that
// killed it.
func exitStatus(ps *os.ProcessState) int {
	if ps == nil {
		return -1
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}
