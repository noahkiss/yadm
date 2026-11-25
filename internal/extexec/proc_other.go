//go:build !unix

package extexec

import (
	"os"
	"os/exec"
)

func setProcessGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

var passSignals = []os.Signal{os.Interrupt}

func forwarded(os.Signal) bool { return false }

func exitStatus(ps *os.ProcessState) int {
	if ps == nil {
		return -1
	}
	return ps.ExitCode()
}
