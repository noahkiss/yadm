package extexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
)

// PassSpec is a run with the caller's stdio passed through.
type PassSpec struct {
	Argv   []string // argv[0] is a path; it is run directly, never looked up on PATH
	Dir    string   // working directory; "" keeps the caller's
	Env    []string // added to the tool's environment, which loses every inherited YADM_ variable first
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Passthrough runs spec.Argv in the foreground and returns its exit code.
//
// Unlike Run it sends no request, captures nothing, sets no timeout and
// keeps the command in the caller's process group, so it owns the
// terminal: an editor, a pager or a prompt works, and a heredoc on stdin
// reaches it unchanged. When Stdin, Stdout or Stderr is an *os.File (the
// tool's own stdio), the command gets that file descriptor itself.
//
// While the command runs, the tool ignores the interrupt and quit signals
// (the terminal sends them to the command too, as a shell does for a
// foreground job) and forwards hangup and terminate to it. A command
// killed by a signal returns 128 plus the signal number, as a shell
// reports it. The error is non-nil only when the command did not start.
func Passthrough(ctx context.Context, spec PassSpec) (int, error) {
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return -1, ErrNoCommand
	}
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Dir = spec.Dir
	cmd.Env = append(parentEnv(), spec.Env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Stdin, spec.Stdout, spec.Stderr

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, passSignals...)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("%s: %w", spec.Argv[0], err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if forwarded(s) {
					_ = cmd.Process.Signal(s)
				}
			case <-ctx.Done():
				_ = cmd.Process.Signal(os.Interrupt)
				return
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return -1, fmt.Errorf("%s: %w", spec.Argv[0], err)
	}
	return exitStatus(cmd.ProcessState), nil
}

// PassEnv returns Env(req) for a passthrough run. YADM_JSON is 1 only when
// the caller asked for JSON; otherwise it is absent.
func PassEnv(req Request) []string {
	var out []string
	for _, kv := range Env(req) {
		if strings.HasPrefix(kv, "YADM_JSON=") {
			continue
		}
		out = append(out, kv)
	}
	if req.JSON {
		out = append(out, "YADM_JSON=1")
	}
	return out
}
