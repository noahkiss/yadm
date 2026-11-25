//go:build unix

package extexec

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPassthroughStdioAndExit: stdin reaches the command unchanged, its
// stdout and stderr are its own, the tool's own files are handed over as
// file descriptors, and the exit code is the command's.
func TestPassthroughStdioAndExit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("YADM_STALE", "leak")
	p := script(t, dir, "c", `cat; echo "env:${YADM_STALE:-none}:$EXTRA"; echo err >&2
if [ -f /dev/stdout ]; then echo "stdout-is-file" >&2; fi
exit 5
`)
	var out, errb bytes.Buffer
	code, err := Passthrough(context.Background(), PassSpec{Argv: []string{p}, Env: []string{"EXTRA=x"},
		Stdin: strings.NewReader("line one\nline two\n"), Stdout: &out, Stderr: &errb})
	if err != nil || code != 5 {
		t.Fatalf("code %d err %v", code, err)
	}
	if out.String() != "line one\nline two\nenv:none:x\n" || errb.String() != "err\n" {
		t.Fatalf("stdout %q stderr %q", out.String(), errb.String())
	}

	// An *os.File is passed as the descriptor itself, as a terminal is.
	f, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	errb.Reset()
	if code, err := Passthrough(context.Background(), PassSpec{Argv: []string{p}, Stdin: strings.NewReader(""), Stdout: f, Stderr: &errb}); err != nil || code != 5 {
		t.Fatalf("code %d err %v", code, err)
	}
	if !strings.Contains(errb.String(), "stdout-is-file") {
		t.Fatalf("the command's stdout was not the file itself: %q", errb.String())
	}

	if _, err := Passthrough(context.Background(), PassSpec{Argv: []string{filepath.Join(dir, "missing")}}); err == nil {
		t.Fatal("a missing command started")
	}
}

// TestPassthroughSignals: a command killed by a signal reports 128 plus the
// signal; the tool ignores an interrupt while the command runs and forwards
// a terminate to it.
func TestPassthroughSignals(t *testing.T) {
	dir := t.TempDir()
	self := script(t, dir, "self", "kill -TERM $$\nsleep 5\n")
	if code, err := Passthrough(context.Background(), PassSpec{Argv: []string{self}}); err != nil || code != 128+int(syscall.SIGTERM) {
		t.Fatalf("self-killed: code %d err %v", code, err)
	}

	ready := filepath.Join(dir, "ready")
	wait := script(t, dir, "wait", `trap 'echo got-int >> "$0.log"' INT
touch "`+ready+`"
i=0; while [ $i -lt 40 ]; do sleep 0.1; i=$((i+1)); done
exit 3
`)
	send := func(sig syscall.Signal) {
		go func() {
			for i := 0; i < 100; i++ {
				if _, err := os.Stat(ready); err == nil {
					_ = syscall.Kill(os.Getpid(), sig)
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}

	// Interrupt to the tool alone: ignored, not forwarded; the command
	// runs to its own exit.
	send(syscall.SIGINT)
	if code, err := Passthrough(context.Background(), PassSpec{Argv: []string{wait}}); err != nil || code != 3 {
		t.Fatalf("after SIGINT to the tool: code %d err %v", code, err)
	}
	if _, err := os.Stat(wait + ".log"); err == nil {
		t.Fatal("the tool forwarded an interrupt the terminal would have sent itself")
	}

	os.Remove(ready)
	send(syscall.SIGTERM)
	if code, err := Passthrough(context.Background(), PassSpec{Argv: []string{wait}}); err != nil || code != 128+int(syscall.SIGTERM) {
		t.Fatalf("after SIGTERM to the tool: code %d err %v", code, err)
	}
}

func TestPassEnvJSON(t *testing.T) {
	has := func(env []string, kv string) bool {
		for _, e := range env {
			if e == kv {
				return true
			}
		}
		return false
	}
	req := testReq(t.TempDir())
	if env := PassEnv(req); has(env, "YADM_JSON=1") {
		t.Fatal("YADM_JSON=1 without --json")
	}
	req.JSON = true
	if env := PassEnv(req); !has(env, "YADM_JSON=1") {
		t.Fatal("no YADM_JSON=1 with --json")
	}
}

func TestRunKeepOrder(t *testing.T) {
	home := t.TempDir()
	p := script(t, t.TempDir(), "n", "cat >/dev/null; printf 'b\\n\\na\\na\\n'\n")
	res, err := NewRunner().Run(context.Background(), Spec{Argv: []string{p}, Timeout: 5 * time.Second, KeepOrder: true}, testReq(home))
	if err != nil || strings.Join(res.Items, ",") != "b,a,a" {
		t.Fatalf("items %v err %v", res.Items, err)
	}
	req := testReq(home)
	req.Session = "session-1"
	if env := Env(req); !strings.Contains(strings.Join(env, "\n"), "YADM_SESSION=session-1") {
		t.Fatal("no YADM_SESSION")
	}
}
