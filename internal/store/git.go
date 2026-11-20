package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// MinGitVersion is the oldest git the store accepts. `git merge-tree
// --write-tree --merge-base` needs 2.40.
var MinGitVersion = [3]int{2, 40, 0}

// Default timeouts for one git call when the caller's context has no deadline.
const (
	localTimeout   = 2 * time.Minute
	networkTimeout = 3 * time.Minute
)

// secrecyArgs go before every git subcommand. Hooks of the clone never run,
// no textconv cache is written, and no fsmonitor daemon is started.
var secrecyArgs = []string{
	"-c", "diff.cachetextconv=false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.fsmonitor=false",
	"-c", "advice.detachedHead=false",
}

// envDrop lists inherited variables that would redirect git away from the
// source clone (for example when the tool runs inside another repo's hook).
var envDrop = []string{
	"GIT_DIR=", "GIT_WORK_TREE=", "GIT_INDEX_FILE=", "GIT_OBJECT_DIRECTORY=",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES=", "GIT_NAMESPACE=", "GIT_PREFIX=",
	"GIT_COMMON_DIR=", "GIT_CEILING_DIRECTORIES=",
}

// gitError is a failed git call. Stderr is kept for callers that branch on it;
// it never holds plaintext because git only ever sees blobs the tool wrote.
type gitError struct {
	args   []string
	code   int
	stderr string
	err    error
}

func (e *gitError) Error() string {
	msg := strings.TrimSpace(e.stderr)
	if msg == "" && e.err != nil {
		msg = e.err.Error()
	}
	return fmt.Sprintf("git %s: exit %d: %s", strings.Join(e.args, " "), e.code, msg)
}

func (e *gitError) Unwrap() error { return e.err }

// exitCode returns the git exit code of err, or -1.
func exitCode(err error) int {
	var ge *gitError
	if errors.As(err, &ge) {
		return ge.code
	}
	return -1
}

// call describes one git invocation.
type call struct {
	dir     string
	args    []string
	stdin   []byte
	env     []string // extra KEY=VALUE pairs
	base    []string // filtered environment from gitEnv(nil); nil builds it
	network bool
}

// spawns counts git processes started by run and the batch reader. Tests
// and benchmarks read it.
var spawns atomic.Int64

// run executes git and returns stdout. A non-zero exit is a *gitError.
func run(ctx context.Context, c call) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		d := localTimeout
		if c.network {
			d = networkTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	args := append([]string{}, secrecyArgs...)
	if c.dir != "" {
		args = append([]string{"-C", c.dir}, args...)
	}
	args = append(args, c.args...)
	cmd := exec.CommandContext(ctx, "git", args...)
	killGroup(cmd)
	if c.base != nil {
		cmd.Env = append(c.base[:len(c.base):len(c.base)], c.env...)
	} else {
		cmd.Env = gitEnv(c.env)
	}
	if c.stdin != nil {
		cmd.Stdin = bytes.NewReader(c.stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	spawns.Add(1)
	err := cmd.Run()
	if err != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return out.Bytes(), &gitError{args: c.args, code: code, stderr: errb.String(), err: err}
	}
	return out.Bytes(), nil
}

func gitEnv(extra []string) []string {
	var env []string
outer:
	for _, kv := range os.Environ() {
		for _, d := range envDrop {
			if strings.HasPrefix(kv, d) {
				continue outer
			}
		}
		if strings.HasPrefix(kv, "LC_ALL=") || strings.HasPrefix(kv, "GIT_TERMINAL_PROMPT=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "LC_ALL=C", "GIT_TERMINAL_PROMPT=0")
	return append(env, extra...)
}

// CheckGitVersion fails when the git binary is missing or older than MinGitVersion.
func CheckGitVersion(ctx context.Context) error {
	out, err := run(ctx, call{args: []string{"version"}})
	if err != nil {
		return fmt.Errorf("git not usable: %w", err)
	}
	v, err := parseGitVersion(string(out))
	if err != nil {
		return err
	}
	for i := range v {
		if v[i] != MinGitVersion[i] {
			if v[i] < MinGitVersion[i] {
				return fmt.Errorf("git %d.%d.%d is too old: need %d.%d.%d or newer",
					v[0], v[1], v[2], MinGitVersion[0], MinGitVersion[1], MinGitVersion[2])
			}
			return nil
		}
	}
	return nil
}

// parseGitVersion reads "git version 2.43.0" and vendor suffixes such as
// "git version 2.39.3 (Apple Git-146)" or "2.45.1.windows.1".
func parseGitVersion(s string) ([3]int, error) {
	var v [3]int
	f := strings.Fields(s)
	if len(f) < 3 || f[0] != "git" || f[1] != "version" {
		return v, fmt.Errorf("unrecognized git version output %q", strings.TrimSpace(s))
	}
	parts := strings.Split(f[2], ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			if i == 0 {
				return v, fmt.Errorf("unrecognized git version %q", f[2])
			}
			break
		}
		v[i] = n
	}
	return v, nil
}
