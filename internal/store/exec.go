package store

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/model"
)

// HashBlob writes b to the object store as a blob and returns its id. No
// attribute filter runs on it. Callers pass only bytes that may enter the
// repository: plaintext of shared files or sealed blobs, never enclave
// plaintext.
func (r *Repo) HashBlob(ctx context.Context, b []byte) (string, error) {
	return r.hashBlob(ctx, b)
}

// ConfigKeys returns the sorted config keys that match the extended regular
// expression re, in every config scope the clone sees (local only when
// localOnly is set). No match is an empty list, not an error.
func (r *Repo) ConfigKeys(ctx context.Context, re string, localOnly bool) ([]string, error) {
	args := []string{"config"}
	if localOnly {
		args = append(args, "--local")
	}
	args = append(args, "--null", "--name-only", "--get-regexp", re)
	out, err := r.git(ctx, args...)
	if err != nil {
		if exitCode(err) == 1 {
			return []string{}, nil
		}
		return nil, err
	}
	keys := []string{}
	for _, k := range strings.Split(string(out), "\x00") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Git runs one git command in the source clone with the secrecy overrides
// and the cleaned environment, wiring the given streams through. It returns
// git's exit code; err is set only when git could not run at all. It is the
// passthrough behind `yadm git`; the caller's context bounds it.
func (r *Repo) Git(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) (int, error) {
	return Passthrough(ctx, r.dir, stdin, stdout, stderr, args...)
}

// Passthrough is Repo.Git for a directory that is not an opened source
// clone (an import output directory, for example).
func Passthrough(ctx context.Context, dir string, stdin io.Reader, stdout, stderr io.Writer, args ...string) (int, error) {
	full := append([]string{"-C", dir}, secrecyArgs...)
	cmd := exec.CommandContext(ctx, "git", append(full, args...)...)
	cmd.Env = gitEnv(nil)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	}
	return -1, err
}

// Output runs one git command in dir with the secrecy overrides and returns
// its stdout. A non-zero exit is an error that GitExitCode reads.
func Output(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return run(ctx, call{dir: dir, args: args})
}

// GitExitCode returns git's exit code from an error of Output, or -1.
func GitExitCode(err error) int { return exitCode(err) }

// RemoteHeads lists main and every ref under refs/yadm/ on origin with
// `git ls-remote`, without fetching objects. It is the cheap check a quick
// sync runs before deciding whether a full sync is needed.
func (r *Repo) RemoteHeads(ctx context.Context) (map[string]model.CommitID, error) {
	out, err := run(ctx, call{dir: r.dir, network: true, args: []string{"ls-remote", "--", "origin", RefMain, "refs/yadm/*"}})
	if err != nil {
		return nil, err
	}
	refs := map[string]model.CommitID{}
	for _, l := range strings.Split(string(out), "\n") {
		id, name, ok := strings.Cut(strings.TrimSpace(l), "\t")
		if ok && name != "" {
			refs[name] = model.CommitID(id)
		}
	}
	return refs, nil
}
