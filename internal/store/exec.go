package store

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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

// AttributeDrivers returns the filter and merge drivers that git attributes
// can assign to a path of the clone, as "filter.<name>" and "merge.<name>".
// It reads every attribute source git consults: each .gitattributes in main's
// tree and in the worktree (tracked or not), $GIT_DIR/info/attributes, the
// global file (core.attributesFile, else $XDG_CONFIG_HOME/git/attributes)
// and the system file. A name counts when any line sets it, whether or not
// its pattern matches a path today, since a later path can match it.
func (r *Repo) AttributeDrivers(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	scan := func(b []byte) {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, f := range strings.Fields(line) {
				for _, kind := range []string{"filter", "merge"} {
					if name, ok := strings.CutPrefix(f, kind+"="); ok && name != "" {
						out[kind+"."+name] = true
					}
				}
			}
		}
	}
	isAttr := func(p string) bool { return p == ".gitattributes" || strings.HasSuffix(p, "/.gitattributes") }

	// main's tree: what the next checkout or merge reads.
	if head, err := r.ResolveRef(ctx, RefMain); err != nil {
		return nil, err
	} else if head != "" {
		tree, err := r.ListTree(ctx, head)
		if err != nil {
			return nil, err
		}
		for _, te := range tree {
			if isAttr(string(te.Path)) {
				b, err := r.ReadBlob(ctx, te.Blob)
				if err != nil {
					return nil, err
				}
				scan(b)
			}
		}
	}
	// The worktree, tracked or not.
	ls, err := r.git(ctx, "ls-files", "-z", "--cached", "--others", "--", ":(glob)**/.gitattributes")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, p := range strings.Split(string(ls), "\x00") {
		if isAttr(p) {
			files = append(files, filepath.Join(r.dir, filepath.FromSlash(p)))
		}
	}
	info, err := r.git(ctx, "rev-parse", "--path-format=absolute", "--git-path", "info/attributes")
	if err != nil {
		return nil, err
	}
	files = append(files, strings.TrimSpace(string(info)))
	files = append(files, r.attributeFiles(ctx)...)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
				continue
			}
			return nil, err
		}
		scan(b)
	}
	return out, nil
}

// attributeFiles returns the global and system attribute files git reads.
// git 2.42 and newer name them with `git var`; older git falls back to
// core.attributesFile or its XDG default, and the system file is skipped.
func (r *Repo) attributeFiles(ctx context.Context) []string {
	var files []string
	for _, v := range []string{"GIT_ATTR_GLOBAL", "GIT_ATTR_SYSTEM"} {
		if b, err := r.git(ctx, "var", v); err == nil {
			if p := strings.TrimSpace(string(b)); p != "" {
				files = append(files, p)
			}
		}
	}
	if len(files) > 0 {
		return files
	}
	if b, err := r.git(ctx, "config", "--path", "--get", "core.attributesFile"); err == nil {
		if p := strings.TrimSpace(string(b)); p != "" {
			return []string{p}
		}
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		return []string{filepath.Join(x, "git", "attributes")}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return []string{filepath.Join(h, ".config", "git", "attributes")}
	}
	return nil
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
	out, err := run(ctx, call{dir: r.dir, base: r.env, network: true, args: []string{"ls-remote", "--", "origin", RefMain, "refs/yadm/*"}})
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
