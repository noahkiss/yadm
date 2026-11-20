package importer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// legacyFile is one entry of the legacy head tree.
type legacyFile struct {
	Path    string
	Mode    string // git mode: 100644, 100755 or 120000
	Blob    string
	Filter  string // the gitattributes filter, empty when unset
	Symlink bool
	Exec    bool
}

// legacyRepo is a read-only view of the legacy head commit.
type legacyRepo struct {
	dir    string
	Head   string
	Files  []legacyFile // in git's path order
	byPath map[string]*legacyFile
	blobs  map[string][]byte
}

// gitEnv isolates git from the user's and the system's configuration, so a
// global textconv or filter never runs on legacy content.
func gitEnv() []string {
	env := []string{}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "GIT_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0")
}

func runGit(ctx context.Context, dir string, stdin io.Reader, args ...string) ([]byte, error) {
	full := append([]string{"-C", dir, "-c", "diff.cachetextconv=false", "-c", "core.quotePath=false"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = gitEnv()
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// readLegacy reads the head tree, the filter attribute of every path and
// every blob. It never reads the worktree.
func readLegacy(ctx context.Context, dir string) (*legacyRepo, error) {
	head, err := runGit(ctx, dir, nil, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return nil, fmt.Errorf("legacy repository %s: %w", dir, err)
	}
	r := &legacyRepo{dir: dir, Head: strings.TrimSpace(string(head)), byPath: map[string]*legacyFile{}, blobs: map[string][]byte{}}
	tree, err := runGit(ctx, dir, nil, "ls-tree", "-r", "-z", "--full-tree", r.Head)
	if err != nil {
		return nil, err
	}
	for _, rec := range bytes.Split(tree, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, ok := strings.Cut(string(rec), "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("unexpected ls-tree line %q", rec)
		}
		if f[1] != "blob" {
			return nil, fmt.Errorf("%s: %s entries (submodules) are not supported", path, f[1])
		}
		r.Files = append(r.Files, legacyFile{Path: path, Mode: f[0], Blob: f[2], Symlink: f[0] == "120000", Exec: f[0] == "100755"})
	}
	for i := range r.Files {
		r.byPath[r.Files[i].Path] = &r.Files[i]
	}
	if err := r.readAttrs(ctx); err != nil {
		return nil, err
	}
	if err := r.readBlobs(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *legacyRepo) readAttrs(ctx context.Context) error {
	var in bytes.Buffer
	for _, f := range r.Files {
		in.WriteString(f.Path)
		in.WriteByte(0)
	}
	out, err := runGit(ctx, r.dir, &in, "check-attr", "--source="+r.Head, "-z", "--stdin", "filter")
	if err != nil {
		return err
	}
	// Output records: path NUL attr NUL value NUL.
	parts := strings.Split(string(out), "\x00")
	for i := 0; i+2 < len(parts); i += 3 {
		f := r.byPath[parts[i]]
		if f == nil {
			continue
		}
		switch v := parts[i+2]; v {
		case "unspecified", "unset", "set":
		default:
			f.Filter = v
		}
	}
	return nil
}

func (r *legacyRepo) readBlobs(ctx context.Context) error {
	var in bytes.Buffer
	for _, f := range r.Files {
		in.WriteString(f.Blob + "\n")
	}
	out, err := runGit(ctx, r.dir, &in, "cat-file", "--batch")
	if err != nil {
		return err
	}
	br := bufio.NewReader(bytes.NewReader(out))
	for range r.Files {
		hdr, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("cat-file: %w", err)
		}
		f := strings.Fields(hdr)
		if len(f) != 3 {
			return fmt.Errorf("cat-file: unexpected header %q", hdr)
		}
		n, err := strconv.Atoi(f[2])
		if err != nil {
			return err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		if _, err := br.ReadByte(); err != nil { // trailing LF
			return err
		}
		r.blobs[f[0]] = b
	}
	return nil
}

// cryptFilters returns "crypt" plus every filter name whose smudge, clean or
// textconv command runs transcrypt, read from the legacy repository's own
// local config. dir may be a bare repository. It only reads config: it
// writes nothing and runs no filter.
func cryptFilters(ctx context.Context, dir string) map[string]bool {
	out := map[string]bool{"crypt": true}
	b, err := runGit(ctx, dir, nil, "config", "--local", "--get-regexp", `^filter\..*\.(smudge|clean|textconv)$`)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := strings.Cut(line, " ")
		if !ok || !strings.Contains(val, "transcrypt") {
			continue
		}
		name := strings.TrimPrefix(key, "filter.")
		if i := strings.LastIndexByte(name, '.'); i > 0 {
			out[name[:i]] = true
		}
	}
	return out
}
