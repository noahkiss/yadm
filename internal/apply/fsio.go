package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// errTimeout marks a filesystem call that did not return within its bound.
var errTimeout = errors.New("filesystem call timed out")

// tmpMarker is part of every temp file name apply creates next to a target.
const tmpMarker = ".yadm-tmp-"

// fsys is the filesystem apply reads through. Tests replace it to simulate
// slow mounts and crashes.
type fsys interface {
	Lstat(name string) (fs.FileInfo, error)
	ReadFile(name string) ([]byte, error)
	// BeforeRename runs after a temp file is complete and before it is
	// renamed over its target. A non-nil error aborts like a crash: the temp
	// file is left behind and the target is untouched.
	BeforeRename(tmp, dst string) error
}

type osFS struct{}

func (osFS) Lstat(n string) (fs.FileInfo, error) { return os.Lstat(n) }
func (osFS) ReadFile(n string) ([]byte, error)   { return os.ReadFile(n) }
func (osFS) BeforeRename(string, string) error   { return nil }

// bounded runs f and gives up after d. A call that hangs (a dead network
// mount) leaks one goroutine until the kernel returns; the command goes on.
func bounded[T any](ctx context.Context, d time.Duration, f func() (T, error)) (T, error) {
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() {
		v, err := f()
		ch <- res{v, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	var zero T
	select {
	case r := <-ch:
		return r.v, r.err
	case <-t.C:
		return zero, errTimeout
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

// live is what is on disk at one target.
type live struct {
	exists bool
	info   fs.FileInfo
	bytes  []byte
}

// readTarget stats and reads one target within the stat timeout. A missing
// file is not an error. Only regular files are read.
func (e *Engine) readTarget(ctx context.Context, abs string) (live, error) {
	info, err := bounded(ctx, e.StatTimeout, func() (fs.FileInfo, error) { return e.fs.Lstat(abs) })
	if errors.Is(err, fs.ErrNotExist) {
		return live{}, nil
	}
	if err != nil {
		return live{}, err
	}
	if !info.Mode().IsRegular() {
		return live{exists: true, info: info}, nil
	}
	b, err := bounded(ctx, e.StatTimeout, func() ([]byte, error) { return e.fs.ReadFile(abs) })
	if err != nil {
		return live{}, err
	}
	return live{exists: true, info: info, bytes: b}, nil
}

// abs returns the absolute path of a target under $HOME. It refuses paths
// that are absolute or climb out of $HOME.
func (e *Engine) abs(t model.Target) (string, error) {
	s := string(t)
	if s == "" || strings.HasPrefix(s, "/") || path.Clean(s) != s || s == "." || s == ".." || strings.HasPrefix(s, "../") {
		return "", fmt.Errorf("target %q: not a clean path relative to $HOME", t)
	}
	if e.Home == "" {
		return "", errors.New("apply: Home is not set")
	}
	return filepath.Join(e.Home, filepath.FromSlash(s)), nil
}

func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// writeAtomic writes b to dst through a temp file in the same directory and a
// rename, so a reader or a crash sees either the old bytes or the new ones.
// The temp file is created 0600 and gets its final mode before the rename.
func (e *Engine) writeAtomic(dst string, b []byte, mode fs.FileMode) error {
	dir, base := filepath.Split(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cleanStaleTemps(dir, base)
	f, err := os.CreateTemp(dir, "."+base+tmpMarker+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	crashed := false
	defer func() {
		if !crashed {
			_ = os.Remove(tmp) // no-op after a successful rename
		}
	}()
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode.Perm()); err != nil {
		return err
	}
	if err := e.fs.BeforeRename(tmp, dst); err != nil {
		crashed = true
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// cleanStaleTemps removes temp files a crashed write left next to base.
func cleanStaleTemps(dir, base string) {
	m, _ := filepath.Glob(filepath.Join(dir, "."+globEscape(base)+tmpMarker+"*"))
	for _, p := range m {
		_ = os.Remove(p)
	}
}

func globEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	return r.Replace(s)
}

func isTempName(name string) bool { return strings.Contains(name, tmpMarker) }

// backupDir is where replaced target bytes go.
func (e *Engine) backupDir() string { return filepath.Join(e.StateDir, "backup") }

// backup copies the bytes apply is about to replace or delete into
// backup/<time>/<target>, mode 0600.
func (e *Engine) backup(now time.Time, t model.Target, b []byte) error {
	if e.StateDir == "" {
		return errors.New("apply: StateDir is not set; refusing to replace a file without a backup")
	}
	p := filepath.Join(e.backupDir(), now.UTC().Format("20060102T150405.000000000Z"), filepath.FromSlash(string(t)))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// pruneBackups removes backup sets older than BackupRetention.
func (e *Engine) pruneBackups(now time.Time) {
	if e.StateDir == "" {
		return
	}
	ents, err := os.ReadDir(e.backupDir())
	if err != nil {
		return
	}
	for _, d := range ents {
		ts, err := time.Parse("20060102T150405.000000000Z", d.Name())
		if err != nil {
			continue
		}
		if now.Sub(ts) > BackupRetention {
			_ = os.RemoveAll(filepath.Join(e.backupDir(), d.Name()))
		}
	}
}

// fileDB is the JSON StateDB.
type fileDB struct{ dir string }

func (d fileDB) path() string { return filepath.Join(d.dir, StateFile) }

// Load reads the state file. A missing file is an empty state.
func (d fileDB) Load() (*State, error) {
	b, err := os.ReadFile(d.path())
	if errors.Is(err, fs.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("state %s: %w", d.path(), err)
	}
	if st.Schema > StateSchema {
		return nil, fmt.Errorf("state %s: schema %d is newer than this tool (%d)", d.path(), st.Schema, StateSchema)
	}
	st.normalize()
	return &st, nil
}

// Save writes the state file atomically with mode 0600.
func (d fileDB) Save(st *State) error {
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		return err
	}
	st.Schema = StateSchema
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(d.dir, "."+StateFile+tmpMarker+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, d.path())
}

func newState() *State {
	st := &State{Schema: StateSchema}
	st.normalize()
	return st
}

func (st *State) normalize() {
	if st.Schema == 0 {
		st.Schema = StateSchema
	}
	if st.Targets == nil {
		st.Targets = map[model.Target]TargetState{}
	}
	if st.Seen == nil {
		st.Seen = map[model.Target]time.Time{}
	}
}

func (e *Engine) loadState() (*State, error) {
	if e.State == nil {
		return nil, errors.New("apply: no StateDB")
	}
	st, err := e.State.Load()
	if err != nil {
		return nil, err
	}
	if st == nil {
		st = newState()
	}
	st.normalize()
	if st.Machine == "" {
		st.Machine = e.Self
	}
	return st, nil
}
