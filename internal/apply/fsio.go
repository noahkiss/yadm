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
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
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
	if _, err := bounded(ctx, e.StatTimeout, func() (struct{}, error) { return struct{}{}, InsideHome(e.Home, abs) }); err != nil {
		return live{}, err
	}
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

// ErrOutsideHome is returned for a path under $HOME whose parent directory
// resolves, through a symlink, to a directory outside $HOME. Such a target
// is never read or written.
var ErrOutsideHome = errors.New("a parent directory is a symlink that leaves $HOME")

// InsideHome checks that the real path of p's parent directory stays under
// the real path of home. It resolves the nearest existing ancestor, so a
// directory apply would create is checked through the part that exists.
func InsideHome(home, p string) error {
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		realHome = filepath.Clean(home)
	}
	dir := filepath.Dir(p)
	for {
		real, err := filepath.EvalSymlinks(dir)
		if err == nil {
			rel, err := filepath.Rel(realHome, real)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return ErrOutsideHome
			}
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		up := filepath.Dir(dir)
		if up == dir {
			return nil
		}
		dir = up
	}
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

// dirMode is the mode for directories apply creates on the way to dst:
// 0700 under a private directory (.ssh, .gnupg), else 0755.
func (e *Engine) dirMode(dst string) fs.FileMode {
	if rel, err := filepath.Rel(e.Home, dst); err == nil && privateTarget(model.Target(filepath.ToSlash(rel))) {
		return 0o700
	}
	return 0o755
}

// writeAtomic writes b to dst through a temp file in the same directory and a
// rename, so a reader or a crash sees either the old bytes or the new ones.
// The temp file is created 0600 and gets its final mode before the rename.
// guard, if set, runs just before the rename and aborts it with its error.
func (e *Engine) writeAtomic(dst string, b []byte, mode fs.FileMode, guard func() error) error {
	if err := InsideHome(e.Home, dst); err != nil {
		return err
	}
	dir, base := filepath.Split(dst)
	if err := os.MkdirAll(dir, e.dirMode(dst)); err != nil {
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
	if guard != nil {
		if err := guard(); err != nil {
			return err
		}
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

// backupTimeFormat names one backup set.
const backupTimeFormat = "20060102T150405.000000000Z"

// enclaveBackupDir holds the backup sets of files that carry enclave
// plaintext: backup/enclave/<enclaves>/<time>/<target>, where <enclaves> is
// the enclave names joined by "+" (an enclave name never holds "+").
const enclaveBackupDir = "enclave"

// regionMarker finds the enclave of each region marker in target bytes.
var regionMarker = regexp.MustCompile(`yadm:seal ([A-Za-z0-9][A-Za-z0-9._-]*)`)

// backupEnclaves lists the enclaves whose plaintext the bytes b of a target
// with protection p may hold: its whole-file enclave, its seal enclaves and
// the enclaves its region markers name.
func backupEnclaves(p protection, b []byte) []model.EnclaveName {
	set := map[model.EnclaveName]bool{}
	if p.Enclave != "" {
		set[p.Enclave] = true
	}
	for _, e := range p.Seal {
		if e != "" {
			set[e] = true
		}
	}
	if p.Regions {
		for _, m := range regionMarker.FindAllSubmatch(b, -1) {
			set[model.EnclaveName(m[1])] = true
		}
	}
	out := make([]model.EnclaveName, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// union merges two protections, keeping everything either one seals.
func union(a, b protection) protection {
	out := protection{Enclave: a.Enclave, Regions: a.Regions || b.Regions, Seal: map[string]model.EnclaveName{}}
	if out.Enclave == "" {
		out.Enclave = b.Enclave
	}
	for k, v := range a.Seal {
		out.Seal[k] = v
	}
	for k, v := range b.Seal {
		if out.Seal[k] == "" {
			out.Seal[k] = v
		}
	}
	return out
}

// backup copies the bytes apply is about to replace or delete, mode 0600:
// to backup/<time>/<target>, or, when the bytes may hold enclave plaintext
// (see backupEnclaves), to backup/enclave/<enclaves>/<time>/<target>, so
// pruneBackups can drop them when this machine leaves an enclave.
//
// Bytes that may hold plaintext of an on-demand enclave are never backed
// up. written is the hash apply last wrote (or, for a union merge, the
// live hash, whose lines the merge keeps): bytes equal to it are
// reproducible from the source, so they are replaced without a backup.
// Other such bytes are not replaced at all: backup refuses, so no edit is
// lost silently.
func (e *Engine) backup(now time.Time, t model.Target, p protection, b []byte, written string) error {
	if e.StateDir == "" {
		return errors.New("apply: StateDir is not set; refusing to replace a file without a backup")
	}
	dir := e.backupDir()
	if encs := backupEnclaves(p, b); len(encs) > 0 {
		names := make([]string, len(encs))
		for i, x := range encs {
			if slices.Contains(e.OnDemand, x) {
				if written != "" && hashOf(b) == written {
					return nil
				}
				return fmt.Errorf("%s: may hold plaintext of %s, which is on demand here and never backed up, and differs from what yadm wrote; move it aside first", t, x)
			}
			names[i] = string(x)
		}
		dir = filepath.Join(dir, enclaveBackupDir, strings.Join(names, "+"))
	}
	f := filepath.Join(dir, now.UTC().Format(backupTimeFormat), filepath.FromSlash(string(t)))
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return err
	}
	return os.WriteFile(f, b, 0o600)
}

// pruneBackups removes backup sets older than BackupRetention, and every
// backup that holds plaintext of an enclave whose verified key log no
// longer lists this machine or that this machine reads on demand only
// (onDemand). A refused log prunes nothing, so a pusher cannot wipe backups
// with one bad entry.
func (e *Engine) pruneBackups(now time.Time, loads map[model.EnclaveName]crypt.EnclaveLoad, onDemand map[model.EnclaveName]bool) {
	if e.StateDir == "" {
		return
	}
	pruneSets(e.backupDir(), now)
	encDir := filepath.Join(e.backupDir(), enclaveBackupDir)
	groups, err := os.ReadDir(encDir)
	if err != nil {
		return
	}
	for _, g := range groups {
		gone := false
		for _, name := range strings.Split(g.Name(), "+") {
			if l, ok := loads[model.EnclaveName(name)]; ok && l.Err == nil && !l.Member {
				gone = true
			}
			if onDemand[model.EnclaveName(name)] {
				gone = true
			}
		}
		if gone {
			_ = os.RemoveAll(filepath.Join(encDir, g.Name()))
			continue
		}
		pruneSets(filepath.Join(encDir, g.Name()), now)
	}
}

// pruneSets removes the backup sets in dir older than BackupRetention.
func pruneSets(dir string, now time.Time) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, d := range ents {
		ts, err := time.Parse(backupTimeFormat, d.Name())
		if err != nil {
			continue
		}
		if now.Sub(ts) > BackupRetention {
			_ = os.RemoveAll(filepath.Join(dir, d.Name()))
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
	if st.Baseline == nil {
		st.Baseline = map[model.Target]time.Time{}
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
