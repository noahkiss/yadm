package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/schedule"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
	"github.com/noahkiss/yadm/internal/tasks"
)

// hooks are the process-wide collaborators tests replace.
var hooks = struct {
	scheduler func() (schedule.Scheduler, error)
	now       func() time.Time
	exec      func() extexec.Runner
	units     func() tasks.UnitReloader
	binary    func() string
}{
	scheduler: func() (schedule.Scheduler, error) { return schedule.ForOS(runtime.GOOS) },
	now:       time.Now,
	exec:      extexec.NewRunner,
	units: func() tasks.UnitReloader {
		u, err := tasks.SystemReloader(runtime.GOOS)
		if err != nil {
			return nil
		}
		return u
	},
	binary: func() string {
		p, err := os.Executable()
		if err != nil {
			return "yadm"
		}
		return p
	},
}

// errNotInitialized means this machine has no machine.toml or source clone.
var errNotInitialized = errors.New("this machine is not set up: no machine.toml or source clone")

// machineEnv is everything a command that works on this machine needs.
type machineEnv struct {
	paths Paths
	home  string
	user  string
	local fleet.Identity  // machine.toml
	id    *crypt.Identity // nil when no identity exists yet
	repo  *store.Repo
	eng   *apply.Engine
	exec  extexec.Runner
	allow tasks.AllowList
	snap  *apply.Snapshot // set by load
}

func homeAndUser() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	name := os.Getenv("USER")
	if name == "" {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}
	return home, name, nil
}

func identityPath(p Paths) string { return filepath.Join(p.Config, fleet.IdentityFile) }

// open loads machine.toml, the identity and the source clone. It does not
// read the source; load does.
func open(ctx context.Context) (*machineEnv, error) {
	p, err := DefaultPaths()
	if err != nil {
		return nil, err
	}
	home, usr, err := homeAndUser()
	if err != nil {
		return nil, err
	}
	local, err := fleet.LoadIdentity(identityPath(p))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errNotInitialized
		}
		return nil, err
	}
	id, err := crypt.LoadIdentity(p.State)
	switch {
	case err == nil:
		if id.Machine != local.Machine {
			return nil, fmt.Errorf("%w: identity keys belong to %s, machine.toml names %s", ErrRefused, id.Machine, local.Machine)
		}
	case errors.Is(err, fs.ErrNotExist):
		id = nil
	default:
		return nil, fmt.Errorf("%w: identity: %v", ErrRefused, err)
	}
	if _, err := os.Stat(filepath.Join(p.Source, ".git")); err != nil {
		return nil, errNotInitialized
	}
	repo, err := store.Open(p.Source, p.State)
	if err != nil {
		return nil, err
	}
	ex := hooks.exec()
	allow := tasks.FileAllowList(p.State)
	m := &machineEnv{paths: p, home: home, user: usr, local: local, id: id, repo: repo, exec: ex, allow: allow}
	m.eng = apply.New(apply.Deps{
		Store:    repo,
		Self:     local.Machine,
		Identity: id,
		Pins:     crypt.FilePins(p.State),
		State:    apply.FileStateDB(p.State),
		Home:     home,
		User:     usr,
		StateDir: p.State,
		Tasks:    &tasks.Runner{Exec: ex, Allow: allow, Units: hooks.units()},
		Now:      hooks.now,
	})
	return m, nil
}

// openLoaded opens and loads the snapshot at main.
func openLoaded(ctx context.Context) (*machineEnv, error) {
	m, err := open(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := m.load(ctx); err != nil {
		return m, err
	}
	return m, nil
}

// head is local main, or "" when main is unborn.
func (m *machineEnv) head(ctx context.Context) (model.CommitID, error) {
	return m.repo.ResolveRef(ctx, store.RefMain)
}

// load reads the snapshot at local main.
func (m *machineEnv) load(ctx context.Context) (*apply.Snapshot, error) {
	if m.snap != nil {
		return m.snap, nil
	}
	h, err := m.head(ctx)
	if err != nil {
		return nil, err
	}
	if h == "" {
		return nil, errors.New("the source has no commits on main yet")
	}
	s, err := m.eng.Load(ctx, h)
	if err != nil {
		return nil, err
	}
	m.snap = s
	return s, nil
}

// request is the shared exec-contract context for this machine.
func (m *machineEnv) request(kind extexec.Kind, name string, asJSON bool) extexec.Request {
	req := extexec.Request{Schema: extexec.Schema, Kind: kind, Name: name, Home: m.home, Source: m.paths.Source, JSON: asJSON}
	if m.snap != nil {
		req.Machine = m.snap.Context.Machine
		req.Commit = m.snap.Commit
	} else {
		req.Machine = model.Machine{ID: m.local.Machine}
	}
	return req
}

// policy is the auto-commit policy from the manifest.
func policy(s *apply.Snapshot) sync.Policy {
	p := sync.Policy{Quiet: sync.DefaultQuiet, MassChange: sync.DefaultMassChange, Protected: append([]string(nil), manifest.BuiltinProtected...)}
	if s != nil && s.Manifest != nil {
		if q := s.Manifest.Defaults.Quiet.D(); q > 0 {
			p.Quiet = q
		}
		p.Protected = append(p.Protected, s.Manifest.Protected...)
	}
	return p
}

// syncer wires a sync.Syncer. The snapshot may be nil when the source does
// not load; the syncer then reports its own error.
func (m *machineEnv) syncer(version string) *sync.Syncer {
	d := sync.Deps{
		Store:    m.repo,
		Apply:    m.eng,
		Status:   store.StatusRefs(m.repo, m.local.Machine),
		Exec:     m.exec,
		Identity: m.local,
		Lock:     sync.FileLock(m.paths.State),
		Leases:   sync.FileLeases(m.paths.State),
		Policy:   policy(m.snap),
		Version:  version,
		Now:      hooks.now,
	}
	var checks map[string]manifest.CheckDef
	if m.snap != nil {
		d.Fleet = m.snap.Fleet
		d.Keys = m.snap.Keys
		if m.snap.Plan != nil {
			checks = m.snap.Plan.Checks
		}
	}
	d.Gate = tasks.NewGateIn(checks, m.exec, m.allow, m.paths.State)
	return &sync.Syncer{Deps: d}
}

// selfStatus is this machine's last published status record, or nil.
func (m *machineEnv) selfStatus(ctx context.Context) *model.Status {
	all, err := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	if err != nil {
		return nil
	}
	if s, ok := all[m.local.Machine]; ok {
		return &s
	}
	return nil
}

// commitDirect makes one manual, protected commit on main from pre-built
// changes (key-log entries, retag), moves main by compare-and-swap and moves
// the source worktree. It is for changes that never auto-commit and that
// sync.CommitOptions cannot carry.
func (m *machineEnv) commitDirect(ctx context.Context, changes []store.Change, subject string, scope model.Scope) (model.CommitID, error) {
	h, err := m.head(ctx)
	if err != nil {
		return "", err
	}
	msg := store.Message{Subject: subject, Trailers: []store.Trailer{
		{Key: store.TrailerMachine, Value: string(m.local.Machine)},
		{Key: store.TrailerScope, Value: string(scope)},
	}}
	id, err := m.repo.CommitPaths(ctx, h, changes, msg)
	if err != nil {
		return "", err
	}
	if err := m.repo.UpdateRef(ctx, store.RefMain, id, h); err != nil {
		return "", err
	}
	if err := m.repo.SyncWorktree(ctx, id); err != nil {
		return id, fmt.Errorf("committed %s but the source worktree did not move: %w", id, err)
	}
	return id, nil
}

// keyLogs reads every enclave's key-log entries at rev, in sequence order.
func (m *machineEnv) keyLogs(ctx context.Context, rev model.CommitID, enclaves []model.EnclaveName) (map[model.EnclaveName][]crypt.LogEntry, error) {
	out := map[model.EnclaveName][]crypt.LogEntry{}
	if rev == "" {
		return out, nil
	}
	tree, err := m.repo.ListTree(ctx, rev)
	if err != nil {
		return nil, err
	}
	sort.Slice(tree, func(i, j int) bool { return tree[i].Path < tree[j].Path })
	for _, enc := range enclaves {
		prefix := string(crypt.LogDir(enc)) + "/"
		for _, te := range tree {
			if !strings.HasPrefix(string(te.Path), prefix) || !strings.HasSuffix(string(te.Path), ".toml") {
				continue
			}
			b, err := m.repo.ReadBlob(ctx, te.Blob)
			if err != nil {
				return nil, err
			}
			le, err := crypt.ParseLogEntry(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", te.Path, err)
			}
			out[enc] = append(out[enc], le)
		}
	}
	return out, nil
}

// target converts a command-line path to a target relative to $HOME.
// An absolute path must be under $HOME; "~/x" is $HOME/x; any other relative
// path is already relative to $HOME.
func target(home, p string) (model.Target, error) {
	if p == "" {
		return "", usagef("empty path")
	}
	switch {
	case p == "~":
		return "", usagef("%q is $HOME itself, not a target", p)
	case strings.HasPrefix(p, "~/"):
		p = p[2:]
	case filepath.IsAbs(p):
		rel, err := filepath.Rel(home, p)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return "", usagef("%q is not under $HOME", p)
		}
		p = rel
	}
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "." || strings.HasPrefix(p, "../") || p == ".." {
		return "", usagef("%q is not under $HOME", p)
	}
	return model.Target(p), nil
}

func targets(home string, args []string) ([]model.Target, error) {
	var out []model.Target
	for _, a := range args {
		t, err := target(home, a)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// withHoldNext fills each hold's suggested commands when it has none.
func withHoldNext(hs []model.Hold) []model.Hold {
	out := make([]model.Hold, len(hs))
	for i, h := range hs {
		if h.ID == "" {
			h.ID = apply.HoldID(h)
		}
		if len(h.Next) == 0 {
			h.Next = []string{"yadm hold show " + h.ID}
			if h.Task != "" {
				h.Next = append(h.Next, "yadm task allow "+h.Task)
			} else {
				h.Next = append(h.Next, "yadm hold resolve "+h.ID+" --take source", "yadm hold resolve "+h.ID+" --take target")
			}
		}
		out[i] = h
	}
	if out == nil {
		out = []model.Hold{}
	}
	return out
}

// attention returns ErrAttention when holds exist.
func attention(hs []model.Hold) error {
	if len(hs) > 0 {
		return fmt.Errorf("%w: %d held", ErrAttention, len(hs))
	}
	return nil
}

// notInit adds the setup hint to a not-initialized error.
func notInit(err error) result {
	if errors.Is(err, errNotInitialized) {
		return result{next: []string{"yadm init <remote> --machine <name>", "yadm clone <remote> --machine <name>"}}
	}
	return result{}
}
