package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	gosync "sync"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/schedule"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
	"github.com/noahkiss/yadm/internal/tasks"
)

// forOSLive builds the scheduler behind the default hooks.scheduler. A test
// replaces it to see the arguments without a real service manager.
var forOSLive = schedule.ForOSLive

// hooks are the process-wide collaborators tests replace.
var hooks = struct {
	scheduler func() (schedule.Scheduler, error)
	now       func() time.Time
	exec      func() extexec.Runner
	units     func() tasks.UnitReloader
	binary    func() string
	nudge     func() []string // argv run after a push that moved main
	lockWait  time.Duration   // how long a command waits for the lock
	hookWait  time.Duration   // how long a harness hook waits for the lock
	stdin     func() io.Reader
}{
	// The CLI changes the real schedule: init, adopt and `schedule install`
	// need the live scheduler. Tests replace this hook.
	scheduler: func() (schedule.Scheduler, error) { return forOSLive(runtime.GOOS, true) },
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
	nudge: func() []string {
		if p, err := extexec.FindSubcommand("nudge"); err == nil {
			return []string{p}
		}
		return nil
	},
	lockWait: sync.LockTimeout,
	hookWait: 3 * time.Second,
	stdin:    func() io.Reader { return os.Stdin },
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

// openRepos are the source clones this command opened. mainWith closes
// them when the command finishes, which stops their batch readers.
var openRepos struct {
	gosync.Mutex
	list []*store.Repo
}

func trackRepo(r *store.Repo) {
	openRepos.Lock()
	defer openRepos.Unlock()
	openRepos.list = append(openRepos.list, r)
}

// closeRepos closes every repository trackRepo recorded.
func closeRepos() {
	openRepos.Lock()
	list := openRepos.list
	openRepos.list = nil
	openRepos.Unlock()
	for _, r := range list {
		_ = r.Close()
	}
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
	trackRepo(repo)
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
		Allow:    allow,
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

// reload reads the snapshot at local main again. A writer calls it once it
// holds the lock: a sync it waited for may have moved main.
func (m *machineEnv) reload(ctx context.Context) (*apply.Snapshot, error) {
	m.snap = nil
	return m.load(ctx)
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
		// A named-conditions include decides which machines get which
		// entries, as manifest.toml does: it never auto-commits.
		p.Protected = append(p.Protected, s.Manifest.Includes()...)
	}
	if s != nil && s.Plan != nil {
		plan := s.Plan
		p.MergeFor = func(t model.Target) sync.MergePolicy {
			if r, ok := plan.Targets[t]; ok {
				return sync.MergePolicy(r.Entry.Merge)
			}
			return ""
		}
		p.VolatileFor = func(t model.Target) []string {
			if r, ok := plan.Targets[t]; ok {
				return r.Entry.Volatile
			}
			return nil
		}
	}
	return p
}

// lock is the sync lock with the command's bounded wait.
func (m *machineEnv) lock(wait time.Duration) sync.Lock {
	if wait <= 0 {
		wait = hooks.lockWait
	}
	return sync.FileLockTimeout(m.paths.State, wait)
}

// locked runs fn under the sync lock, so apply, capture, collect and
// enclave writes never interleave with a sync or a commit.
func (m *machineEnv) locked(ctx context.Context, fn func() error) error {
	release, err := m.lock(0).Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	return fn()
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
		Lock:     m.lock(0),
		Leases:   sync.FileLeases(m.paths.State),
		Policy:   policy(m.snap),
		Version:  version,
		Now:      hooks.now,
		Nudge:    hooks.nudge(),

		Structural: rules.Structural{},
		Guard:      &apply.Guard{List: m.allow},
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

// commitThrough commits through sync.Commit (lock, gate, private index) and,
// with opts.Push, fetches, replays and pushes in the same call. A failure
// after the commit landed comes back as pushErr: the commit stands and the
// next sync pushes it.
func (m *machineEnv) commitThrough(ctx context.Context, version string, opts sync.CommitOptions) (rep sync.Report, pushErr, err error) {
	return m.hookCommit(ctx, version, opts, 0)
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

// landed returns the commit of rep that holds source path p, or an error
// that says the gate or a hold kept it out.
func (m *machineEnv) landed(ctx context.Context, rep sync.Report, p model.SourcePath) (model.CommitID, error) {
	for _, id := range rep.Committed {
		cs, err := m.repo.Log(ctx, string(id)+"^!", []model.SourcePath{p})
		if err == nil && len(cs) > 0 {
			return id, nil
		}
	}
	if len(rep.Holds) > 0 {
		return "", fmt.Errorf("%w: %s did not commit: %d held", ErrAttention, p, len(rep.Holds))
	}
	return "", fmt.Errorf("%s did not commit", p)
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
	if model.HasControl(p) {
		return "", usagef("%q: the path holds a control character", p)
	}
	if err := apply.InsideHome(home, filepath.Join(home, filepath.FromSlash(p))); err != nil {
		return "", usagef("%q is not under $HOME: %v", p, err)
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
				h.Next = append(h.Next, "yadm task allow "+model.ShellQuote(h.Task))
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
