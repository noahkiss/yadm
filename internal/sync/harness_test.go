package sync

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
)

// TestMain isolates git from the user's configuration and $HOME.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "sync-home-")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{
		"HOME":                home,
		"XDG_CONFIG_HOME":     filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME":     "test",
		"GIT_AUTHOR_EMAIL":    "test@example.invalid",
		"GIT_COMMITTER_NAME":  "test",
		"GIT_COMMITTER_EMAIL": "test@example.invalid",
	} {
		os.Setenv(k, v)
	}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// clock is the fake clock every machine shares: real time plus an offset,
// so file mtimes and the quiet period agree.
type clock struct{ offset time.Duration }

func (c *clock) Now() time.Time { return time.Now().Add(c.offset) }

// fakeExec answers every external call. A check fails when fail returns true
// for the check and one of its staged targets.
type fakeExec struct {
	fail  func(check string, t model.Target) bool
	calls []extexec.Request
}

func (x *fakeExec) Run(_ context.Context, _ extexec.Spec, req extexec.Request) (extexec.Result, error) {
	x.calls = append(x.calls, req)
	switch req.Kind {
	case extexec.KindCheck:
		for _, t := range req.Changed {
			if x.fail != nil && x.fail(req.Name, t) {
				return extexec.Result{ExitCode: 1}, &checkErr{string(t)}
			}
		}
	case extexec.KindCollector:
		return extexec.Result{Items: []string{"tool-one", "tool-two"}}, nil
	}
	return extexec.Result{}, nil
}

type checkErr struct{ t string }

func (e *checkErr) Error() string { return "check failed on " + e.t }

type nopUnits struct{}

func (nopUnits) Reload(context.Context, manifest.Unit, string) error { return nil }

// world is a bare remote plus simulated machines, each with its own clone,
// $HOME and state directory.
type world struct {
	t        *testing.T
	f        *fixture.Fixture
	remote   string
	clock    *clock
	machines map[model.MachineID]*machine
}

type machine struct {
	w      *world
	id     model.MachineID
	home   string
	state  string
	repo   *store.Repo
	st     store.Store
	eng    *apply.Engine
	s      *Syncer
	exec   *fakeExec
	allows tasks.AllowList
}

// newWorld builds the fixture, lets edit change its source tree, commits it
// to a fresh bare remote and sets up the machines.
func newWorld(t *testing.T, edit func(f *fixture.Fixture), ids ...model.MachineID) *world {
	t.Helper()
	f := fixture.Build(t)
	if edit != nil {
		edit(f)
	}
	w := &world{t: t, f: f, clock: &clock{offset: 3 * time.Hour}, machines: map[model.MachineID]*machine{}}
	w.remote = filepath.Join(t.TempDir(), "remote.git")
	git(t, filepath.Dir(w.remote), "init", "-q", "--bare", "-b", "main", w.remote)
	git(t, f.Root, "init", "-q", "-b", "main")
	git(t, f.Root, "add", "-A")
	git(t, f.Root, "commit", "-q", "-m", "seed")
	git(t, f.Root, "push", "-q", w.remote, "main")
	for _, id := range ids {
		w.machines[id] = w.newMachine(id)
	}
	return w
}

func (w *world) newMachine(id model.MachineID) *machine {
	t := w.t
	ctx := context.Background()
	m := &machine{w: w, id: id, home: t.TempDir(), state: t.TempDir(), exec: &fakeExec{}}
	src := filepath.Join(t.TempDir(), "source")
	repo, err := store.Clone(ctx, w.remote, src, m.state)
	if err != nil {
		t.Fatal(err)
	}
	m.repo, m.st = repo, repo
	if err := w.f.PinAll(m.state); err != nil {
		t.Fatal(err)
	}
	m.allows = tasks.FileAllowList(m.state)
	w.allowAll(m)
	runner := &tasks.Runner{Exec: m.exec, Allow: m.allows, Units: nopUnits{}}
	m.eng = apply.New(apply.Deps{Store: repo, Self: id, Identity: w.f.Identities[id], Pins: crypt.FilePins(m.state),
		State: apply.FileStateDB(m.state), Home: m.home, User: "user", StateDir: m.state, Tasks: runner, Allow: m.allows, Now: w.clock.Now})
	if head := m.main(); head != "" {
		m.allowRoots(head)
	}
	m.s = &Syncer{Deps: Deps{Store: repo, Apply: m.eng, Status: store.StatusRefs(repo, id), Exec: m.exec,
		Identity: fleet.Identity{Machine: id, Notify: []string{"notify-hook"}}, Lock: FileLock(m.state), Leases: FileLeases(m.state),
		Version: "test", Now: w.clock.Now, Backoff: time.Millisecond}}
	return m
}

// allowAll allows every task, check and collector of the seed source.
func (w *world) allowAll(m *machine) {
	t := w.t
	mb, err := os.ReadFile(filepath.Join(w.f.Root, manifest.FileName))
	if err != nil {
		t.Fatal(err)
	}
	man, err := manifest.Parse(mb)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.ReadFile(filepath.Join(w.f.Root, fleet.FileName))
	if err != nil {
		t.Fatal(err)
	}
	fl, err := fleet.Parse(fb)
	if err != nil {
		t.Fatal(err)
	}
	allow := func(kind extexec.Kind, name string, def any) {
		h, err := tasks.DefinitionHash(def)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.allows.Allow(kind, name, h); err != nil {
			t.Fatal(err)
		}
	}
	for n, d := range man.Tasks {
		allow(extexec.KindTask, n, d)
	}
	for n, d := range man.Checks {
		allow(extexec.KindCheck, n, d)
	}
	for n, d := range fl.Collectors {
		allow(extexec.KindCollector, n, d)
	}
}

// allowRoots allows every owned root in m's plan at rev, as the owner does
// with `yadm root allow` on a machine they trust.
func (m *machine) allowRoots(rev model.CommitID) {
	t := m.w.t
	t.Helper()
	ctx := context.Background()
	snap, err := m.eng.Load(ctx, rev)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range snap.Plan.Roots {
		if err := m.eng.AllowRoot(ctx, rev, r.Path); err != nil {
			t.Fatal(err)
		}
	}
}

// pinnedAt returns a PinStore pinned at head, as the signer's machine has
// after it loaded the log up to head.
func pinnedAt(t *testing.T, head crypt.LogEntry) crypt.PinStore {
	t.Helper()
	p, err := crypt.PinOf(head)
	if err != nil {
		t.Fatal(err)
	}
	pins := crypt.MemPins()
	if err := pins.Set(head.Enclave, p); err != nil {
		t.Fatal(err)
	}
	return pins
}

func (m *machine) path(t model.Target) string {
	return filepath.Join(m.home, filepath.FromSlash(string(t)))
}

func (m *machine) read(t model.Target) string {
	m.w.t.Helper()
	b, err := os.ReadFile(m.path(t))
	if err != nil {
		m.w.t.Fatalf("%s: read %s: %v", m.id, t, err)
	}
	return string(b)
}

// write edits a target; the mtime moves back one second per call so stat
// checks always see a change.
func (m *machine) write(t model.Target, content string) {
	m.w.t.Helper()
	p := m.path(t)
	info, _ := os.Stat(p)
	mode := os.FileMode(0o644)
	if info != nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		m.w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		m.w.t.Fatal(err)
	}
}

func (m *machine) sync() Report {
	m.w.t.Helper()
	r, err := m.s.Run(context.Background(), Options{Auto: true, Push: true})
	if err != nil {
		m.w.t.Fatalf("%s: sync: %v", m.id, err)
	}
	return r
}

func (m *machine) main() model.CommitID {
	m.w.t.Helper()
	id, err := m.st.ResolveRef(context.Background(), store.RefMain)
	if err != nil {
		m.w.t.Fatal(err)
	}
	return id
}

func (w *world) remoteMain() string {
	return git(w.t, w.remote, "rev-parse", "main")
}

// remoteFile reads a path at the remote's main.
func (w *world) remoteFile(p string) string {
	return git(w.t, w.remote, "show", "main:"+p)
}

func holdsOf(r Report, reason model.HoldReason) []model.Hold {
	var out []model.Hold
	for _, h := range r.Holds {
		if h.Reason == reason {
			out = append(out, h)
		}
	}
	return out
}

func contains(ts []model.Target, t model.Target) bool {
	for _, x := range ts {
		if x == t {
			return true
		}
	}
	return false
}
