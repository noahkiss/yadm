package apply

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

// isolateGit keeps the user's git configuration and hooks out of the test.
func isolateGit(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	for k, v := range map[string]string{
		"HOME":                home,
		"XDG_CONFIG_HOME":     filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME":     "test",
		"GIT_AUTHOR_EMAIL":    "test@example.invalid",
		"GIT_COMMITTER_NAME":  "test",
		"GIT_COMMITTER_EMAIL": "test@example.invalid",
	} {
		t.Setenv(k, v)
	}
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// fixtureRepo builds the synthetic fixture as a git repository. The whole
// sealed personal file loses its `when`, so it is in every machine's plan
// and a non-member must decide not to deliver it.
func fixtureRepo(t *testing.T) *fixture.Fixture {
	t.Helper()
	isolateGit(t)
	f := fixture.Build(t)
	mp := filepath.Join(f.Root, "manifest.toml")
	b, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	old := "target = \".config/notes/private.md\"\nenclave = \"personal\"\nwhen = \"type:personal\"\n"
	if !bytes.Contains(b, []byte(old)) {
		t.Fatal("fixture manifest changed; update this test")
	}
	b = bytes.Replace(b, []byte(old), []byte("target = \".config/notes/private.md\"\nenclave = \"personal\"\n"), 1)
	if err := os.WriteFile(mp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, f.Root, "init", "-q", "-b", "main")
	gitIn(t, f.Root, "add", "-A")
	gitIn(t, f.Root, "commit", "-q", "-m", "fixture")
	return f
}

type machineRun struct {
	home, state string
	res         Result
	snap        *Snapshot
}

// runMachine loads, plans and applies the fixture for one machine with a
// fresh home and state directory. pinned writes the enclave pins first.
func runMachine(t *testing.T, f *fixture.Fixture, id model.MachineID, pinned bool) machineRun {
	t.Helper()
	ctx := context.Background()
	m := machineRun{home: t.TempDir(), state: t.TempDir()}
	if pinned {
		if err := f.PinAll(m.state); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := store.Open(f.Root, m.state)
	if err != nil {
		t.Fatal(err)
	}
	eng := New(Deps{
		Store:    repo,
		Self:     id,
		Identity: f.Identities[id],
		Pins:     crypt.FilePins(m.state),
		State:    FileStateDB(m.state),
		Home:     m.home,
		User:     "user",
		StateDir: m.state,
	})
	snap, err := eng.Load(ctx, "main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m.snap = snap
	plan, err := eng.Plan(ctx, snap.Commit)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if entries, _ := os.ReadDir(m.home); len(entries) != 0 {
		t.Fatal("Plan wrote into $HOME")
	}
	if m.res, err = eng.Apply(ctx, snap.Commit, ApplyOptions{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plan) != len(m.res.Actions) {
		t.Fatalf("plan has %d actions, apply %d", len(plan), len(m.res.Actions))
	}
	return m
}

func (m machineRun) read(t *testing.T, tg model.Target) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(m.home, filepath.FromSlash(string(tg))))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (m machineRun) mode(t *testing.T, tg model.Target) os.FileMode {
	t.Helper()
	info, err := os.Stat(filepath.Join(m.home, filepath.FromSlash(string(tg))))
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestIntegrationApplyMemberAndNonMember(t *testing.T) {
	f := fixtureRepo(t)
	personal := f.Canaries["personal"]
	all := f.AllCanaries()

	// host-a is the only personal member.
	a := runMachine(t, f, fixture.HostA, true)
	if !a.snap.canOpen("personal") || a.snap.canOpen("client") {
		t.Fatalf("host-a enclaves: %+v", a.snap.Enclaves)
	}
	if got := actionOf(a.res, ".config/notes/private.md"); got.Kind != ActWrite {
		t.Fatalf("member private.md: %+v", got)
	}
	if s := a.read(t, ".config/notes/private.md"); !strings.Contains(s, personal.String()) {
		t.Fatal("member did not get the sealed file's plaintext")
	}
	if s := a.read(t, ".config/editor/settings.json"); !strings.Contains(s, "sync-secret-"+personal.String()) {
		t.Fatal("member did not get the sealed value")
	}
	if s := a.read(t, ".ssh/config"); !strings.Contains(s, "Host private-box") || !strings.Contains(s, personal.String()) {
		t.Fatal("member did not get the sealed region")
	}
	if m := a.mode(t, ".config/notes/private.md"); m != 0o644 {
		t.Errorf("member sealed file mode %#o, want 0644 (follows the source)", m)
	}
	if m := a.mode(t, ".ssh/config"); m != 0o600 {
		t.Errorf(".ssh/config mode %#o", m)
	}
	if s := a.read(t, ".gitconfig"); !strings.Contains(s, "editor = editor-one") || !strings.Contains(s, a.home+"/.config/git/ignore") {
		t.Errorf("rendered .gitconfig: %q", s)
	}
	secrecytest.AssertTreeClean(t, a.home, f.Canaries["client"])
	secrecytest.AssertTreeClean(t, a.state, all...)

	// host-b is in no enclave; the sealed file is in its plan.
	b := runMachine(t, f, fixture.HostB, true)
	if got := actionOf(b.res, ".config/notes/private.md"); got.Kind != ActSealed {
		t.Fatalf("non-member private.md: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(b.home, ".config/notes/private.md")); err == nil {
		t.Fatal("non-member got the sealed file")
	}
	if s := b.read(t, ".config/editor/settings.json"); strings.Contains(s, `"token"`) || strings.Contains(s, "yadm:1:") {
		t.Fatalf("non-member settings carry the sealed key: %s", s)
	}
	if s := b.read(t, ".ssh/config"); !strings.Contains(s, "# yadm:seal personal hosts\n# yadm:end") {
		t.Fatalf("non-member region not empty: %s", s)
	}
	secrecytest.AssertTreeClean(t, b.home, all...)
	secrecytest.AssertTreeClean(t, b.state, all...)

	// host-a without its pins: listed, but refused, so it gets nothing sealed.
	u := runMachine(t, f, fixture.HostA, false)
	if got := actionOf(u.res, ".config/notes/private.md"); got.Kind != ActSealed {
		t.Fatalf("unpinned private.md: %+v", got)
	}
	secrecytest.AssertTreeClean(t, u.home, all...)
	secrecytest.AssertTreeClean(t, u.state, all...)

	secrecytest.AssertRepoClean(t, f.Root, all...)
}
