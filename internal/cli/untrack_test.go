package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

type untrackData struct {
	Target, Source, Scope, Commit string
	SourceKept                    bool `json:"source_kept"`
	Pushed                        bool
}

// TestUntrack: untrack removes an entry and its source in one pushed
// commit and leaves the file on disk with no hold or drift, even inside an
// owned root, where the timer then leaves it alone. The peer removes its
// unchanged copy. It refuses a glob's file, a root's file and an unknown
// path, and --dry-run commits nothing.
func TestUntrack(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = hookManifest + `
[[file]]
target = ".config/kit/**"
`
	tree["files/.config/kit/one"] = "one\n"
	remote := seedRemote(t, root, tree)
	b := hookMachine(t, root, remote, "b", "host-b")
	a := hookMachine(t, root, remote, "a", "host-a")
	const cfg = ".config/tool/config"
	head := git(t, a.Source, "rev-parse", "main")

	writeFile(t, filepath.Join(a.Home, ".config/tool/new"), "n\n")
	for _, x := range []struct {
		args []string
		msg  string
	}{
		{[]string{"untrack", ".config/kit/one"}, `glob entry ".config/kit/**" covers it`},
		{[]string{"untrack", ".config/tool/new"}, `owned root ".config/tool" covers it`},
		{[]string{"untrack", ".nothing"}, "no manifest entry names it"},
		{[]string{"untrack", "files/.nothing"}, "no manifest entry reads files/.nothing"},
	} {
		env, code, _ := yadm(t, x.args...)
		if code != ExitUsage || env.Error == nil || !strings.Contains(env.Error.Message, x.msg) {
			t.Errorf("yadm %v: exit %d %+v; want exit 2 with %q", x.args, code, env.Error, x.msg)
		}
	}
	env := yadmOK(t, "untrack", cfg, "--dry-run")
	if d := decode[untrackData](t, env.Data); d.Commit != "" || d.Source != "files/"+cfg || d.SourceKept {
		t.Fatalf("dry run: %+v", d)
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatal("a refused or dry-run untrack committed")
	}
	if err := os.Remove(filepath.Join(a.Home, ".config/tool/new")); err != nil {
		t.Fatal(err)
	}

	env = yadmOK(t, "untrack", cfg)
	d := decode[untrackData](t, env.Data)
	if d.Commit == "" || !d.Pushed || d.Target != cfg || d.Scope != "shared" {
		t.Fatalf("untrack: %+v", d)
	}
	if subj := git(t, a.Source, "log", "-1", "--format=%s", "main"); subj != "untrack "+cfg {
		t.Fatalf("subject %q", subj)
	}
	if files := git(t, remote, "show", "--name-status", "--format=", "main"); files != "D\tfiles/"+cfg+"\nM\tmanifest.toml" {
		t.Fatalf("commit files: %q", files)
	}
	if man := git(t, remote, "show", "main:manifest.toml"); strings.Contains(man, `"`+cfg+`"`) || !strings.Contains(man, ".config/tool/work-only") {
		t.Fatalf("manifest:\n%s", man)
	}
	if got := readFile(t, filepath.Join(a.Home, cfg)); got != "color = blue\n" {
		t.Fatalf("the file did not stay: %q", got)
	}
	assertClean(t)
	// The timer finds the file in the owned root and leaves it alone.
	after := git(t, a.Source, "rev-parse", "main")
	yadmOK(t, "sync", "--auto", "--full")
	if got := git(t, a.Source, "rev-parse", "main"); got != after {
		t.Fatalf("the timer committed the untracked file:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}
	assertClean(t)
	if m := decode[struct{ Managed bool }](t, yadmOK(t, "managed", cfg).Data); m.Managed {
		t.Fatal("the untracked file is still managed")
	}

	useMachine(t, root, "b")
	yadmOK(t, "sync")
	if _, err := os.Stat(filepath.Join(b.Home, cfg)); !os.IsNotExist(err) {
		t.Fatalf("the peer kept its unchanged copy: %v", err)
	}
	assertClean(t)
}

// TestUntrackVariant: untrack picks one entry of a target by --source, or
// by naming the source path itself. A variant that does not apply here
// leaves this machine's file managed; the one that applies leaves it on
// disk, unmanaged. A source another entry reads stays.
func TestUntrackVariant(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := variantTree()
	tree["manifest.toml"] = variantManifest + `
[[file]]
target = ".profile-alias"
source = "files/.profile-work"
when = "type:work"
`
	remote := seedRemote(t, root, tree)
	a := kitMachine(t, root, remote, "a", "host-a")
	const osh = ".config/os.sh"

	if env, code, _ := yadm(t, "untrack", osh); code != ExitUsage || !strings.Contains(env.Error.Message, "--source") {
		t.Fatalf("untrack without --source: exit %d %+v", code, env.Error)
	}
	env := yadmOK(t, "untrack", osh, "--source", "files/.config/os-darwin.sh")
	if d := decode[untrackData](t, env.Data); d.Commit == "" || d.Source != "files/.config/os-darwin.sh" {
		t.Fatalf("untrack the darwin variant: %+v", d)
	}
	if m := decode[struct{ Managed bool }](t, yadmOK(t, "managed", osh).Data); !m.Managed {
		t.Fatal("the linux variant stopped being managed here")
	}
	assertClean(t)

	env = yadmOK(t, "untrack", "files/.config/os-linux.sh")
	if d := decode[untrackData](t, env.Data); d.Commit == "" || d.Target != osh {
		t.Fatalf("untrack by source: %+v", d)
	}
	if got := readFile(t, filepath.Join(a.Home, osh)); got != "linux\n" {
		t.Fatalf("the file did not stay: %q", got)
	}
	if m := decode[struct{ Managed bool }](t, yadmOK(t, "managed", osh).Data); m.Managed {
		t.Fatal("the untracked file is still managed")
	}
	assertClean(t)
	if man := git(t, remote, "show", "main:manifest.toml"); strings.Contains(man, `".config/os.sh"`) || strings.Contains(man, "per-system") || !strings.Contains(man, "target = \".profile\"") {
		t.Fatalf("manifest:\n%s", man)
	}

	// A source another entry reads stays.
	env = yadmOK(t, "untrack", ".profile-alias")
	if d := decode[untrackData](t, env.Data); !d.SourceKept {
		t.Fatalf("untrack a shared source: %+v", d)
	}
	if out := git(t, remote, "ls-tree", "--name-only", "main", "files/.profile-work"); out != "files/.profile-work" {
		t.Fatalf("the shared source went: %q", out)
	}
	assertClean(t)
}

// TestUntrackSealedSecrecy: a member untracks a whole sealed file that sits
// in a plain owned root: the entry and the ciphertext go, the member keeps
// its file unmanaged and ignored, so neither the timer nor an unnamed
// commit captures its plaintext into the plain root, and no plaintext
// reaches a repository, the state directory or the non-member. A
// non-member cannot untrack an enclave's entry (exit 6).
func TestUntrackSealedSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	man := filepath.Join(fx.Root, "manifest.toml")
	writeFile(t, man, readFile(t, man)+"\n[[root]]\npath = \".config/notes\"\n")
	remote := fixtureRemote(t, root, fx)
	canaries := fx.AllCanaries()
	const private = ".config/notes/private.md"

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	head := git(t, b.Source, "rev-parse", "main")
	for _, p := range []string{".config/client-tool/token", private, ".ssh/config"} {
		if env, code, _ := yadm(t, "untrack", p); code != ExitRefused {
			t.Errorf("non-member untrack %s: exit %d %+v", p, code, env.Error)
		}
	}
	if git(t, b.Source, "rev-parse", "main") != head {
		t.Fatal("a refused untrack committed")
	}

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/notes")
	want := readFile(t, filepath.Join(a.Home, private))
	env, code, out := yadm(t, "untrack", private)
	if code != ExitOK {
		t.Fatalf("untrack: exit %d %+v", code, env.Error)
	}
	if d := decode[untrackData](t, env.Data); d.Scope != "personal" || d.Source != "sealed/personal/"+private {
		t.Fatalf("untrack: %+v", d)
	}
	for _, c := range canaries {
		if strings.Contains(string(out), c.String()) {
			t.Fatalf("untrack printed %s plaintext", c.Label)
		}
	}
	if got := readFile(t, filepath.Join(a.Home, private)); got != want {
		t.Fatalf("the member's file changed: %q", got)
	}
	assertCleanOn(t, private)
	if tree := git(t, remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(tree, "sealed/personal/"+private) {
		t.Fatalf("the sealed source stayed:\n%s", tree)
	}
	// The plain root around the file never captures it.
	after := git(t, a.Source, "rev-parse", "main")
	yadmOK(t, "sync", "--auto", "--full")
	yadmOK(t, "commit")
	if got := git(t, a.Source, "rev-parse", "main"); got != after {
		t.Fatalf("the untracked file was committed again:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}
	assertCleanOn(t, private)
	secrecytest.AssertTreeClean(t, a.State, canaries...)

	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)
}
