package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

type moveData struct {
	From, To, Scope, Commit string
	Targets                 []string
	Pushed                  bool
}

// TestSourceMove: `yadm source mv` renames a plain source and points its
// entry's source line at the new path in one pushed commit, keeping the
// line's comment; a move to the default path drops the line. It refuses a
// scope change, an existing or claimed destination, a source no entry
// reads and a glob's source, committing nothing; --dry-run commits nothing.
func TestSourceMove(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := variantTree()
	tree["manifest.toml"] = variantManifest + `
[[file]]
target = ".config/kit/**"
`
	tree["files/.config/kit/one"] = "one\n"
	remote := seedRemote(t, root, tree)
	a := kitMachine(t, root, remote, "a", "host-a")
	head := git(t, a.Source, "rev-parse", "main")

	for _, x := range []struct {
		args []string
		msg  string
	}{
		{[]string{"source", "mv", "files/.config/os-linux.sh", "sealed/home/.config/os-linux.sh"}, "use yadm retag"},
		{[]string{"source", "mv", "files/.config/os-linux.sh", "files/.profile-home"}, "already exists"},
		{[]string{"source", "mv", "files/.config/os-linux.sh", "files/.config/kit/two"}, `entry ".config/kit/**" would read`},
		{[]string{"source", "mv", "files/.config/nope", "files/.config/nope2"}, "not in the source tree"},
		{[]string{"source", "mv", "files/.config/kit/one", "files/.config/one"}, "glob entry"},
		{[]string{"source", "mv", "files/.config/os-linux.sh", "files/.config/os-linux.sh"}, "the same"},
		{[]string{"source", "mv", "files/../x", "files/y"}, "not a clean path"},
		{[]string{"source", "mv", "manifest.toml", "files/manifest.toml"}, "not under files/"},
	} {
		env, code, _ := yadm(t, x.args...)
		if code != ExitUsage || env.Error == nil || !strings.Contains(env.Error.Message, x.msg) {
			t.Errorf("yadm %v: exit %d %+v; want exit 2 with %q", x.args, code, env.Error, x.msg)
		}
	}
	env := yadmOK(t, "source", "mv", "files/.config/os-darwin.sh", "files/.config/os/darwin.sh", "--dry-run")
	if d := decode[moveData](t, env.Data); d.Commit != "" || strings.Join(d.Targets, ",") != ".config/os.sh" {
		t.Fatalf("dry run: %+v", d)
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatalf("a refused or dry-run move committed:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}

	// A variant that does not apply here: only the source line changes.
	env = yadmOK(t, "source", "mv", "files/.config/os-darwin.sh", "files/.config/os/darwin.sh")
	d := decode[moveData](t, env.Data)
	if d.Commit == "" || !d.Pushed || d.Scope != "shared" {
		t.Fatalf("move: %+v", d)
	}
	if subj := git(t, a.Source, "log", "-1", "--format=%s", "main"); subj != "move files/.config/os-darwin.sh to files/.config/os/darwin.sh" {
		t.Fatalf("subject %q", subj)
	}
	if files := git(t, remote, "show", "--name-status", "--no-renames", "--format=", "main"); files != "D\tfiles/.config/os-darwin.sh\nA\tfiles/.config/os/darwin.sh\nM\tmanifest.toml" {
		t.Fatalf("commit files: %q", files)
	}
	man := git(t, remote, "show", "main:manifest.toml")
	if !strings.Contains(man, "source = \"files/.config/os/darwin.sh\"   # the mac one\nwhen = \"type:work & os:darwin\"") {
		t.Fatalf("manifest:\n%s", man)
	}

	// The variant that applies here: the target stays as it is.
	yadmOK(t, "source", "mv", "files/.config/os-linux.sh", "files/.config/os/linux.sh")
	if got := readFile(t, filepath.Join(a.Home, ".config/os.sh")); got != "linux\n" {
		t.Fatalf(".config/os.sh: %q", got)
	}
	assertClean(t)

	// To a custom path and back: the default path needs no source line.
	before := git(t, remote, "show", "main:manifest.toml")
	yadmOK(t, "source", "mv", "files/.config/tool/config", "files/.config/tool/config.toml")
	if man := git(t, remote, "show", "main:manifest.toml"); !strings.Contains(man, "target = \".config/tool/config\"\nsource = \"files/.config/tool/config.toml\"\n") {
		t.Fatalf("manifest after move away:\n%s", man)
	}
	assertClean(t)
	yadmOK(t, "source", "mv", "files/.config/tool/config.toml", "files/.config/tool/config")
	if man := git(t, remote, "show", "main:manifest.toml"); man != before {
		t.Fatalf("manifest after move back:\n%s\nwant:\n%s", man, before)
	}
	assertClean(t)
	if out, _, code := yadmRaw(t, "git", "status", "--porcelain"); code != 0 || out != "" {
		t.Fatalf("the clone is not clean: exit %d %q", code, out)
	}
}

// TestSourceMoveSecrecy: a member renames a whole sealed file, a file with
// a sealed region and a file with a sealed value. Each is opened under the
// old path and sealed under the new one in memory: no plaintext reaches a
// repository, the temp directory or a non-member, the member's targets keep
// their bytes, and a non-member's move of any of them is refused (exit 6).
func TestSourceMoveSecrecy(t *testing.T) {
	hermetic(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canaries := fx.AllCanaries()
	const (
		private  = ".config/notes/private.md"
		sshCfg   = ".ssh/config"
		settings = ".config/editor/settings.json"
	)

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	want := map[string]string{}
	for _, p := range []string{private, sshCfg, settings} {
		want[p] = readFile(t, filepath.Join(a.Home, p))
	}
	// The member must see canary plaintext, or this test proves nothing.
	found := false
	for _, c := range canaries {
		found = found || strings.Contains(want[private]+want[sshCfg]+want[settings], c.String())
	}
	if !found {
		t.Fatal("the member's targets hold no canary")
	}

	moves := [][2]string{
		{"sealed/personal/" + private, "sealed/personal/.config/notes/moved.md"},
		{"files/" + sshCfg, "files/.ssh/config.shared"},
		{"files/" + settings, "files/.config/editor/settings.jsonc"},
	}
	for _, mv := range moves {
		env, code, out := yadm(t, "source", "mv", mv[0], mv[1])
		if code != ExitOK {
			t.Fatalf("source mv %s: exit %d %+v", mv[0], code, env.Error)
		}
		for _, c := range canaries {
			if strings.Contains(string(out), c.String()) {
				t.Fatalf("source mv printed %s plaintext", c.Label)
			}
		}
	}
	if tree := git(t, remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(tree, "sealed/personal/"+private) || !strings.Contains(tree, "sealed/personal/.config/notes/moved.md") {
		t.Fatalf("tree after the moves:\n%s", tree)
	}
	// The member's targets keep their bytes and nothing drifts.
	for p, w := range want {
		if got := readFile(t, filepath.Join(a.Home, p)); got != w {
			t.Fatalf("%s changed on the member: %q", p, got)
		}
	}
	yadmOK(t, "apply")
	assertCleanOn(t, private, sshCfg, settings)
	// A fresh clone of the member writes the same bytes from the moved
	// sources: they open under their new paths.
	a2 := fixtureMachine(t, t.TempDir(), remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	for p, w := range want {
		if got := readFile(t, filepath.Join(a2.Home, p)); got != w {
			t.Fatalf("%s from the moved source: %q, want %q", p, got, w)
		}
	}

	// The non-member cannot move any of them.
	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	assertCleanOn(t, sshCfg, settings)
	for _, mv := range [][2]string{
		{"sealed/personal/.config/notes/moved.md", "sealed/personal/.config/notes/x.md"},
		{"files/.ssh/config.shared", "files/.ssh/config.x"},
		{"files/.config/editor/settings.jsonc", "files/.config/editor/settings.x"},
	} {
		env, code, _ := yadm(t, "source", "mv", mv[0], mv[1])
		if code != ExitRefused {
			t.Errorf("non-member source mv %s: exit %d %+v; want %d", mv[0], code, env.Error, ExitRefused)
		}
	}
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertTreeClean(t, tmp, canaries...)
	secrecytest.AssertTreeClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)
}
