package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
)

// variantFleet has two work machines on different systems and one home
// machine.
const variantFleet = `schema = 1

[types.work]

[types.home]

[machines.m-aaaaaa000001]
name = "host-a"
types = ["work"]
os = "linux"
arch = "amd64"

[machines.m-bbbbbb000002]
name = "host-b"
types = ["work"]
os = "darwin"
arch = "arm64"

[machines.m-cccccc000003]
name = "host-c"
types = ["home"]
os = "linux"
arch = "amd64"
`

const variantManifest = `schema = 1

[[file]]
target = ".config/tool/config"

# per-system shell setup
[[file]]
target = ".config/os.sh"
source = "files/.config/os-linux.sh"
when = "type:work & os:linux"

[[file]]
target = ".config/os.sh"
source = "files/.config/os-darwin.sh"   # the mac one
when = "type:work & os:darwin"

[[file]]
target = ".profile"
source = "files/.profile-work"
when = "type:work"

[[file]]
target = ".profile"
source = "files/.profile-home"
when = "type:home"

[[file]]
target = ".negated"
when = "!type:home"
`

func variantTree() map[string]string {
	return map[string]string{
		"fleet.toml":                 variantFleet,
		"manifest.toml":              variantManifest,
		"files/.config/tool/config":  "color = blue\n",
		"files/.config/os-linux.sh":  "linux\n",
		"files/.config/os-darwin.sh": "darwin\n",
		"files/.profile-work":        "work\n",
		"files/.profile-home":        "home\n",
		"files/.negated":             "n\n",
	}
}

type retagData struct {
	Commit    string   `json:"commit"`
	RemovedOn []string `json:"removed_on"`
	Source    string   `json:"source"`
	When      string   `json:"when"`
}

// TestRetagVariant: retag picks one of several entries for a target with
// --source, keeps the non-type terms of its when, and commits through the
// normal path even when the variant does not apply on this machine. It
// refuses an ambiguous target, a when it cannot rewrite faithfully and an
// edit that makes two variants apply on one machine, committing nothing.
func TestRetagVariant(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, variantTree())
	c := kitMachine(t, root, remote, "c", "host-c")
	a := kitMachine(t, root, remote, "a", "host-a")
	head := git(t, a.Source, "rev-parse", "main")

	for _, x := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"retag", ".config/os.sh", "home"}, ExitUsage, "--source"},
		{[]string{"retag", ".config/os.sh", "home"}, ExitUsage, "files/.config/os-darwin.sh"},
		{[]string{"retag", ".config/os.sh", "home", "--source", "files/.config/nope.sh"}, ExitError, "no manifest entry for it reads files/.config/nope.sh"},
		{[]string{"retag", ".negated", "work"}, ExitUsage, "cannot replace the type terms"},
		{[]string{"retag", ".profile", "home", "--source", "files/.profile-work"}, ExitError, "host-c would get .profile from more than one entry"},
		{[]string{"retag", ".config/os.sh", "home", "--source", "files/.config/os-darwin.sh", "--enclave", "work"}, ExitError, "not an enclave type"},
	} {
		env, code, _ := yadm(t, x.args...)
		if code != x.code || env.Error == nil || !strings.Contains(env.Error.Message, x.msg) {
			t.Errorf("yadm %v: exit %d %+v; want exit %d with %q", x.args, code, env.Error, x.code, x.msg)
		}
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatalf("a refused retag committed:\n%s", git(t, a.Source, "show", "main"))
	}

	// The darwin variant does not apply on host-a: it commits as a source
	// change, keeps os:darwin and the comments, and host-b loses the file.
	env, code, _ := yadm(t, "retag", ".config/os.sh", "home", "--source", "files/.config/os-darwin.sh")
	if code != ExitOK {
		t.Fatalf("retag the darwin variant: exit %d %+v", code, env.Error)
	}
	d := decode[retagData](t, env.Data)
	if d.Commit == "" || d.When != "type:home & os:darwin" || d.Source != "files/.config/os-darwin.sh" || strings.Join(d.RemovedOn, ",") != "m-bbbbbb000002" {
		t.Fatalf("retag data: %+v", d)
	}
	man := git(t, remote, "show", "main:manifest.toml")
	want := strings.Replace(variantManifest, `source = "files/.config/os-darwin.sh"   # the mac one
when = "type:work & os:darwin"`, `source = "files/.config/os-darwin.sh"   # the mac one
when = "type:home & os:darwin"`, 1)
	if man != strings.TrimSpace(want) {
		t.Fatalf("manifest after retag:\n%s", man)
	}
	if files := git(t, a.Source, "show", "--name-only", "--format=", "main"); files != "manifest.toml" {
		t.Fatalf("retag commit files: %q", files)
	}
	if got := readFile(t, filepath.Join(a.Home, ".config/os.sh")); got != "linux\n" {
		t.Fatalf("host-a .config/os.sh: %q", got)
	}
	assertClean(t)

	// The linux variant applies here: its when widens to home, keeping
	// os:linux, and host-c receives it on its next sync.
	env = yadmOK(t, "retag", ".config/os.sh", "work,home", "--source", "files/.config/os-linux.sh")
	if d := decode[retagData](t, env.Data); d.When != "(type:work | type:home) & os:linux" || len(d.RemovedOn) != 0 || d.Commit == "" {
		t.Fatalf("retag the linux variant: %+v", d)
	}
	assertClean(t)
	useMachine(t, root, "c")
	yadmOK(t, "sync")
	if got := readFile(t, filepath.Join(c.Home, ".config/os.sh")); got != "linux\n" {
		t.Fatalf("host-c .config/os.sh: %q", got)
	}
}

// assertCleanOn fails when the current machine has drift or a hold on one
// of targets.
func assertCleanOn(t *testing.T, targets ...string) {
	t.Helper()
	st := decode[struct {
		Drift []struct{ Target string }
		Holds []struct{ Target string }
	}](t, yadmOK(t, "status").Data)
	for _, x := range append(st.Drift, st.Holds...) {
		for _, p := range targets {
			if x.Target == p {
				t.Fatalf("status names %s: %+v", p, st)
			}
		}
	}
}

// assertClean fails when the current machine has drift or holds.
func assertClean(t *testing.T) {
	t.Helper()
	st := decode[struct {
		Drift []any
		Holds []any
	}](t, yadmOK(t, "status").Data)
	if len(st.Drift) != 0 || len(st.Holds) != 0 {
		t.Fatalf("status: %+v", st)
	}
}

// TestRetagVariantIntoEnclave: on host-a (darwin), the linux variant of a
// fixture target does not apply. Retag moves it into the personal enclave
// without the gate: its ciphertext lands under sealed/personal/, the plain
// source goes, host-a's own variant stays clean, and the linux machine
// loses it. Moving a variant that does not apply here out of an enclave is
// refused: the gate would need its plaintext here.
func TestRetagVariantIntoEnclave(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	const osh = ".config/shell/os.sh"
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	before := readFile(t, filepath.Join(a.Home, osh))

	env, code, _ := yadm(t, "retag", osh, "personal", "--source", "files/.config/shell/os-linux.sh", "--enclave", "personal")
	if code != ExitOK {
		t.Fatalf("retag: exit %d %+v", code, env.Error)
	}
	d := decode[retagData](t, env.Data)
	if d.Commit == "" || d.Source != "sealed/personal/.config/shell/os-linux.sh" || d.When != "type:personal & os:linux" || strings.Join(d.RemovedOn, ",") != string(fixture.HostC) {
		t.Fatalf("retag data: %+v", d)
	}
	tree := git(t, remote, "ls-tree", "-r", "--name-only", "main")
	if strings.Contains(tree, "files/.config/shell/os-linux.sh") || !strings.Contains(tree, "sealed/personal/.config/shell/os-linux.sh") {
		t.Fatalf("tree after retag:\n%s", tree)
	}
	if blob := git(t, remote, "show", "main:sealed/personal/.config/shell/os-linux.sh"); !strings.HasPrefix(blob, "yadm-sealed") {
		t.Fatalf("the moved variant is not sealed: %q", blob)
	}
	if files := git(t, remote, "show", "--name-only", "--format=", "main"); files != "files/.config/shell/os-linux.sh\nmanifest.toml\nsealed/personal/.config/shell/os-linux.sh" {
		t.Fatalf("retag commit files: %q", files)
	}
	assertCleanOn(t, osh)
	if got := readFile(t, filepath.Join(a.Home, osh)); got != before {
		t.Fatalf("host-a's variant changed: %q", got)
	}

	head := git(t, a.Source, "rev-parse", "main")
	env, code, _ = yadm(t, "retag", osh, "work", "--source", "sealed/personal/.config/shell/os-linux.sh")
	if code == ExitOK || env.Error == nil || !strings.Contains(env.Error.Message, "does not apply on this machine") {
		t.Fatalf("unseal a variant that does not apply here: exit %d %+v", code, env.Error)
	}
	if git(t, a.Source, "rev-parse", "main") != head {
		t.Fatal("a refused retag committed")
	}
}
