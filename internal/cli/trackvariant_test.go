package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

type trackData struct {
	Target, Source, Scope, Commit string
	Pushed                        bool
}

// TestTrackVariant: track --variant adds a second entry for a target that an
// entry already names, with source <target>.<name> before the extension and
// this machine's bytes. It refuses an unsafe name, a missing --when, a
// target no entry names, a when false here, and a when that makes two
// entries apply on one machine (here or elsewhere), committing nothing. The
// other machine keeps its variant, and untrack --source removes only the
// new one.
func TestTrackVariant(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := variantTree()
	tree["manifest.toml"] = variantManifest + `
[[file]]
target = ".config/app.toml"
when = "type:work"
`
	tree["files/.config/app.toml"] = "work\n"
	remote := seedRemote(t, root, tree)
	a := kitMachine(t, root, remote, "a", "host-a")
	c := kitMachine(t, root, remote, "c", "host-c")
	const app = ".config/app.toml"
	writeFile(t, filepath.Join(c.Home, app), "home\n")
	writeFile(t, filepath.Join(c.Home, ".config/tool/config"), "color = red\n")
	writeFile(t, filepath.Join(c.Home, ".loose"), "l\n")
	head := git(t, c.Source, "rev-parse", "main")

	for _, x := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"track", app, "--variant", "home"}, ExitUsage, "needs --when"},
		{[]string{"track", app, "--variant", "../up", "--when", "type:home"}, ExitUsage, "variant name"},
		{[]string{"track", app, "--variant", "a/b", "--when", "type:home"}, ExitUsage, "variant name"},
		{[]string{"track", app, "--variant", "..", "--when", "type:home"}, ExitUsage, "variant name"},
		{[]string{"track", ".loose", "--variant", "home", "--when", "type:home"}, ExitUsage, "no manifest entry names it"},
		{[]string{"track", app, "--variant", "home", "--when", "type:work"}, ExitUsage, "does not apply on this machine"},
		{[]string{"track", app, "--variant", "lin", "--when", "os:linux"}, ExitError, "host-a would get .config/app.toml from more than one entry"},
		{[]string{"track", ".config/tool/config", "--variant", "home", "--when", "type:home"}, ExitError, "this machine would get it from more than one entry"},
		{[]string{"track", app, "--variant", "home", "--when", "type:home", "--enclave", "work"}, ExitError, "not an enclave type"},
	} {
		env, code, _ := yadm(t, x.args...)
		if code != x.code || env.Error == nil || !strings.Contains(env.Error.Message, x.msg) {
			t.Errorf("yadm %v: exit %d %+v; want exit %d with %q", x.args, code, env.Error, x.code, x.msg)
		}
	}
	if got := git(t, c.Source, "rev-parse", "main"); got != head {
		t.Fatalf("a refused track committed:\n%s", git(t, c.Source, "show", "--stat", "main"))
	}

	env, code, _ := yadm(t, "track", app, "--variant", "home", "--when", "type:home")
	if code != ExitOK {
		t.Fatalf("track --variant: exit %d %+v", code, env.Error)
	}
	d := decode[trackData](t, env.Data)
	if d.Source != "files/.config/app.home.toml" || d.Scope != "shared" || d.Commit == "" || !d.Pushed {
		t.Fatalf("track data: %+v", d)
	}
	if files := git(t, c.Source, "show", "--name-only", "--format=", d.Commit); files != "files/.config/app.home.toml\nmanifest.toml" {
		t.Fatalf("track commit files: %q", files)
	}
	if got := git(t, remote, "show", "main:files/.config/app.home.toml"); got != "home" {
		t.Fatalf("variant source: %q", got)
	}
	man := git(t, remote, "show", "main:manifest.toml")
	if !strings.Contains(man, "[[file]]\ntarget = '.config/app.toml'\nsource = 'files/.config/app.home.toml'\nwhen = 'type:home'") ||
		!strings.Contains(man, "target = \".config/app.toml\"\nwhen = \"type:work\"") {
		t.Fatalf("manifest:\n%s", man)
	}
	if m := decode[struct{ Managed bool }](t, yadmOK(t, "managed", app).Data); !m.Managed {
		t.Fatal("the new variant is not managed here")
	}
	assertCleanOn(t, app)
	if env, code, _ := yadm(t, "track", app, "--variant", "home", "--when", "type:home & os:linux"); code != ExitUsage || !strings.Contains(env.Error.Message, "already exists") {
		t.Fatalf("a second variant with the same name: exit %d %+v", code, env.Error)
	}

	useMachine(t, root, "a")
	yadmOK(t, "sync")
	if got := readFile(t, filepath.Join(a.Home, app)); got != "work\n" {
		t.Fatalf("host-a lost its variant: %q", got)
	}

	// retag --source picks the new variant.
	useMachine(t, root, "c")
	if env, code, _ := yadm(t, "retag", app, "work", "--source", "files/.config/app.home.toml"); code != ExitError || !strings.Contains(env.Error.Message, "more than one entry") {
		t.Fatalf("retag the variant onto the work one: exit %d %+v", code, env.Error)
	}
	if r := decode[retagData](t, yadmOK(t, "retag", app, "home", "--source", "files/.config/app.home.toml", "--dry-run").Data); r.Source != "files/.config/app.home.toml" || r.When != "type:home" {
		t.Fatalf("retag --dry-run of the variant: %+v", r)
	}

	// untrack --source removes the home variant alone; host-c keeps its file.
	env = yadmOK(t, "untrack", app, "--source", "files/.config/app.home.toml")
	if u := decode[untrackData](t, env.Data); u.Commit == "" || u.Source != "files/.config/app.home.toml" || u.SourceKept {
		t.Fatalf("untrack the variant: %+v", u)
	}
	man = git(t, remote, "show", "main:manifest.toml")
	if strings.Contains(man, "app.home.toml") || !strings.Contains(man, "target = \".config/app.toml\"\nwhen = \"type:work\"") {
		t.Fatalf("manifest after untrack:\n%s", man)
	}
	if out := git(t, remote, "ls-tree", "--name-only", "-r", "main", "files/.config"); !strings.Contains(out, "files/.config/app.toml") || strings.Contains(out, "app.home.toml") {
		t.Fatalf("sources after untrack: %q", out)
	}
	if got := readFile(t, filepath.Join(c.Home, app)); got != "home\n" {
		t.Fatalf("host-c file after untrack: %q", got)
	}
}

// TestTrackVariantSealedSecrecy: a member adds a sealed variant of a target
// a plain entry names. A non-member of the enclave is refused, and so is a
// variant that would overlap another machine's. The sealed variant's
// plaintext reaches neither a non-member's $HOME nor any object store, the
// non-members keep the plain variant, and untrack --source removes only the
// sealed one.
func TestTrackVariantSealedSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	mp := filepath.Join(fx.Root, "manifest.toml")
	man := dropFixtureCheck(t, readFile(t, mp)) + "\n[[file]]\ntarget = \".config/tool/route.toml\"\nwhen = \"type:work\"\n"
	writeFile(t, mp, man)
	writeFile(t, filepath.Join(fx.Root, "files/.config/tool/route.toml"), "route = \"work\"\n")
	remote := fixtureRemote(t, root, fx)
	canary := secrecytest.NewCanary(t, "sealed-variant")
	canaries := append(fx.AllCanaries(), canary)

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	c := fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	yadmOK(t, "apply")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")

	const route = ".config/tool/route.toml"
	writeFile(t, filepath.Join(a.Home, route), "route = \""+canary.String()+"\"\n")
	head := git(t, a.Source, "rev-parse", "main")
	for _, x := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"track", route, "--variant", "cl", "--when", "type:personal", "--enclave", "client"}, ExitRefused, "client"},
		{[]string{"track", route, "--variant", "mac", "--when", "os:darwin", "--enclave", "personal"}, ExitError, "host-b would get " + route + " from more than one entry"},
	} {
		env, code, out := yadm(t, x.args...)
		if code != x.code || env.Error == nil || !strings.Contains(env.Error.Message, x.msg) {
			t.Errorf("yadm %v: exit %d %+v; want exit %d with %q", x.args, code, env.Error, x.code, x.msg)
		}
		if strings.Contains(string(out), canary.String()) {
			t.Fatalf("yadm %v printed the plaintext", x.args)
		}
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatal("a refused track committed")
	}

	env, code, out := yadm(t, "track", route, "--variant", "personal", "--when", "type:personal", "--enclave", "personal")
	if code != ExitOK {
		t.Fatalf("track a sealed variant: exit %d %+v", code, env.Error)
	}
	if strings.Contains(string(out), canary.String()) {
		t.Fatal("track printed the plaintext")
	}
	const src = "sealed/personal/.config/tool/route.personal.toml"
	d := decode[trackData](t, env.Data)
	if d.Source != src || d.Scope != "personal" || d.Commit == "" || !d.Pushed {
		t.Fatalf("track data: %+v", d)
	}
	if files := git(t, a.Source, "show", "--name-only", "--format=", d.Commit); files != "manifest.toml\n"+src {
		t.Fatalf("track commit files: %q", files)
	}
	if m := decode[struct{ Managed bool }](t, yadmOK(t, "managed", route).Data); !m.Managed {
		t.Fatal("the sealed variant is not managed here")
	}
	assertCleanOn(t, route)

	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	useMachine(t, root, string(fixture.HostC))
	yadmOK(t, "sync")
	// host-c is a member of client, so only personal plaintext is foreign there.
	personal := []secrecytest.Canary{canary, fx.Canaries["personal"]}
	for _, m := range []machineDirs{b, c} {
		if got := readFile(t, filepath.Join(m.Home, route)); got != "route = \"work\"\n" {
			t.Fatalf("a non-member's %s: %q", route, got)
		}
		secrecytest.AssertTreeClean(t, m.Home, personal...)
		secrecytest.AssertTreeClean(t, m.State, personal...)
		secrecytest.AssertRepoClean(t, m.Source, canaries...)
	}
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	// untrack --source removes only the sealed variant.
	useMachine(t, root, string(fixture.HostA))
	env = yadmOK(t, "untrack", route, "--source", src)
	if u := decode[untrackData](t, env.Data); u.Commit == "" || u.Source != src || u.SourceKept {
		t.Fatalf("untrack the sealed variant: %+v", u)
	}
	if ls := git(t, remote, "ls-tree", "--name-only", "-r", "main"); strings.Contains(ls, "route.personal.toml") || !strings.Contains(ls, "files/"+route) {
		t.Fatalf("sources after untrack:\n%s", ls)
	}
	if got := git(t, remote, "show", "main:manifest.toml"); strings.Contains(got, "route.personal.toml") || !strings.Contains(got, "target = \""+route+"\"\nwhen = \"type:work\"") {
		t.Fatalf("manifest after untrack:\n%s", got)
	}
	secrecytest.AssertRepoClean(t, remote, canaries...)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	if _, err := os.Stat(filepath.Join(a.Home, route)); err != nil {
		t.Fatalf("the member's file went: %v", err)
	}
}

// dropFixtureCheck removes the fixture's check, which runs a tool the test
// machines lack, so a commit reaches the gate's outcome and not an
// untrusted-task hold.
func dropFixtureCheck(t *testing.T, man string) string {
	t.Helper()
	old := "[checks.no-private-keys]\npaths = [\"**\"]\ncommand = [\"secret-check\", \"--stdin-json\"]\ntimeout = \"20s\"\n"
	if !strings.Contains(man, old) {
		t.Fatal("fixture manifest changed: no check to drop")
	}
	return strings.Replace(man, old, "", 1)
}

// TestTrackVariantKeepsProtection: a member whose sealed copy of a target
// stopped applying here (and stays, drifted) cannot add a plain variant of
// it: that would commit enclave plaintext under files/.
func TestTrackVariantKeepsProtection(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	mp := filepath.Join(fx.Root, "manifest.toml")
	writeFile(t, mp, dropFixtureCheck(t, readFile(t, mp)))
	remote := fixtureRemote(t, root, fx)
	canaries := fx.AllCanaries()
	secret := fx.Canaries["personal"].String()
	const private = ".config/notes/private.md"

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	live := filepath.Join(a.Home, private)
	if !strings.Contains(readFile(t, live), secret) {
		t.Fatal("the member did not receive the sealed file")
	}
	writeFile(t, live, readFile(t, live)+"local edit\n")

	// A raw commit elsewhere sends the sealed entry to work machines only.
	work := filepath.Join(root, "other")
	git(t, root, "clone", "-q", remote, work)
	wm := filepath.Join(work, "manifest.toml")
	old := "enclave = \"personal\"\nwhen = \"type:personal\"\n"
	m := readFile(t, wm)
	if !strings.Contains(m, old) {
		t.Fatal("fixture manifest changed: no personal entry")
	}
	writeFile(t, wm, strings.Replace(m, old, "enclave = \"personal\"\nwhen = \"type:work\"\n", 1))
	git(t, work, "commit", "-q", "-am", "retag by hand")
	git(t, work, "push", "-q", "origin", "main")
	yadm(t, "sync", "--no-push")
	if !strings.Contains(readFile(t, live), secret) {
		t.Fatal("the drifted copy went")
	}

	head := git(t, a.Source, "rev-parse", "main")
	env, code, out := yadm(t, "track", private, "--variant", "mine", "--when", "type:personal")
	if code != ExitUsage || env.Error == nil || !strings.Contains(env.Error.Message, "protection") {
		t.Errorf("plain variant of a sealed copy: exit %d %+v", code, env.Error)
	}
	if strings.Contains(string(out), secret) {
		t.Fatal("track printed the plaintext")
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Error("a refused track committed")
	}
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	// Sealed for the same enclave, the variant is fine.
	yadmOK(t, "track", private, "--variant", "mine", "--when", "type:personal", "--enclave", "personal")
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)
}
