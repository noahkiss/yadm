package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// A plain root that ignores the subtree a deeper enclave root owns. The
// enclave root applies on members of personal only.
const rootIgnoreManifest = `
[[root]]
path = ".config/app"
ignore = ["cache/**", "team/**"]

[[root]]
path = ".config/app/team"
enclave = "personal"
when = "type:personal"
`

// TestRootIgnoreRefusedByName: `yadm commit`, `track` and `retag` refuse a
// file under a plain root's ignored subtree, on a non-member and on a
// member that has not allowed the deeper enclave root, and the agent hooks
// commit nothing. The refusal names the ignore glob or the enclave root.
// After the member allows the enclave root, the named commit seals the
// file. No enclave plaintext reaches any repository or the non-member's
// $HOME.
func TestRootIgnoreRefusedByName(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	mp := filepath.Join(fx.Root, "manifest.toml")
	man, err := os.ReadFile(mp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, append(man, rootIgnoreManifest...), 0o644); err != nil {
		t.Fatal(err)
	}
	remote := fixtureRemote(t, root, fx)
	const (
		work = ".config/app/team/x.toml"
		home = ".config/app/cache/y.toml"
	)
	cb := secrecytest.NewCanary(t, "personal via host-b")
	ca := secrecytest.NewCanary(t, "personal via host-a")

	refused := func(t *testing.T, code int, raw []byte, want string, args []string) {
		t.Helper()
		if code != ExitRefused || !strings.Contains(string(raw), want) {
			t.Errorf("yadm %v: exit %d, want %d mentioning %q:\n%s", args, code, ExitRefused, want, raw)
		}
	}

	// host-b is not a member of personal; the enclave root does not apply.
	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/app")
	passGate(t)
	writeFile(t, filepath.Join(b.Home, work), "token = \""+cb.String()+"\"\n")
	writeFile(t, filepath.Join(b.Home, home), "local = 1\n")
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"commit", work}, ExitRefused, "enclave root .config/app/team"},
		{[]string{"commit", "--dry-run", work}, ExitRefused, "does not apply on this machine"},
		{[]string{"commit", home}, ExitRefused, `ignore glob \"cache/**\"`},
		{[]string{"retag", work, "work"}, ExitRefused, "pass --enclave personal"},
		{[]string{"track", work}, ExitUsage, "ignore glob"},
	} {
		_, code, raw := yadm(t, c.args...)
		if c.code == ExitRefused {
			refused(t, code, raw, c.want, c.args)
		} else if code != c.code || !strings.Contains(string(raw), c.want) {
			t.Errorf("yadm %v: exit %d, want %d mentioning %q:\n%s", c.args, code, c.code, c.want, raw)
		}
	}
	file := filepath.Join(b.Home, work)
	if code, stdout, stderr := hookRun(t, payload(payloadWrite, "session-r", b.Home, file), HookPostEdit); code != HookAllow || stdout != "" {
		t.Errorf("post-edit: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if code, _, stderr := hookRun(t, payload(payloadStop, "session-r", b.Home, ""), HookStop); code != HookAllow {
		t.Errorf("stop: exit %d\n%s", code, stderr)
	}
	yadmOK(t, "sync")
	if out := git(t, b.Source, "ls-tree", "-r", "--name-only", "main"); strings.Contains(out, ".config/app/") {
		t.Errorf("host-b committed a file under the ignored subtree:\n%s", out)
	}
	secrecytest.AssertRepoClean(t, b.Source, cb)
	secrecytest.AssertRepoClean(t, remote, cb)

	// host-a is a member but has not allowed the enclave root yet.
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/app")
	passGate(t)
	writeFile(t, filepath.Join(a.Home, work), "token = \""+ca.String()+"\"\n")
	_, code, raw := yadm(t, "commit", work)
	refused(t, code, raw, "yadm root allow .config/app/team", []string{"commit", work})
	secrecytest.AssertRepoClean(t, remote, ca, cb)

	// Allowed: the named commit seals it for personal.
	yadmOK(t, "root", "allow", ".config/app/team")
	yadmOK(t, "commit", work)
	if out := git(t, a.Source, "ls-tree", "-r", "--name-only", "main"); !strings.Contains(out, "sealed/personal/"+work) || strings.Contains(out, "files/"+work) {
		t.Fatalf("member commit after allow:\n%s", out)
	}
	secrecytest.AssertRepoClean(t, a.Source, ca, cb)
	secrecytest.AssertRepoClean(t, remote, ca, cb)

	// host-b receives nothing of it.
	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	secrecytest.AssertTreeClean(t, b.Home, ca)
	secrecytest.AssertRepoClean(t, b.Source, ca, cb)
}
