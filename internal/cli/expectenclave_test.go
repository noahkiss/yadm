package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// A plain owned root holding an enclave root, and inside the enclave root a
// plain glob entry and a plain file entry that take files away from it,
// plus an enclave root this machine never allows.
const expectEnclaveManifest = `
[[root]]
path = ".config/stash"

[[root]]
path = ".config/stash/vault"
enclave = "personal"
when = "type:personal"
ignore = ["*.log"]

[[root]]
path = ".config/stash/locked"
enclave = "personal"
when = "type:personal"

[[file]]
target = ".config/stash/vault/*.toml"
when = "type:personal"

[[file]]
target = ".config/stash/vault/plain.conf"
when = "type:personal"
`

// TestCommitExpectEnclave: `yadm commit --expect-enclave` refuses, and
// commits nothing, for every way a brand-new or plain file under an enclave
// root would land outside the enclave: a plain glob entry, a plain file
// entry, an ignore rule, an unallowed root, a plain root, a member that
// reads the enclave on demand only. A file the enclave root seals commits.
// The canary never reaches a repository or the non-member's $HOME.
func TestCommitExpectEnclave(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	mp := filepath.Join(fx.Root, "manifest.toml")
	writeFile(t, mp, dropFixtureCheck(t, readFile(t, mp))+expectEnclaveManifest)
	writeFile(t, filepath.Join(fx.Root, "files/.config/stash/vault/plain.conf"), "plain\n")
	writeFile(t, filepath.Join(fx.Root, "files/.config/stash/readme"), "shared\n")
	remote := fixtureRemote(t, root, fx)
	canary := secrecytest.NewCanary(t, "expect-enclave")
	canaries := append(fx.AllCanaries(), canary)

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/stash")
	yadmOK(t, "root", "allow", ".config/stash/vault")

	secret := "token = \"" + canary.String() + "\"\n"
	refused := []string{
		".config/stash/vault/new.toml",   // a plain glob entry takes it
		".config/stash/vault/plain.conf", // a plain file entry takes it
		".config/stash/vault/debug.log",  // the enclave root ignores it
		".config/stash/locked/key.txt",   // the enclave root is not allowed here
		".config/stash/note.txt",         // the plain root takes it
	}
	for _, p := range refused {
		writeFile(t, filepath.Join(a.Home, p), secret)
	}
	head := git(t, a.Source, "rev-parse", "main")
	for _, p := range refused {
		for _, extra := range [][]string{nil, {"--dry-run"}} {
			args := append([]string{"commit", "--expect-enclave", "personal", p}, extra...)
			env, code, out := yadm(t, args...)
			if code != ExitRefused || env.Error == nil {
				t.Errorf("yadm %v: exit %d %+v; want exit %d", args, code, env.Error, ExitRefused)
			}
			if strings.Contains(string(out), canary.String()) {
				t.Fatalf("yadm %v printed the plaintext", args)
			}
		}
	}
	// Several paths: one bad path refuses them all.
	ok := ".config/stash/vault/secret.txt"
	writeFile(t, filepath.Join(a.Home, ok), secret)
	if _, code, _ := yadm(t, "commit", "--expect-enclave", "personal", ok, refused[0]); code != ExitRefused {
		t.Errorf("a mixed commit: exit %d, want %d", code, ExitRefused)
	}
	// The wrong enclave refuses a file sealed for another.
	if _, code, _ := yadm(t, "commit", "--expect-enclave", "client", ok); code != ExitRefused {
		t.Errorf("wrong enclave: exit %d, want %d", code, ExitRefused)
	}
	if _, code, _ := yadm(t, "commit", "--expect-enclave", "personal"); code != ExitUsage {
		t.Errorf("no paths: exit %d, want %d", code, ExitUsage)
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatalf("a refused commit committed:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	// The file the enclave root seals commits, sealed.
	yadmOK(t, "commit", "--expect-enclave", "personal", ok)
	if tree := git(t, a.Source, "ls-tree", "-r", "--name-only", "main"); !strings.Contains(tree, "sealed/personal/"+ok) || strings.Contains(tree, "files/"+ok) {
		t.Fatalf("not sealed:\n%s", tree)
	}
	// An unchanged sealed target passes; the commit is empty.
	yadmOK(t, "commit", "--expect-enclave", "personal", ok)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	// A member that reads the enclave on demand only never commits a new
	// file in plaintext either.
	yadmOK(t, "enclave", "on-demand", "personal")
	od := ".config/stash/vault/on-demand.txt"
	writeFile(t, filepath.Join(a.Home, od), secret)
	if _, code, _ := yadm(t, "commit", "--expect-enclave", "personal", od); code != ExitOK && code != ExitRefused {
		t.Errorf("on-demand member: exit %d", code)
	}
	if tree := git(t, a.Source, "ls-tree", "-r", "--name-only", "main"); strings.Contains(tree, "files/"+od) {
		t.Fatalf("an on-demand member committed plaintext:\n%s", tree)
	}
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)
}
