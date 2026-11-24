package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// An enclave root with a plain entry for one file under it that applies on
// work machines only.
const enclaveRootEntryManifest = `
[[root]]
path = ".config/vault"
enclave = "personal"
when = "type:personal"

[[file]]
target = ".config/vault/x.toml"
when = "type:work"
`

// TestEnclaveRootEntryKeepsEnclave: a file under an enclave root is that
// enclave's plaintext. A member cannot add a variant of it outside the
// enclave, nor retag its sealed entry out of the enclave (one path or
// several). Sealed for the enclave, both go ahead. No enclave plaintext
// reaches a repository or the non-member's $HOME.
func TestEnclaveRootEntryKeepsEnclave(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	mp := filepath.Join(fx.Root, "manifest.toml")
	writeFile(t, mp, dropFixtureCheck(t, readFile(t, mp))+enclaveRootEntryManifest)
	writeFile(t, filepath.Join(fx.Root, "files/.config/vault/x.toml"), "work\n")
	remote := fixtureRemote(t, root, fx)
	canary := secrecytest.NewCanary(t, "enclave-root-entry")
	canaries := append(fx.AllCanaries(), canary)
	const (
		x = ".config/vault/x.toml"
		y = ".config/vault/y.toml"
		z = ".config/plain.toml"
	)

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/vault")
	writeFile(t, filepath.Join(a.Home, x), "x = \""+canary.String()+"\"\n")
	writeFile(t, filepath.Join(a.Home, y), "y = \""+canary.String()+"\"\n")
	writeFile(t, filepath.Join(a.Home, z), "z\n")

	// y gets its own sealed entry.
	yadmOK(t, "retag", y, "personal", "--enclave", "personal")
	head := git(t, a.Source, "rev-parse", "main")
	for _, args := range [][]string{
		{"track", x, "--variant", "mine", "--when", "type:personal"},
		{"retag", y, "personal"},
		{"retag", z, y, "personal"},
	} {
		env, code, out := yadm(t, args...)
		if code != ExitRefused || env.Error == nil || !strings.Contains(env.Error.Message, "enclave root .config/vault") {
			t.Errorf("yadm %v: exit %d %+v; want exit %d naming the enclave root", args, code, env.Error, ExitRefused)
		}
		if strings.Contains(string(out), canary.String()) {
			t.Fatalf("yadm %v printed the plaintext", args)
		}
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatalf("a refused command committed:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	// Sealed for the enclave, both go ahead.
	yadmOK(t, "track", x, "--variant", "mine", "--when", "type:personal", "--enclave", "personal")
	yadmOK(t, "retag", z, y, "personal", "--enclave", "personal")
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)
	// The root does not deliver the variant's source as a file of its own.
	yadmOK(t, "sync")
	if _, err := os.Stat(filepath.Join(a.Home, ".config/vault/x.mine.toml")); !os.IsNotExist(err) {
		t.Fatalf("the enclave root delivered the variant's source as a file: %v", err)
	}

	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	if got := readFile(t, filepath.Join(b.Home, x)); got != "work\n" {
		t.Fatalf("the non-member's %s: %q", x, got)
	}
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)
}
