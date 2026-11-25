package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// TestExpectEnclaveRefusalNotSharedByTimer: a file `yadm commit
// --expect-enclave` refused stays out of every repository when the timer
// runs after its quiet period, whatever would otherwise take it in
// plaintext: a plain glob entry, a plain file entry, a plain root. Its hold
// goes with the file, and an attended commit that names it still commits.
func TestExpectEnclaveRefusalNotSharedByTimer(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	mp := filepath.Join(fx.Root, "manifest.toml")
	writeFile(t, mp, dropFixtureCheck(t, readFile(t, mp))+expectEnclaveManifest)
	writeFile(t, filepath.Join(fx.Root, "files/.config/stash/vault/plain.conf"), "plain\n")
	writeFile(t, filepath.Join(fx.Root, "files/.config/stash/readme"), "shared\n")
	remote := fixtureRemote(t, root, fx)
	canary := secrecytest.NewCanary(t, "expect-enclave-timer")
	canaries := append(fx.AllCanaries(), canary)

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/stash")
	yadmOK(t, "root", "allow", ".config/stash/vault")

	secret := "token = \"" + canary.String() + "\"\n"
	refused := []string{
		".config/stash/vault/new.toml",   // a plain glob entry takes it
		".config/stash/vault/plain.conf", // a plain file entry takes it
		".config/stash/note.txt",         // the plain root takes it
	}
	for _, p := range refused {
		writeFile(t, filepath.Join(a.Home, p), secret)
		if _, code, _ := yadm(t, "commit", "--expect-enclave", "personal", p); code != ExitRefused {
			t.Fatalf("commit --expect-enclave %s: exit %d, want %d", p, code, ExitRefused)
		}
	}
	held := func() []string {
		var out []string
		for _, h := range decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds {
			if h.Task == apply.ExpectTask {
				out = append(out, string(h.Target))
			}
		}
		return out
	}
	if hs := held(); len(hs) != len(refused) {
		t.Fatalf("expect-enclave holds %v, want one on each of %v", hs, refused)
	}
	timerSyncs(t)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	// A deleted file takes its hold with it.
	if err := os.Remove(filepath.Join(a.Home, refused[2])); err != nil {
		t.Fatal(err)
	}
	timerSyncs(t)
	if hs := held(); len(hs) != len(refused)-1 {
		t.Fatalf("expect-enclave holds after a delete: %v", hs)
	}
	// The user names a held file: the commit goes ahead and clears its hold.
	writeFile(t, filepath.Join(a.Home, refused[0]), "shared = 1\n")
	yadmOK(t, "commit", refused[0])
	if got := git(t, a.Source, "show", "main:files/"+refused[0]); got != "shared = 1" {
		t.Fatalf("an attended commit did not commit it: %q", got)
	}
	if hs := held(); len(hs) != len(refused)-2 {
		t.Fatalf("expect-enclave holds after an attended commit: %v", hs)
	}
	secrecytest.AssertRepoClean(t, remote, canaries...)
}
