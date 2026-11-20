package apply

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

// secretWorld commits a source with a whole sealed file, a sealed value and
// a sealed file inside a template-free entry, all carrying the canary.
func secretWorld(t *testing.T, canary secrecytest.Canary, members ...model.EnclaveName) (*world, model.CommitID) {
	w := newWorld(t, members...)
	full := fakeCrypto{members: map[model.EnclaveName]bool{"personal": true}}
	tok, err := full.SealValue("personal", "TOKEN", canary.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	c := w.commit(map[model.SourcePath]string{
		"sealed/personal/.config/notes/private.md": "notes " + canary.String() + "\n",
		"files/.env":                       "PLAIN=1\nTOKEN=" + tok + "\n",
		"files/.config/shell/aliases.sh":   "alias x=y\n",
		"sealed/personal/.config/tool/key": canary.String(),
	},
		manifest.Entry{Target: ".config/notes/private.md", Enclave: "personal"},
		manifest.Entry{Target: ".env", Format: manifest.FormatText, Seal: map[string]model.EnclaveName{"TOKEN": "personal"}},
		manifest.Entry{Target: aliases},
		manifest.Entry{Target: ".config/tool/key", Enclave: "personal", Mode: 0o644},
	)
	return w, c
}

func TestSecrecyNonMemberGetsNoPlaintext(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w, c := secretWorld(t, canary) // member of nothing
	r, err := w.eng.Apply(context.Background(), c, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a := actionOf(r, ".config/notes/private.md"); a.Kind != ActSealed {
		t.Errorf("sealed file: %+v", a)
	}
	if _, err := os.Stat(w.path(".config/notes/private.md")); err == nil {
		t.Error("sealed file delivered to a non-member")
	}
	if got := w.read(".env"); got != "PLAIN=1\n" {
		t.Errorf("non-member .env: %q", got)
	}
	secrecytest.AssertTreeClean(t, w.home, canary)
	secrecytest.AssertTreeClean(t, w.stateDir, canary)

	// A non-member's capture keeps the stored token and seals nothing new.
	w.write(".env", "PLAIN=2\n")
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, err := w.eng.Capture(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 1 || !strings.Contains(string(cp.Changes[0].Blob), "TOKEN=tok:personal:") {
		t.Fatalf("non-member capture lost the token: %+v", cp)
	}
	assertObjectsClean(t, cp.Changes, canary)

	// Resolving and adopting never deliver plaintext either.
	if _, err := w.eng.Adopt(context.Background(), c, AdoptOptions{}); err != nil {
		t.Fatal(err)
	}
	secrecytest.AssertTreeClean(t, w.home, canary)
	secrecytest.AssertTreeClean(t, w.stateDir, canary)
}

func TestSecrecyRefusedEnclaveIsNotApplied(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w, c := secretWorld(t, canary, "personal")
	w.loads = map[model.EnclaveName]crypt.EnclaveLoad{"personal": {Err: crypt.ErrBrokenChain}}
	r, err := w.eng.Apply(context.Background(), c, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a := actionOf(r, ".config/notes/private.md"); a.Kind != ActSealed || !strings.Contains(a.Reason, "refused") {
		t.Errorf("%+v", a)
	}
	secrecytest.AssertTreeClean(t, w.home, canary)
	secrecytest.AssertTreeClean(t, w.stateDir, canary)
}

func TestSecrecyMemberCaptureSealsBeforeTheStore(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w, c := secretWorld(t, canary, "personal")
	w.apply(c)
	if !bytes.Contains([]byte(w.read(".config/notes/private.md")), canary.Bytes()) {
		t.Fatal("member did not get the plaintext")
	}
	info, _ := os.Stat(w.path(".config/notes/private.md"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("enclave file mode %v, want 0600", info.Mode().Perm())
	}
	// State holds hashes only.
	secrecytest.AssertTreeClean(t, w.stateDir, canary)

	// Edit both sealed targets; the captured blobs are ciphertext.
	edit := secrecytest.NewCanary(t, "personal-edit")
	w.write(".config/notes/private.md", "notes "+canary.String()+" "+edit.String()+"\n")
	w.write(".env", "PLAIN=1\nTOKEN="+edit.String()+"\n")
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, err := w.eng.Capture(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 2 {
		t.Fatalf("changes: %+v holds %+v", cp.Changes, cp.Holds)
	}
	for _, ch := range cp.Changes {
		if ch.Path == "sealed/personal/.config/notes/private.md" && !crypt.IsSealedFile(ch.Blob) {
			t.Error("sealed file captured as plaintext")
		}
	}
	assertObjectsClean(t, cp.Changes, canary, edit)
	if cp.Scopes[".config/notes/private.md"] != "personal" {
		t.Errorf("scope %+v", cp.Scopes)
	}

	// Merge output is sealed too.
	snap, _ := w.load(context.Background(), c)
	ours, _ := w.crypto.SealFile("personal", []byte(canary.String()+"\nours\n"))
	base, _ := w.crypto.SealFile("personal", []byte(canary.String()+"\n"))
	theirs, _ := w.crypto.SealFile("personal", []byte(canary.String()+"\ntheirs\n"))
	for _, b := range [][]byte{ours, base, theirs} {
		w.st.blobs[blobID(b)] = b
	}
	ch, h, err := w.eng.MergeSealed(context.Background(), snap, store.Conflict{Path: "sealed/personal/.config/notes/private.md", Base: blobID(base), Ours: blobID(ours), Theirs: blobID(theirs)})
	if err != nil {
		t.Fatal(err)
	}
	if ch != nil {
		assertObjectsClean(t, []store.Change{*ch}, canary)
	}
	if h != nil && strings.Contains(h.Detail, canary.String()) {
		t.Error("conflict hold carries plaintext")
	}
}

// assertObjectsClean writes capture blobs into a fresh git object store and
// asserts no canary is in it.
func assertObjectsClean(t *testing.T, changes []store.Change, canaries ...secrecytest.Canary) {
	t.Helper()
	repo := t.TempDir()
	git := func(stdin []byte, args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		cmd.Stdin = bytes.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				t.Fatalf("git %v: %s", args, out)
			}
			t.Fatal(err)
		}
	}
	git(nil, "init", "-q")
	for _, ch := range changes {
		if !ch.Delete {
			git(ch.Blob, "hash-object", "-w", "--stdin")
		}
	}
	secrecytest.AssertRepoClean(t, repo, canaries...)
}
