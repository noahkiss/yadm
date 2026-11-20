package sync

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

const sec2Private model.Target = ".config/notes/private.md"

// G1: a pushed named-condition flip swaps the enclave entry of a target
// for a plain one. The guard must refuse it and nothing may leak.
func TestSec2ConditionFlipToPlainEntry(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, func(f *fixture.Fixture) {
		p := filepath.Join(f.Root, "manifest.toml")
		mb, _ := os.ReadFile(p)
		s := strings.Replace(string(mb), "enclave = \"personal\"\nwhen = \"type:personal\"", "enclave = \"personal\"\nwhen = \"cond:priv\"", 1)
		s = strings.Replace(s, "[defaults]", "[conditions]\npriv = \"type:personal\"\n\n[defaults]", 1)
		_ = os.WriteFile(p, []byte(s), 0o644)
	}, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b] // A is the member; B pushes
	A.s.Guard = &apply.Guard{List: A.allows}
	canary := secrecytest.NewCanary(t, "personal note")
	A.write(sec2Private, "note "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)

	ch := sec2Manifest(t, B, func(s string) string {
		s = strings.Replace(s, "priv = \"type:personal\"", "priv = \"type:work\"", 1)
		return s + "\n[[file]]\ntarget = \".config/notes/private.md\"\nsource = \"files/notes-plain.md\"\nwhen = \"!cond:priv\"\nquiet = \"0s\"\n"
	})
	ch = append(ch, store.Change{Path: "files/notes-plain.md", Blob: []byte("plain\n"), Mode: 0o100644})
	B.sync()
	pushRaw(t, B, ch)
	before := A.main()
	r := A.sync()
	t.Logf("guard hold=%v main moved=%v holds=%+v", holdTask(r, HoldTaskGuard) != nil, A.main() != before, r.Holds)
	if holdTask(r, HoldTaskGuard) == nil {
		t.Error("condition flip to a plain entry was not refused")
	}
	A.write(sec2Private, "note edited "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)
}

// G2: an enclave owned root shares a sealed file by root expansion (no
// entry). A pusher adds an explicit plain entry for that target.
func TestSec2PlainEntryOverRootExpandedSealedTarget(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, func(f *fixture.Fixture) {
		p := filepath.Join(f.Root, "manifest.toml")
		mb, _ := os.ReadFile(p)
		mb = append(mb, []byte("\n[[root]]\npath = \".config/vault\"\nenclave = \"personal\"\nwhen = \"type:personal\"\n")...)
		_ = os.WriteFile(p, mb, 0o644)
	}, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.s.Guard = &apply.Guard{List: A.allows}
	canary := secrecytest.NewCanary(t, "vault file")
	const tgt model.Target = ".config/vault/token"
	A.write(tgt, canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	r := A.sync()
	t.Logf("new vault file: committed=%d", len(r.Committed))
	if out := git(t, w.remote, "ls-tree", "-r", "--name-only", "main"); !strings.Contains(out, "sealed/personal/.config/vault/token") {
		t.Fatalf("vault file not sealed in the remote:\n%s", out)
	}
	secrecytest.AssertRepoClean(t, w.remote, canary)
	A.sync()

	B.sync()
	ch := sec2Manifest(t, B, func(s string) string {
		return s + "\n[[file]]\ntarget = \".config/vault/token\"\nsource = \"files/vault-token\"\nquiet = \"0s\"\n"
	})
	ch = append(ch, store.Change{Path: "files/vault-token", Blob: []byte("plain\n"), Mode: 0o100644})
	pushRaw(t, B, ch)
	before := A.main()
	r = A.sync()
	t.Logf("guard hold=%v main moved=%v holds=%+v", holdTask(r, HoldTaskGuard) != nil, A.main() != before, r.Holds)
	if holdTask(r, HoldTaskGuard) == nil {
		t.Error("plain entry over a root-expanded sealed target was not refused")
	}
	A.write(tgt, "edited "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)

	// G3: same attack, but the plain file sits at the root's own default
	// path files/<root>/..., with the root's enclave stripped in the manifest.
	ch = sec2Manifest(t, B, func(s string) string {
		return strings.Replace(s, "path = \".config/vault\"\nenclave = \"personal\"\n", "path = \".config/vault\"\n", 1)
	})
	ch = append(ch, store.Change{Path: "files/.config/vault/token", Blob: []byte("plain\n"), Mode: 0o100644},
		store.Change{Path: "sealed/personal/.config/vault/token", Delete: true})
	pushRaw(t, B, ch)
	r = A.sync()
	t.Logf("G3 guard hold=%v holds=%+v", holdTask(r, HoldTaskGuard) != nil, r.Holds)
	A.write(tgt, "edited again "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)
}

// A1: an owned root directory that is a symlink when the root is accepted.
// The baseline walk sees nothing behind it. Adopt later materializes the
// link; the files it copied must not be shared as new files.
func TestSec2AdoptMaterializedRootFilesShared(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, b)
	w.machines[b].sync()
	A := w.newMachine(a)
	w.machines[a] = A
	canary := secrecytest.NewCanary(t, "file behind the link")
	variant := filepath.Join(A.home, "variants", "shell")
	if err := os.MkdirAll(variant, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(variant, "local-secrets.sh"), []byte("export X="+canary.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(A.home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(variant, A.path(".config/shell")); err != nil {
		t.Fatal(err)
	}
	r := A.sync()
	st, _ := A.eng.State.Load()
	t.Logf("first sync: holds=%d baseline=%v", len(r.Holds), st.Baseline)
	res, err := A.eng.Adopt(context.Background(), A.main(), apply.AdoptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Actions {
		if strings.Contains(x.Reason, "materialize") {
			t.Logf("adopt: %s %s", x.Target, x.Reason)
		}
	}
	w.clock.offset += 3 * time.Hour
	r = A.sync()
	t.Logf("after adopt: committed=%d pushed=%v holds=%+v", len(r.Committed), r.Pushed, r.Holds)
	secrecytest.AssertRepoClean(t, w.remote, canary)
}
