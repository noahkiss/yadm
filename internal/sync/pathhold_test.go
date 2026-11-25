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

// A held path: a fetched commit that weakens one target's protection holds
// that target alone. The machine takes every other change, pushes its own
// commits, and never writes, captures or pushes the weakened target.

const (
	heldSealed = "sealed/personal/.config/notes/private.md"
	heldPlain  = "files/.config/notes/private.md"
)

// unsealPrivate is the weakening a pusher sends: the private note loses its
// enclave and moves to a plain source holding body. The sealed source goes.
func unsealPrivate(t *testing.T, m *machine, body string) []store.Change {
	t.Helper()
	ch := sec2Manifest(t, m, func(s string) string {
		return strings.Replace(s, "target = \".config/notes/private.md\"\nenclave = \"personal\"\n", "target = \".config/notes/private.md\"\n", 1)
	})
	return append(ch,
		store.Change{Path: heldPlain, Blob: []byte(body), Mode: 0o100644},
		store.Change{Path: heldSealed, Delete: true})
}

// resealPrivate puts the enclave back on the private note's entry, with the
// sealed source it had at rev.
func resealPrivate(t *testing.T, m *machine, rev model.CommitID) []store.Change {
	t.Helper()
	sealed, err := m.st.ReadPath(context.Background(), rev, heldSealed)
	if err != nil {
		t.Fatal(err)
	}
	ch := sec2Manifest(t, m, func(s string) string {
		return strings.Replace(s, "target = \".config/notes/private.md\"\n", "target = \".config/notes/private.md\"\nenclave = \"personal\"\n", 1)
	})
	return append(ch, store.Change{Path: heldSealed, Blob: sealed, Mode: 0o100644}, store.Change{Path: heldPlain, Delete: true})
}

func heldOn(r Report, tgt model.Target) *model.Hold {
	for i, h := range r.Holds {
		if h.Target == tgt && h.Task == HoldTaskGuard {
			return &r.Holds[i]
		}
	}
	return nil
}

func wholeRefusal(r Report) *model.Hold {
	for i, h := range r.Holds {
		if h.Target == "" && h.Task == HoldTaskGuard {
			return &r.Holds[i]
		}
	}
	return nil
}

func (m *machine) descends(remote string) bool {
	m.w.t.Helper()
	ok, err := m.st.IsAncestor(context.Background(), model.CommitID(remote), m.main())
	if err != nil {
		m.w.t.Fatal(err)
	}
	return ok
}

// The weakening and an unrelated edit arrive in one commit. The member
// takes the edit, keeps its note as it is, pushes its own commit, and its
// later edits of the note never reach the remote or its object store.
func TestPathHoldTakesTheRestOfTheFetch(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b] // A is the member; B pushes
	A.s.Guard = &apply.Guard{List: A.allows}
	canary := secrecytest.NewCanary(t, "private note")
	A.write(sec2Private, "note "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)

	B.sync()
	sealedAt := B.main()
	ch := unsealPrivate(t, B, "planted by the pusher\n")
	ch = append(ch, store.Change{Path: "files/" + model.SourcePath(aliases), Blob: []byte("alias fetched=\"yes\"\n"), Mode: 0o100644})
	weak := pushRaw(t, B, ch)

	A.write(pkgList, "tool-one\ntool-two\ntool-local\n")
	w.clock.offset += 3 * time.Hour
	r := A.sync()
	if h := heldOn(r, sec2Private); h == nil || !strings.Contains(h.Detail, "no longer sealed for personal") || h.Next[0] != "yadm protection allow .config/notes/private.md" {
		t.Fatalf("no held path for the note: %+v", r.Holds)
	}
	if h := wholeRefusal(r); h != nil {
		t.Fatalf("the whole fetch was refused: %+v", h)
	}
	if !A.descends(string(weak)) {
		t.Fatal("main did not take the fetched commit")
	}
	if got := A.read(aliases); got != "alias fetched=\"yes\"\n" {
		t.Errorf("the unrelated change was not applied: %q", got)
	}
	if got := A.read(sec2Private); got != "note "+canary.String()+"\n" {
		t.Errorf("the held note changed: %q", got)
	}
	if !r.Pushed || !strings.Contains(w.remoteFile("files/"+string(pkgList)), "tool-local") {
		t.Fatalf("A's own commit did not go out: pushed %v", r.Pushed)
	}
	var alerted bool
	for _, al := range r.Alerts {
		alerted = alerted || (al.Kind == AlertPathHeld && strings.Contains(al.Detail, string(sec2Private)))
	}
	if !alerted {
		t.Errorf("no held-path alert: %+v", r.Alerts)
	}

	// A local edit of the held note is never captured into files/.
	A.write(sec2Private, "note edited "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	r = A.sync()
	if heldOn(r, sec2Private) == nil {
		t.Fatalf("hold lost after a local edit: %+v", r.Holds)
	}
	n := 0
	for _, h := range r.Holds {
		if h.Target == sec2Private {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d holds name the note, want one: %+v", n, r.Holds)
	}
	// Neither an attended commit naming it nor either side of a resolve
	// takes the held note.
	if rc, err := A.s.Commit(context.Background(), CommitOptions{Paths: []model.Target{sec2Private}, Push: true}); err == nil && len(rc.Committed) != 0 {
		t.Errorf("a named commit took the held note: %+v", rc)
	}
	h := heldOn(r, sec2Private)
	for _, take := range []string{"source", "target"} {
		if _, err := A.eng.ResolveHold(context.Background(), h.ID, apply.ResolveOptions{Take: take}); err == nil && take == "source" {
			t.Errorf("resolve --take %s settled the held note", take)
		}
	}
	if got := A.read(sec2Private); !strings.Contains(got, "note edited") {
		t.Errorf("a resolve rewrote the held note: %q", got)
	}
	if got := w.remoteFile(heldPlain); got != "planted by the pusher" {
		t.Errorf("remote plain note %q", got)
	}
	// A later, unrelated fetch (the accepted base has moved past the
	// weakening) keeps the hold.
	B.sync()
	pushRaw(t, B, []store.Change{{Path: "files/" + model.SourcePath(aliases), Blob: []byte("alias later=\"yes\"\n"), Mode: 0o100644}})
	r = A.sync()
	if heldOn(r, sec2Private) == nil || !strings.Contains(A.read(aliases), "later") {
		t.Fatalf("after a later fetch: aliases %q holds %+v", A.read(aliases), r.Holds)
	}
	if got := A.read(sec2Private); !strings.Contains(got, "note edited") {
		t.Errorf("the held note changed: %q", got)
	}
	secrecytest.AssertRepoClean(t, w.remote, canary)
	secrecytest.AssertRepoClean(t, A.repo.Dir(), canary)
	secrecytest.AssertRepoClean(t, B.repo.Dir(), canary)
	secrecytest.AssertTreeClean(t, B.home, canary)

	// A later commit restores the enclave: the hold goes by itself.
	B.sync()
	pushRaw(t, B, resealPrivate(t, B, sealedAt))
	r = A.sync()
	if heldOn(r, sec2Private) != nil {
		t.Fatalf("hold stayed after the protection came back: %+v", r.Holds)
	}
	if r = A.sync(); heldOn(r, sec2Private) != nil {
		t.Fatalf("hold came back: %+v", r.Holds)
	}
}

// `yadm protection allow` settles a held path: the new protection applies.
// A second, different weakening after that is held again.
func TestPathHoldAllowThenNewWeakening(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.s.Guard = &apply.Guard{List: A.allows}
	ctx := context.Background()
	pushRaw(t, B, unsealPrivate(t, B, "now plain\n"))
	if r := A.sync(); heldOn(r, sec2Private) == nil {
		t.Fatalf("no hold: %+v", r.Holds)
	}
	if err := A.eng.AllowProtection(ctx, A.main(), sec2Private); err != nil {
		t.Fatal(err)
	}
	r := A.sync()
	if heldOn(r, sec2Private) != nil || A.read(sec2Private) != "now plain\n" {
		t.Fatalf("after allow: note %q holds %+v", A.read(sec2Private), r.Holds)
	}

	B.sync()
	pushRaw(t, B, sec2Manifest(t, B, func(s string) string {
		return strings.Replace(s, "target = \".ssh/config\"\nregions = true\n", "target = \".ssh/config\"\n", 1)
	}))
	r = A.sync()
	if h := heldOn(r, ".ssh/config"); h == nil || !strings.Contains(h.Detail, "regions were turned off") {
		t.Fatalf("second weakening not held: %+v", r.Holds)
	}
	if heldOn(r, sec2Private) != nil {
		t.Errorf("the allowed note is held again: %+v", r.Holds)
	}
}

// The pusher removes the held entry, then adds it back plain in a later
// commit. The floor outlives the removal, so the re-added plain file is held
// and never written over the member's copy.
func TestPathHoldRemovedThenReaddedPlain(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.s.Guard = &apply.Guard{List: A.allows}
	canary := secrecytest.NewCanary(t, "private note")
	A.write(sec2Private, "note "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()

	B.sync()
	pushRaw(t, B, unsealPrivate(t, B, "planted\n"))
	if r := A.sync(); heldOn(r, sec2Private) == nil {
		t.Fatalf("no hold: %+v", r.Holds)
	}
	// Remove the entry and its source.
	pushRaw(t, B, append(sec2Manifest(t, B, func(s string) string {
		return strings.Replace(s, "[[file]]\ntarget = \".config/notes/private.md\"\nwhen = \"type:personal\"\n", "", 1)
	}), store.Change{Path: heldPlain, Delete: true}))
	r := A.sync()
	if heldOn(r, sec2Private) != nil {
		t.Errorf("hold stayed on a target that left the plan: %+v", r.Holds)
	}
	// Add it back plain, as a new entry.
	pushRaw(t, B, append(sec2Manifest(t, B, func(s string) string {
		return s + "\n[[file]]\ntarget = \".config/notes/private.md\"\nwhen = \"type:personal\"\n"
	}), store.Change{Path: heldPlain, Blob: []byte("planted again\n"), Mode: 0o100644}))
	r = A.sync()
	if heldOn(r, sec2Private) == nil {
		t.Fatalf("the re-added plain entry was not held: %+v", r.Holds)
	}
	if b, err := os.ReadFile(A.path(sec2Private)); err == nil && strings.Contains(string(b), "planted") {
		t.Fatalf("the re-added plain source was written: %q", b)
	}
	// Whatever is on disk now, an edit is never captured plain.
	A.write(sec2Private, "note again "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)
}

// A local, unpushed commit of the sealed note meets a fetched commit that
// moved it to a plain source. The replay keeps the commit's other paths,
// nothing plain is pushed, and the note stays held.
func TestPathHoldLocalSealedCommitReplayed(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.s.Guard = &apply.Guard{List: A.allows}
	ctx := context.Background()
	canary := secrecytest.NewCanary(t, "private note")

	// A commits an edit of the sealed note and of the package list, and
	// pushes nothing.
	A.write(sec2Private, "note "+canary.String()+"\n")
	A.write(pkgList, "tool-one\ntool-two\ntool-replayed\n")
	w.clock.offset += 3 * time.Hour
	if _, err := A.s.Run(ctx, Options{Auto: true}); err != nil {
		t.Fatal(err)
	}
	B.sync()
	pushRaw(t, B, append(unsealPrivate(t, B, "planted\n"),
		store.Change{Path: "files/" + model.SourcePath(aliases), Blob: []byte("alias fetched=\"yes\"\n"), Mode: 0o100644}))
	r := A.sync()
	if heldOn(r, sec2Private) == nil {
		t.Fatalf("no held path: %+v", r.Holds)
	}
	if wholeRefusal(r) != nil || !strings.Contains(A.read(aliases), "fetched") {
		t.Fatalf("fetch not taken: %+v", r.Holds)
	}
	if !strings.Contains(w.remoteFile("files/"+string(pkgList)), "tool-replayed") {
		t.Error("the replayed local commit's other path did not go out")
	}
	if got := A.read(sec2Private); got != "note "+canary.String()+"\n" {
		t.Errorf("the held note changed: %q", got)
	}
	secrecytest.AssertRepoClean(t, w.remote, canary)
	secrecytest.AssertTreeClean(t, B.home, canary)
}

// A non-member plans a sealed file it cannot open and never wrote. A member
// pushes the file's plaintext as a plain source with an unrelated edit. The
// non-member takes the edit and pushes its own commit, and the plaintext
// never reaches its $HOME.
func TestPathHoldNonMemberNeverWritesPlaintext(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, func(f *fixture.Fixture) {
		p := filepath.Join(f.Root, "manifest.toml")
		mb, _ := os.ReadFile(p)
		s := strings.Replace(string(mb), "target = \".config/notes/private.md\"\nenclave = \"personal\"\nwhen = \"type:personal\"\n", "target = \".config/notes/private.md\"\nenclave = \"personal\"\n", 1)
		_ = os.WriteFile(p, []byte(s), 0o644)
	}, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b] // B is the non-member
	B.s.Guard = &apply.Guard{List: B.allows}
	canary := secrecytest.NewCanary(t, "private note")
	if _, err := os.Stat(B.path(sec2Private)); err == nil {
		t.Fatal("the non-member holds the sealed note")
	}
	A.sync()
	ch := unsealPrivate(t, A, "note "+canary.String()+"\n")
	ch = append(ch, store.Change{Path: "files/" + model.SourcePath(aliases), Blob: []byte("alias fetched=\"yes\"\n"), Mode: 0o100644})
	pushRaw(t, A, ch)

	B.write(pkgList, "tool-one\ntool-two\ntool-b\n")
	w.clock.offset += 3 * time.Hour
	r := B.sync()
	if heldOn(r, sec2Private) == nil {
		t.Fatalf("no held path on the non-member: %+v", r.Holds)
	}
	if !strings.Contains(B.read(aliases), "fetched") || !strings.Contains(w.remoteFile("files/"+string(pkgList)), "tool-b") {
		t.Fatalf("the rest of the fetch or B's own commit did not sync: %+v", r)
	}
	secrecytest.AssertTreeClean(t, B.home, canary)
	if _, err := os.Stat(B.path(sec2Private)); err == nil {
		t.Error("the plaintext note reached the non-member's $HOME")
	}
	r = B.sync()
	if heldOn(r, sec2Private) == nil {
		t.Fatalf("hold lost on the next sync: %+v", r.Holds)
	}
	secrecytest.AssertTreeClean(t, B.home, canary)
}

// A weakened owned root is not held per path: the files under it would
// leave the plan. The whole fetch is refused, as before.
func TestPathHoldRootWeakeningRefusesWhole(t *testing.T) {
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
	B.sync()
	pushRaw(t, B, sec2Manifest(t, B, func(s string) string {
		return strings.Replace(s, "path = \".config/vault\"\nenclave = \"personal\"\n", "path = \".config/vault\"\n", 1)
	}))
	before := A.main()
	r := A.sync()
	if wholeRefusal(r) == nil || A.main() != before {
		t.Fatalf("root weakening: main moved %v holds %+v", A.main() != before, r.Holds)
	}
}
