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

// Two-step launders: a pusher takes a protected target out of this
// machine's plan in one commit and brings it back weaker in another, so no
// single fetch weakens a target both sources plan.

const (
	privEntry      = "[[file]]\ntarget = \".config/notes/private.md\"\nenclave = \"personal\"\nwhen = \"type:personal\"\n"
	privEntryPlain = "[[file]]\ntarget = \".config/notes/private.md\"\nwhen = \"type:personal\"\n"
)

// sealedNoteSynced writes a canary into the sealed note on A and syncs it.
func sealedNoteSynced(t *testing.T, w *world, A *machine) secrecytest.Canary {
	t.Helper()
	A.s.Guard = &apply.Guard{List: A.allows}
	canary := secrecytest.NewCanary(t, "private note")
	A.write(sec2Private, "note "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	return canary
}

// editAndTimer edits the note with the canary and runs the timer twice.
func editAndTimer(w *world, A *machine, canary secrecytest.Canary) {
	A.write(sec2Private, "note again "+canary.String()+"\n")
	for i := 0; i < 2; i++ {
		w.clock.offset += 3 * time.Hour
		A.sync()
	}
}

// The pusher turns the sealed note's when off for this machine (it leaves
// the plan and is deleted here), then turns it back on as a plain entry.
// The note is held, the planted plain source is never written, and a later
// edit is never captured plain.
func TestPathHoldWhenOffThenPlain(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	canary := sealedNoteSynced(t, w, A)
	B.sync()
	off := strings.Replace(privEntry, "type:personal", "type:client", 1)
	pushRaw(t, B, sec2Manifest(t, B, func(s string) string { return strings.Replace(s, privEntry, off, 1) }))
	A.sync()
	if _, err := os.Stat(A.path(sec2Private)); err == nil {
		t.Fatal("the note stayed after it left the plan")
	}
	pushRaw(t, B, append(sec2Manifest(t, B, func(s string) string { return strings.Replace(s, off, privEntryPlain, 1) }),
		store.Change{Path: heldPlain, Blob: []byte("planted\n"), Mode: 0o100644}, store.Change{Path: heldSealed, Delete: true}))
	if r := A.sync(); heldOn(r, sec2Private) == nil {
		t.Fatalf("the plain note that came back was not held: %+v", r.Holds)
	}
	if b, err := os.ReadFile(A.path(sec2Private)); err == nil {
		t.Fatalf("the plain source was written: %q", b)
	}
	editAndTimer(w, A, canary)
	secrecytest.AssertRepoClean(t, w.remote, canary)
	secrecytest.AssertRepoClean(t, A.repo.Dir(), canary)

	// Allowing the new protection here settles it.
	if err := A.eng.AllowProtection(context.Background(), A.main(), sec2Private); err != nil {
		t.Fatal(err)
	}
	if r := A.sync(); heldOn(r, sec2Private) != nil {
		t.Fatalf("held after allow: %+v", r.Holds)
	}
}

// The pusher removes the sealed note's entry and source, then adds a plain
// entry back.
func TestPathHoldRemovedThenPlainWithoutWeakening(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	canary := sealedNoteSynced(t, w, A)
	B.sync()
	pushRaw(t, B, append(sec2Manifest(t, B, func(s string) string { return strings.Replace(s, privEntry, "", 1) }),
		store.Change{Path: heldSealed, Delete: true}))
	A.sync()
	pushRaw(t, B, append(sec2Manifest(t, B, func(s string) string { return s + "\n" + privEntryPlain }),
		store.Change{Path: heldPlain, Blob: []byte("planted\n"), Mode: 0o100644}))
	if r := A.sync(); heldOn(r, sec2Private) == nil {
		t.Fatalf("the plain note that came back was not held: %+v", r.Holds)
	}
	editAndTimer(w, A, canary)
	secrecytest.AssertRepoClean(t, w.remote, canary)
}

// A held path whose entry the pusher then replaces with a plain owned root
// over its directory: once the root is allowed here, neither the timer nor
// a commit that names the note captures it plain.
func TestPathHoldThenPlainRoot(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	canary := sealedNoteSynced(t, w, A)
	B.sync()
	pushRaw(t, B, unsealPrivate(t, B, "planted\n"))
	if r := A.sync(); heldOn(r, sec2Private) == nil {
		t.Fatalf("no hold: %+v", r.Holds)
	}
	pushRaw(t, B, append(sec2Manifest(t, B, func(s string) string {
		return strings.Replace(s, privEntryPlain, "", 1) + "\n[[root]]\npath = \".config/notes\"\n"
	}), store.Change{Path: heldPlain, Delete: true}))
	A.sync()
	A.allowRoots(A.main())
	A.sync()
	editAndTimer(w, A, canary)
	_, _ = A.s.Commit(context.Background(), CommitOptions{Paths: []model.Target{sec2Private}, Push: true})
	secrecytest.AssertRepoClean(t, w.remote, canary)
	secrecytest.AssertRepoClean(t, A.repo.Dir(), canary)
}

// state.json is lost after a held path: the note, which yadm never wrote as
// far as the new state knows, is not overwritten or captured.
func TestPathHoldStateLost(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	canary := sealedNoteSynced(t, w, A)
	B.sync()
	pushRaw(t, B, unsealPrivate(t, B, "planted\n"))
	if r := A.sync(); heldOn(r, sec2Private) == nil {
		t.Fatalf("no hold: %+v", r.Holds)
	}
	if err := os.Remove(filepath.Join(A.state, apply.StateFile)); err != nil {
		t.Fatal(err)
	}
	A.sync()
	if got := A.read(sec2Private); !strings.Contains(got, canary.String()) {
		t.Fatalf("the note was overwritten: %q", got)
	}
	editAndTimer(w, A, canary)
	secrecytest.AssertRepoClean(t, w.remote, canary)
}
