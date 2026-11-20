package sync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// The fixture's owned root is .config/shell; no entry covers new files in it.
const (
	rootNewA model.Target = ".config/shell/new-a.sh"
	rootNewB model.Target = ".config/shell/new-b.sh"
)

// TestNewRootFileReachesPeer: a file created in an owned root after the
// root was accepted is captured by a sync, and a peer's sync delivers it.
// The origin then manages it and stops reporting it.
func TestNewRootFileReachesPeer(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]

	A.write(rootNewA, "echo new on a\n")
	w.clock.offset += 3 * time.Hour
	r := A.sync()
	if len(r.Committed) != 1 || !r.Pushed {
		t.Fatalf("new root file not committed and pushed: %+v", r)
	}
	B.sync()
	if got := B.read(rootNewA); got != "echo new on a\n" {
		t.Fatalf("peer got %q", got)
	}
	// The origin manages it now: nothing pending, nothing to commit.
	r = A.sync()
	if len(r.Captured) != 0 || len(r.Pending) != 0 || len(r.Committed) != 0 {
		t.Errorf("origin still reports the shared file: %+v", r)
	}
	st, err := A.eng.State.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Targets[rootNewA]; !ok {
		t.Error("origin does not manage the shared file")
	}
	// An edit on the peer flows back.
	B.write(rootNewA, "echo edited on b\n")
	w.clock.offset += 3 * time.Hour
	B.sync()
	A.sync()
	if got := A.read(rootNewA); got != "echo edited on b\n" {
		t.Errorf("origin got %q after the peer's edit", got)
	}
}

// TestNewRootFileSharedByName is the hook packet's "share" option: an
// unattended commit holds the new file, and `yadm commit <path>` shares it.
func TestNewRootFileSharedByName(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()

	A.write(rootNewA, "echo shared by name\n")
	r, err := A.s.Commit(ctx, CommitOptions{Paths: []model.Target{rootNewA}, Trigger: TriggerHook, Unattended: true, Push: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Committed) != 0 || len(holdsOf(r, model.HoldProtected)) != 1 {
		t.Fatalf("unattended commit of a new root file: %+v", r)
	}
	if r, err = A.s.Commit(ctx, CommitOptions{Paths: []model.Target{rootNewA}, Push: true}); err != nil {
		t.Fatal(err)
	}
	if len(r.Committed) != 1 || !r.Pushed {
		t.Fatalf("commit by name: %+v", r)
	}
	B.sync()
	if got := B.read(rootNewA); got != "echo shared by name\n" {
		t.Fatalf("peer got %q", got)
	}
	if r := A.sync(); len(r.Captured) != 0 || len(r.Holds) != 0 {
		t.Errorf("origin after sharing: %+v", r)
	}
}

// TestNewRootFilesOnTwoMachinesConverge: two machines each create a new
// file in the root at the same time; both files reach both machines.
func TestNewRootFilesOnTwoMachinesConverge(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]

	A.write(rootNewA, "echo a\n")
	B.write(rootNewB, "echo b\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	rb := B.sync()
	if len(rb.Holds) != 0 {
		t.Fatalf("second machine holds: %+v", rb.Holds)
	}
	A.sync()
	for _, m := range []*machine{A, B} {
		if got := m.read(rootNewA); got != "echo a\n" {
			t.Errorf("%s: %s = %q", m.id, rootNewA, got)
		}
		if got := m.read(rootNewB); got != "echo b\n" {
			t.Errorf("%s: %s = %q", m.id, rootNewB, got)
		}
	}
	if A.main() != B.main() {
		t.Errorf("machines diverged: %s %s", A.main(), B.main())
	}
}

// TestBaselineRootFileStaysLocal: a file that was in the root before it
// was accepted is held, never shared automatically.
func TestBaselineRootFileStaysLocal(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, b)
	B := w.machines[b]
	B.sync()
	A := w.newMachine(a)
	w.machines[a] = A
	A.write(rootNewA, "echo old local\n") // before the first apply accepts the root
	A.sync()
	w.clock.offset += 3 * time.Hour
	r := A.sync()
	if len(r.Committed) != 0 || len(holdsOf(r, model.HoldProtected)) != 1 {
		t.Fatalf("baseline file: %+v", r)
	}
	B.sync()
	if _, err := B.repo.ReadPath(context.Background(), B.main(), "files/"+model.SourcePath(rootNewA)); err == nil {
		t.Error("baseline file reached the source")
	}
}

// TestRootExpansionAddsNothingAtSeed: in the seed source every file under
// the root's directory is named by an entry (os.sh has two variants, one
// per OS), so expansion adds no target on any host.
func TestRootExpansionAddsNothingAtSeed(t *testing.T) {
	a, b, c := fixture.HostA, fixture.HostB, fixture.HostC
	w := newWorld(t, nil, a, b, c)
	for _, id := range []model.MachineID{a, b, c} {
		m := w.machines[id]
		snap, err := m.eng.Load(context.Background(), m.main())
		if err != nil {
			t.Fatal(err)
		}
		for tg, r := range snap.Plan.Targets {
			if r.Index == apply.RootIndex {
				t.Errorf("%s: root expansion added %s (%s)", id, tg, r.Source)
			}
		}
	}
}

// TestNewFileInEnclaveRootStaysSealed: a member's new file in an enclave
// root is shared sealed: git holds only ciphertext, the member's peer in
// the root's types gets nothing it cannot open, and a non-member's home
// and clone never see the plaintext.
func TestNewFileInEnclaveRootStaysSealed(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, func(f *fixture.Fixture) {
		appendManifest(t, f, "\n[[root]]\npath = \".config/private-notes\"\nenclave = \"personal\"\n")
	}, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	canary := secrecytest.NewCanary(t, "root-new")
	tg := model.Target(".config/private-notes/new.md")
	A.write(tg, "note "+canary.String()+"\n")
	w.clock.offset += 3 * time.Hour
	if r := A.sync(); len(r.Committed) != 1 || !r.Pushed {
		t.Fatalf("enclave root file not shared: %+v", r)
	}
	blob := git(t, w.remote, "show", "main:sealed/personal/"+string(tg))
	if !crypt.IsSealedFile([]byte(blob)) {
		t.Fatal("enclave root file stored without sealing")
	}
	B.sync()
	if _, err := os.Stat(B.path(tg)); err == nil {
		t.Error("non-member got the enclave root file")
	}
	// The origin manages it as a sealed target.
	if r := A.sync(); len(r.Captured) != 0 {
		t.Errorf("origin still captures it: %+v", r)
	}
	secrecytest.AssertRepoClean(t, w.remote, canary)
	for _, m := range []*machine{A, B} {
		secrecytest.AssertRepoClean(t, m.repo.Dir(), canary)
	}
	secrecytest.AssertTreeClean(t, B.home, canary)
	secrecytest.AssertTreeClean(t, B.state, canary)
}

// TestRetagAfterShareNarrowsIt: a shared root file retagged to one type
// leaves the machines without it, and the root does not bring it back.
func TestRetagAfterShareNarrowsIt(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()
	A.write(rootNewA, "echo shared\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	B.sync()
	if B.read(rootNewA) != "echo shared\n" {
		t.Fatal("not shared")
	}
	c, err := A.eng.Retag(ctx, rootNewA, apply.RetagOptions{Types: []model.TypeName{"personal"}})
	if err != nil {
		t.Fatal(err)
	}
	last := len(c.Changes) - 1
	target := apply.Capture{Changes: c.Changes[last:], Paths: c.Paths, Scopes: c.Scopes}
	if _, err := A.s.Commit(ctx, CommitOptions{Message: "retag", Capture: &target, Changes: c.Changes[:last], Push: true}); err != nil {
		t.Fatal(err)
	}
	B.sync()
	if _, err := os.Stat(B.path(rootNewA)); err == nil {
		t.Error("the other type kept the retagged file")
	}
	snap, err := B.eng.Load(ctx, B.main())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.Plan.Targets[rootNewA]; ok {
		t.Error("the root brought the retagged file back")
	}
	if A.read(rootNewA) != "echo shared\n" {
		t.Error("the retag's own type lost the file")
	}
}

// TestSameNewRootFileOnTwoMachines: both machines create the same path
// with different bytes. The second to sync holds a conflict and keeps its
// own bytes; nothing fails.
func TestSameNewRootFileOnTwoMachines(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.write(rootNewA, "echo from a\n")
	B.write(rootNewA, "echo from b\n")
	w.clock.offset += 3 * time.Hour
	A.sync()
	r, err := B.s.Run(context.Background(), Options{Auto: true, Push: true})
	if err != nil {
		t.Fatalf("second machine's sync failed: %v", err)
	}
	if got := B.read(rootNewA); got != "echo from b\n" {
		t.Errorf("second machine's bytes overwritten: %q", got)
	}
	if len(holdsOf(r, model.HoldConflict)) == 0 && len(holdsOf(r, model.HoldDrifted)) == 0 {
		t.Errorf("no hold for the clash: %+v", r)
	}
	if got := w.remoteFile("files/" + string(rootNewA)); got != "echo from a" {
		t.Errorf("remote %q", got)
	}
}

func appendManifest(t *testing.T, f *fixture.Fixture, s string) {
	t.Helper()
	p := filepath.Join(f.Root, "manifest.toml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, s...), 0o644); err != nil {
		t.Fatal(err)
	}
}
