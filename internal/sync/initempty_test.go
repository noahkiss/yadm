package sync

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
)

// TestInitAgainstEmptyRemoteThenFetch is the importer machine at cutover:
// it clones the remote while it is still empty (unborn main), a writer
// pushes the imported source, and the first sync moves the worktree from
// nothing to the fetched main. The clone must stay clean, and later syncs
// must push.
func TestInitAgainstEmptyRemoteThenFetch(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil)
	w.remote = filepath.Join(t.TempDir(), "empty.git")
	git(t, filepath.Dir(w.remote), "init", "-q", "--bare", "-b", "main", w.remote)
	A := w.newMachine(a)
	w.machines[a] = A
	if head := A.main(); head != "" {
		t.Fatalf("clone of an empty remote has main %s", head)
	}

	// The writer pushes the import.
	git(t, w.f.Root, "push", "-q", w.remote, "main")

	r := A.sync()
	if hs := holdsOf(r, model.HoldSourceDirty); len(hs) != 0 {
		t.Fatalf("first sync after the import: source_dirty %+v", hs)
	}
	if st := git(t, A.repo.Dir(), "status", "--porcelain"); st != "" {
		t.Fatalf("source clone not clean after the first sync:\n%s", st)
	}
	if A.main() != model.CommitID(w.remoteMain()) || r.Applied != A.main() {
		t.Fatalf("main %s, remote %s, applied %s", A.main(), w.remoteMain(), r.Applied)
	}
	if got := A.read(aliases); got == "" {
		t.Fatal("aliases not applied")
	}

	// A later edit commits and pushes.
	A.write(aliases, "alias ll=\"ls -la\"\nalias after=\"init\"\n")
	w.clock.offset += 3 * time.Hour
	r = A.sync()
	if hs := holdsOf(r, model.HoldSourceDirty); len(hs) != 0 {
		t.Fatalf("second sync: source_dirty %+v", hs)
	}
	if len(r.Committed) != 1 || !r.Pushed {
		t.Fatalf("edit not committed and pushed: %+v", r)
	}
	if st := git(t, A.repo.Dir(), "status", "--porcelain"); st != "" {
		t.Fatalf("source clone not clean after the second sync:\n%s", st)
	}
}

// TestCommitThenFetchFailsStillAppliesInFull: the apply after a commit
// covers only the committed targets; when the fetch then fails (a late
// network), the run still ends with a full apply of the new main.
func TestCommitThenFetchFailsStillAppliesInFull(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	A.sync()
	A.write(aliases, "alias ll=\"ls -la\"\nalias offline=\"yes\"\n")
	w.clock.offset += 3 * time.Hour
	moved := w.remote + ".away"
	if err := os.Rename(w.remote, moved); err != nil {
		t.Fatal(err)
	}
	r, err := A.s.Run(context.Background(), Options{Auto: true, Push: true})
	if err == nil {
		t.Fatal("sync with the remote gone did not fail")
	}
	if len(r.Committed) != 1 {
		t.Fatalf("edit not committed locally: %+v", r)
	}
	st, err := A.eng.State.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Applied != A.main() {
		t.Errorf("state applied %s, main %s: the full apply did not run", st.Applied, A.main())
	}
	if err := os.Rename(moved, w.remote); err != nil {
		t.Fatal(err)
	}
	if r := A.sync(); !r.Pushed {
		t.Errorf("next sync did not push: %+v", r)
	}
}

// TestFullApplyOncePerRun: within one run, a second full apply of the
// commit already applied in full does nothing, unless integrate raised
// holds (again), which apply must see.
func TestFullApplyOncePerRun(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	A.sync()
	ctx := context.Background()
	end := A.s.begin()
	defer end()
	tip := A.main()
	var rep Report
	if _, err := A.s.moveAndApply(ctx, &rep, tip, false); err != nil {
		t.Fatal(err)
	}
	// A deleted target is held by any apply that runs.
	if err := os.Remove(A.path(pkgList)); err != nil {
		t.Fatal(err)
	}
	held := func() bool {
		st, err := A.eng.State.Load()
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range st.Holds {
			if h.Target == pkgList {
				return true
			}
		}
		return false
	}
	if _, err := A.s.moveAndApply(ctx, &rep, tip, false); err != nil {
		t.Fatal(err)
	}
	if held() || rep.Applied != tip {
		t.Fatalf("second full apply of %s in one run ran (held %v, applied %s)", tip, held(), rep.Applied)
	}
	if _, err := A.s.moveAndApply(ctx, &rep, tip, true); err != nil {
		t.Fatal(err)
	}
	if !held() {
		t.Fatal("apply after integrate holds did not run")
	}
}
