package sync

import (
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
