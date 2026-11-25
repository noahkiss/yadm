package sync

import (
	"context"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
)

// A hold that appears while nothing else changes (no commit, no new tip, no
// alert) republishes the status record at once, with its kind, instead of
// waiting for the hourly record. So does a hold that clears.
func TestStatusRepublishesWhenHoldsChange(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	ctx := context.Background()
	A.sync()
	A.sync()
	ref := fleet.StatusRef(a)
	read := func() (model.CommitID, model.Status) {
		t.Helper()
		id, err := A.st.ResolveRef(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		all, err := A.s.Status.ReadAll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return id, all[a]
	}
	before, st := read()
	if st.Held != 0 {
		t.Fatalf("held %d before", st.Held)
	}

	// A sync that does not auto-commit: the edit is captured, not
	// committed, and held as drift.
	manual := func() Report {
		t.Helper()
		r, err := A.s.Run(ctx, Options{Push: true})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	A.write(aliases, "alias quiet=\"yes\"\n")
	r := manual()
	if len(r.Committed) != 0 || r.Applied != A.main() {
		t.Fatalf("the edit committed or moved main: %+v", r)
	}
	after, st := read()
	if after == before {
		t.Fatal("a new hold did not republish the status record")
	}
	if st.Held == 0 || st.HoldKinds[string(model.HoldDrifted)] == 0 {
		t.Fatalf("record: held %d kinds %v", st.Held, st.HoldKinds)
	}

	// Nothing changed: no new record.
	manual()
	if again, _ := read(); again != after {
		t.Error("an unchanged hold set republished")
	}

	// The edit goes back: the hold settles and the record follows.
	A.write(aliases, A.w.remoteFile("files/"+string(aliases))+"\n")
	manual()
	last, st := read()
	if last == after || st.Held != 0 || len(st.HoldKinds) != 0 {
		t.Fatalf("cleared hold: moved %v held %d kinds %v", last != after, st.Held, st.HoldKinds)
	}
}
