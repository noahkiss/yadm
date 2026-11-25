package sync

import (
	"context"
	"fmt"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
)

// A hold that appears while nothing else changes (no commit, no new tip, no
// alert) republishes the status record at once, with its kind and with the
// facts of a collector that reports the holds, instead of waiting for the
// hourly record. So does a hold that clears. An edit still pending commit
// is not a hold the record counts.
func TestStatusRepublishesWhenHoldsChange(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	ctx := context.Background()
	// The packages collector reports this machine's hold count, as a
	// fleet-alert collector reports hold kinds.
	A.exec.collect = func() []string {
		hs, err := A.eng.Holds(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, h := range hs {
			if h.Reason == model.HoldCheckFailed {
				n++
			}
		}
		return []string{fmt.Sprintf("held-%d", n)}
	}
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
	items := func(st model.Status) string {
		f, ok := st.Observed["packages"]
		if !ok || len(f.Items) != 1 {
			return fmt.Sprint(st.Observed)
		}
		return f.Items[0]
	}
	before, st := read()
	if st.Held != 0 || items(st) != "held-0" {
		t.Fatalf("before: held %d facts %s", st.Held, items(st))
	}

	// A sync that does not auto-commit leaves an edit pending: no hold
	// the record counts, so no record.
	r, err := A.s.Run(ctx, Options{Push: true})
	if err != nil {
		t.Fatal(err)
	}
	A.write(aliases, "alias pending=\"yes\"\n")
	if r, err = A.s.Run(ctx, Options{Push: true}); err != nil || len(r.Pending) == 0 {
		t.Fatalf("pending edit: %+v %v", r, err)
	}
	if id, st := read(); id != before || st.Held != 0 {
		t.Fatalf("a pending edit published held %d (moved %v)", st.Held, id != before)
	}

	// The gate fails the edit: a check_failed hold, nothing committed.
	A.exec.fail = func(_ string, tg model.Target) bool { return tg == aliases }
	r = A.sync()
	if len(r.Committed) != 0 || r.Applied != A.main() || len(holdsOf(r, model.HoldCheckFailed)) == 0 {
		t.Fatalf("gate hold: %+v", r)
	}
	after, st := read()
	if after == before {
		t.Fatal("a new hold did not republish the status record")
	}
	if st.Held != 1 || st.HoldKinds[string(model.HoldCheckFailed)] != 1 {
		t.Fatalf("record: held %d kinds %v", st.Held, st.HoldKinds)
	}
	if items(st) != "held-1" {
		t.Errorf("the record carries collector facts from before the hold: %s", items(st))
	}

	// Nothing changed: no new record.
	A.sync()
	if again, _ := read(); again != after {
		t.Error("an unchanged hold set republished")
	}

	// The edit goes back: the hold settles and the record follows.
	A.exec.fail = nil
	A.write(aliases, w.remoteFile("files/"+string(aliases))+"\n")
	A.sync()
	last, st := read()
	if last == after || st.Held != 0 || len(st.HoldKinds) != 0 || items(st) != "held-0" {
		t.Fatalf("cleared hold: moved %v held %d kinds %v facts %s", last != after, st.Held, st.HoldKinds, items(st))
	}
}

// Collectors run before replay and apply. When the apply raises a hold (a
// held path from a fetched weakening), the record that goes out carries a
// collector's facts from after it, so a fleet alert reading both agrees.
func TestStatusCollectsAgainAfterApplyHolds(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()
	A.s.Guard = &apply.Guard{List: A.allows}
	A.exec.collect = func() []string {
		hs, err := A.eng.Holds(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, h := range hs {
			if h.Task == HoldTaskGuard {
				n++
			}
		}
		return []string{fmt.Sprintf("guard-%d", n)}
	}
	A.sync()
	pushRaw(t, B, unsealPrivate(t, B, "plain\n"))
	if r := A.sync(); heldOn(r, sec2Private) == nil {
		t.Fatalf("no held path: %+v", r.Holds)
	}
	all, err := A.s.Status.ReadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := all[a]
	if st.HoldKinds["seal_guard:"+HoldTaskGuard] != 1 {
		t.Errorf("kinds %v", st.HoldKinds)
	}
	if f := st.Observed["packages"]; len(f.Items) != 1 || f.Items[0] != "guard-1" {
		t.Errorf("the record carries collector facts from before the apply: %+v", f)
	}
}
