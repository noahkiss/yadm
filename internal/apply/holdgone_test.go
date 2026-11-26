package apply

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// TestHoldsHideGoneFile: a hold that goes with its file is gone from Holds
// as soon as the file is, before any sync drops it from the state. A hold
// whose cause outlives the file stays: a held deletion of a managed target,
// a conflict, a weakened-protection or held-path hold, and a hold without
// a target. Holds never writes the state; the next complete scan's
// SettleHolds drops the same holds.
func TestHoldsHideGoneFile(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "a\n"}, manifest.Entry{Target: ".a"})
	w.apply(c)
	if err := os.Remove(w.path(".a")); err != nil { // a held deletion
		t.Fatal(err)
	}
	w.write(".kept", "still here\n")
	st := w.state()
	now := w.clock
	expect := fileHold(st, now, ".expect", model.ScopeShared, model.HoldSealGuard, now, "refused")
	expect.Task = ExpectTask
	untrusted := model.Hold{Task: "setup", Scope: model.ScopeShared, Reason: model.HoldTaskUntrusted, Since: now}
	guard := model.Hold{Task: GuardTask, Scope: model.ScopeShared, Reason: model.HoldProtected, Since: now}
	st.Holds = append(st.Holds,
		// Go with the file.
		fileHold(st, now, ".gated", model.ScopeShared, model.HoldCheckFailed, now, "failed checks: scan"),
		fileHold(st, now, ".untrusted", model.ScopeShared, model.HoldTaskUntrusted, now, "check definition is not allowed"),
		fileHold(st, now, ".new", model.ScopeShared, model.HoldProtected, now, "protected; commit it by name"),
		fileHold(st, now, ".enc/new", "client", model.HoldSealGuard, now, newInEnclaveRootDetail+"not a member"),
		expect,
		// Stay.
		fileHold(st, now, ".kept", model.ScopeShared, model.HoldCheckFailed, now, "failed checks: scan"),
		fileHold(st, now, ".a", model.ScopeShared, model.HoldProtected, now, "deletion; commit it by name"),
		fileHold(st, now, ".a", model.ScopeShared, model.HoldCheckFailed, now, "failed checks: scan"),
		fileHold(st, now, ".conflict", model.ScopeShared, model.HoldConflict, now, "conflict"),
		fileHold(st, now, ".weak", model.ScopeShared, model.HoldSealGuard, now, "the manifest weakened this file's protection (x)"),
		fileHold(st, now, ".mode", model.ScopeShared, model.HoldSealGuard, now, "mode grants a bit the source lacks"),
		floorHold(st, now, ".floor", model.ScopeShared, now, []string{"drops enclave client"}),
		untrusted,
		guard,
	)
	if err := w.eng.State.Save(st); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		".kept:check_failed": true, ".a:protected": true, ".a:check_failed": true,
		".conflict:conflict": true, ".weak:seal_guard": true, ".mode:seal_guard": true,
		".floor:seal_guard": true, "task:setup:task_untrusted": true, "task:manifest-guard:protected": true,
	}
	key := func(h model.Hold) string {
		if h.Target == "" {
			return "task:" + h.Task + ":" + string(h.Reason)
		}
		return string(h.Target) + ":" + string(h.Reason)
	}
	check := func(what string, hs []model.Hold) {
		t.Helper()
		got := map[string]bool{}
		for _, h := range hs {
			got[key(h)] = true
		}
		for k := range want {
			if !got[k] {
				t.Errorf("%s: hold %s is missing", what, k)
			}
		}
		for k := range got {
			if !want[k] {
				t.Errorf("%s: hold %s stayed after its file was gone", what, k)
			}
		}
	}
	hs, err := w.eng.Holds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("Holds", hs)
	if n := len(w.state().Holds); n != 14 {
		t.Fatalf("Holds changed the state: %d holds left, want 14", n)
	}

	drift, err := w.eng.Scan(ctx, ScanOptions{FullHash: true})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.eng.SettleHolds(ctx, drift); err != nil || n != 5 {
		t.Fatalf("settled %d, want 5: %v", n, err)
	}
	check("state after SettleHolds", w.state().Holds)

	// A file that comes back brings back nothing: the hold went with it.
	w.write(".gated", "back\n")
	if hs, err = w.eng.Holds(ctx); err != nil {
		t.Fatal(err)
	}
	check("Holds after the file came back", hs)
}

// TestHoldsDoesNotHangOnSlowMount: Holds stats a held file to see whether
// it is gone. Every stat of a target is bounded, so a hung mount neither
// hangs `status`, `hold list` and the hooks nor hides the hold.
func TestHoldsDoesNotHangOnSlowMount(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	st := w.state()
	now := w.clock
	st.Holds = append(st.Holds, fileHold(st, now, ".slow", model.ScopeShared, model.HoldProtected, now, "protected; commit it by name"))
	if err := w.eng.State.Save(st); err != nil {
		t.Fatal(err)
	}
	cfs := &countFS{hang: w.path(".slow"), block: make(chan struct{})}
	defer close(cfs.block)
	w.eng.fs = cfs
	w.eng.StatTimeout = 100 * time.Millisecond

	done := make(chan []model.Hold, 1)
	go func() {
		hs, err := w.eng.Holds(ctx)
		if err != nil {
			t.Error(err)
		}
		done <- hs
	}()
	select {
	case hs := <-done:
		if len(hs) != 1 || hs[0].Target != ".slow" {
			t.Fatalf("Holds on a hung mount: %+v", hs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Holds hangs on a stat of a held file")
	}
	if n, err := w.eng.SettleHolds(ctx, nil); err != nil || n != 0 {
		t.Fatalf("SettleHolds on a hung mount: settled %d, %v", n, err)
	}
}
