package sync

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

func quick(t *testing.T, m *machine) Report {
	t.Helper()
	r, err := m.s.Run(context.Background(), Options{Auto: true, Push: true, Quick: true})
	if err != nil {
		t.Fatalf("%s: quick sync: %v", m.id, err)
	}
	return r
}

// TestQuickSyncSkipsUntilSomethingMoves: the quick check stops a run when
// nothing moved, and runs in full on local drift, a remote push, the
// periodic interval and a wake gap.
func TestQuickSyncSkipsUntilSomethingMoves(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	A, B := w.machines[a], w.machines[b]
	if r := quick(t, A); r.Skipped || r.Reason != "first run" {
		t.Fatalf("first run: %+v", r)
	}
	quick(t, B)
	if r := quick(t, A); !r.Skipped {
		t.Fatalf("nothing moved, yet a full sync ran: %+v", r)
	}

	// Local drift runs in full and commits (the quiet period has passed on
	// the test clock).
	A.write(pkgList, "tool-one\ntool-two\ntool-q\n")
	r := quick(t, A)
	if r.Skipped || r.Reason != "local drift" || len(r.Committed) != 1 || !r.Pushed {
		t.Fatalf("drift: %+v", r)
	}
	if r := quick(t, A); !r.Skipped {
		t.Fatalf("after its own push: %+v", r)
	}

	// B sees A's push through ls-remote alone.
	if r := quick(t, B); r.Skipped || r.Reason != "remote moved" || B.read(pkgList) != "tool-one\ntool-two\ntool-q\n" {
		t.Fatalf("b after a's push: %+v %q", r, B.read(pkgList))
	}
	if r := quick(t, B); !r.Skipped {
		t.Fatalf("b settled: %+v", r)
	}

	// A held edit is drift every scan; unchanged, it does not count again.
	B.exec.fail = func(_ string, t model.Target) bool { return t == pkgList }
	B.write(pkgList, "tool-one\ntool-two\ntool-q\ntool-held\n")
	if r := quick(t, B); r.Skipped || len(holdsOf(r, model.HoldCheckFailed)) != 1 {
		t.Fatalf("held edit: %+v", r)
	}
	if r := quick(t, B); !r.Skipped {
		t.Fatalf("an unchanged held edit ran a full sync: %+v", r)
	}
	B.write(pkgList, "tool-one\ntool-two\ntool-q\ntool-held-2\n")
	if r := quick(t, B); r.Skipped {
		t.Fatalf("a new edit to a held file was skipped: %+v", r)
	}

	// The periodic full sync and the wake gap.
	w.clock.offset += FullEvery
	if r := quick(t, B); r.Skipped || r.Reason != "wake" {
		t.Fatalf("after a long gap: %+v", r)
	}
	w.clock.offset += WakeGap - time.Second
	if r := quick(t, B); !r.Skipped {
		t.Fatalf("within the wake gap: %+v", r)
	}
	for i := 0; i < 8 && quick(t, B).Skipped; i++ {
		w.clock.offset += WakeGap - time.Second
	}
	if r := quick(t, B); !r.Skipped {
		t.Fatalf("right after a periodic full sync: %+v", r)
	}
}

// TestNudgeAfterPush: a push that moves main runs the nudge with the pushed
// commit; a sync that pushes nothing new does not.
func TestNudgeAfterPush(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	A.s.Nudge = []string{"yadm-nudge"}
	A.sync()
	nudges := func() []extexec.Request {
		var out []extexec.Request
		for _, c := range A.exec.calls {
			if c.Kind == extexec.KindNudge {
				out = append(out, c)
			}
		}
		return out
	}
	if n := nudges(); len(n) != 0 {
		t.Fatalf("nudged with nothing pushed: %+v", n)
	}
	A.write(pkgList, "tool-one\ntool-two\ntool-n\n")
	r := A.sync()
	n := nudges()
	if len(n) != 1 || n[0].Commit != r.Applied || n[0].Event["kind"] != "pushed" {
		t.Fatalf("nudges %+v after %+v", n, r)
	}
}

// TestCommitPushesInTheSameCall: a hook commit is pushed before Commit
// returns, carries the hook trailers and a human subject.
func TestCommitPushesInTheSameCall(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	A.sync()
	A.write(pkgList, "tool-one\ntool-two\ntool-h\n")
	r, err := A.s.Commit(context.Background(), CommitOptions{Paths: []model.Target{pkgList}, Unattended: true,
		Trigger: TriggerHook, Session: "session-1", Tool: "Edit", Push: true})
	if err != nil || len(r.Committed) != 1 || !r.Pushed {
		t.Fatalf("commit: %+v %v", r, err)
	}
	if w.remoteMain() != string(A.main()) {
		t.Fatal("not pushed in the same call")
	}
	cs, err := A.st.Log(context.Background(), string(A.main())+"~1.."+string(A.main()), nil)
	if err != nil || len(cs) != 1 {
		t.Fatalf("log %v %v", cs, err)
	}
	m := cs[0].Message
	if m.Subject != "update "+string(pkgList) || trailer(m, store.TrailerAuto) != TriggerHook ||
		trailer(m, TrailerSession) != "session-1" || trailer(m, TrailerTool) != "Edit" {
		t.Fatalf("message %+v", m)
	}
}

func TestCommitMessageSubjects(t *testing.T) {
	for _, c := range []struct {
		items []MessageItem
		info  MessageInfo
		want  string
	}{
		{[]MessageItem{{".zshrc", "update"}}, MessageInfo{}, "update .zshrc"},
		{[]MessageItem{{".a/x/1", "add"}, {".a/x/2", "add"}, {".a/x/y/3", "add"}}, MessageInfo{}, "add 3 files in .a/x"},
		{[]MessageItem{{".a", "add"}, {".b/c", "update"}}, MessageInfo{}, "update 2 files"},
		{[]MessageItem{{".a", "remove"}}, MessageInfo{Subject: "tidy\nsecond line"}, "tidy"},
	} {
		m := commitMessage(c.info, "m-x", model.ScopeShared, c.items)
		if m.Subject != c.want || trailer(m, store.TrailerAuto) != TriggerManual {
			t.Errorf("%v: %+v", c.items, m)
		}
	}
	m := commitMessage(MessageInfo{Trigger: TriggerStop, Session: "s\nx", Tool: "Write"}, "m-x", "personal", []MessageItem{{".n", "update"}})
	if trailer(m, TrailerSession) != "s x" || trailer(m, store.TrailerScope) != "personal" || trailer(m, store.TrailerAuto) != TriggerStop {
		t.Errorf("trailers %+v", m.Trailers)
	}
}

// TestQuickSyncBacksOffAnUnreachableRemote: a failed remote check skips the
// run and backs off (1 min, doubling, capped) instead of a full sync that
// reaches the same remote; hooks read the backoff; a later answer clears it.
func TestQuickSyncBacksOffAnUnreachableRemote(t *testing.T) {
	if netBackoff(1) != time.Minute || netBackoff(2) != 2*time.Minute || netBackoff(10) != NetBackoffMax {
		t.Fatalf("backoff steps: %s %s %s", netBackoff(1), netBackoff(2), netBackoff(10))
	}
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	quick(t, A)
	gone := w.remote + ".gone"
	if err := os.Rename(w.remote, gone); err != nil {
		t.Fatal(err)
	}
	if r := quick(t, A); !r.Skipped {
		t.Fatalf("a failed remote check ran a full sync: %+v", r)
	}
	if !NetBackingOff(A.state, w.clock.Now()) {
		t.Fatal("no backoff recorded after a failed remote check")
	}
	if r := quick(t, A); !r.Skipped {
		t.Fatalf("within the backoff: %+v", r)
	}
	if err := os.Rename(gone, w.remote); err != nil {
		t.Fatal(err)
	}
	w.clock.offset += 2 * time.Minute
	if r := quick(t, A); !r.Skipped {
		t.Fatalf("remote back, nothing moved: %+v", r)
	}
	if NetBackingOff(A.state, w.clock.Now()) {
		t.Fatal("backoff still set after the remote answered")
	}
}
