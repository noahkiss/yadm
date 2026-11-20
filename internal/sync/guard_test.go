package sync

import (
	"context"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// pushRaw commits changes on m's main and pushes, bypassing sync, as any
// machine that can push could.
func pushRaw(t *testing.T, m *machine, changes []store.Change) model.CommitID {
	t.Helper()
	ctx := context.Background()
	head := m.main()
	id, err := m.st.CommitPaths(ctx, head, changes, store.Message{Subject: "raw", Trailers: []store.Trailer{{Key: store.TrailerMachine, Value: string(m.id)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.st.UpdateRef(ctx, store.RefMain, id, head); err != nil {
		t.Fatal(err)
	}
	if err := m.st.Push(ctx, []string{store.RefMain + ":" + store.RefMain}); err != nil {
		t.Fatal(err)
	}
	return id
}

func holdTask(r Report, task string) *model.Hold {
	for i, h := range r.Holds {
		if h.Task == task {
			return &r.Holds[i]
		}
	}
	return nil
}

func TestKeyLogRewriteRefused(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()
	entry := crypt.LogPath("personal", 1)
	orig, err := B.st.ReadPath(ctx, B.main(), entry)
	if err != nil {
		t.Fatal(err)
	}
	forged := pushRaw(t, B, []store.Change{
		{Path: entry, Blob: append(append([]byte(nil), orig...), []byte("# rewritten\n")...), Mode: 0o100644},
		{Path: "files/.config/shell/aliases.sh", Blob: []byte("alias evil=\"x\"\n"), Mode: 0o100644},
	})

	before := A.main()
	A.write(pkgList, "tool-one\ntool-two\ntool-a\n")
	r := A.sync()
	h := holdTask(r, HoldTaskKeyLog)
	if h == nil || !strings.Contains(h.Detail, "rewr") {
		t.Fatalf("no key-log hold: %+v", r.Holds)
	}
	if len(r.Alerts) != 1 || r.Alerts[0].Kind != AlertKeyLogRewrite || r.Alerts[0].Commit != forged {
		t.Fatalf("alerts %+v", r.Alerts)
	}
	if strings.Contains(A.read(aliases), "evil") {
		t.Fatal("the refused source was applied")
	}
	if ok, _ := A.st.IsAncestor(ctx, before, A.main()); !ok || A.main() == forged {
		t.Fatal("local main moved onto the refused remote")
	}
	if w.remoteMain() != string(forged) {
		t.Fatal("refused machine pushed main over the remote")
	}
	// A second sync keeps refusing, without a second alert.
	r = A.sync()
	if holdTask(r, HoldTaskKeyLog) == nil || len(r.Alerts) != 0 {
		t.Fatalf("second sync: holds %+v alerts %+v", r.Holds, r.Alerts)
	}

	// The fix: drop the rewriting commit upstream (history, not a revert,
	// since entries never change in history). The hold clears; sync resumes.
	git(t, w.remote, "update-ref", "refs/heads/main", string(before))
	r = A.sync()
	if holdTask(r, HoldTaskKeyLog) != nil || !r.Pushed {
		t.Fatalf("after the fix: %+v", r)
	}
	if !strings.Contains(w.remoteFile("files/.config/packages/list"), "tool-a") {
		t.Error("A's commit did not land after the fix")
	}
}

func TestKeyLogAppendRules(t *testing.T) {
	w := newWorld(t, nil, fixture.HostA)
	A := w.machines[fixture.HostA]
	A.sync()
	ctx := context.Background()
	base := A.main()
	head := A.main()
	commit := func(ch store.Change) model.CommitID {
		id, err := A.st.CommitPaths(ctx, head, []store.Change{ch}, store.Message{Subject: "k"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	next := commit(store.Change{Path: crypt.LogPath("personal", 2), Blob: []byte("x"), Mode: 0o100644})
	if v, err := A.s.keyLogViolations(ctx, base, next); err != nil || len(v) != 0 {
		t.Errorf("next entry refused: %v %v", v, err)
	}
	skip := commit(store.Change{Path: crypt.LogPath("personal", 4), Blob: []byte("x"), Mode: 0o100644})
	if v, _ := A.s.keyLogViolations(ctx, base, skip); len(v) != 1 {
		t.Errorf("a skipped seq was accepted: %v", v)
	}
	del := commit(store.Change{Path: crypt.LogPath("personal", 1), Delete: true})
	if v, _ := A.s.keyLogViolations(ctx, base, del); len(v) == 0 {
		t.Error("a deleted entry was accepted")
	}
}

type denyGuard struct{ calls int }

func (g *denyGuard) Allow(_ context.Context, from, to *apply.Snapshot) (bool, string, error) {
	g.calls++
	if from == nil || to == nil {
		return true, "", nil
	}
	return false, "entry .config/notes/private.md lost its enclave", nil
}

func TestRemoteGuardRefusesFetchedSource(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	g := &denyGuard{}
	A.s.Guard = g
	pushRaw(t, B, []store.Change{{Path: "files/.config/shell/aliases.sh", Blob: []byte("alias guarded=\"x\"\n"), Mode: 0o100644}})
	before := A.main()
	r := A.sync()
	if h := holdTask(r, HoldTaskGuard); h == nil || !strings.Contains(h.Detail, "lost its enclave") {
		t.Fatalf("holds %+v", r.Holds)
	}
	if g.calls == 0 || A.main() != before || strings.Contains(A.read(aliases), "alias guarded") {
		t.Fatalf("refused source applied: calls %d main moved %v holds %+v", g.calls, A.main() != before, r.Holds)
	}
	A.s.Guard = nil
	r = A.sync()
	if holdTask(r, HoldTaskGuard) != nil || !strings.Contains(A.read(aliases), "alias guarded") {
		t.Fatalf("after allowing: %+v", r.Holds)
	}
}

func TestPreExistingFileUnderNewRootNotCommitted(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()

	old := model.Target(".config/private-dir/old.txt")
	A.write(old, "pre-existing\n")
	man, err := B.st.ReadPath(ctx, B.main(), "manifest.toml")
	if err != nil {
		t.Fatal(err)
	}
	man = append(man, []byte("\n[[root]]\npath = \".config/private-dir\"\n")...)
	pushRaw(t, B, []store.Change{{Path: "manifest.toml", Blob: man, Mode: 0o100644}})
	A.sync() // applies the new root
	r := A.sync()
	if len(r.Committed) != 0 {
		t.Fatalf("pre-existing file committed: %+v", r)
	}
	var held bool
	for _, h := range holdsOf(r, model.HoldProtected) {
		held = held || h.Target == old
	}
	if !held {
		t.Fatalf("holds %+v", r.Holds)
	}
	// A file made after the root arrived is captured and committed.
	fresh := model.Target(".config/private-dir/new.txt")
	A.write(fresh, "new\n")
	r = A.sync()
	if len(r.Committed) != 1 {
		t.Fatalf("new file: %+v", r)
	}
	if got := w.remoteFile("files/.config/private-dir/new.txt"); got != "new" {
		t.Errorf("remote new.txt %q", got)
	}
	if out := git(t, w.remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(out, "old.txt") {
		t.Error("pre-existing file reached the remote")
	}
	// An edit after the root arrived does not make it new.
	A.write(old, "pre-existing, edited\n")
	r = A.sync()
	if len(r.Committed) != 0 {
		t.Fatalf("edited pre-existing file committed: %+v", r)
	}
	if out := git(t, w.remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(out, "old.txt") {
		t.Error("edited pre-existing file reached the remote")
	}
	// Named, it commits manually.
	rc, err := A.s.Commit(ctx, CommitOptions{Paths: []model.Target{old}})
	if err != nil || len(rc.Committed) != 1 {
		t.Fatalf("manual commit of a named pre-existing file: %+v %v", rc, err)
	}
}
