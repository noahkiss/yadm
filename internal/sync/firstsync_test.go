package sync

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

// forgeKeyLog has B push a commit that replaces the personal seq-1 key-log
// entry with one B signed itself, plus an aliases file holding evil.
func forgeKeyLog(t *testing.T, w *world, B *machine, evil string) model.CommitID {
	t.Helper()
	ctx := context.Background()
	entry := crypt.LogPath("personal", 1)
	orig, err := B.st.ReadPath(ctx, B.main(), entry)
	if err != nil {
		t.Fatal(err)
	}
	head, _, err := crypt.Create("personal", w.f.Identities[B.id], w.f.Recovery.Member(), crypt.MemPins())
	if err != nil {
		t.Fatal(err)
	}
	rewrite, err := crypt.MarshalLogEntry(head)
	if err != nil {
		t.Fatal(err)
	}
	if string(rewrite) == string(orig) {
		t.Fatal("forged entry equals the original")
	}
	return pushRaw(t, B, []store.Change{
		{Path: entry, Blob: rewrite, Mode: 0o100644},
		{Path: "files/.config/shell/aliases.sh", Blob: []byte("alias evil=\"" + evil + "\"\n"), Mode: 0o100644},
	})
}

// tick runs one sync of kind i%3: a timer sync, a quick sync (which may
// stop at its cheap check when nothing moved), or a manual commit that
// pushes. Every kind that fetches judges the source through the same guard.
func tick(t *testing.T, m *machine, i int) Report {
	t.Helper()
	m.w.clock.offset += 3 * time.Hour
	ctx := context.Background()
	var r Report
	var err error
	switch i % 3 {
	case 0:
		return m.sync()
	case 1:
		r, err = m.s.Run(ctx, Options{Auto: true, Push: true, Quick: true})
	default:
		r, err = m.s.Commit(ctx, CommitOptions{Push: true})
	}
	if err != nil && !strings.Contains(err.Error(), "nothing to commit") {
		t.Fatalf("tick %d: %v", i, err)
	}
	return r
}

// A first sync (nothing accepted yet) guards against the remote main the
// clone had before this run's fetch, not the fetched one: the fetch runs
// before the guard, so a base read afterwards would compare a source with
// itself. The refusal holds on every later sync until the remote drops the
// rewrite; a fetch that moved origin/main does not make the forged source
// trusted.
func TestFirstSyncGuardsAgainstPreFetchRemote(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(b) // A has cloned and never synced
	A, B := w.machines[a], w.machines[b]
	if A.s.accepted() != "" {
		t.Fatal("A accepted a source before its first sync")
	}
	ctx := context.Background()
	clean := B.main()
	evil := secrecytest.NewCanary(t, "forged alias")
	forged := forgeKeyLog(t, w, B, evil.String())

	notes := model.Target(".config/notes/private.md")
	edit := secrecytest.NewCanary(t, "edit while refused")
	alerts := 0
	for i := 0; i < 6; i++ {
		if i == 2 {
			// A sealed edit made while the remote is refused.
			A.write(notes, "private "+edit.String()+"\n")
		}
		r := tick(t, A, i)
		alerts += len(r.Alerts)
		if holdTask(r, HoldTaskKeyLog) == nil {
			t.Fatalf("tick %d took a key-log rewrite: holds %+v", i, r.Holds)
		}
		if strings.Contains(A.read(aliases), "evil") {
			t.Fatalf("tick %d applied the refused source", i)
		}
		secrecytest.AssertTreeClean(t, A.home, evil)
		if ok, _ := A.st.IsAncestor(ctx, forged, A.main()); ok {
			t.Fatalf("tick %d: local main took the forged commit", i)
		}
		if w.remoteMain() != string(forged) {
			t.Fatalf("tick %d pushed main over the refused remote", i)
		}
		if A.s.accepted() == forged {
			t.Fatalf("tick %d recorded the forged commit as accepted", i)
		}
	}
	if alerts != 1 {
		t.Errorf("%d alerts over the ticks, want 1", alerts)
	}
	if !strings.Contains(A.read(notes), edit.String()) {
		t.Fatal("the sealed edit is gone from the target")
	}
	secrecytest.AssertRepoClean(t, w.remote, edit)
	secrecytest.AssertRepoClean(t, A.repo.Dir(), edit)

	// The documented fix: drop the rewriting commit upstream. The hold
	// clears, the record advances and A's work goes out.
	git(t, w.remote, "update-ref", "refs/heads/main", string(clean))
	r := A.sync()
	if holdTask(r, HoldTaskKeyLog) != nil || !r.Pushed {
		t.Fatalf("after the fix: holds %+v pushed %v", r.Holds, r.Pushed)
	}
	if strings.Contains(A.read(aliases), "evil") || A.main() != model.CommitID(w.remoteMain()) {
		t.Fatal("after the fix: A is not on the clean remote")
	}
	if A.s.accepted() == "" || A.s.accepted() == forged {
		t.Fatalf("after the fix: accepted %q", A.s.accepted())
	}
	secrecytest.AssertTreeClean(t, A.home, evil)
	secrecytest.AssertRepoClean(t, w.remote, edit)
	secrecytest.AssertRepoClean(t, A.repo.Dir(), edit)
	// B is not a member of personal: the edit never reaches it.
	B.sync()
	secrecytest.AssertTreeClean(t, B.home, edit)
	secrecytest.AssertTreeClean(t, B.state, edit)
	secrecytest.AssertRepoClean(t, B.repo.Dir(), edit)
}

// The fetch records the start before it moves origin/main: a run whose
// fetch succeeded but that then stopped (the sync lock was held) leaves the
// pre-fetch start, not the forged commit, for the next sync.
func TestFetchRecordsStartBeforeMovingOriginMain(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(b)
	A, B := w.machines[a], w.machines[b]
	forged := forgeKeyLog(t, w, B, "x")
	release, err := FileLockTimeout(A.state, time.Second).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	A.s.Lock = FileLockTimeout(A.state, 100*time.Millisecond)
	if _, err := A.s.Run(context.Background(), Options{Auto: true, Push: true}); err == nil {
		t.Fatal("run with the sync lock held did not fail")
	}
	release()
	origin, err := A.st.ResolveRef(context.Background(), store.RemoteMain)
	if err != nil || origin != forged {
		t.Fatalf("the fetch did not run: origin %s %v", origin, err)
	}
	if A.s.accepted() == forged || A.s.accepted() == "" {
		t.Fatalf("record %q after the stopped run", A.s.accepted())
	}
	if r := A.sync(); holdTask(r, HoldTaskKeyLog) == nil || strings.Contains(A.read(aliases), "evil") {
		t.Fatalf("next sync took the forged source: holds %+v", r.Holds)
	}
}

// A machine that refused a first sync before the accepted record existed
// (no record, an open hold, origin/main at the forged commit) starts from
// local main, not from origin/main.
func TestRefusalWithoutRecordStartsFromLocalMain(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(b)
	A, B := w.machines[a], w.machines[b]
	clean := B.main()
	forged := forgeKeyLog(t, w, B, "x")
	if r := A.sync(); holdTask(r, HoldTaskKeyLog) == nil {
		t.Fatalf("first sync: holds %+v", r.Holds)
	}
	if err := os.Remove(filepath.Join(A.state, AcceptedFile)); err != nil {
		t.Fatal(err)
	}
	// A notes push seeds through SeedStart with origin/main, the forged
	// commit: the open hold makes it record local main.
	ctx := context.Background()
	origin, err := A.st.ResolveRef(ctx, store.RemoteMain)
	if err != nil || origin != forged {
		t.Fatalf("origin %s %v", origin, err)
	}
	holds, err := A.eng.Holds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SeedStart(ctx, A.st, A.state, holds, origin); err != nil {
		t.Fatal(err)
	}
	if id := A.s.accepted(); id != A.main() {
		t.Fatalf("seeded %q, want local main %s", id, A.main())
	}
	// A sync with no record takes the same rule.
	if err := os.Remove(filepath.Join(A.state, AcceptedFile)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r := A.sync()
		if holdTask(r, HoldTaskKeyLog) == nil || strings.Contains(A.read(aliases), "evil") {
			t.Fatalf("tick %d without a record: holds %+v", i, r.Holds)
		}
		if A.s.accepted() == forged {
			t.Fatalf("tick %d recorded the forged commit", i)
		}
	}
	git(t, w.remote, "update-ref", "refs/heads/main", string(clean))
	if r := A.sync(); holdTask(r, HoldTaskKeyLog) != nil || A.main() != model.CommitID(w.remoteMain()) {
		t.Fatalf("after the fix: main %s holds %+v", A.main(), r.Holds)
	}
}

// A machine that cloned an empty remote records that start: history a peer
// pushed later that rewrites a key-log entry stays refused on every sync.
func TestEmptyCloneRefusesRewrittenHistory(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil)
	w.remote = filepath.Join(t.TempDir(), "empty.git")
	git(t, filepath.Dir(w.remote), "init", "-q", "--bare", "-b", "main", w.remote)
	A := w.newMachine(a)
	w.machines[a] = A
	git(t, w.f.Root, "push", "-q", w.remote, "main")
	B := w.newMachine(b)
	w.machines[b] = B
	clean := B.main()
	forgeKeyLog(t, w, B, "x")
	for i := 0; i < 4; i++ {
		r := tick(t, A, i)
		if holdTask(r, HoldTaskKeyLog) == nil {
			t.Fatalf("tick %d took rewritten history: holds %+v", i, r.Holds)
		}
		if b, _ := os.ReadFile(A.path(aliases)); strings.Contains(string(b), "evil") || A.main() != "" {
			t.Fatalf("tick %d applied the refused source", i)
		}
		if id, ok := A.s.acceptedRecord(); !ok || id != "" {
			t.Fatalf("tick %d: record %q %v, want the empty start", i, id, ok)
		}
	}
	git(t, w.remote, "update-ref", "refs/heads/main", string(clean))
	r := A.sync()
	if holdTask(r, HoldTaskKeyLog) != nil || A.main() != clean || A.read(aliases) == "" {
		t.Fatalf("after the fix: main %s holds %+v", A.main(), r.Holds)
	}
	if A.s.accepted() != clean {
		t.Fatalf("accepted %q, want %s", A.s.accepted(), clean)
	}
}

// A manifest-guard weakening on a first sync holds its target on every
// later sync until `protection allow` names it. The rest of the fetch is
// taken at once, and the held target is never written.
func TestFirstSyncManifestGuardPersistsUntilAllowed(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()
	A.s.Guard = &apply.Guard{List: A.allows}
	man, err := B.st.ReadPath(ctx, B.main(), "manifest.toml")
	if err != nil {
		t.Fatal(err)
	}
	weak := strings.Replace(string(man), "target = \".ssh/config\"\nregions = true\n", "target = \".ssh/config\"\n", 1)
	if weak == string(man) {
		t.Fatal("fixture manifest changed; update the test")
	}
	pushed := pushRaw(t, B, []store.Change{{Path: "manifest.toml", Blob: []byte(weak), Mode: 0o100644}})
	for i := 0; i < 4; i++ {
		r := tick(t, A, i)
		if h := holdTask(r, HoldTaskGuard); h == nil || h.Target != ".ssh/config" || A.main() != pushed {
			t.Fatalf("tick %d: main at the fetch %v holds %+v", i, A.main() == pushed, r.Holds)
		}
		if _, err := os.Stat(A.path(".ssh/config")); err == nil {
			t.Fatalf("tick %d: the held target was written", i)
		}
	}
	if err := A.eng.AllowProtection(ctx, A.main(), ".ssh/config"); err != nil {
		t.Fatal(err)
	}
	r := A.sync()
	if holdTask(r, HoldTaskGuard) != nil {
		t.Fatalf("after allow: holds %+v", r.Holds)
	}
	if _, err := os.Stat(A.path(".ssh/config")); err != nil {
		t.Fatalf("after allow: %v", err)
	}
	if A.s.accepted() != pushed {
		t.Fatalf("accepted %q, want %s", A.s.accepted(), pushed)
	}
}

func TestSeedAcceptedNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	if _, ok := ReadAccepted(dir); ok {
		t.Fatal("record in an empty directory")
	}
	if err := SeedAccepted(dir, ""); err != nil {
		t.Fatal(err)
	}
	if id, ok := ReadAccepted(dir); !ok || id != "" {
		t.Fatalf("empty start: %q %v", id, ok)
	}
	if err := SeedAccepted(dir, "abc"); err != nil {
		t.Fatal(err)
	}
	if id, _ := ReadAccepted(dir); id != "" {
		t.Fatalf("seed replaced a record: %q", id)
	}
}
