package sync

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

func TestConflictHeldPerFileOthersSync(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]

	A.write(aliases, "alias ll=\"ls -A\"\nalias gs=\"status-tool\"\n")
	A.sync()
	B.write(aliases, "alias ll=\"ls -B\"\nalias gs=\"status-tool\"\n")
	B.write(pkgList, "tool-one\ntool-two\ntool-b\n")
	r := B.sync()

	cs := holdsOf(r, model.HoldConflict)
	if len(cs) != 1 || cs[0].Target != aliases || cs[0].Ours == "" || cs[0].Theirs == "" || cs[0].Base == "" {
		t.Fatalf("conflict holds %+v", r.Holds)
	}
	if len(holdsOf(r, model.HoldDrifted)) != 0 {
		t.Errorf("a conflict also reported as drift: %+v", r.Holds)
	}
	// The other file landed and was pushed; this machine's side stays in $HOME.
	if got := w.remoteFile("files/.config/packages/list"); !strings.Contains(got, "tool-b") {
		t.Errorf("remote list %q", got)
	}
	if got := w.remoteFile("files/.config/shell/aliases.sh"); !strings.Contains(got, "ls -A") {
		t.Errorf("remote aliases %q", got)
	}
	if got := B.read(aliases); !strings.Contains(got, "ls -B") {
		t.Errorf("B's side overwritten: %q", got)
	}
	// The conflicted commit is kept on the local-only held ref.
	held, err := B.st.ResolveRef(context.Background(), store.RefHeld(b))
	if err != nil || held == "" {
		t.Fatalf("held ref: %q %v", held, err)
	}
	if out := git(t, w.remote, "for-each-ref", "refs/yadm/held/"); out != "" {
		t.Errorf("held ref pushed: %s", out)
	}
	if !hasTrailerResolved(r, "hold") {
		t.Errorf("resolutions %+v", r.Resolutions)
	}

	// The next sync neither recommits the held file nor overwrites it.
	r2 := B.sync()
	if len(r2.Committed) != 0 {
		t.Errorf("held file recommitted: %+v", r2)
	}
	if got := B.read(aliases); !strings.Contains(got, "ls -B") {
		t.Errorf("B's side overwritten on resync: %q", got)
	}
	// A touch plus the daily full-hash pass re-hash the file; the local side
	// still stays on disk.
	w.clock.offset += 25 * time.Hour
	now := time.Now()
	os.Chtimes(B.path(aliases), now, now)
	if r3 := B.sync(); len(r3.Committed) != 0 {
		t.Errorf("held file recommitted after a re-hash: %+v", r3)
	}
	if got := B.read(aliases); !strings.Contains(got, "ls -B") {
		t.Errorf("B's side overwritten after a re-hash: %q", got)
	}
	if got := w.remoteFile("files/.config/shell/aliases.sh"); !strings.Contains(got, "ls -A") {
		t.Errorf("remote aliases changed: %q", got)
	}
	A.sync()
	if got := A.read(pkgList); !strings.Contains(got, "tool-b") {
		t.Errorf("A did not get the clean file: %q", got)
	}
}

func hasTrailerResolved(r Report, rung string) bool {
	for _, x := range r.Resolutions {
		if x.Rung == rung {
			return true
		}
	}
	return false
}

// racingStore lets another machine push first, once, just before Push.
type racingStore struct {
	store.Store
	before func()
}

func (r *racingStore) Push(ctx context.Context, specs []string) error {
	if f := r.before; f != nil {
		r.before = nil
		f()
	}
	return r.Store.Push(ctx, specs)
}

func TestPushRaceLosesNothing(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]

	A.write(aliases, "alias ll=\"ls -la\"\nalias gs=\"status-tool\"\nalias a=\"tool-a\"\n")
	B.write(pkgList, "tool-one\ntool-two\ntool-b\n")
	rs := &racingStore{Store: B.repo, before: func() { A.sync() }}
	B.s.Store = rs
	r := B.sync()
	if r.Retries != 1 || !r.Pushed {
		t.Fatalf("B: retries %d pushed %v", r.Retries, r.Pushed)
	}
	sts, err := store.StatusRefs(B.st, b).ReadAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := sts[b].Applied; got != B.main() {
		t.Errorf("published status names %s, main is %s", got, B.main())
	}
	if got := git(t, w.remote, "rev-parse", "refs/yadm/status/"+string(b)); got != git(t, B.repo.Dir(), "rev-parse", "refs/yadm/status/"+string(b)) {
		t.Error("the pushed status ref is not the latest record")
	}
	if !strings.Contains(w.remoteFile("files/.config/shell/aliases.sh"), "tool-a") ||
		!strings.Contains(w.remoteFile("files/.config/packages/list"), "tool-b") {
		t.Fatal("a pushed change was lost")
	}
	A.sync()
	if A.main() != B.main() || string(A.main()) != w.remoteMain() {
		t.Errorf("machines diverged: %s %s %s", A.main(), B.main(), w.remoteMain())
	}
	if !strings.Contains(B.read(aliases), "tool-a") || !strings.Contains(A.read(pkgList), "tool-b") {
		t.Error("targets did not converge")
	}
	if n := git(t, w.remote, "rev-list", "--merges", "--count", "main"); n != "0" {
		t.Errorf("%s merge commits", n)
	}
}

func TestGateBlocksOneFileCommitsOthers(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, func(f *fixture.Fixture) {
		p := filepath.Join(f.Root, "manifest.toml")
		b, _ := os.ReadFile(p)
		b = append(b, []byte("\n[checks.list-lint]\npaths = [\".config/packages/list\"]\ncommand = [\"list-lint\"]\n")...)
		os.WriteFile(p, b, 0o644)
	}, a)
	A := w.machines[a]
	A.sync()
	A.exec.fail = func(check string, t model.Target) bool { return check == "list-lint" }

	A.write(aliases, "alias ll=\"ls -la\"\nalias gs=\"status-tool\"\nalias x=\"y\"\n")
	A.write(pkgList, "tool-one\nbad-entry\n")
	r := A.sync()
	if len(r.Committed) != 1 {
		t.Fatalf("committed %v holds %+v", r.Committed, r.Holds)
	}
	hs := holdsOf(r, model.HoldCheckFailed)
	if len(hs) != 1 || hs[0].Target != pkgList {
		t.Fatalf("gate holds %+v", r.Holds)
	}
	if !strings.Contains(w.remoteFile("files/.config/shell/aliases.sh"), "alias x") {
		t.Error("passing file not committed")
	}
	if strings.Contains(w.remoteFile("files/.config/packages/list"), "bad-entry") {
		t.Error("failing file committed")
	}
	// Staged plaintext went to temp files under the state directory, and
	// they are gone.
	ents, _ := filepath.Glob(filepath.Join(A.state, "yadm-check-*"))
	if len(ents) != 0 {
		t.Errorf("staged files left: %v", ents)
	}

	// Once the check passes, the held file commits.
	A.exec.fail = nil
	r = A.sync()
	if len(r.Committed) != 1 || len(holdsOf(r, model.HoldCheckFailed)) != 0 {
		t.Fatalf("after fix: %+v", r)
	}
	if !strings.Contains(w.remoteFile("files/.config/packages/list"), "bad-entry") {
		t.Error("file not committed after the check passed")
	}
}

func TestQuietPeriodNotCommittedEarly(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	w.clock.offset = 0
	A := w.machines[a]
	A.sync()
	before := w.remoteMain()

	A.write(aliases, "alias ll=\"ls -la\"\nalias gs=\"status-tool\"\nalias q=\"quiet\"\n")
	r := A.sync()
	if len(r.Committed) != 0 || !contains(r.Pending, aliases) {
		t.Fatalf("committed during the quiet period: %+v", r)
	}
	if len(r.Holds) != 0 {
		t.Errorf("a pending edit reported as a hold: %+v", r.Holds)
	}
	if git(t, w.remote, "rev-parse", "main") != before {
		t.Fatal("remote moved during the quiet period")
	}
	if got := A.read(aliases); !strings.Contains(got, "quiet") {
		t.Fatalf("pending edit overwritten: %q", got)
	}

	w.clock.offset = time.Hour
	if r := A.sync(); len(r.Committed) != 0 {
		t.Fatalf("committed after 1h of a 2h quiet period: %+v", r)
	}
	w.clock.offset = 3 * time.Hour
	r = A.sync()
	if len(r.Committed) != 1 || !r.Pushed {
		t.Fatalf("not committed after the quiet period: %+v", r)
	}
	if !strings.Contains(w.remoteFile("files/.config/shell/aliases.sh"), "quiet") {
		t.Error("remote lacks the edit")
	}
}

func TestPendingEditMergesWithRemoteChange(t *testing.T) {
	// A pending (quiet) edit spans a fetch that changed the same file. The
	// later commit merges against the newer source instead of reverting it.
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.write(aliases, aliasesLong)
	A.sync()
	B.sync()

	w.clock.offset = 0
	A.write(aliases, strings.Replace(aliasesLong, "# one", "# one edited on A", 1))
	if r := A.sync(); len(r.Committed) != 0 {
		t.Fatalf("committed early: %+v", r)
	}
	w.clock.offset = 3 * time.Hour
	B.write(aliases, strings.Replace(aliasesLong, "# three", "# three edited on B", 1))
	B.sync()
	A.sync() // fetches B's edit while A's edit is still pending... and now commits
	A.sync()
	B.sync()
	want := strings.Replace(strings.Replace(aliasesLong, "# one", "# one edited on A", 1), "# three", "# three edited on B", 1)
	if got := w.remoteFile("files/.config/shell/aliases.sh"); got+"\n" != want && got != want {
		t.Errorf("remote = %q, want %q", got, want)
	}
	for _, m := range []*machine{A, B} {
		if got := m.read(aliases); got != want {
			t.Errorf("%s = %q, want %q", m.id, got, want)
		}
	}
}

func TestSleepingLaptopCatchesUp(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]

	for i := 0; i < 12; i++ {
		B.write(pkgList, "tool-one\ntool-two\n"+strings.Repeat("tool-x\n", i+1))
		if r := B.sync(); len(r.Committed) != 1 {
			t.Fatalf("B commit %d: %+v", i, r)
		}
	}
	// The laptop wakes with its own edit and many remote commits.
	A.write(aliases, "alias ll=\"ls -la\"\nalias gs=\"status-tool\"\nalias woke=\"yes\"\n")
	r := A.sync()
	if r.Replayed != 1 || !r.Pushed || len(r.Holds) != 0 {
		t.Fatalf("catch-up: %+v", r)
	}
	if got := A.read(pkgList); strings.Count(got, "tool-x") != 12 {
		t.Errorf("A list after catch-up: %q", got)
	}
	if string(A.main()) != w.remoteMain() {
		t.Error("A main differs from remote")
	}
	B.sync()
	if !strings.Contains(B.read(aliases), "woke") {
		t.Error("B did not get A's edit")
	}
}

// addMember adds m to enclave e in the fixture's key log and fleet file.
func addMember(t *testing.T, f *fixture.Fixture, e model.EnclaveName, m model.MachineID, fleetFrom, fleetTo string) {
	t.Helper()
	log := f.Logs[e]
	by := f.Identities[fixture.Members[e][0]]
	head, err := f.Rings[e].Add(log[len(log)-1], f.Identities[m].Member(), by, crypt.MemPins())
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypt.MarshalLogEntry(head)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.Root, filepath.FromSlash(string(crypt.LogPath(e, head.Seq))))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	f.Logs[e] = append(log, head)
	fp := filepath.Join(f.Root, "fleet.toml")
	fb, _ := os.ReadFile(fp)
	if !strings.Contains(string(fb), fleetFrom) {
		t.Fatalf("fleet.toml lacks %q", fleetFrom)
	}
	os.WriteFile(fp, []byte(strings.Replace(string(fb), fleetFrom, fleetTo, 1)), 0o644)
}

func TestSealedConflictMergesInPlaintextForMembers(t *testing.T) {
	a, b, c := fixture.HostA, fixture.HostB, fixture.HostC
	w := newWorld(t, func(f *fixture.Fixture) {
		addMember(t, f, "personal", fixture.HostB, "nicknames = [\"desk-b\"]\ntypes = [\"work\"]", "nicknames = [\"desk-b\"]\ntypes = [\"work\", \"personal\"]")
	}, a, b, c)
	w.syncAll(a, b, c)
	A, B, C := w.machines[a], w.machines[b], w.machines[c]
	notes := model.Target(".config/notes/private.md")
	canary := w.f.Canaries["personal"]
	orig := A.read(notes)
	if !strings.Contains(orig, canary.String()) || B.read(notes) != orig {
		t.Fatal("members did not get the sealed file")
	}
	if _, err := os.Stat(C.path(notes)); err == nil {
		t.Fatal("non-member got the sealed file")
	}

	editA := secrecytest.NewCanary(t, "edit-a")
	editB := secrecytest.NewCanary(t, "edit-b")
	A.write(notes, strings.Replace(orig, "# Private notes", "# Private notes "+editA.String(), 1))
	B.write(notes, orig+"\nB line "+editB.String()+"\n")
	A.sync()
	r := B.sync()
	if len(holdsOf(r, model.HoldConflict)) != 0 || r.Replayed != 1 {
		t.Fatalf("sealed merge: %+v", r)
	}
	if !hasTrailerResolved(r, RungText) {
		t.Errorf("resolutions %+v", r.Resolutions)
	}
	A.sync()
	C.sync()
	for _, m := range []*machine{A, B} {
		got := m.read(notes)
		if !strings.Contains(got, editA.String()) || !strings.Contains(got, editB.String()) {
			t.Errorf("%s did not converge: %q", m.id, got)
		}
	}
	all := append(w.f.AllCanaries(), editA, editB)
	secrecytest.AssertRepoClean(t, w.remote, all...)
	for _, m := range []*machine{A, B, C} {
		secrecytest.AssertRepoClean(t, m.repo.Dir(), all...)
	}
	personal := []secrecytest.Canary{canary, editA, editB}
	secrecytest.AssertTreeClean(t, C.home, personal...)
	secrecytest.AssertTreeClean(t, C.state, personal...)
	// The status refs carry no plaintext either (they are in the repo scan),
	// and git only ever saw ciphertext for the sealed path.
	blob := git(t, w.remote, "show", "main:sealed/personal/.config/notes/private.md")
	if !crypt.IsSealedFile([]byte(blob)) {
		t.Error("sealed path holds plaintext in git")
	}
}

func TestNonMemberEnclaveCommitAlerts(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()

	// B is not in "personal" but can push: it copies a sealed blob around.
	head := B.main()
	blob, err := B.st.ReadPath(ctx, head, "sealed/personal/.config/notes/private.md")
	if err != nil {
		t.Fatal(err)
	}
	msg := store.Message{Subject: "forged", Trailers: []store.Trailer{{Key: store.TrailerMachine, Value: string(b)}}}
	id, err := B.st.CommitPaths(ctx, head, []store.Change{{Path: "sealed/personal/.config/notes/copy.md", Blob: blob, Mode: 0o100644}}, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := B.st.UpdateRef(ctx, store.RefMain, id, head); err != nil {
		t.Fatal(err)
	}
	if err := B.st.Push(ctx, []string{store.RefMain + ":" + store.RefMain}); err != nil {
		t.Fatal(err)
	}

	r := A.sync()
	if len(r.Alerts) != 1 || r.Alerts[0].Kind != "non_member_enclave_commit" || r.Alerts[0].Commit != id || r.Alerts[0].Machine != b {
		t.Fatalf("alerts %+v", r.Alerts)
	}
	if A.main() != id {
		t.Errorf("the commit was not taken: main %s", A.main())
	}
	notified := false
	for _, c := range A.exec.calls {
		if c.Kind == "notify" && c.Event["kind"] == "non_member_enclave_commit" {
			notified = true
		}
	}
	if !notified {
		t.Error("notify hook not called")
	}
	sts, err := store.StatusRefs(A.st, a).ReadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := sts[a].Alerts; len(got) != 1 || got[0].Commit != id {
		t.Errorf("status alerts %+v", got)
	}
	if kh := sts[a].KeyHeads["personal"]; kh.Seq == 0 || kh.Hash == "" {
		t.Errorf("status key heads %+v", sts[a].KeyHeads)
	}
}

func TestSealedUnionMergeKeepsCiphertextInGit(t *testing.T) {
	// A sealed file under a non-default policy goes through the resolver's
	// own open, merge and reseal path, not apply.MergeSealed.
	a, b, c := fixture.HostA, fixture.HostB, fixture.HostC
	w := newWorld(t, func(f *fixture.Fixture) {
		addMember(t, f, "personal", fixture.HostB, "nicknames = [\"desk-b\"]\ntypes = [\"work\"]", "nicknames = [\"desk-b\"]\ntypes = [\"work\", \"personal\"]")
	}, a, b, c)
	notes := model.Target(".config/notes/private.md")
	for _, m := range w.machines {
		m.s.Policy.MergeFor = func(t model.Target) MergePolicy {
			if t == notes {
				return MergeUnion
			}
			return ""
		}
	}
	w.syncAll(a, b, c)
	A, B, C := w.machines[a], w.machines[b], w.machines[c]
	orig := A.read(notes)
	editA := secrecytest.NewCanary(t, "union-a")
	editB := secrecytest.NewCanary(t, "union-b")
	// Both append at the same place: a line merge would conflict.
	A.write(notes, orig+"A "+editA.String()+"\n")
	B.write(notes, orig+"B "+editB.String()+"\n")
	A.sync()
	r := B.sync()
	if len(holdsOf(r, model.HoldConflict)) != 0 || !hasTrailerResolved(r, RungUnion) {
		t.Fatalf("sealed union: %+v", r)
	}
	A.sync()
	C.sync()
	for _, m := range []*machine{A, B} {
		got := m.read(notes)
		if !strings.Contains(got, editA.String()) || !strings.Contains(got, editB.String()) {
			t.Errorf("%s: %q", m.id, got)
		}
	}
	personal := []secrecytest.Canary{w.f.Canaries["personal"], editA, editB}
	secrecytest.AssertRepoClean(t, w.remote, personal...)
	for _, m := range []*machine{A, B, C} {
		secrecytest.AssertRepoClean(t, m.repo.Dir(), personal...)
	}
	secrecytest.AssertTreeClean(t, C.home, personal...)
	secrecytest.AssertTreeClean(t, C.state, personal...)
	if blob := git(t, w.remote, "show", "main:sealed/personal/.config/notes/private.md"); !crypt.IsSealedFile([]byte(blob)) {
		t.Error("sealed path holds plaintext in git")
	}
}

func TestUnreadableDriftNeverCommits(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	a := fixture.HostA
	w := newWorld(t, nil, a)
	A := w.machines[a]
	A.sync()
	before := w.remoteMain()
	A.write(aliases, "alias unreadable=\"x\"\n")
	os.Chmod(A.path(aliases), 0)
	defer os.Chmod(A.path(aliases), 0o644)
	r := A.sync()
	if len(r.Committed) != 0 || w.remoteMain() != before {
		t.Fatalf("unreadable drift committed: %+v", r)
	}
}
