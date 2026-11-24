package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/reroot"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
)

// rerootFleet is pauseFleet with backups on the personal type
// (reroot_keep = 2), so host-a backs up and host-b and host-c do not. Every
// machine pins personal's key log, so each verifies host-a's records.
func rerootFleet(t *testing.T) (root, remote string, fx *fixture.Fixture, clk *fakeClock, m map[model.MachineID]machineDirs) {
	t.Helper()
	hermetic(t)
	root = t.TempDir()
	fx = fixture.Build(t)
	fl := filepath.Join(fx.Root, "fleet.toml")
	b := readFile(t, fl)
	if !strings.Contains(b, "[types.personal]\nenclave = true\n") {
		t.Fatal("fixture fleet.toml changed shape")
	}
	writeFile(t, fl, strings.Replace(b, "[types.personal]\nenclave = true\n", "[types.personal]\nenclave = true\nreroot_keep = 2\n", 1))
	remote = fixtureRemote(t, root, fx)
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	clk = &fakeClock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	hooks.now = clk.Now
	hooks.sleep = func(context.Context, time.Duration) error { clk.Add(3 * time.Second); return nil }
	pin, err := crypt.PinOf(fx.Logs["personal"][len(fx.Logs["personal"])-1])
	if err != nil {
		t.Fatal(err)
	}
	m = map[model.MachineID]machineDirs{}
	for _, id := range []model.MachineID{fixture.HostA, fixture.HostB, fixture.HostC} {
		d := fixtureMachine(t, root, remote, fx, id, true)
		if err := crypt.FilePins(d.State).Set("personal", pin); err != nil {
			t.Fatal(err)
		}
		yadmOK(t, "task", "allow")
		yadmOK(t, "apply")
		yadmOK(t, "sync", "--full")
		m[id] = d
	}
	return root, remote, fx, clk, m
}

func trimmed(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return strings.TrimSpace(git(t, dir, args...))
}

// squash makes a parentless commit with main's tree in the clone at dir.
func squash(t *testing.T, dir, msg string) string {
	t.Helper()
	return trimmed(t, dir, "commit-tree", "-m", msg, "main^{tree}")
}

// homeFiles hashes every file in a home outside yadm's own directories,
// with its modification time.
func homeFiles(t *testing.T, home string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(home, p)
		if d.IsDir() && (rel == ".local" || rel == filepath.Join(".config", "yadm")) {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(h[:]) + " " + info.ModTime().String()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func holdTask(t *testing.T, task string) *model.Hold {
	t.Helper()
	for _, h := range decode[statusData](t, yadmOK(t, "status").Data).Holds {
		if h.Task == task {
			return &h
		}
	}
	return nil
}

func checkItemNamed(t *testing.T, name string) checkItem {
	t.Helper()
	env, _, _ := yadm(t, "check")
	for _, c := range decode[struct {
		Checks []checkItem `json:"checks"`
	}](t, env.Data).Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check has no %s item", name)
	return checkItem{}
}

// assertBundlesClean clones each bundle in dir and checks its object store
// for enclave plaintext. A backup is the old history: it holds what that
// history held, which is ciphertext only.
func assertBundlesClean(t *testing.T, root, dir string, canaries ...secrecytest.Canary) int {
	t.Helper()
	bs, err := reroot.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range bs {
		info, err := os.Stat(b.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("bundle %s: %v mode %v", b.Path, err, info.Mode())
		}
		clone := filepath.Join(root, "bundle-clone", b.Name, string(rune('a'+i)))
		git(t, root, "clone", "-q", "--mirror", b.Path, clone)
		secrecytest.AssertRepoClean(t, clone, canaries...)
	}
	return len(bs)
}

// TestRerootSquash: host-a replaces the history with one squashed commit
// of the same tree. It backs up first (personal keeps 2). host-b, held by
// host-a's pause, switches during the pause with no file change and no
// backup; host-c is offline and switches days later, together with a
// commit host-b made on the new history. Two more re-roots on host-a leave
// two backups. No enclave plaintext reaches any store or backup.
func TestRerootSquash(t *testing.T) {
	root, remote, fx, clk, m := rerootFleet(t)
	a, b, c := m[fixture.HostA], m[fixture.HostB], m[fixture.HostC]
	shared := ".config/shell/aliases.sh"

	on(t, root, fixture.HostB)
	beforeB := homeFiles(t, b.Home)

	on(t, root, fixture.HostA)
	old := trimmed(t, a.Source, "rev-parse", "main")
	newHead := squash(t, a.Source, "new root")

	// Unreviewed commits block it until --fold-unreviewed; no pause starts.
	env, code, _ := yadm(t, "reroot", "--new-head", newHead, "--no-wait")
	if code != ExitError || !strings.Contains(env.Error.Message, "unreviewed") {
		t.Fatalf("reroot with an unreviewed queue: exit %d %+v", code, env.Error)
	}
	if ps := decode[statusData](t, yadmOK(t, "status").Data).Pause; ps != nil && ps.Own != nil {
		t.Fatalf("a refused reroot started a pause: %+v", ps)
	}

	env = yadmOK(t, "reroot", "--new-head", newHead, "--reason", "purge old history", "--fold-unreviewed", "--no-wait")
	d := decode[rerootData](t, env.Data)
	if !d.Pushed || !d.PauseStart || string(d.OldHead) != old || string(d.NewHead) != newHead || d.Backup == "" {
		t.Fatalf("reroot: %+v", d)
	}
	id := d.ID
	if got := trimmed(t, remote, "rev-parse", "main"); got != newHead {
		t.Fatalf("remote main %s, want %s", got, newHead)
	}
	if got := trimmed(t, a.Source, "rev-parse", "main"); got != newHead {
		t.Fatalf("host-a main %s, want %s", got, newHead)
	}
	if heads := git(t, root, "bundle", "list-heads", d.Backup); !strings.Contains(heads, old) {
		t.Fatalf("backup does not hold the old head:\n%s", heads)
	}
	if !strings.HasPrefix(d.Backup, reroot.BackupDir(a.Source)) || strings.HasPrefix(d.Backup, a.State) || strings.HasPrefix(d.Backup, a.Source+string(filepath.Separator)) {
		t.Fatalf("backup %s is not beside the source clone", d.Backup)
	}

	// host-b is held by host-a's pause and still switches.
	on(t, root, fixture.HostB)
	s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data)
	if !s.Paused || string(s.Applied) != newHead {
		t.Fatalf("host-b sync: %+v", s)
	}
	if got := trimmed(t, b.Source, "rev-parse", "main"); got != newHead {
		t.Fatalf("host-b main %s, want %s", got, newHead)
	}
	if after := homeFiles(t, b.Home); len(after) != len(beforeB) {
		t.Fatalf("host-b files changed: %d before, %d after", len(beforeB), len(after))
	} else {
		for p, h := range beforeB {
			if after[p] != h {
				t.Fatalf("host-b %s changed in the switch", p)
			}
		}
	}
	if st := selfStatus(t, fixture.HostB); st.Reroot != id || st.RerootHeld != "" {
		t.Fatalf("host-b status: reroot %q held %q", st.Reroot, st.RerootHeld)
	}
	if bs, _ := reroot.List(reroot.BackupDir(b.Source)); len(bs) != 0 {
		t.Fatalf("host-b took a backup: %+v", bs)
	}
	if it := checkItemNamed(t, "reroot"); !it.OK || !strings.Contains(it.Detail, id) {
		t.Fatalf("host-b reroot check: %+v", it)
	}

	// host-a sees host-b switched, then resumes.
	on(t, root, fixture.HostA)
	if out, _, _ := yadmRaw(t, "fleet", "list"); !strings.Contains(out, "rerooted "+id) {
		t.Fatalf("fleet list does not show the switch:\n%s", out)
	}
	yadmOK(t, "resume")

	// host-b works on the new history: commit, push, review.
	on(t, root, fixture.HostB)
	yadmOK(t, "sync", "--full")
	writeFile(t, filepath.Join(b.Home, shared), "# after the re-root\n")
	if c := decode[map[string]any](t, yadmOK(t, "commit", "-m", "after the re-root", shared).Data); c["pushed"] != true {
		t.Fatalf("host-b commit after the re-root: %+v", c)
	}
	afterCommit := trimmed(t, b.Source, "rev-parse", "main")
	if trimmed(t, b.Source, "rev-parse", "main~1") != newHead {
		t.Fatal("host-b's commit is not on the new history")
	}
	yadmOK(t, "review", "ok", "shared", afterCommit)

	// host-c was offline the whole time; days later it switches and takes
	// host-b's commit.
	clk.Add(72 * time.Hour)
	on(t, root, fixture.HostC)
	s = decode[syncOut](t, yadmOK(t, "sync", "--auto").Data)
	if s.Paused || string(s.Applied) != afterCommit {
		t.Fatalf("host-c sync: %+v", s)
	}
	if got := readFile(t, filepath.Join(c.Home, shared)); got != "# after the re-root\n" {
		t.Fatalf("host-c %s: %q", shared, got)
	}
	if st := selfStatus(t, fixture.HostC); st.Reroot != id {
		t.Fatalf("host-c status reroot %q", st.Reroot)
	}
	if bs, _ := reroot.List(reroot.BackupDir(c.Source)); len(bs) != 0 {
		t.Fatalf("host-c took a backup: %+v", bs)
	}

	// Two more re-roots on host-a: two backups stay.
	on(t, root, fixture.HostA)
	yadmOK(t, "sync", "--full")
	for i, msg := range []string{"second root", "third root"} {
		clk.Add(time.Minute)
		nh := squash(t, a.Source, msg)
		env := yadmOK(t, "reroot", "--new-head", nh, "--fold-unreviewed", "--no-wait")
		if d := decode[rerootData](t, env.Data); !d.Pushed || d.Backup == "" {
			t.Fatalf("re-root %d: %+v", i+2, d)
		}
		yadmOK(t, "resume")
	}
	bl := decode[struct {
		Keep    int             `json:"keep"`
		Bundles []reroot.Bundle `json:"bundles"`
	}](t, yadmOK(t, "backups", "list").Data)
	if bl.Keep != 2 || len(bl.Bundles) != 2 {
		t.Fatalf("backups list: %+v", bl)
	}
	canaries := fx.AllCanaries()
	if n := assertBundlesClean(t, root, reroot.BackupDir(a.Source), canaries...); n != 2 {
		t.Fatalf("%d bundles", n)
	}
	pr := decode[struct {
		Deleted []reroot.Bundle `json:"deleted"`
	}](t, yadmOK(t, "backups", "prune", "--keep", "1").Data)
	if len(pr.Deleted) != 1 || pr.Deleted[0].Name != bl.Bundles[1].Name {
		t.Fatalf("prune: %+v", pr)
	}

	for _, r := range []string{remote, a.Source, b.Source, c.Source} {
		secrecytest.AssertRepoClean(t, r, canaries...)
	}
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
}

// writeRecord signs rec with id (nil leaves it unsigned) and writes it on
// the re-root ref of the clone at dir.
func writeRecord(t *testing.T, dir, state string, rec reroot.Record, id *crypt.Identity) {
	t.Helper()
	ctx := context.Background()
	repo, err := store.Open(dir, state)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if rec.ID == "" {
		if rec.ID, err = reroot.NewID(); err != nil {
			t.Fatal(err)
		}
	}
	if id != nil {
		if rec, err = reroot.Sign(rec, id); err != nil {
			t.Fatal(err)
		}
	} else {
		rec.Schema, rec.Signer = reroot.Schema, rec.Initiator
	}
	if _, _, err := reroot.Write(ctx, repo, rec); err != nil {
		t.Fatal(err)
	}
}

// forcePush replaces the remote main with rev, by hand, the way a user
// would without yadm, and pushes the re-root ref too when it exists.
func forcePush(t *testing.T, dir, rev string) {
	t.Helper()
	args := []string{"push", "-q", "--force", "origin", rev + ":refs/heads/main"}
	if out := trimmed(t, dir, "for-each-ref", reroot.Ref); out != "" {
		args = append(args, "+"+reroot.Ref+":"+reroot.Ref)
	}
	git(t, dir, args...)
}

// TestRerootRefused: an unannounced force-push, an unsigned record and one
// whose signer no pinned key log lists are refused and flagged; a rewrite
// that changes a key-log file is refused on the initiator and on a peer.
// Restoring the remote clears the hold.
func TestRerootRefused(t *testing.T) {
	root, _, fx, clk, m := rerootFleet(t)
	a, b := m[fixture.HostA], m[fixture.HostB]
	on(t, root, fixture.HostA)
	old := trimmed(t, a.Source, "rev-parse", "main")

	refused := func(peer model.MachineID, task, want string) {
		t.Helper()
		on(t, root, peer)
		env, code, _ := yadm(t, "sync", "--full")
		if code != ExitAttention {
			t.Fatalf("%s sync over a rewrite: exit %d %+v", peer, code, env.Error)
		}
		h := holdTask(t, task)
		if h == nil || !strings.Contains(h.Detail, want) {
			t.Fatalf("%s: no %s hold with %q: %+v", peer, task, want, h)
		}
		if got := trimmed(t, m[peer].Source, "rev-parse", "main"); got != old {
			t.Fatalf("%s main moved to %s", peer, got)
		}
		if it := checkItemNamed(t, "reroot"); it.OK {
			t.Fatalf("%s check passes over a refused rewrite: %+v", peer, it)
		}
		if st := selfStatus(t, peer); st.RerootHeld != task {
			t.Fatalf("%s status reroot_held %q", peer, st.RerootHeld)
		}
	}
	restore := func() {
		t.Helper()
		on(t, root, fixture.HostA)
		git(t, a.Source, "push", "-q", "--force", "origin", old+":refs/heads/main")
		for _, p := range []model.MachineID{fixture.HostB, fixture.HostC} {
			on(t, root, p)
			yadmOK(t, "sync", "--full")
			if h := holdTask(t, sync.HoldTaskRewrite); h != nil {
				t.Fatalf("%s still holds after the remote was restored: %+v", p, h)
			}
			if h := holdTask(t, sync.HoldTaskReroot); h != nil {
				t.Fatalf("%s still holds after the remote was restored: %+v", p, h)
			}
		}
	}

	// An unannounced force-push.
	on(t, root, fixture.HostA)
	sq := squash(t, a.Source, "unannounced")
	forcePush(t, a.Source, sq)
	refused(fixture.HostB, sync.HoldTaskRewrite, "no verified re-root record")
	restore()

	// An unsigned record by host-a and one signed by host-b, which no
	// pinned key log lists.
	clk.Add(time.Minute)
	on(t, root, fixture.HostA)
	sq = squash(t, a.Source, "unverified")
	writeRecord(t, a.Source, a.State, reroot.Record{Initiator: fixture.HostA, Created: clk.Now(), OldHead: model.CommitID(old), NewHead: model.CommitID(sq)}, nil)
	writeRecord(t, a.Source, a.State, reroot.Record{Initiator: fixture.HostB, Created: clk.Now(), OldHead: model.CommitID(old), NewHead: model.CommitID(sq)}, fx.Identities[fixture.HostB])
	forcePush(t, a.Source, sq)
	refused(fixture.HostC, sync.HoldTaskRewrite, "carries no signature")
	refused(fixture.HostC, sync.HoldTaskRewrite, "no key log this machine pinned lists "+string(fixture.HostB))
	restore()

	// A rewrite that changes a key-log file: an orphan commit whose
	// personal entry 1 gained a byte.
	on(t, root, fixture.HostA)
	work := filepath.Join(root, "work-keys")
	git(t, root, "clone", "-q", a.Source, work)
	git(t, work, "checkout", "-q", "--orphan", "bad")
	kf := filepath.Join(work, "keys", "personal", "000001.toml")
	writeFile(t, kf, readFile(t, kf)+"\n")
	git(t, work, "commit", "-q", "-a", "-m", "keys changed")
	git(t, a.Source, "fetch", "-q", work, "bad:refs/heads/bad")
	bad := trimmed(t, a.Source, "rev-parse", "bad")
	env, code, _ := yadm(t, "reroot", "--new-head", "bad", "--fold-unreviewed", "--no-wait")
	if code != ExitRefused || !strings.Contains(env.Error.Message, "keys/personal/000001.toml") {
		t.Fatalf("reroot with a key-log change: exit %d %+v", code, env.Error)
	}
	if ps := decode[statusData](t, yadmOK(t, "status").Data).Pause; ps != nil && ps.Own != nil {
		t.Fatalf("a refused reroot started a pause: %+v", ps)
	}
	// The same rewrite with a record host-a did sign, pushed by hand.
	clk.Add(time.Minute)
	writeRecord(t, a.Source, a.State, reroot.Record{Initiator: fixture.HostA, Created: clk.Now(), OldHead: model.CommitID(old), NewHead: model.CommitID(bad)}, fx.Identities[fixture.HostA])
	forcePush(t, a.Source, bad)
	refused(fixture.HostB, sync.HoldTaskReroot, "changes key-log files")
	secrecytest.AssertRepoClean(t, b.Source, fx.AllCanaries()...)
	restore()
}

// TestRerootCarry: host-b holds a commit it has not pushed when host-a
// re-roots. During the pause it does not switch; after it, the re-root is
// held and the commit kept; `yadm reroot carry` replays it onto the new
// history, keeps the original on the carry ref and pushes.
func TestRerootCarry(t *testing.T) {
	root, remote, _, _, m := rerootFleet(t)
	a, b := m[fixture.HostA], m[fixture.HostB]
	shared := ".config/shell/aliases.sh"

	on(t, root, fixture.HostB)
	writeFile(t, filepath.Join(b.Home, shared), "# unpushed on host-b\n")
	yadmOK(t, "commit", "--no-push", "-m", "unpushed work", shared)
	mine := trimmed(t, b.Source, "rev-parse", "main")

	on(t, root, fixture.HostA)
	newHead := squash(t, a.Source, "new root")
	d := decode[rerootData](t, yadmOK(t, "reroot", "--new-head", newHead, "--fold-unreviewed", "--no-wait").Data)

	on(t, root, fixture.HostB)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("host-b not paused: %+v", s)
	}
	if got := trimmed(t, b.Source, "rev-parse", "main"); got != mine {
		t.Fatalf("host-b switched during the pause with unpushed work: main %s", got)
	}

	on(t, root, fixture.HostA)
	yadmOK(t, "resume")
	on(t, root, fixture.HostB)
	if _, code, _ := yadm(t, "sync", "--full"); code != ExitAttention {
		t.Fatalf("host-b sync with unpushed work: exit %d", code)
	}
	h := holdTask(t, sync.HoldTaskReroot)
	if h == nil || !strings.Contains(h.Detail, "1 local commit") || !strings.Contains(strings.Join(h.Next, " "), "yadm reroot carry") {
		t.Fatalf("host-b hold: %+v", h)
	}
	if got := trimmed(t, b.Source, "rev-parse", "main"); got != mine {
		t.Fatalf("host-b dropped its work: main %s", got)
	}

	env := yadmOK(t, "reroot", "carry")
	if out := decode[map[string]any](t, env.Data); out["reroot"] == nil {
		t.Fatalf("carry: %+v", out)
	}
	tip := trimmed(t, b.Source, "rev-parse", "main")
	if trimmed(t, b.Source, "rev-parse", "main~1") != newHead {
		t.Fatal("carried commit is not on the new history")
	}
	if got := trimmed(t, b.Source, "rev-parse", sync.RefCarry(d.ID)); got != mine {
		t.Fatalf("carry ref %s, want %s", got, mine)
	}
	if got := trimmed(t, remote, "rev-parse", "main"); got != tip {
		t.Fatalf("carried commit not pushed: remote %s, local %s", got, tip)
	}
	if got := readFile(t, filepath.Join(b.Home, shared)); got != "# unpushed on host-b\n" {
		t.Fatalf("host-b %s: %q", shared, got)
	}
	if h := holdTask(t, sync.HoldTaskReroot); h != nil {
		t.Fatalf("hold left after carry: %+v", h)
	}
}
