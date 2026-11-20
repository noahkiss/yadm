package store

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// TestMain isolates git from the user's configuration and $HOME.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "store-home-")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{
		"HOME":                home,
		"XDG_CONFIG_HOME":     filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME":     "test",
		"GIT_AUTHOR_EMAIL":    "test@example.invalid",
		"GIT_COMMITTER_NAME":  "test",
		"GIT_COMMITTER_EMAIL": "test@example.invalid",
	} {
		os.Setenv(k, v)
	}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

func rawGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newBareRemote makes an empty bare remote whose default branch is main.
func newBareRemote(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "remote.git")
	cmd := exec.Command("git", "init", "-q", "--bare", "-b", "main", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}
	return dir
}

func cloneOf(t *testing.T, remote string) *Repo {
	t.Helper()
	base := t.TempDir()
	r, err := Clone(context.Background(), remote, filepath.Join(base, "source"), filepath.Join(base, "state"))
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return r
}

func msg(subject string) Message {
	return Message{Subject: subject, Trailers: []Trailer{{Key: TrailerMachine, Value: "m-test"}}}
}

func change(path, body string) Change {
	return Change{Path: model.SourcePath(path), Blob: []byte(body), Mode: 0o100644}
}

// commitMain commits changes on main and moves main with a compare-and-swap.
func commitMain(t *testing.T, r *Repo, subject string, changes ...Change) model.CommitID {
	t.Helper()
	ctx := context.Background()
	parent, err := r.ResolveRef(ctx, RefMain)
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.CommitPaths(ctx, parent, changes, msg(subject))
	if err != nil {
		t.Fatalf("CommitPaths: %v", err)
	}
	if err := r.UpdateRef(ctx, RefMain, id, parent); err != nil {
		t.Fatalf("UpdateRef: %v", err)
	}
	return id
}

// seeded returns a bare remote holding one commit, and two clones of it.
func seeded(t *testing.T) (remote string, a, b *Repo) {
	t.Helper()
	remote = newBareRemote(t)
	a = cloneOf(t, remote)
	commitMain(t, a, "seed", change("files/.base", "base\n"))
	if err := a.Push(context.Background(), []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatalf("seed push: %v", err)
	}
	b = cloneOf(t, remote)
	return remote, a, b
}

func TestParseGitVersion(t *testing.T) {
	for in, want := range map[string][3]int{
		"git version 2.43.0\n":               {2, 43, 0},
		"git version 2.39.3 (Apple Git-146)": {2, 39, 3},
		"git version 2.45.1.windows.1":       {2, 45, 1},
		"git version 2.50.0-rc1":             {2, 50, 0},
		"git version 3.0":                    {3, 0, 0},
	} {
		got, err := parseGitVersion(in)
		if err != nil || got != want {
			t.Errorf("parseGitVersion(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseGitVersion("hub version 1"); err == nil {
		t.Error("want error for foreign output")
	}
	if err := CheckGitVersion(context.Background()); err != nil {
		t.Fatalf("installed git: %v", err)
	}
}

func TestOpenRejectsNonRepo(t *testing.T) {
	if _, err := Open(t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("Open on a plain directory: want error")
	}
}

func TestCloneConfiguresYadmRefspec(t *testing.T) {
	r := cloneOf(t, newBareRemote(t))
	got := rawGit(t, r.Dir(), "config", "--get-all", "remote.origin.fetch")
	if !strings.Contains(got, FetchRefspecYadm) {
		t.Fatalf("fetch refspecs %q lack %q", got, FetchRefspecYadm)
	}
	if h, err := r.Head(context.Background()); err != nil || h != "" {
		t.Fatalf("Head of empty clone = %q, %v; want unborn", h, err)
	}
	// Open twice does not duplicate the refspec.
	if _, err := Open(r.Dir(), r.stateDir); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(rawGit(t, r.Dir(), "config", "--get-all", "remote.origin.fetch"), FetchRefspecYadm); n != 1 {
		t.Fatalf("yadm refspec configured %d times", n)
	}
}

func TestReadAndListTree(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	id := commitMain(t, a, "add", change("files/.zshrc", "z\n"),
		Change{Path: "files/bin/run", Blob: []byte("#!/bin/sh\n"), Mode: 0o100755})
	if h, _ := a.Head(ctx); h != id {
		t.Fatalf("Head = %s, want %s", h, id)
	}
	entries, err := a.ListTree(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	got := map[model.SourcePath]uint32{}
	for _, e := range entries {
		got[e.Path] = e.Mode
	}
	want := map[model.SourcePath]uint32{"files/.base": 0o100644, "files/.zshrc": 0o100644, "files/bin/run": 0o100755}
	if len(got) != len(want) {
		t.Fatalf("ListTree = %v", got)
	}
	for p, m := range want {
		if got[p] != m {
			t.Errorf("%s mode %o, want %o", p, got[p], m)
		}
	}
	b, err := a.ReadPath(ctx, id, "files/.zshrc")
	if err != nil || string(b) != "z\n" {
		t.Fatalf("ReadPath = %q, %v", b, err)
	}
	if _, err := a.ReadPath(ctx, id, "files/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadPath missing: %v, want fs.ErrNotExist", err)
	}
	if r, err := a.ResolveRef(ctx, "refs/heads/nope"); err != nil || r != "" {
		t.Fatalf("ResolveRef missing = %q, %v", r, err)
	}
	// Delete through the private index.
	id2 := commitMain(t, a, "rm", Change{Path: "files/.zshrc", Delete: true})
	if _, err := a.ReadPath(ctx, id2, "files/.zshrc"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("deleted path still readable: %v", err)
	}
}

func TestBadPathsRefused(t *testing.T) {
	_, a, _ := seeded(t)
	h, _ := a.Head(context.Background())
	for _, p := range []string{"", "/abs", "a/../b", ".git/config", "a//b", "x/.GIT/y"} {
		if _, err := a.CommitPaths(context.Background(), h, []Change{change(p, "x")}, msg("bad")); err == nil {
			t.Errorf("CommitPaths(%q): want error", p)
		}
	}
}

func TestMessageRoundTripAndLog(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	m := Message{
		Subject: "auto(host-a): 2 files [shared]",
		Body:    ".config/a\n.config/b",
		Trailers: []Trailer{
			{Key: TrailerMachine, Value: "m-a1b2c3"},
			{Key: TrailerAuto, Value: "1"},
			{Key: TrailerScope, Value: "shared"},
		},
	}
	parent, _ := a.Head(ctx)
	id, err := a.CommitPaths(ctx, parent, []Change{change("files/.config/a", "1"), change("files/.config/b", "2")}, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.UpdateRef(ctx, RefMain, id, parent); err != nil {
		t.Fatal(err)
	}
	log, err := a.Log(ctx, string(parent)+".."+RefMain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 {
		t.Fatalf("Log len %d, want 1", len(log))
	}
	c := log[0]
	if c.ID != id || len(c.Parents) != 1 || c.Parents[0] != parent {
		t.Fatalf("commit ids: %+v", c)
	}
	if c.Message.Subject != m.Subject || c.Message.Body != m.Body || len(c.Message.Trailers) != 3 ||
		c.Message.Trailers[0] != m.Trailers[0] || c.Message.Trailers[2] != m.Trailers[2] {
		t.Fatalf("message round trip: %+v", c.Message)
	}
	if strings.Join(pathsOf(c.Paths), ",") != "files/.config/a,files/.config/b" {
		t.Fatalf("paths %v", c.Paths)
	}
	if c.Author != "test <test@example.invalid>" || time.Since(c.When) > time.Hour {
		t.Fatalf("author %q when %v", c.Author, c.When)
	}
	// Path filter keeps the full path list of matching commits.
	full, err := a.Log(ctx, RefMain, []model.SourcePath{"files/.config/b"})
	if err != nil || len(full) != 1 || len(full[0].Paths) != 2 {
		t.Fatalf("filtered Log = %+v, %v", full, err)
	}
	all, err := a.Log(ctx, "", nil)
	if err != nil || len(all) != 2 {
		t.Fatalf("Log HEAD = %d commits, %v", len(all), err)
	}
}

func pathsOf(ps []model.SourcePath) []string {
	var s []string
	for _, p := range ps {
		s = append(s, string(p))
	}
	return s
}

// Two clones race to push. The loser gets ErrRejected, replays its commit
// onto the fetched main with merge-tree, and nothing is lost.
func TestPushRaceLoserRejectedNothingLost(t *testing.T) {
	ctx := context.Background()
	remote, a, b := seeded(t)
	base, _ := b.Head(ctx)

	commitMain(t, a, "a edits", change("files/.a", "from a\n"))
	bLocal := commitMain(t, b, "b edits", change("files/.b", "from b\n"))

	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatalf("winner push: %v", err)
	}
	err := b.Push(ctx, []string{RefMain + ":" + RefMain})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("loser push: %v, want ErrRejected", err)
	}
	// The remote holds exactly the winner's history; the loser's commit is intact locally.
	if got := rawGit(t, remote, "rev-parse", RefMain); got == string(bLocal) {
		t.Fatal("remote took the loser's commit")
	}
	if h, _ := b.ResolveRef(ctx, RefMain); h != bLocal {
		t.Fatal("loser's local main moved")
	}

	// Sync loop: fetch, replay, CAS, push.
	if err := b.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	upstream, _ := b.ResolveRef(ctx, RemoteMain)
	if ok, _ := b.IsAncestor(ctx, bLocal, upstream); ok {
		t.Fatal("local main should not be an ancestor of origin/main")
	}
	res, err := b.MergeTree(ctx, base, upstream, bLocal)
	if err != nil || len(res.Conflicts) != 0 || res.Tree == "" {
		t.Fatalf("MergeTree = %+v, %v", res, err)
	}
	orig, _ := b.Log(ctx, string(base)+".."+string(bLocal), nil)
	replayed, err := b.CommitTree(ctx, res.Tree, []model.CommitID{upstream}, orig[0].Message)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateRef(ctx, RefMain, replayed, bLocal); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatalf("retry push: %v", err)
	}
	if err := b.SyncWorktree(ctx, replayed); err != nil {
		t.Fatalf("SyncWorktree: %v", err)
	}
	for _, f := range []string{"files/.a", "files/.b", "files/.base"} {
		if _, err := os.Stat(filepath.Join(b.Dir(), f)); err != nil {
			t.Errorf("worktree lacks %s: %v", f, err)
		}
		rawGit(t, remote, "cat-file", "-e", RefMain+":"+f)
	}
	if n := rawGit(t, remote, "rev-list", "--count", "--merges", RefMain); n != "0" {
		t.Fatalf("history has %s merge commits; want linear", n)
	}
}

func TestPushRefusesForceAndHeld(t *testing.T) {
	_, a, _ := seeded(t)
	for _, spec := range []string{"+" + RefMain + ":" + RefMain, RefHeld("m-x") + ":" + RefHeld("m-x"), RefMain + ":" + RefHeld("m-x")} {
		if err := a.Push(context.Background(), []string{spec}); err == nil || errors.Is(err, ErrRejected) {
			t.Errorf("Push(%q) = %v; want refusal", spec, err)
		}
	}
}

// An atomic push of main plus a status ref lands neither when main is rejected.
func TestPushAtomic(t *testing.T) {
	ctx := context.Background()
	remote, a, b := seeded(t)
	commitMain(t, a, "a", change("files/.a", "a"))
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}
	commitMain(t, b, "b", change("files/.b", "b"))
	if err := StatusRefs(b, "m-b").Publish(ctx, model.Status{Machine: "m-b"}); err != nil {
		t.Fatal(err)
	}
	ref := fleet.StatusRef("m-b")
	err := b.Push(ctx, []string{RefMain + ":" + RefMain, ref + ":" + ref})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("push = %v, want ErrRejected", err)
	}
	if out := rawGit(t, remote, "for-each-ref", ref); out != "" {
		t.Fatalf("status ref landed despite atomic rejection: %s", out)
	}
}

// Commits built through the private index leave a dirty shared index and
// worktree exactly as they were, and parallel commits do not sweep each other.
func TestPrivateIndexLeavesSharedIndexAlone(t *testing.T) {
	ctx := context.Background()
	_, _, a := seeded(t) // the second clone has a checked-out worktree
	if err := os.WriteFile(filepath.Join(a.Dir(), "files", "staged"), []byte("staged by hand\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rawGit(t, a.Dir(), "add", "files/staged")
	if err := os.WriteFile(filepath.Join(a.Dir(), "files", ".base"), []byte("edited by hand\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(a.Dir(), ".git", "index")
	before, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	statusBefore := rawGit(t, a.Dir(), "status", "--porcelain")

	parent, _ := a.Head(ctx)
	var wg sync.WaitGroup
	ids := make([]model.CommitID, 4)
	errs := make([]error, 4)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := "files/p" + string(rune('0'+i))
			ids[i], errs[i] = a.CommitPaths(ctx, parent, []Change{change(p, p)}, msg(p))
		}(i)
	}
	wg.Wait()
	for i, id := range ids {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		entries, _ := a.ListTree(ctx, id)
		var names []string
		for _, e := range entries {
			names = append(names, string(e.Path))
		}
		want := "files/.base,files/p" + string(rune('0'+i))
		if strings.Join(names, ",") != want {
			t.Errorf("commit %d tree = %v, want %s", i, names, want)
		}
		if b, _ := a.ReadPath(ctx, id, "files/.base"); string(b) != "base\n" {
			t.Errorf("commit %d swept the hand edit of files/.base", i)
		}
	}
	after, _ := os.ReadFile(indexPath)
	if !bytes.Equal(before, after) {
		t.Fatal("shared index changed")
	}
	if got := rawGit(t, a.Dir(), "status", "--porcelain"); got != statusBefore {
		t.Fatalf("status changed:\n%s\nwant\n%s", got, statusBefore)
	}
	left, _ := os.ReadDir(a.indexDir)
	if len(left) != 0 {
		t.Fatalf("private index files left behind: %d", len(left))
	}
}

func TestMergeTreeReturnsConflictStages(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	base := commitMain(t, a, "base", change("files/f", "a\n"), change("files/g", "g\n"))
	ours, err := a.CommitPaths(ctx, base, []Change{change("files/f", "ours\n"), {Path: "files/g", Delete: true}}, msg("ours"))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := a.CommitPaths(ctx, base, []Change{change("files/f", "theirs\n"), change("files/g", "g2\n"), change("files/clean", "c")}, msg("theirs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mb := range []model.CommitID{base, ""} {
		res, err := a.MergeTree(ctx, mb, ours, theirs)
		if err != nil {
			t.Fatal(err)
		}
		if res.Tree != "" {
			t.Errorf("conflicted merge returned tree %s", res.Tree)
		}
		got := map[model.SourcePath]Conflict{}
		for _, c := range res.Conflicts {
			got[c.Path] = c
		}
		if len(got) != 2 {
			t.Fatalf("conflicts = %+v, want files/f and files/g", res.Conflicts)
		}
		blob := func(rev model.CommitID, p string) string { return rawGit(t, a.Dir(), "rev-parse", string(rev)+":"+p) }
		f := got["files/f"]
		if f.Base != blob(base, "files/f") || f.Ours != blob(ours, "files/f") || f.Theirs != blob(theirs, "files/f") {
			t.Errorf("files/f stages = %+v", f)
		}
		g := got["files/g"]
		if g.Base != blob(base, "files/g") || g.Ours != "" || g.Theirs != blob(theirs, "files/g") {
			t.Errorf("files/g modify/delete stages = %+v", g)
		}
		ob, _ := a.ReadBlob(ctx, f.Ours)
		if string(ob) != "ours\n" {
			t.Errorf("ours stage blob = %q", ob)
		}
	}
	// Resolve in memory and write the tree on ours.
	tree, err := a.WriteTree(ctx, ours, []Change{change("files/f", "resolved\n"), change("files/g", "g2\n"), change("files/clean", "c")})
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.CommitTree(ctx, tree, []model.CommitID{ours}, msg("resolved"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := a.ReadPath(ctx, id, "files/f"); string(b) != "resolved\n" {
		t.Fatalf("resolved blob = %q", b)
	}
}

func TestUpdateRefCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	c1, _ := a.Head(ctx)
	c2 := commitMain(t, a, "two", change("files/2", "2"))
	ref := RefReviewed(model.ScopeShared)

	if err := a.UpdateRef(ctx, ref, c1, ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := a.UpdateRef(ctx, ref, c2, ""); !errors.Is(err, ErrStaleRef) {
		t.Fatalf("create over existing = %v, want ErrStaleRef", err)
	}
	if err := a.UpdateRef(ctx, ref, c2, c2); !errors.Is(err, ErrStaleRef) {
		t.Fatalf("stale old = %v, want ErrStaleRef", err)
	}
	if got, _ := a.ResolveRef(ctx, ref); got != c1 {
		t.Fatalf("ref moved on a failed CAS: %s", got)
	}
	if err := a.UpdateRef(ctx, ref, c2, c1); err != nil {
		t.Fatalf("CAS: %v", err)
	}
	if err := a.UpdateRef(ctx, ref, "", c1); !errors.Is(err, ErrStaleRef) {
		t.Fatalf("stale delete = %v, want ErrStaleRef", err)
	}
	if err := a.UpdateRef(ctx, ref, "", c2); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, _ := a.ResolveRef(ctx, ref); got != "" {
		t.Fatalf("deleted ref resolves to %s", got)
	}
}

// Custom refs under refs/yadm/* round-trip through push and fetch, and status
// records published by one machine are read by another.
func TestYadmRefsRoundTrip(t *testing.T) {
	ctx := context.Background()
	remote, a, b := seeded(t)
	head, _ := a.Head(ctx)
	reviewed := RefReviewed("personal")
	if err := a.UpdateRef(ctx, reviewed, head, ""); err != nil {
		t.Fatal(err)
	}
	stA := StatusRefs(a, "m-a")
	if err := stA.Publish(ctx, model.Status{Machine: "m-a", Applied: head, Pending: 2}); err != nil {
		t.Fatal(err)
	}
	if err := stA.Publish(ctx, model.Status{Machine: "m-a", Applied: head, Pending: 3}); err != nil {
		t.Fatal(err)
	}
	if err := stA.Publish(ctx, model.Status{Machine: "m-other"}); err == nil {
		t.Fatal("published a status record for another machine")
	}
	statusA := fleet.StatusRef("m-a")
	if err := a.Push(ctx, []string{reviewed + ":" + reviewed, statusA + ":" + statusA}); err != nil {
		t.Fatal(err)
	}
	rawGit(t, remote, "rev-parse", "--verify", reviewed)

	if err := b.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := b.ResolveRef(ctx, "refs/remotes/origin/yadm/reviewed/personal")
	if got != head {
		t.Fatalf("fetched reviewed ref = %q, want %s", got, head)
	}
	stB := StatusRefs(b, "m-b")
	if err := stB.Publish(ctx, model.Status{Machine: "m-b", Held: 1}); err != nil {
		t.Fatal(err)
	}
	all, err := stB.ReadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all["m-a"].Pending != 3 || all["m-a"].Schema != model.StatusSchema || all["m-b"].Held != 1 {
		t.Fatalf("ReadAll = %+v", all)
	}
	// The status chain fast-forwards: two publishes, two commits.
	if n := rawGit(t, remote, "rev-list", "--count", statusA); n != "2" {
		t.Fatalf("status chain length %s, want 2", n)
	}
	// B's later publish continues the chain from its fetched copy when local is absent.
	stB2 := StatusRefs(b, "m-a")
	if err := stB2.Publish(ctx, model.Status{Machine: "m-a", Pending: 9}); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(ctx, []string{statusA + ":" + statusA}); err != nil {
		t.Fatalf("status push from continued chain: %v", err)
	}
	// Held refs never leave the machine.
	if err := a.UpdateRef(ctx, RefHeld("m-a"), head, ""); err != nil {
		t.Fatal(err)
	}
	if out := rawGit(t, remote, "for-each-ref", "refs/yadm/held/"); out != "" {
		t.Fatalf("held ref on remote: %s", out)
	}
}

func TestCheckSecrecyConfig(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	if err := a.CheckSecrecyConfig(ctx); err != nil {
		t.Fatalf("clean repo: %v", err)
	}
	rawGit(t, a.Dir(), "config", "diff.sealed.cachetextconv", "yes")
	err := a.CheckSecrecyConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "diff.sealed.cachetextconv") {
		t.Fatalf("cachetextconv: %v", err)
	}
	rawGit(t, a.Dir(), "config", "diff.sealed.cachetextconv", "false")
	if err := a.CheckSecrecyConfig(ctx); err != nil {
		t.Fatalf("cachetextconv=false: %v", err)
	}
	head, _ := a.Head(ctx)
	rawGit(t, a.Dir(), "update-ref", "refs/notes/textconv/sealed", string(head))
	err = a.CheckSecrecyConfig(ctx)
	if err == nil || !strings.Contains(err.Error(), "refs/notes/textconv") {
		t.Fatalf("textconv notes ref: %v", err)
	}
	// The harness agrees on both checks.
	probs, _ := secrecytest.SecrecyConfigProblems(a.Dir())
	if len(probs) == 0 {
		t.Fatal("secrecytest sees no problem")
	}
}

func TestSyncWorktree(t *testing.T) {
	ctx := context.Background()
	_, a, b := seeded(t)
	next := commitMain(t, a, "a", change("files/.base", "base v2\n"), change("files/new", "n\n"))
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}
	if err := b.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	old, _ := b.Head(ctx)
	// Main moves first (step 6 CAS), then the worktree.
	if err := b.UpdateRef(ctx, RefMain, next, old); err != nil {
		t.Fatal(err)
	}

	// Unstaged edit: ErrDirty, nothing moves.
	basePath := filepath.Join(b.Dir(), "files", ".base")
	os.WriteFile(basePath, []byte("local edit\n"), 0o644)
	if err := b.SyncWorktree(ctx, next); !errors.Is(err, ErrDirty) {
		t.Fatalf("unstaged: %v, want ErrDirty", err)
	}
	if got, _ := os.ReadFile(basePath); string(got) != "local edit\n" {
		t.Fatal("local edit lost")
	}
	// Staged edit: ErrDirty.
	rawGit(t, b.Dir(), "add", "files/.base")
	if err := b.SyncWorktree(ctx, next); !errors.Is(err, ErrDirty) {
		t.Fatalf("staged: %v, want ErrDirty", err)
	}
	rawGit(t, b.Dir(), "reset", "-q", string(old), "--", "files/.base")
	os.WriteFile(basePath, []byte("base\n"), 0o644)

	// Untracked file in the way: ErrDirty.
	newPath := filepath.Join(b.Dir(), "files", "new")
	os.WriteFile(newPath, []byte("mine\n"), 0o644)
	if err := b.SyncWorktree(ctx, next); !errors.Is(err, ErrDirty) {
		t.Fatalf("untracked: %v, want ErrDirty", err)
	}
	os.Remove(newPath)

	// Touched but unchanged is not dirty.
	future := time.Now().Add(time.Hour)
	os.Chtimes(basePath, future, future)
	if err := b.SyncWorktree(ctx, next); err != nil {
		t.Fatalf("clean sync: %v", err)
	}
	if got, _ := os.ReadFile(basePath); string(got) != "base v2\n" {
		t.Fatalf("worktree not moved: %q", got)
	}
	if st := rawGit(t, b.Dir(), "status", "--porcelain"); st != "" {
		t.Fatalf("status after sync:\n%s", st)
	}
	// A second sync to the same commit is a no-op.
	if err := b.SyncWorktree(ctx, next); err != nil {
		t.Fatal(err)
	}
}

// The store only stores the bytes it is given. Sealed bytes committed, merged
// and pushed through it leave no plaintext canary anywhere when the caller
// passes ciphertext, and git config the store runs with writes no textconv cache.
func TestStoreWritesOnlyGivenBytes(t *testing.T) {
	ctx := context.Background()
	remote, a, b := seeded(t)
	c := secrecytest.NewCanary(t, "personal")
	sealed := bytes.Map(func(r rune) rune { return r ^ 0x55 }, c.Bytes()) // stand-in ciphertext
	if bytes.Contains(sealed, c.Bytes()) {
		t.Fatal("stand-in ciphertext contains the canary")
	}
	commitMain(t, a, "sealed", Change{Path: "sealed/personal/.secret", Blob: sealed, Mode: 0o100644})
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}
	if err := StatusRefs(a, "m-a").Publish(ctx, model.Status{Machine: "m-a"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Log(ctx, RemoteMain, nil); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{a.Dir(), b.Dir(), remote} {
		secrecytest.AssertRepoClean(t, repo, c)
	}
	secrecytest.AssertTreeClean(t, a.stateDir, c)
}
