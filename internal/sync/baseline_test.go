package sync

import (
	"context"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// TestBaselineIgnoreAndTrack: files that predate a newly allowed root are
// held once; `hold ignore` stops one from showing for good, the root's
// ignore globs keep others from ever showing, and retag tracks the last
// one for chosen types with a new manifest entry.
func TestBaselineIgnoreAndTrack(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()

	local := model.Target(".config/app/local.txt")
	keep := model.Target(".config/app/keep.txt")
	cached := model.Target(".config/app/cache/blob.bin")
	A.write(local, "machine-local\n")
	A.write(keep, "worth sharing\n")
	A.write(cached, "cache\n")
	man, err := B.st.ReadPath(ctx, B.main(), "manifest.toml")
	if err != nil {
		t.Fatal(err)
	}
	man = append(man, []byte("\n[[root]]\npath = \".config/app\"\nignore = [\"cache/**\"]\n")...)
	pushRaw(t, B, []store.Change{{Path: "manifest.toml", Blob: man, Mode: 0o100644}})
	A.sync()
	if err := A.eng.AllowRoot(ctx, A.main(), ".config/app"); err != nil {
		t.Fatal(err)
	}
	A.sync()
	r := A.sync()
	held := map[model.Target]string{}
	for _, h := range holdsOf(r, model.HoldProtected) {
		held[h.Target] = h.ID
	}
	if held[local] == "" || held[keep] == "" {
		t.Fatalf("baseline files not held: %+v", r.Holds)
	}
	if _, ok := held[cached]; ok {
		t.Fatal("a file under the root's ignore glob was held")
	}

	if err := A.eng.Ignore(ctx, nil, local); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		r = A.sync()
		for _, h := range r.Holds {
			if h.Target == local {
				t.Fatalf("ignored file still held: %+v", h)
			}
		}
	}
	if err := A.eng.Ignore(ctx, nil, ".config/shell/aliases.sh"); err == nil {
		t.Error("a managed file was ignored")
	}

	c, err := A.eng.Retag(ctx, keep, apply.RetagOptions{Types: []model.TypeName{"personal"}})
	if err != nil {
		t.Fatal(err)
	}
	last := len(c.Changes) - 1
	target := apply.Capture{Changes: c.Changes[last:], Paths: c.Paths, Scopes: c.Scopes}
	rc, err := A.s.Commit(ctx, CommitOptions{Message: "retag", Capture: &target, Changes: c.Changes[:last], ChangesScope: model.ScopeShared, Push: true})
	if err != nil || len(rc.Committed) != 1 {
		t.Fatalf("track commit: %+v %v", rc, err)
	}
	if got := w.remoteFile("files/" + string(keep)); got != "worth sharing" {
		t.Errorf("tracked source %q", got)
	}
	if mf := w.remoteFile("manifest.toml"); !strings.Contains(mf, "target = '.config/app/keep.txt'\nwhen = 'type:personal'") &&
		!strings.Contains(mf, "target = \".config/app/keep.txt\"\nwhen = \"type:personal\"") {
		t.Errorf("manifest entry missing:\n%s", mf)
	}
	r = A.sync()
	for _, h := range r.Holds {
		if h.Target == keep || h.Target == local {
			t.Errorf("hold after track: %+v", h)
		}
	}
	if out := git(t, w.remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(out, "local.txt") || strings.Contains(out, "blob.bin") {
		t.Error("an ignored file reached the remote")
	}

	// Ignore refuses a directory, a missing file and a path outside roots.
	for _, p := range []model.Target{".config/app/cache", ".config/app/missing.txt", ".config/elsewhere.txt"} {
		if err := A.eng.Ignore(ctx, nil, p); err == nil {
			t.Errorf("ignored %s", p)
		}
	}

	// A file made under the glob after the root arrived, then a pusher
	// drops the glob: the files it hid are held, never auto-committed.
	later := model.Target(".config/app/cache/later.bin")
	A.write(later, "cache made later\n")
	A.sync()
	B.sync()
	man, err = B.st.ReadPath(ctx, B.main(), "manifest.toml")
	if err != nil {
		t.Fatal(err)
	}
	open := strings.Replace(string(man), "ignore = [\"cache/**\"]\n", "", 1)
	if open == string(man) {
		t.Fatal("manifest lacks the ignore glob")
	}
	pushRaw(t, B, []store.Change{{Path: "manifest.toml", Blob: []byte(open), Mode: 0o100644}})
	for i := 0; i < 3; i++ {
		r = A.sync()
		if len(r.Committed) != 0 {
			t.Fatalf("glob removal committed hidden files: %+v", r)
		}
	}
	if out := git(t, w.remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(out, "blob.bin") || strings.Contains(out, "later.bin") {
		t.Error("a file the dropped glob hid reached the remote")
	}
}
