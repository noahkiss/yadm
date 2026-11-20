package sync

import (
	"context"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

func TestAddOnly(t *testing.T) {
	got, ok := addOnly([]byte("a\nb\n"), []byte("a\nb\nc\n"), []byte("a\nx\nb\n"))
	if !ok || string(got) != "a\nb\nc\nx\n" {
		t.Errorf("add-only = %q %v", got, ok)
	}
	if _, ok := addOnly([]byte("a\nb\n"), []byte("a\nB\n"), []byte("a\nb\nc\n")); ok {
		t.Error("a modified line was accepted")
	}
}

// keyMerger is a Structural that records the volatile keys it was given.
type keyMerger struct {
	volatile []string
	format   string
}

func (k *keyMerger) Merge3(format string, volatile []string, _, _, _ []byte) ([]byte, bool, error) {
	k.format, k.volatile = format, volatile
	return []byte("{\"merged\": true}\n"), true, nil
}

// TestLadderPolicies drives resolve directly with real blobs.
func TestLadderPolicies(t *testing.T) {
	w := newWorld(t, nil, fixture.HostA)
	A := w.machines[fixture.HostA]
	A.sync()
	ctx := context.Background()
	blob := func(s string) string {
		id, err := A.s.blobID(ctx, []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	st := &apply.State{}
	km := &keyMerger{}
	A.s.Structural = km
	pol := map[model.Target]MergePolicy{}
	A.s.Policy.MergeFor = func(t model.Target) MergePolicy { return pol[t] }
	A.s.Policy.VolatileFor = func(t model.Target) []string { return []string{"window.state"} }
	r := &resolver{s: A.s, st: st}
	run := func(path string, p MergePolicy, base, ours, theirs string) (*store.Change, *model.Hold, string) {
		t.Helper()
		pol[r.target(model.SourcePath(path))] = p
		c := conflict{Conflict: store.Conflict{Path: model.SourcePath(path), Base: blob(base), Ours: blob(ours), Theirs: blob(theirs)}}
		ch, h, rung, err := r.resolve(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return ch, h, rung
	}
	cases := []struct {
		name, path   string
		pol          MergePolicy
		wantRung     string
		wantBlob     string
		base, o, thr string
	}{
		{"text overlap holds", "files/a.txt", "", RungHold, "", "x\n", "o\n", "t\n"},
		{"ours", "files/b.txt", MergeOurs, RungOurs, "o\n", "x\n", "o\n", "t\n"},
		{"theirs", "files/c.txt", MergeTheirs, RungTheirs, "t\n", "x\n", "o\n", "t\n"},
		{"generated", "files/d.txt", MergeGenerated, RungGenerated, "t\n", "x\n", "o\n", "t\n"},
		{"union", "files/e.list", MergeUnion, RungUnion, "o\nt\n", "x\n", "o\n", "t\n"},
		{"add-only", "files/f.log", MergeAddOnly, RungAddOnly, "x\no\nt\n", "x\n", "x\no\n", "x\nt\n"},
		{"add-only modify", "files/g.log", MergeAddOnly, RungHold, "", "x\n", "y\n", "x\nt\n"},
		{"json default goes structural", "files/h.json", "", RungStructural, "{\"merged\": true}\n", "{}", "{\"a\":1}", "{\"b\":2}"},
		{"json-keys", "files/i.conf", MergeJSONKeys, RungStructural, "{\"merged\": true}\n", "{}", "{\"a\":1}", "{\"b\":2}"},
	}
	for _, c := range cases {
		ch, h, rung := run(c.path, c.pol, c.base, c.o, c.thr)
		if rung != c.wantRung {
			t.Errorf("%s: rung %s, want %s (hold %+v)", c.name, rung, c.wantRung, h)
			continue
		}
		if c.wantRung == RungHold {
			if h == nil || h.Reason != model.HoldConflict || h.Ours == "" || h.Theirs == "" {
				t.Errorf("%s: hold %+v", c.name, h)
			}
			continue
		}
		if ch == nil || string(ch.Blob) != c.wantBlob {
			t.Errorf("%s: change %+v", c.name, ch)
		}
	}
	if km.format != "json" || len(km.volatile) != 1 {
		t.Errorf("structural got format %q volatile %v", km.format, km.volatile)
	}
	// Without a Structural, json-keys holds instead of falling to a line merge.
	A.s.Structural = nil
	if _, h, rung := run("files/j.json", MergeJSONKeys, "{}", "{\"a\":1}", "{\"b\":2}"); rung != RungHold || h == nil {
		t.Errorf("json-keys without a merger: %s", rung)
	}
}

func TestGeneratedNeverAutoCommits(t *testing.T) {
	now := time.Now()
	st := &apply.State{Targets: map[model.Target]apply.TargetState{"gen": {ChangedAt: now.Add(-3 * time.Hour)}}}
	p := Policy{MergeFor: func(model.Target) MergePolicy { return MergeGenerated }}
	planned, holds, err := PlanCommits(capture("gen"), st, p, nil, "m", now)
	if err != nil || len(planned) != 0 || len(holds) != 0 {
		t.Errorf("generated: %+v %+v %v", planned, holds, err)
	}
}
