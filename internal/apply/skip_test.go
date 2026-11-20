package apply

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// readCounter counts the source reads apply makes.
type readCounter struct {
	*fakeStore
	reads int
}

func (c *readCounter) ReadBlob(ctx context.Context, id string) ([]byte, error) {
	c.reads++
	return c.fakeStore.ReadBlob(ctx, id)
}

func (c *readCounter) ReadPath(ctx context.Context, rev model.CommitID, p model.SourcePath) ([]byte, error) {
	c.reads++
	return c.fakeStore.ReadPath(ctx, rev, p)
}

const (
	skPlain  model.Target = ".config/tool/plain.conf"
	skSealed model.Target = ".config/notes/private.md"
	skTmpl   model.Target = ".config/tool/host.conf"
)

// skipWorld applies a plain file, a sealed file and a template once and
// counts reads from then on.
func skipWorld(t *testing.T) (*world, *readCounter, model.CommitID) {
	t.Helper()
	w := newWorld(t, "personal")
	rev := w.commit(map[model.SourcePath]string{
		"files/" + model.SourcePath(skPlain):            "plain = 1\n",
		"sealed/personal/" + model.SourcePath(skSealed): "private note\n",
		"files/" + model.SourcePath(skTmpl) + ".tmpl":   "host = {{ machine.name }}\n",
	},
		manifest.Entry{Target: skPlain},
		manifest.Entry{Target: skSealed, Enclave: "personal"},
		manifest.Entry{Target: skTmpl, Source: "files/" + model.SourcePath(skTmpl) + ".tmpl", Template: true},
	)
	w.apply(rev)
	rc := &readCounter{fakeStore: w.st}
	w.eng.Store = rc
	return w, rc, rev
}

func targetsJSON(t *testing.T, st *State) string {
	t.Helper()
	b, err := json.Marshal(st.Targets)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSkipUnchangedReadsNothing: a second apply of the same commit reads no
// source, opens nothing, writes nothing and leaves the state as it was.
func TestSkipUnchangedReadsNothing(t *testing.T) {
	w, rc, rev := skipWorld(t)
	before := targetsJSON(t, w.state())
	ids := map[model.Target]fileID{}
	for _, tg := range []model.Target{skPlain, skSealed, skTmpl} {
		ids[tg] = w.id(tg)
	}
	w.tick(time.Hour)
	r := w.apply(rev)
	if rc.reads != 0 {
		t.Errorf("apply of an unchanged commit read the source %d times", rc.reads)
	}
	for _, tg := range []model.Target{skPlain, skSealed, skTmpl} {
		if a := actionOf(r, tg); a.Kind != ActSkip {
			t.Errorf("%s: %s, want skip", tg, a.Kind)
		}
		if w.id(tg) != ids[tg] {
			t.Errorf("%s rewritten", tg)
		}
	}
	if after := targetsJSON(t, w.state()); after != before {
		t.Errorf("state changed by a skipping apply:\nbefore %s\nafter  %s", before, after)
	}
	if got := w.read(skSealed); got != "private note\n" {
		t.Errorf("sealed target %q", got)
	}
}

// TestSkipRecomputesWhenAnInputChanged: each input of a target, when it
// changes, makes apply read and recompute that target again.
func TestSkipRecomputesWhenAnInputChanged(t *testing.T) {
	t.Run("touched, same bytes", func(t *testing.T) {
		w, rc, rev := skipWorld(t)
		later := time.Now().Add(-time.Minute)
		if err := os.Chtimes(w.path(skPlain), later, later); err != nil {
			t.Fatal(err)
		}
		r := w.apply(rev)
		if rc.reads != 1 || actionOf(r, skPlain).Kind != ActSkip {
			t.Fatalf("reads %d, action %+v", rc.reads, actionOf(r, skPlain))
		}
		// The state now records the new stat tuple: the next apply skips.
		rc.reads = 0
		w.apply(rev)
		if rc.reads != 0 {
			t.Errorf("reads %d after the stat was refreshed", rc.reads)
		}
	})
	t.Run("edited", func(t *testing.T) {
		w, _, rev := skipWorld(t)
		w.write(skPlain, "plain = 2\n")
		r := w.apply(rev)
		if a := actionOf(r, skPlain); a.Kind != ActHold {
			t.Fatalf("edited target: %+v", a)
		}
		if got := w.read(skPlain); got != "plain = 2\n" {
			t.Errorf("edit overwritten: %q", got)
		}
	})
	t.Run("source changed", func(t *testing.T) {
		w, _, _ := skipWorld(t)
		rev := w.commit(map[model.SourcePath]string{
			"files/" + model.SourcePath(skPlain):            "plain = 3\n",
			"sealed/personal/" + model.SourcePath(skSealed): "private note\n",
			"files/" + model.SourcePath(skTmpl) + ".tmpl":   "host = {{ machine.name }}\n",
		},
			manifest.Entry{Target: skPlain},
			manifest.Entry{Target: skSealed, Enclave: "personal"},
			manifest.Entry{Target: skTmpl, Source: "files/" + model.SourcePath(skTmpl) + ".tmpl", Template: true},
		)
		r := w.apply(rev)
		if a := actionOf(r, skPlain); a.Kind != ActWrite || w.read(skPlain) != "plain = 3\n" {
			t.Fatalf("changed source: %+v %q", a, w.read(skPlain))
		}
		if a := actionOf(r, skSealed); a.Kind != ActSkip {
			t.Errorf("unchanged sealed target: %+v", a)
		}
	})
	t.Run("render context changed", func(t *testing.T) {
		w, rc, rev := skipWorld(t)
		w.machine.Name = "host-renamed"
		r := w.apply(rev)
		if a := actionOf(r, skTmpl); a.Kind != ActWrite || w.read(skTmpl) != "host = host-renamed\n" {
			t.Fatalf("template after a context change: %+v %q", a, w.read(skTmpl))
		}
		if rc.reads != 1 {
			t.Errorf("reads %d, want 1 (the template only)", rc.reads)
		}
	})
	t.Run("observed collection time only", func(t *testing.T) {
		w, rc, rev := skipWorld(t)
		snap, err := w.load(context.Background(), rev)
		if err != nil {
			t.Fatal(err)
		}
		k1 := applyKey(snap, snap.Plan.Targets[skTmpl])
		snap.Context.Observed = map[string]model.ObservedFact{"tools": {Collector: "tools", Items: []string{"a"}, CollectedAt: time.Now()}}
		k2 := applyKey(snap, snap.Plan.Targets[skTmpl])
		snap.Context.Observed["tools"] = model.ObservedFact{Collector: "tools", Items: []string{"a"}, CollectedAt: time.Now().Add(time.Hour)}
		k3 := applyKey(snap, snap.Plan.Targets[skTmpl])
		if k1 == k2 || k2 != k3 {
			t.Errorf("observed items must change the key and collection time must not: %v %v", k1 != k2, k2 == k3)
		}
		_ = rc
	})
	t.Run("entry changed", func(t *testing.T) {
		w, rc, _ := skipWorld(t)
		rev := w.commit(map[model.SourcePath]string{
			"files/" + model.SourcePath(skPlain):            "plain = 1\n",
			"sealed/personal/" + model.SourcePath(skSealed): "private note\n",
			"files/" + model.SourcePath(skTmpl) + ".tmpl":   "host = {{ machine.name }}\n",
		},
			manifest.Entry{Target: skPlain, Mode: 0o600},
			manifest.Entry{Target: skSealed, Enclave: "personal"},
			manifest.Entry{Target: skTmpl, Source: "files/" + model.SourcePath(skTmpl) + ".tmpl", Template: true},
		)
		r := w.apply(rev)
		if a := actionOf(r, skPlain); a.Kind != ActWrite || w.mode(skPlain) != 0o600 {
			t.Fatalf("mode change: %+v %#o", a, w.mode(skPlain))
		}
		if rc.reads != 1 {
			t.Errorf("reads %d, want 1", rc.reads)
		}
	})
	t.Run("state from before the key", func(t *testing.T) {
		w, rc, rev := skipWorld(t)
		st := w.state()
		for tg, ts := range st.Targets {
			ts.ApplyKey = ""
			st.Targets[tg] = ts
		}
		if err := w.eng.State.Save(st); err != nil {
			t.Fatal(err)
		}
		w.apply(rev)
		if rc.reads != 3 {
			t.Errorf("reads %d, want 3 (every target once)", rc.reads)
		}
		rc.reads = 0
		w.apply(rev)
		if rc.reads != 0 {
			t.Errorf("reads %d once the key is recorded", rc.reads)
		}
	})
	t.Run("hold on the target", func(t *testing.T) {
		w, rc, rev := skipWorld(t)
		st := w.state()
		st.Holds = append(st.Holds, model.Hold{ID: "h1", Target: skPlain, Scope: model.ScopeShared, Reason: model.HoldConflict})
		if err := w.eng.State.Save(st); err != nil {
			t.Fatal(err)
		}
		w.apply(rev)
		if rc.reads != 1 {
			t.Errorf("reads %d, want 1 (the held target)", rc.reads)
		}
	})
}

func (w *world) mode(t model.Target) os.FileMode {
	w.t.Helper()
	info, err := os.Stat(w.path(t))
	if err != nil {
		w.t.Fatal(err)
	}
	return info.Mode().Perm()
}
