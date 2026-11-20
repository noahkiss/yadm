package apply

import (
	"context"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

// countExec records how often each task ran and always succeeds.
type countExec struct{ runs map[string]int }

func (c *countExec) Run(_ context.Context, _ extexec.Spec, req extexec.Request) (extexec.Result, error) {
	c.runs[req.Name]++
	return extexec.Result{}, nil
}

func taskHolds(hs []model.Hold) []model.Hold {
	var out []model.Hold
	for _, h := range hs {
		if h.Task != "" {
			out = append(out, h)
		}
	}
	return out
}

func TestFirstApplyWaitsForTaskHolds(t *testing.T) {
	w := newWorld(t)
	exec := &countExec{runs: map[string]int{}}
	allow := tasks.FileAllowList(t.TempDir())
	w.eng.Tasks = &tasks.Runner{Exec: exec, Allow: allow}
	def := manifest.TaskDef{FirstApply: true, Command: []string{"bootstrap-tool"}}
	c := w.commit(map[model.SourcePath]string{"files/.x": "x\n"}, manifest.Entry{Target: ".x"})
	w.plans[c].Tasks = map[string]manifest.TaskDef{"bootstrap": def}

	r1 := w.apply(c)
	h1 := taskHolds(r1.Holds)
	if len(h1) != 1 || h1[0].Task != "bootstrap" || h1[0].Reason != model.HoldTaskUntrusted || h1[0].ID != model.HoldID(h1[0]) {
		t.Fatalf("first apply holds: %+v", r1.Holds)
	}
	if w.state().FirstApplyDone {
		t.Fatal("first apply marked done while its task is held")
	}

	w.tick(time.Hour)
	r2 := w.apply(c)
	h2 := taskHolds(r2.Holds)
	if len(h2) != 1 || h2[0].ID != h1[0].ID || !h2[0].Since.Equal(h1[0].Since) {
		t.Fatalf("hold id not stable: %+v vs %+v", h2, h1)
	}
	if got := taskHolds(w.state().Holds); len(got) != 1 || got[0].ID != h1[0].ID {
		t.Fatalf("state holds: %+v", got)
	}
	if w.state().FirstApplyDone || exec.runs["bootstrap"] != 0 {
		t.Fatal("held task ran or first apply marked done")
	}

	hash, err := tasks.DefinitionHash(def)
	if err != nil {
		t.Fatal(err)
	}
	if err := allow.Allow(extexec.KindTask, "bootstrap", hash); err != nil {
		t.Fatal(err)
	}
	r3 := w.apply(c)
	if exec.runs["bootstrap"] != 1 || len(taskHolds(r3.Holds)) != 0 {
		t.Fatalf("allowed task: runs=%d holds=%+v", exec.runs["bootstrap"], r3.Holds)
	}
	st := w.state()
	if !st.FirstApplyDone || len(taskHolds(st.Holds)) != 0 {
		t.Fatalf("after allow: done=%v holds=%+v", st.FirstApplyDone, st.Holds)
	}
	w.apply(c)
	if exec.runs["bootstrap"] != 1 {
		t.Fatal("first-apply task ran twice")
	}
}

func TestTaskHoldOfRemovedTaskIsPruned(t *testing.T) {
	w := newWorld(t)
	w.eng.Tasks = &tasks.Runner{Exec: &countExec{runs: map[string]int{}}, Allow: tasks.FileAllowList(t.TempDir())}
	c1 := w.commit(map[model.SourcePath]string{"files/.x": "x\n"}, manifest.Entry{Target: ".x"})
	w.plans[c1].Tasks = map[string]manifest.TaskDef{"gone": {FirstApply: true, Command: []string{"tool"}}}
	w.apply(c1)
	if len(taskHolds(w.state().Holds)) != 1 {
		t.Fatal("no task hold")
	}
	c2 := w.commit(map[model.SourcePath]string{"files/.x": "y\n"}, manifest.Entry{Target: ".x"})
	w.apply(c2)
	st := w.state()
	if len(taskHolds(st.Holds)) != 0 || !st.FirstApplyDone {
		t.Fatalf("stale task hold kept: done=%v holds=%+v", st.FirstApplyDone, st.Holds)
	}
}
