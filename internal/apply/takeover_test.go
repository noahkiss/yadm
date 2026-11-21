package apply

import (
	"context"
	"os"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

// takeoverWorld puts byte-identical package-list files on disk, with a path
// task on them, a path task on nothing adopted and a first-apply task.
func takeoverWorld(t *testing.T) (*world, *countExec, tasks.AllowList, model.CommitID) {
	t.Helper()
	w := newWorld(t)
	exec := &countExec{runs: map[string]int{}}
	allow := tasks.FileAllowList(t.TempDir())
	w.eng.Tasks = &tasks.Runner{Exec: exec, Allow: allow}
	c := w.commit(map[model.SourcePath]string{"files/.pkglist": "a\n", "files/.rc": "rc\n"},
		manifest.Entry{Target: ".pkglist"}, manifest.Entry{Target: ".rc"})
	w.plans[c].Tasks = map[string]manifest.TaskDef{
		"bundle":    {On: []string{".pkglist"}, Command: []string{"pkg-tool"}},
		"elsewhere": {On: []string{".config/other/**"}, Command: []string{"other-tool"}},
		"bootstrap": {FirstApply: true, Command: []string{"bootstrap-tool"}},
	}
	w.write(".pkglist", "a\n")
	w.write(".rc", "rc\n")
	return w, exec, allow, c
}

// TestAdoptFiresPathTasksOnce: adopt takes over byte-identical targets
// without writing them, and an allowed path task matching one runs once. A
// task matching nothing adopted does not run, the first-apply task waits
// for the first apply, and later identical applies fire nothing.
func TestAdoptFiresPathTasksOnce(t *testing.T) {
	ctx := context.Background()
	w, exec, _, c := takeoverWorld(t)
	res, err := w.eng.Adopt(ctx, c, AdoptOptions{AllowTasks: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range res.Actions {
		if a.Target == ".pkglist" && a.Kind != ActAdopt {
			t.Fatalf(".pkglist action %s, want adopt", a.Kind)
		}
	}
	if exec.runs["bundle"] != 1 || exec.runs["elsewhere"] != 0 || exec.runs["bootstrap"] != 0 || w.state().FirstApplyDone {
		t.Fatalf("adopt ran %v, first apply done %v", exec.runs, w.state().FirstApplyDone)
	}
	if len(res.Tasks) != 1 || res.Tasks[0].Task != "bundle" || res.Tasks[0].Trigger != tasks.TriggerPaths {
		t.Fatalf("adopt task results: %+v", res.Tasks)
	}
	w.apply(c)
	if exec.runs["bootstrap"] != 1 || exec.runs["bundle"] != 1 || !w.state().FirstApplyDone {
		t.Fatalf("first apply after adopt: %v", exec.runs)
	}
	w.apply(c)
	if exec.runs["bootstrap"] != 1 || exec.runs["bundle"] != 1 || exec.runs["elsewhere"] != 0 {
		t.Fatalf("identical apply fired tasks: %v", exec.runs)
	}
}

// TestAdoptHoldsUnallowedPathTask: a path task that is not allowed becomes
// the usual task_untrusted hold, never a run.
func TestAdoptHoldsUnallowedPathTask(t *testing.T) {
	w, exec, _, c := takeoverWorld(t)
	res, err := w.eng.Adopt(context.Background(), c, AdoptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hs := taskHolds(res.Holds)
	if len(hs) != 1 || hs[0].Task != "bundle" || hs[0].Reason != model.HoldTaskUntrusted || len(exec.runs) != 0 {
		t.Fatalf("holds %+v, runs %v", res.Holds, exec.runs)
	}
}

// TestAdoptWritesMissingAndFires: a target adopt writes because it was
// missing is taken over too.
func TestAdoptWritesMissingAndFires(t *testing.T) {
	w, exec, _, c := takeoverWorld(t)
	if err := os.Remove(w.path(".pkglist")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.eng.Adopt(context.Background(), c, AdoptOptions{AllowTasks: true}); err != nil {
		t.Fatal(err)
	}
	if w.read(".pkglist") != "a\n" || exec.runs["bundle"] != 1 {
		t.Fatalf("missing target: runs %v", exec.runs)
	}
}

// TestFirstApplyFiresForIdenticalTargets: a first apply that finds a
// target's bytes already in place runs its path task once; the next apply
// does not.
func TestFirstApplyFiresForIdenticalTargets(t *testing.T) {
	w, exec, allow, c := takeoverWorld(t)
	for name, def := range w.plans[c].Tasks {
		h, err := tasks.DefinitionHash(def)
		if err != nil {
			t.Fatal(err)
		}
		if err := allow.Allow(extexec.KindTask, name, h); err != nil {
			t.Fatal(err)
		}
	}
	w.apply(c)
	if exec.runs["bundle"] != 1 || exec.runs["bootstrap"] != 1 || exec.runs["elsewhere"] != 0 {
		t.Fatalf("first apply: %v", exec.runs)
	}
	w.apply(c)
	if exec.runs["bundle"] != 1 || exec.runs["bootstrap"] != 1 {
		t.Fatalf("second apply fired tasks: %v", exec.runs)
	}
}

// TestAdoptFirstApplyTaskRunsOnce: a first-apply task that also matches an
// adopted target runs at adopt as a path task and not again for the first
// apply at the same commit.
func TestAdoptFirstApplyTaskRunsOnce(t *testing.T) {
	ctx := context.Background()
	w, exec, _, c := takeoverWorld(t)
	w.plans[c].Tasks = map[string]manifest.TaskDef{
		"setup": {On: []string{".pkglist"}, FirstApply: true, Command: []string{"setup-tool"}},
	}
	if _, err := w.eng.Adopt(ctx, c, AdoptOptions{AllowTasks: true}); err != nil {
		t.Fatal(err)
	}
	w.apply(c)
	if exec.runs["setup"] != 1 || !w.state().FirstApplyDone {
		t.Fatalf("setup ran %d times, first apply done %v", exec.runs["setup"], w.state().FirstApplyDone)
	}
}
