package apply

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

// lastExec records the trigger of each task's last run.
type lastExec struct {
	runs    map[string]int
	trigger map[string]string
}

func (c *lastExec) Run(_ context.Context, _ extexec.Spec, req extexec.Request) (extexec.Result, error) {
	c.runs[req.Name]++
	c.trigger[req.Name] = req.Trigger
	return extexec.Result{}, nil
}

func allowTask(t *testing.T, al tasks.AllowList, name string, def manifest.TaskDef) {
	t.Helper()
	h, err := tasks.DefinitionHash(def)
	if err != nil {
		t.Fatal(err)
	}
	if err := al.Allow(extexec.KindTask, name, h); err != nil {
		t.Fatal(err)
	}
}

func TestOnFactAndOnRender(t *testing.T) {
	w := newWorld(t)
	w.machine.Facts = map[string]string{"editor": "editor-one", "shell": "zsh"}
	ex := &lastExec{runs: map[string]int{}, trigger: map[string]string{}}
	al := tasks.FileAllowList(t.TempDir())
	w.eng.Tasks = &tasks.Runner{Exec: ex, Allow: al}
	onFact := manifest.TaskDef{OnFact: []string{"fact:editor"}, Command: []string{"gen-a"}}
	onRender := manifest.TaskDef{OnRender: true, Command: []string{"gen-b"}}
	plain := manifest.TaskDef{On: []string{".y"}, Command: []string{"gen-c"}}
	allowTask(t, al, "fact", onFact)
	allowTask(t, al, "render", onRender)
	allowTask(t, al, "plain", plain)
	c := w.commit(map[model.SourcePath]string{"files/.x": "x\n"}, manifest.Entry{Target: ".x"})
	w.plans[c].Tasks = map[string]manifest.TaskDef{"fact": onFact, "render": onRender, "plain": plain}

	// No record yet: both watchers run once.
	w.apply(c)
	if ex.runs["fact"] != 1 || ex.runs["render"] != 1 || ex.runs["plain"] != 0 {
		t.Fatalf("first apply runs: %v", ex.runs)
	}
	st := w.state()
	if len(st.TaskInputs["fact"]) != 1 || st.TaskInputs["fact"]["fact:editor"] == "" {
		t.Fatalf("recorded inputs: %+v", st.TaskInputs)
	}
	if b, _ := json.Marshal(st.TaskInputs); strings.Contains(string(b), "editor-one") {
		t.Error("task inputs hold a fact value; they should hold only fingerprints")
	}
	// Nothing changed: nothing runs.
	w.apply(c)
	if ex.runs["fact"] != 1 || ex.runs["render"] != 1 {
		t.Fatalf("unchanged apply ran: %v", ex.runs)
	}
	// Another fact changes: only the render watcher runs.
	w.machine.Facts["shell"] = "bash"
	w.apply(c)
	if ex.runs["fact"] != 1 || ex.runs["render"] != 2 || ex.trigger["render"] != tasks.TriggerRender {
		t.Fatalf("shell change: runs %v triggers %v", ex.runs, ex.trigger)
	}
	// The watched fact changes: both run.
	w.machine.Facts["editor"] = "editor-two"
	w.apply(c)
	if ex.runs["fact"] != 2 || ex.runs["render"] != 3 || ex.trigger["fact"] != tasks.TriggerFact {
		t.Fatalf("editor change: runs %v triggers %v", ex.runs, ex.trigger)
	}
	// A type change is a render change.
	w.machine.Types = append(w.machine.Types, "personal")
	w.apply(c)
	if ex.runs["fact"] != 2 || ex.runs["render"] != 4 {
		t.Fatalf("type change: runs %v", ex.runs)
	}
	if ex.runs["plain"] != 0 {
		t.Fatalf("a task without inputs ran: %v", ex.runs)
	}
}

// TestOnFactHeldThenAllowed: a change that arrives while the task is held
// is not lost; the task runs once it is allowed.
func TestOnFactHeldThenAllowed(t *testing.T) {
	w := newWorld(t)
	w.machine.Facts = map[string]string{"editor": "editor-one"}
	ex := &lastExec{runs: map[string]int{}, trigger: map[string]string{}}
	al := tasks.FileAllowList(t.TempDir())
	w.eng.Tasks = &tasks.Runner{Exec: ex, Allow: al}
	def := manifest.TaskDef{OnFact: []string{"fact:editor"}, Command: []string{"gen-a"}}
	allowTask(t, al, "fact", def)
	c := w.commit(map[model.SourcePath]string{"files/.x": "x\n"}, manifest.Entry{Target: ".x"})
	w.plans[c].Tasks = map[string]manifest.TaskDef{"fact": def}
	w.apply(c)
	if ex.runs["fact"] != 1 {
		t.Fatalf("runs %v", ex.runs)
	}
	// The definition changes (now untrusted) and the fact changes.
	def2 := def
	def2.Command = []string{"gen-a", "--v2"}
	c2 := w.commit(map[model.SourcePath]string{"files/.x": "x\n"}, manifest.Entry{Target: ".x"})
	w.plans[c2].Tasks = map[string]manifest.TaskDef{"fact": def2}
	w.machine.Facts["editor"] = "editor-two"
	r := w.apply(c2)
	if ex.runs["fact"] != 1 || len(taskHolds(r.Holds)) != 1 {
		t.Fatalf("held: runs %v holds %+v", ex.runs, r.Holds)
	}
	w.apply(c2)
	if ex.runs["fact"] != 1 {
		t.Fatal("held task ran")
	}
	allowTask(t, al, "fact", def2)
	w.apply(c2)
	if ex.runs["fact"] != 2 || ex.trigger["fact"] != tasks.TriggerFact {
		t.Fatalf("after allow: runs %v", ex.runs)
	}
}

// TestTaskOutputsAreGenerated: a file a task declares in `outputs` is never
// reported by scan, never captured (not even by name), never tracked by
// retag, and is listed by Generated.
func TestTaskOutputsAreGenerated(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.config/agent/base.json": "{}\n"}, manifest.Entry{Target: ".config/agent/base.json"})
	w.plans[c].Roots = []manifest.Root{{Path: ".config/agent"}}
	w.plans[c].Tasks = map[string]manifest.TaskDef{"gen": {OnRender: true, Command: []string{"gen-tool"}, Outputs: []string{".config/agent/gen/**", ".config/agent/hooks.json"}}}
	w.allowRoots(c)
	w.apply(c)
	w.write(".config/agent/gen/a.json", "{}\n")
	w.write(".config/agent/hooks.json", "{}\n")
	w.write(".config/agent/mine.json", "{}\n")
	ctx := context.Background()

	drift, err := w.eng.Scan(ctx, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 1 || drift[0].Target != ".config/agent/mine.json" {
		t.Fatalf("scan drift: %+v", drift)
	}
	named, err := w.eng.Scan(ctx, ScanOptions{Paths: []model.Target{".config/agent/hooks.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(named) != 0 {
		t.Fatalf("named scan reports a generated file: %+v", named)
	}
	cp, err := w.eng.Capture(ctx, []Drift{
		{Target: ".config/agent/hooks.json", Kind: DriftNew, Scope: model.ScopeShared, Named: true},
		{Target: ".config/agent/gen/a.json", Kind: DriftNew, Scope: model.ScopeShared, Named: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 0 || len(cp.Holds) != 0 {
		t.Fatalf("captured a generated file: %+v", cp)
	}
	gen, err := w.eng.Generated(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(gen) != 2 || gen[0] != ".config/agent/gen/a.json" || gen[1] != ".config/agent/hooks.json" {
		t.Fatalf("Generated = %v", gen)
	}
	if _, err := w.eng.track(ctx, c, mustSnap(t, w, c), ".config/agent/hooks.json", "type:work", "", "retag"); err == nil || !strings.Contains(err.Error(), "outputs") {
		t.Fatalf("retag of a generated file: %v", err)
	}
}

func mustSnap(t *testing.T, w *world, c model.CommitID) *Snapshot {
	t.Helper()
	s, err := w.load(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
