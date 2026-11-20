package tasks

import (
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// TestDefinitionHashUnchangedByNewFields pins that a definition which uses
// none of on_fact, on_render or outputs hashes exactly as before those
// fields existed, so every task allowed before stays allowed.
func TestDefinitionHashUnchangedByNewFields(t *testing.T) {
	type before struct {
		On         []string       `json:"on,omitempty"`
		OnRemove   []string       `json:"on_remove,omitempty"`
		FirstApply bool           `json:"first_apply,omitempty"`
		When       string         `json:"when,omitempty"`
		Command    []string       `json:"command"`
		Timeout    model.Duration `json:"timeout"`
	}
	d := manifest.TaskDef{On: []string{".config/packages/list"}, FirstApply: true, When: "os:darwin", Command: []string{"pkg-tool", "bundle"}, Timeout: model.Duration(10 * time.Minute)}
	old := before{On: d.On, FirstApply: true, When: d.When, Command: d.Command, Timeout: d.Timeout}
	h1, err := DefinitionHash(d)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := DefinitionHash(old)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash changed: %s != %s", h1, h2)
	}
}

func TestSelectInputs(t *testing.T) {
	defs := map[string]manifest.TaskDef{
		"f": {OnFact: []string{"packages", "fact:editor"}, Command: []string{"x"}},
		"r": {OnRender: true, Command: []string{"x"}},
		"p": {On: []string{".a"}, OnFact: []string{"packages"}, Command: []string{"x"}},
	}
	in := map[string]string{"packages": "h1", "fact:editor": "h2", RenderInput: "h3"}
	// No Inputs: watchers never fire.
	sel, err := Select(defs, Event{})
	if err != nil || len(sel) != 0 {
		t.Fatalf("no inputs: %+v %v", sel, err)
	}
	// No record: every watcher fires.
	sel, _ = Select(defs, Event{Inputs: in})
	if len(sel) != 3 || sel[0].Name != "f" || sel[0].Trigger != TriggerFact || sel[2].Name != "r" || sel[2].Trigger != TriggerRender {
		t.Fatalf("no record: %+v", sel)
	}
	last := map[string]map[string]string{
		"f": {"packages": "h1", "fact:editor": "h2"},
		"r": {RenderInput: "h3"},
		"p": {"packages": "h1"},
	}
	sel, _ = Select(defs, Event{Inputs: in, LastInputs: last})
	if len(sel) != 0 {
		t.Fatalf("unchanged: %+v", sel)
	}
	in2 := map[string]string{"packages": "h9", "fact:editor": "h2", RenderInput: "h3"}
	sel, _ = Select(defs, Event{Inputs: in2, LastInputs: last, Changed: []model.Target{".a"}})
	if len(sel) != 2 || sel[0].Name != "f" || sel[0].Inputs[0] != "packages" || sel[1].Name != "p" || sel[1].Trigger != TriggerPaths {
		t.Fatalf("packages changed: %+v", sel)
	}
	if got := InputKeys(defs["r"]); len(got) != 1 || got[0] != RenderInput {
		t.Errorf("InputKeys = %v", got)
	}
}
