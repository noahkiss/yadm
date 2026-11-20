package manifest

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

func TestTaskOutputsAndInputs(t *testing.T) {
	const head = "schema = 1\n"
	m, err := Parse([]byte(head + `
[[file]]
target = ".config/agent/base.json"

[tasks.gen]
command = ["gen-tool"]
on_fact = ["packages", "fact:editor"]
on_render = true
outputs = [".config/agent/gen/**", ".config/agent/hooks.json"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Generated(".config/agent/gen/x/a.json") || !m.Generated(".config/agent/hooks.json") || m.Generated(".config/agent/base.json") {
		t.Error("Generated")
	}
	if got := m.Outputs(); len(got) != 2 || got[0] != ".config/agent/gen/**" {
		t.Errorf("Outputs = %q", got)
	}
	tree := []model.SourcePath{"files/.config/agent/base.json"}
	if _, err := m.Resolve(ctxFor(t, "m-a1b2c3"), tree, fixtureVocab(t)); err != nil {
		t.Fatal(err)
	}

	// An output that matches a managed target is an error.
	bad, err := Parse([]byte(head + `
[[file]]
target = ".config/agent/hooks.json"

[tasks.gen]
command = ["gen-tool"]
outputs = [".config/agent/*.json"]
`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = bad.Resolve(ctxFor(t, "m-a1b2c3"), []model.SourcePath{"files/.config/agent/hooks.json"}, fixtureVocab(t))
	if err == nil || !strings.Contains(err.Error(), `tasks.gen: output ".config/agent/*.json" matches managed target .config/agent/hooks.json`) {
		t.Fatalf("output over a managed target: %v", err)
	}

	for _, c := range []struct{ src, msg string }{
		{"[tasks.t]\ncommand = [\"x\"]\noutputs = [\"/abs\"]\n", "outputs"},
		{"[tasks.t]\ncommand = [\"x\"]\non_fact = [\"\"]\n", "on_fact"},
	} {
		if _, err := Parse([]byte(head + c.src)); err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%q: %v", c.src, err)
		}
	}
	for _, c := range []struct{ src, msg string }{
		{"[tasks.t]\ncommand = [\"x\"]\non_fact = [\"nope\"]\n", `on_fact: unknown collector "nope"`},
		{"[tasks.t]\ncommand = [\"x\"]\non_fact = [\"fact:nope\"]\n", `on_fact: unknown fact "nope"`},
	} {
		m, err := Parse([]byte(head + c.src))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Validate(fixtureVocab(t)); err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%q: %v", c.src, err)
		}
	}
}
