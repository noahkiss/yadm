package cli

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/manifest"
)

const queryFleet = `schema = 1

[types.work]
[types.home]

[machines.m-aaaaaa000001]
name = "host-a"
types = ["work"]
os = "linux"
arch = "amd64"

[machines.m-aaaaaa000001.facts]
editor = "editor-one"

[machines.m-bbbbbb000002]
name = "host-b"
types = ["home"]
os = "darwin"
arch = "arm64"

[collectors.packages]
command = ["pkg-tool"]
publish = "plain"
`

const queryManifest = `schema = 1

[conditions]
include = ["conds.toml"]
desk = "type:work & cond:gui.any"

[[file]]
target = ".config/tool/config"
when = "cond:desk"
mode = 0o600
format = "json"
keep = ["a"]
drop = ["list[?name==gen]"]

[[file]]
target = ".config/tool/other"
when = "!cond:desk"

[[root]]
path = ".config/tool"

[tasks.gen]
command = ["gen-tool"]
on_render = true
outputs = [".config/gen/**"]
`

func queryTree() map[string]string {
	return map[string]string{
		"fleet.toml":                fleetHeader + queryFleet,
		"manifest.toml":             queryManifest,
		"conds.toml":                "[conditions]\ngui.any = \"os:linux | os:darwin\"\n",
		"files/.config/tool/config": "{\"a\": 1}\n",
		"files/.config/tool/other":  "other\n",
	}
}

const fleetHeader = "# synthetic fleet\n"

func TestManifestAndEvalQueries(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, queryTree())
	useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a")

	// This machine.
	env := yadmOK(t, "manifest")
	q := decode[manifestQuery](t, env.Data)
	if q.Schema != ManifestQuerySchema || len(q.Machines) != 1 || q.Machines[0].Name != "host-a" || q.Machines[0].Observed != observedLocal {
		t.Fatalf("manifest: %+v", q)
	}
	if len(q.Outputs) != 1 || q.Outputs[0] != ".config/gen/**" {
		t.Errorf("outputs: %v", q.Outputs)
	}
	es := q.Machines[0].Entries
	if len(es) != 1 || es[0].Target != ".config/tool/config" || es[0].Mode != "0600" || es[0].Merge != "text" || es[0].Scope != "shared" {
		t.Fatalf("entries: %+v", es)
	}
	if es[0].When != "cond:desk" || es[0].WhenExpanded != "type:work & (os:linux | os:darwin)" {
		t.Errorf("when: %q / %q", es[0].When, es[0].WhenExpanded)
	}
	if r := es[0].Rules; r == nil || r.Format != manifest.FormatJSON || len(r.Drop) != 1 || r.Drop[0] != "list[?name==gen]" {
		t.Errorf("rules: %+v", es[0].Rules)
	}
	if len(q.Machines[0].Roots) != 1 || len(q.Machines[0].Tasks) != 1 {
		t.Errorf("roots %v tasks %v", q.Machines[0].Roots, q.Machines[0].Tasks)
	}

	// The fleet: host-b is not work, so it gets the other file.
	q = decode[manifestQuery](t, yadmOK(t, "manifest", "--fleet").Data)
	if len(q.Machines) != 2 || q.Machines[1].Name != "host-b" || q.Machines[1].Observed != observedNone {
		t.Fatalf("fleet: %+v", q.Machines)
	}
	if es := q.Machines[1].Entries; len(es) != 1 || es[0].Target != ".config/tool/other" || es[0].WhenExpanded != "!(type:work & (os:linux | os:darwin))" {
		t.Errorf("host-b entries: %+v", es)
	}
	q = decode[manifestQuery](t, yadmOK(t, "manifest", "--as", "host-b").Data)
	if len(q.Machines) != 1 || q.Machines[0].Name != "host-b" {
		t.Fatalf("--as: %+v", q.Machines)
	}
	if _, code, _ := yadm(t, "manifest", "--as", "host-b", "--fleet"); code != ExitUsage {
		t.Errorf("--as with --fleet: exit %d", code)
	}
	if _, code, _ := yadm(t, "manifest", "--as", "nope"); code != ExitUsage {
		t.Errorf("--as unknown: exit %d", code)
	}

	// eval.
	ev := decode[evalQuery](t, yadmOK(t, "eval", "cond:desk & fact:editor=editor-one").Data)
	if ev.Schema != EvalQuerySchema || !ev.Result || ev.Expanded != "type:work & (os:linux | os:darwin) & fact:editor=editor-one" ||
		len(ev.Names) != 2 || ev.Observed != observedLocal || len(ev.Unavailable) != 0 {
		t.Fatalf("eval: %+v", ev)
	}
	ev = decode[evalQuery](t, yadmOK(t, "eval", "cond:desk | observed:packages=tool-one", "--as", "host-b").Data)
	if ev.Result || ev.Name != "host-b" || ev.Observed != observedNone || len(ev.Unavailable) != 1 || ev.Unavailable[0] != "packages" || !strings.Contains(ev.Note, "publishes plain") {
		t.Fatalf("eval --as: %+v", ev)
	}
	if _, code, _ := yadm(t, "eval", "cond:missing"); code != ExitUsage {
		t.Errorf("eval of an unknown name: exit %d", code)
	}

	// why shows the expansion.
	x := decode[manifest.Explanation](t, yadmOK(t, "why", ".config/tool/config").Data)
	if x.WhenExpanded != "type:work & (os:linux | os:darwin)" {
		t.Errorf("why: %+v", x)
	}
}

// TestQueriesPrintNoPlaintext runs the queries as an enclave member that has
// applied its sealed files: no output carries enclave plaintext, because the
// queries read no file content.
func TestQueriesPrintNoPlaintext(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	for _, args := range [][]string{{"manifest"}, {"manifest", "--fleet"}, {"manifest", "--as", "host-c"}, {"eval", "type:personal"}, {"eval", "type:client", "--as", "host-c"}} {
		_, _, out := yadm(t, args...)
		for _, c := range fx.AllCanaries() {
			if strings.Contains(string(out), c.String()) {
				t.Fatalf("yadm %v printed %s plaintext", args, c.Label)
			}
		}
	}
	q := decode[manifestQuery](t, yadmOK(t, "manifest").Data)
	var sealed bool
	for _, e := range q.Machines[0].Entries {
		if e.Enclave != "" {
			sealed = true
		}
	}
	if !sealed {
		t.Fatal("the member's manifest lists no enclave entry; the test proves nothing")
	}
}
