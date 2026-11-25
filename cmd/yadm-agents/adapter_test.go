package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func enabledAll(f *File, h string) []Resolved {
	var out []Resolved
	for _, u := range f.Units {
		if _, ok := f.Cell(u.Name, h); ok {
			r := u.Resolve(h)
			r.Enabled = true
			out = append(out, r)
		}
	}
	return out
}

func TestClaudeMatchers(t *testing.T) {
	cases := []struct {
		acts []string
		want []string
	}{
		{[]string{"shell", "file_read", "file_write", "file_edit"}, []string{"Bash|Read|Glob|Grep|Write|Edit|MultiEdit|NotebookEdit"}},
		{[]string{"shell", "mcp_call:srv-a", "mcp_call:srv-b"}, []string{"Bash", "^mcp__(srv-a|srv-b)__.*"}},
		{[]string{"mcp_call", "mcp_call:srv-a"}, []string{"mcp__.*"}},
		{[]string{"agent_spawn", "web_search"}, []string{"Agent|Task|WebSearch"}},
	}
	for _, c := range cases {
		if got := claudeMatchers(c.acts); !reflect.DeepEqual(got, c.want) {
			t.Errorf("claudeMatchers(%v) = %q, want %q", c.acts, got, c.want)
		}
	}
}

func TestCodexMatchers(t *testing.T) {
	if got := codexMatchers([]string{"shell", "file_write", "file_edit"}); !reflect.DeepEqual(got, []string{"^Bash$|^apply_patch$"}) {
		t.Fatalf("got %q", got)
	}
	if got := codexMatchers([]string{"shell", "mcp_call:a", "mcp_call:b"}); !reflect.DeepEqual(got, []string{"^Bash$|^mcp__(a|b)__.*"}) {
		t.Fatalf("got %q", got)
	}
	if got := codexMatchers([]string{"agent_spawn"}); got != nil {
		t.Fatalf("unmapped action rendered %q", got)
	}
	if got := (codexAdapter{}).Unmapped([]string{"shell", "file_read", "web_search", "mcp_call:x"}); !reflect.DeepEqual(got, []string{"file_read", "web_search"}) {
		t.Fatalf("unmapped = %v", got)
	}
}

const settingsFixture = `{
  "model": "model-x",
  "env": {
    "OTHER": "1",
    "CLAUDE_CODE_PLUGIN_DIRS": "~/.agent/mods/old"
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "\"$HOME/.agent/hooks/guard-a.sh\"", "timeout": 10 }
        ]
      }
    ]
  },
  "statusLine": { "type": "command", "command": "status-x" }
}
`

func TestClaudeApplyKeepsOtherKeys(t *testing.T) {
	f := mustParse(t, fixtureUnits)
	a := claudeAdapter{}
	w, err := a.Render(enabledAll(f, "claude"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Values[claudeModsKey] != "~/.agent/mods/mod-one:~/.agent/mods/mod-two" {
		t.Fatalf("mods = %q", w.Values[claudeModsKey])
	}
	out, err := a.Apply([]byte(settingsFixture), w, Wiring{})
	if err != nil {
		t.Fatal(err)
	}
	if err := proveEdit(a, []byte(settingsFixture), out, w); err != nil {
		t.Fatalf("prove: %v\n%s", err, out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["model"] != "model-x" || doc["env"].(map[string]any)["OTHER"] != "1" {
		t.Fatalf("lost a key: %s", out)
	}
	if !strings.Contains(string(out), `"statusLine": { "type": "command", "command": "status-x" }`) {
		t.Fatalf("an unowned key changed bytes:\n%s", out)
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	// guard-a's names group, guard-b's names group and guard-b's MCP group
	if len(pre) != 3 {
		t.Fatalf("PreToolUse groups = %d:\n%s", len(pre), out)
	}
	ss := doc["hooks"].(map[string]any)["SessionStart"].([]any)[0].(map[string]any)
	if ss["matcher"] != "startup|resume" {
		t.Fatalf("SessionStart matcher = %v", ss["matcher"])
	}
	if _, ok := doc["hooks"].(map[string]any)["Stop"].([]any)[0].(map[string]any)["matcher"]; ok {
		t.Fatal("Stop group got a matcher")
	}
}

func TestClaudeClearsModsWhenAllOff(t *testing.T) {
	f := mustParse(t, fixtureUnits)
	units := enabledAll(f, "claude")
	for i := range units {
		if units[i].Kind == "mod" {
			units[i].Enabled = false
		}
	}
	a := claudeAdapter{}
	w, _ := a.Render(units)
	if v, ok := w.Values[claudeModsKey]; !ok || v != "" {
		t.Fatalf("mods key = %q %v, want owned and empty", v, ok)
	}
	out, err := a.Apply([]byte(settingsFixture), w, Wiring{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "CLAUDE_CODE_PLUGIN_DIRS") || !strings.Contains(string(out), `"OTHER"`) {
		t.Fatalf("mods key not cleared cleanly:\n%s", out)
	}
}

func TestClaudeRowsIgnoreGrouping(t *testing.T) {
	a := claudeAdapter{}
	one := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash|Read","hooks":[{"type":"command","command":"x","timeout":5},{"type":"command","command":"y"}]}]}}`)
	two := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"x","timeout":5}]},{"matcher":"^Bash$","hooks":[{"type":"command","command":"x","timeout":5}]},{"matcher":"Bash|Read","hooks":[{"type":"command","command":"y"}]}]}}`)
	w1, err := a.Load(one)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := a.Load(two)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Rows(w1), a.Rows(w2)) {
		t.Fatalf("rows differ:\n%q\n%q", a.Rows(w1), a.Rows(w2))
	}
}

const codexFixture = `model = "model-x"

# Hooks need trust before they run.
[[hooks.SessionStart]]
[[hooks.SessionStart.hooks]]
type = "command"
command = "old-start"

[mcp_servers.srv-a]
command = "srv-a"

[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "$HOME/.agent/hooks/guard-a.sh"
timeout = 10

[[hooks.Interrupt]]
[[hooks.Interrupt.hooks]]
type = "command"
command = "gone"

[hooks.state.trust-key-1]
trusted_hash = "abc"
`

func TestCodexApplyOwnsEventTablesOnly(t *testing.T) {
	f := mustParse(t, fixtureUnits)
	a := codexAdapter{}
	live, err := a.Load([]byte(codexFixture))
	if err != nil {
		t.Fatal(err)
	}
	w, err := a.Render(enabledAll(f, "codex"))
	if err != nil {
		t.Fatal(err)
	}
	w = a.Order(live, w)
	out, err := a.Apply([]byte(codexFixture), w, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := proveEdit(a, []byte(codexFixture), out, w); err != nil {
		t.Fatalf("prove: %v\n%s", err, out)
	}
	var doc map[string]any
	if err := toml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	hooks := doc["hooks"].(map[string]any)
	if hooks["state"].(map[string]any)["trust-key-1"].(map[string]any)["trusted_hash"] != "abc" {
		t.Fatalf("hooks.state changed:\n%s", out)
	}
	if _, ok := hooks["Interrupt"]; ok {
		t.Fatalf("an event no unit wires survived:\n%s", out)
	}
	if doc["mcp_servers"].(map[string]any)["srv-a"] == nil || !strings.Contains(string(out), "# Hooks need trust") {
		t.Fatalf("unowned content lost:\n%s", out)
	}
	pre := hooks["PreToolUse"].([]any)
	// guard-a kept position 0 (live), guard-b appended
	first := pre[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"]
	if first != "$HOME/.agent/hooks/guard-a.sh" || len(pre) != 2 {
		t.Fatalf("PreToolUse = %v", pre)
	}
	ss := hooks["SessionStart"].([]any)[0].(map[string]any)
	h := ss["hooks"].([]any)[0].(map[string]any)
	if h["statusMessage"] != "Greeting" || h["additionalContextLimit"] != int64(0) || ss["matcher"] != "startup|resume" {
		t.Fatalf("SessionStart = %v", ss)
	}
}

func TestCodexOrderKeepsTrustPositions(t *testing.T) {
	a := codexAdapter{}
	live := Wiring{Entries: []Entry{{Event: "E", Command: "b"}, {Event: "E", Command: "a"}, {Event: "E", Command: "gone"}}}
	w := Wiring{Entries: []Entry{{Event: "E", Command: "a", Timeout: 9}, {Event: "E", Command: "new"}, {Event: "E", Command: "b"}}}
	got := a.Order(live, w)
	var cmds []string
	for _, e := range got.Entries {
		cmds = append(cmds, e.Command)
	}
	if !reflect.DeepEqual(cmds, []string{"b", "a", "new"}) || got.Entries[1].Timeout != 9 {
		t.Fatalf("order = %v %+v", cmds, got.Entries)
	}
}

func TestTOMLString(t *testing.T) {
	cases := map[string]string{
		`plain`:             `"plain"`,
		`h="$x"; exec "$h"`: `'h="$x"; exec "$h"'`,
		`it's "both"`:       `"it's \"both\""`,
		"tab\there":         `"tab\there"`,
		`back\slash`:        `'back\slash'`,
	}
	for in, want := range cases {
		if got := tomlString(in); got != want {
			t.Errorf("tomlString(%q) = %s, want %s", in, got, want)
		}
		var v struct{ S string }
		if err := toml.Unmarshal([]byte("S = "+tomlString(in)), &v); err != nil || v.S != in {
			t.Errorf("tomlString(%q) does not round-trip: %v %q", in, err, v.S)
		}
	}
}

func TestRouteRoundTrip(t *testing.T) {
	a := routeAdapter{name: "tool-r"}
	units := []Resolved{
		{Unit: "g1", Kind: "guard", Enabled: true, Script: "~/h/g1.sh", On: []string{"PreToolUse"}, Actions: []string{"shell", "file_read"}},
		{Unit: "g2", Kind: "guard", Enabled: true, Script: "~/h/g2.sh", On: []string{"PreToolUse"}, Actions: []string{"shell", "mcp_call"}},
		{Unit: "h1", Kind: "hook", Enabled: true, Script: "~/h/h1.sh", On: []string{"PreToolUse"}, Actions: []string{"shell"}},
	}
	w, err := a.Render(units)
	if err != nil {
		t.Fatal(err)
	}
	out, err := a.Apply(nil, w, Wiring{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "PreToolUse\tBash\tg1.sh g2.sh\n") || !strings.Contains(string(out), "PreToolUse\tLS\tg1.sh\n") || !strings.Contains(string(out), "PreToolUse\tmcp__*\tg2.sh\n") {
		t.Fatalf("route:\n%s", out)
	}
	if strings.Contains(string(out), "h1.sh") {
		t.Fatal("a hook was routed; only guards are")
	}
	if err := proveEdit(a, nil, out, w); err != nil {
		t.Fatal(err)
	}
}
