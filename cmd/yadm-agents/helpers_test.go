package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeEval answers conditions from a table: machine -> condition -> result.
// "true" and "false" need no entry. An unknown condition is an error, as
// yadm's strict parser would make it.
type fakeEval struct {
	this      string
	machines  []string
	results   map[string]map[string]bool
	delivered map[string]map[string]bool
	calls     int
}

func (f *fakeEval) Eval(expr, machine string) (bool, error) {
	f.calls++
	expr = strings.TrimSpace(expr)
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	switch expr {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if machine == "" {
		machine = f.this
	}
	r, ok := f.results[machine][expr]
	if !ok {
		return false, fmt.Errorf("fake: no answer for %q on %s", expr, machine)
	}
	return r, nil
}

func (f *fakeEval) This() (string, error)       { return f.this, nil }
func (f *fakeEval) Machines() ([]string, error) { return f.machines, nil }
func (f *fakeEval) Delivered(m string) (map[string]bool, error) {
	if f.delivered == nil {
		return nil, fmt.Errorf("fake: no manifest")
	}
	return f.delivered[m], nil
}

// twoMachines is a fleet of host-a (type work) and host-b (type client).
func twoMachines() *fakeEval {
	return &fakeEval{
		this:     "host-a",
		machines: []string{"host-a", "host-b"},
		results: map[string]map[string]bool{
			"host-a": {"type:work": true, "type:client": false},
			"host-b": {"type:work": false, "type:client": true},
		},
		delivered: map[string]map[string]bool{
			"host-a": setOf(fixtureScripts...),
			"host-b": setOf(fixtureScripts...),
		},
	}
}

// fixtureScripts are the targets the fake manifest gives every machine.
var fixtureScripts = []string{".agent/hooks/guard-a.sh", ".agent/hooks/guard-b.sh", ".agent/hooks/logger.sh"}

func mustParse(t *testing.T, src string) *File {
	t.Helper()
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeScript writes an executable script, as apply leaves one.
func writeScript(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, "#!/bin/sh\nexit 0\n")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A synthetic units file: two guards, one lifecycle hook, one hook only one
// harness wires, a mod and a plugin file wired through via.
const fixtureUnits = `
schema = 1

[harness.tool-r]
config = "~/.local/state/agents/route.tsv"

[[unit]]
name = "guard-a"
kind = "guard"
required = true
effect = "deny"
script = "~/.agent/hooks/guard-a.sh"
on = ["PreToolUse"]
actions = ["shell", "file_read"]
timeout = 10

[[unit]]
name = "guard-b"
kind = "guard"
effect = "deny"
script = "~/.agent/hooks/guard-b.sh"
on = ["PreToolUse"]
actions = ["shell", "mcp_call:srv-a", "mcp_call:srv-b", "web_fetch"]
timeout = 5

[unit.harness.codex]
actions = ["shell", "mcp_call:srv-a"]
note = "this harness fetches nothing"

[[unit]]
name = "greeter"
kind = "hook"
run = '[ -x "$HOME/bin/greet" ] || exit 0; exec "$HOME/bin/greet" {harness} {event}'
on = ["SessionStart", "Stop"]
match = { SessionStart = "startup|resume" }
timeout = 3

[unit.harness.codex]
extra = { statusMessage = "Greeting", additionalContextLimit = 0 }

[[unit]]
name = "logger"
kind = "hook"
script = "~/.agent/hooks/logger.sh"
on = ["PostToolUse"]
actions = ["shell"]

[unit.harness.opencode]
via = "oc-logger"

[[unit]]
name = "mod-one"
kind = "mod"
dir = "~/.agent/mods/mod-one"

[[unit]]
name = "mod-two"
kind = "mod"
dir = "~/.agent/mods/mod-two"

[[unit]]
name = "oc-logger"
kind = "plugin"
file = "~/.config/opencode/plugins/logger.ts"

[conditions]
"guard-a.claude" = "true"
"guard-a.codex" = "cond:work"
"guard-b.claude" = "true"
"guard-b.codex" = "cond:work"
"greeter.claude" = "true"
"greeter.codex" = "type:work"
"logger.claude" = "type:work"
"logger.opencode" = "true"
"mod-one.claude" = "true"
"mod-two.claude" = "type:client"
"oc-logger.opencode" = "true"
work = "type:work"
`
