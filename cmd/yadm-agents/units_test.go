package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestParseFixture(t *testing.T) {
	f := mustParse(t, fixtureUnits)
	if len(f.Units) != 7 {
		t.Fatalf("units = %d, want 7", len(f.Units))
	}
	if got := f.Harnesses(); !reflect.DeepEqual(got, []string{"claude", "codex", "opencode"}) {
		t.Fatalf("harnesses = %v", got)
	}
	g := f.Unit("guard-b")
	if g == nil || deref(g.Script) != "~/.agent/hooks/guard-b.sh" || len(g.Actions) != 4 {
		t.Fatalf("guard-b = %+v", g)
	}
	if f.Harness["tool-r"].Config == "" {
		t.Fatal("harness config not read")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"schema":      "schema = 2\n",
		"unknown key": "schema = 1\n[[unit]]\nname = \"x\"\nkind = \"guard\"\nscrpit = \"a\"\n",
		"dup unit":    "schema = 1\n[[unit]]\nname = \"x\"\n[[unit]]\nname = \"x\"\n",
		"dotted name": "schema = 1\n[[unit]]\nname = \"a.b\"\n",
		"bad action":  "schema = 1\n[[unit]]\nname = \"x\"\nactions = [\"teleport\"]\n",
		"server":      "schema = 1\n[[unit]]\nname = \"x\"\nactions = [\"shell:srv\"]\n",
		"match type":  "schema = 1\n[[unit]]\nname = \"x\"\nmatch = 3\n",
		"cond type":   "schema = 1\n[conditions]\n\"x.claude\" = 1\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

func TestConditionsFlatten(t *testing.T) {
	f := mustParse(t, "schema = 1\n[conditions]\nx.claude = \"true\"\n\"y.codex\" = \"false\"\n")
	if f.Conditions["x.claude"] != "true" || f.Conditions["y.codex"] != "false" {
		t.Fatalf("conditions = %v", f.Conditions)
	}
}

func TestResolveOverride(t *testing.T) {
	f := mustParse(t, fixtureUnits)
	base := f.Unit("guard-b").Resolve("claude")
	over := f.Unit("guard-b").Resolve("codex")
	if len(base.Actions) != 4 || len(over.Actions) != 2 || over.Note == "" || base.Note != "" {
		t.Fatalf("base %v / codex %v", base.Actions, over.Actions)
	}
	if over.Script != base.Script || over.TimeoutFor("PreToolUse") != 5 {
		t.Fatal("codex lost a base field")
	}
	gr := f.Unit("greeter").Resolve("codex")
	if gr.Extra["statusMessage"] != "Greeting" {
		t.Fatalf("extra = %v", gr.Extra)
	}
	if m, ok := gr.MatchFor("SessionStart"); !ok || m != "startup|resume" {
		t.Fatalf("match SessionStart = %q %v", m, ok)
	}
	if _, ok := gr.MatchFor("Stop"); ok {
		t.Fatal("Stop got a matcher")
	}
}

// Every script unit's command is guarded: a script that has not reached
// the machine skips the call instead of failing it.
func TestCommand(t *testing.T) {
	f := mustParse(t, fixtureUnits)
	want := `[ -x "$HOME/.agent/hooks/guard-a.sh" ] || exit 0; exec "$HOME/.agent/hooks/guard-a.sh"`
	for _, h := range []string{"claude", "codex"} {
		if got := f.Unit("guard-a").Resolve(h).Command("PreToolUse"); got != want {
			t.Fatalf("%s = %s", h, got)
		}
	}
	got := f.Unit("greeter").Resolve("codex").Command("Stop")
	if !strings.HasSuffix(got, `exec "$HOME/bin/greet" codex Stop`) {
		t.Fatalf("templated = %s", got)
	}
	u := Resolved{Harness: "h", Script: "~/s.sh", Args: []string{"{harness}", "x"}}
	if got := u.Command("E"); got != `[ -x "$HOME/s.sh" ] || exit 0; exec "$HOME/s.sh" h x` {
		t.Fatalf("args = %s", got)
	}
}

// The guarded form and both plain forms name one script call; anything
// else is its own name.
func TestCanonCommand(t *testing.T) {
	one := `"$HOME/s.sh" a b`
	for _, c := range []string{
		`[ -x "$HOME/s.sh" ] || exit 0; exec "$HOME/s.sh" a b`,
		`"$HOME/s.sh" a b`,
		`$HOME/s.sh a b`,
	} {
		if got := canonCommand(c); got != one {
			t.Errorf("canonCommand(%q) = %q", c, got)
		}
	}
	for _, c := range []string{
		`[ -x "$HOME/s.sh" ] || exit 0; exec "$HOME/other.sh" a b`,
		`[ -x "$HOME/s.sh" ] && exec "$HOME/s.sh" a b || exit 0`,
		`"$HOME/bin/seat" gate "$HOME/s.sh"`,
		`sh "$HOME/s.sh" a b`,
	} {
		if got := canonCommand(c); got == one {
			t.Errorf("canonCommand(%q) matched the script call", c)
		}
	}
}

func TestExpandLocal(t *testing.T) {
	defs := map[string]string{"a": "cond:b & os:x", "b": "type:t", "loop": "cond:loop", "x.y": "cond:a"}
	got, err := expandLocal("cond:x.y | cond:outer", defs)
	if err != nil || got != "(((type:t) & os:x)) | cond:outer" {
		t.Fatalf("expand = %q %v", got, err)
	}
	if _, err := expandLocal("cond:loop", defs); err == nil {
		t.Fatal("cycle not caught")
	}
	if got, _ := expandLocal("!cond:b", defs); got != "!(type:t)" {
		t.Fatalf("negated = %q", got)
	}
}

func TestMatcherTokens(t *testing.T) {
	cases := map[string][]string{
		"":                       {"*"},
		"Bash":                   {"Bash"},
		"Bash|Read":              {"Bash", "Read"},
		"^Bash$|^apply_patch$":   {"Bash", "apply_patch"},
		"^mcp__(a|b)__.*":        {"mcp__(a|b)__.*"},
		"Bash|mcp__.*":           {"Bash", "mcp__.*"},
		`a\|b|c`:                 {`a\|b`, "c"},
		"startup|resume|compact": {"startup", "resume", "compact"},
	}
	for in, want := range cases {
		if got := matcherTokens(in); !reflect.DeepEqual(got, want) {
			t.Errorf("matcherTokens(%q) = %q, want %q", in, got, want)
		}
	}
}

// The release workflow and the formula test read `yadm-agents version`.
func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, strings.NewReader(""), &out, &errb, nil); code != 0 || out.String() != "yadm-agents dev\n" {
		t.Fatalf("exit %d, stdout %q", code, out.String())
	}
}
