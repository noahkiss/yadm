package rules

import (
	"strings"
	"testing"
)

const settingsBase = `{
  // Model chosen on this machine.
  "model": "model-a",
  "feedbackSurveyState": {
    "lastShown": 100
  },
  "env": {
    "EDITOR_MODE": "plain", // trailing note
    "PAGER": "less"
  },
  "permissions": {
    "allow": ["Bash(ls:*)", "Read"],
    "deny": []
  },
  "hooks": {
    "Stop": [
      {"hooks": [{"type": "command", "command": "tool-a stop"}]}
    ]
  }
}
`

func mustMerge(t *testing.T, format string, vol []string, base, ours, theirs string) string {
	t.Helper()
	out, ok, err := Merge3(format, vol, []byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if !ok {
		t.Fatalf("Merge3 did not decide\nbase:\n%s\nours:\n%s\ntheirs:\n%s", base, ours, theirs)
	}
	return string(out)
}

func noMerge(t *testing.T, format string, vol []string, base, ours, theirs string) {
	t.Helper()
	out, ok, err := Merge3(format, vol, []byte(base), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatalf("Merge3: %v", err)
	}
	if ok {
		t.Fatalf("Merge3 decided, want a hold:\n%s", out)
	}
}

func TestMerge3JSONCDisjointEdits(t *testing.T) {
	ours := strings.Replace(settingsBase, `"PAGER": "less"`, `"PAGER": "more"`, 1)
	theirs := strings.Replace(settingsBase, `"deny": []`, `"deny": ["Bash(rm:*)"]`, 1)
	got := mustMerge(t, "jsonc", nil, settingsBase, ours, theirs)
	want := strings.Replace(ours, `"deny": []`, `"deny": ["Bash(rm:*)"]`, 1)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMerge3JSONCTheirsAddsAndDeletes(t *testing.T) {
	ours := strings.Replace(settingsBase, `"model": "model-a"`, `"model": "model-b"`, 1)
	theirs := strings.Replace(settingsBase, `"EDITOR_MODE": "plain", // trailing note
    "PAGER": "less"`, `"EDITOR_MODE": "plain" // trailing note`, 1)
	theirs = strings.Replace(theirs, `"deny": []`, `"deny": [],
    "ask": ["Write"]`, 1)
	got := mustMerge(t, "jsonc", nil, settingsBase, ours, theirs)
	if strings.Contains(got, "PAGER") {
		t.Errorf("deleted key survived:\n%s", got)
	}
	if !strings.Contains(got, `"ask": ["Write"]`) || !strings.Contains(got, `"model": "model-b"`) {
		t.Errorf("merge lost a side:\n%s", got)
	}
	if !strings.Contains(got, "// Model chosen on this machine.") || !strings.Contains(got, "// trailing note") {
		t.Errorf("comments lost:\n%s", got)
	}
	if _, err := (jsonFormat{}).parse([]byte(got)); err != nil {
		t.Fatal(err)
	}
}

func TestMerge3JSONCTheirsAddsNestedObject(t *testing.T) {
	theirs := strings.Replace(settingsBase, `"hooks": {`, `"hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "tool-b start"}]}
    ],`, 1)
	ours := strings.Replace(settingsBase, `"Read"]`, `"Read", "Glob"]`, 1)
	got := mustMerge(t, "jsonc", nil, settingsBase, ours, theirs)
	if !strings.Contains(got, "tool-b start") || !strings.Contains(got, `"Glob"`) {
		t.Fatalf("merge lost a side:\n%s", got)
	}
}

func TestMerge3JSONCSameKeyConflict(t *testing.T) {
	ours := strings.Replace(settingsBase, `"PAGER": "less"`, `"PAGER": "more"`, 1)
	theirs := strings.Replace(settingsBase, `"PAGER": "less"`, `"PAGER": "most"`, 1)
	noMerge(t, "jsonc", nil, settingsBase, ours, theirs)

	// A delete against a change conflicts too.
	del := strings.Replace(settingsBase, `"EDITOR_MODE": "plain", // trailing note
    "PAGER": "less"`, `"EDITOR_MODE": "plain" // trailing note`, 1)
	noMerge(t, "jsonc", nil, settingsBase, ours, del)

	// An array is one value: both sides appending conflicts.
	o := strings.Replace(settingsBase, `"Read"]`, `"Read", "Glob"]`, 1)
	th := strings.Replace(settingsBase, `"Read"]`, `"Read", "Grep"]`, 1)
	noMerge(t, "jsonc", nil, settingsBase, o, th)
}

func TestMerge3JSONCBothSameChange(t *testing.T) {
	both := strings.Replace(settingsBase, `"PAGER": "less"`, `"PAGER": "more"`, 1)
	theirs := strings.Replace(both, `"model": "model-a"`, `"model":   "model-a"`, 1)
	got := mustMerge(t, "jsonc", nil, settingsBase, both, theirs)
	if got != both {
		t.Fatalf("got:\n%s\nwant ours:\n%s", got, both)
	}
}

func TestMerge3JSONCVolatile(t *testing.T) {
	vol := []string{"feedbackSurveyState", "model"}
	ours := strings.Replace(settingsBase, `"lastShown": 100`, `"lastShown": 200`, 1)
	ours = strings.Replace(ours, `"model-a"`, `"model-b"`, 1)
	theirs := strings.Replace(settingsBase, `"lastShown": 100`, `"lastShown": 300`, 1)
	theirs = strings.Replace(theirs, `"model-a"`, `"model-c"`, 1)
	theirs = strings.Replace(theirs, `"PAGER": "less"`, `"PAGER": "most"`, 1)
	got := mustMerge(t, "jsonc", vol, settingsBase, ours, theirs)
	want := strings.Replace(ours, `"PAGER": "less"`, `"PAGER": "most"`, 1)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// Without the volatile list the same edits conflict.
	noMerge(t, "jsonc", nil, settingsBase, ours, theirs)

	// Theirs changing only a volatile key leaves ours as is.
	only := strings.Replace(settingsBase, `"lastShown": 100`, `"lastShown": 300`, 1)
	if got := mustMerge(t, "jsonc", vol, settingsBase, settingsBase, only); got != settingsBase {
		t.Fatalf("volatile-only change was carried:\n%s", got)
	}
}

func TestMerge3ParseFailureAndFormat(t *testing.T) {
	noMerge(t, "jsonc", nil, settingsBase, settingsBase+"{", settingsBase)
	noMerge(t, "jsonc", nil, "{", settingsBase, strings.Replace(settingsBase, "less", "more", 1))
	noMerge(t, "yaml", nil, "a: 1\n", "a: 2\n", "a: 3\n")
	if _, _, err := Merge3("json", []string{"a..b"}, nil, []byte("{}"), []byte(`{"a":1}`)); err == nil {
		t.Fatal("bad volatile path accepted")
	}
	var s Structural
	if out, ok, err := s.Merge3("json", nil, []byte(`{"a":1,"b":1}`), []byte(`{"a":2,"b":1}`), []byte(`{"a":1,"b":2}`)); err != nil || !ok || string(out) != `{"a":2,"b":2}` {
		t.Fatalf("Structural.Merge3: %q %v %v", out, ok, err)
	}
}

const codexBase = `# Agent configuration.
model = "model-a"
approval_policy = "on-request"

[projects."/work/project-a"]
trust_level = "trusted"

[mcp_servers.docs]
command = "docs-server"
args = ["--stdio"]

[mcp_servers.docs.env]
DOCS_TOKEN_FILE = "/work/secrets/docs"
`

func TestMerge3TOMLDisjointEdits(t *testing.T) {
	ours := strings.Replace(codexBase, `approval_policy = "on-request"`, `approval_policy = "never"`, 1)
	theirs := strings.Replace(codexBase, `args = ["--stdio"]`, `args = ["--stdio", "--quiet"]`, 1)
	got := mustMerge(t, "toml", nil, codexBase, ours, theirs)
	want := strings.Replace(ours, `args = ["--stdio"]`, `args = ["--stdio", "--quiet"]`, 1)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMerge3TOMLTheirsAddsTableAndKey(t *testing.T) {
	ours := strings.Replace(codexBase, `trust_level = "trusted"`, `trust_level = "untrusted"`, 1)
	theirs := strings.Replace(codexBase, `[mcp_servers.docs]`, `[projects."/work/project-b"]
trust_level = "trusted"

[mcp_servers.docs]`, 1)
	theirs = strings.Replace(theirs, `DOCS_TOKEN_FILE = "/work/secrets/docs"`, `DOCS_TOKEN_FILE = "/work/secrets/docs"
DOCS_REGION = "region-a"`, 1)
	got := mustMerge(t, "toml", nil, codexBase, ours, theirs)
	for _, s := range []string{`[projects."/work/project-b"]`, `DOCS_REGION = "region-a"`, `trust_level = "untrusted"`, "# Agent configuration."} {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q in:\n%s", s, got)
		}
	}
	if _, err := (tomlFormat{}).parse([]byte(got)); err != nil {
		t.Fatal(err)
	}
}

func TestMerge3TOMLTheirsDeletes(t *testing.T) {
	ours := strings.Replace(codexBase, `model = "model-a"`, `model = "model-b"`, 1)
	theirs := strings.Replace(codexBase, `approval_policy = "on-request"
`, ``, 1)
	got := mustMerge(t, "toml", nil, codexBase, ours, theirs)
	want := strings.Replace(ours, `approval_policy = "on-request"
`, ``, 1)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMerge3TOMLConflictAndVolatile(t *testing.T) {
	ours := strings.Replace(codexBase, `model = "model-a"`, `model = "model-b"`, 1)
	theirs := strings.Replace(codexBase, `model = "model-a"`, `model = "model-c"`, 1)
	noMerge(t, "toml", nil, codexBase, ours, theirs)
	theirs = strings.Replace(theirs, `trust_level = "trusted"`, `trust_level = "untrusted"`, 1)
	got := mustMerge(t, "toml", []string{"model"}, codexBase, ours, theirs)
	want := strings.Replace(ours, `trust_level = "trusted"`, `trust_level = "untrusted"`, 1)
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// A volatile subtree via a wildcard.
	o := strings.Replace(codexBase, `trust_level = "trusted"`, `trust_level = "a"`, 1)
	th := strings.Replace(codexBase, `trust_level = "trusted"`, `trust_level = "b"`, 1)
	if got := mustMerge(t, "toml", []string{"projects.*.trust_level"}, codexBase, o, th); got != o {
		t.Fatalf("volatile wildcard: got:\n%s", got)
	}
	noMerge(t, "toml", nil, codexBase, codexBase+"[[[\n", theirs)
}

func TestMerge3TOMLTheirsAddsServerWithSubtable(t *testing.T) {
	ours := strings.Replace(codexBase, `model = "model-a"`, `model = "model-b"`, 1)
	theirs := codexBase + `
[mcp_servers.search]
command = "search-server"

[mcp_servers.search.env]
SEARCH_MODE = "fast"
`
	got := mustMerge(t, "toml", nil, codexBase, ours, theirs)
	root, err := (tomlFormat{}).parse([]byte(got))
	if err != nil {
		t.Fatal(err)
	}
	if n := find(root, []string{"mcp_servers", "search", "env", "SEARCH_MODE"}); n == nil || n.str != "fast" {
		t.Fatalf("subtable not inserted:\n%s", got)
	}
	if n := find(root, []string{"model"}); n == nil || n.str != "model-b" {
		t.Fatalf("ours lost:\n%s", got)
	}
}
