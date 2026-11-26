package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
)

// oneGuard is a units file with one required guard on claude and codex.
const oneGuard = `
schema = 1

[[unit]]
name = "guard-a"
kind = "guard"
required = true
effect = "deny"
script = "~/.agent/hooks/guard-a.sh"
on = ["PreToolUse"]
actions = ["shell", "file_write"]
timeout = 10

[[unit]]
name = "hook-b"
kind = "hook"
run = "hook-b"
on = ["Stop"]

[conditions]
"guard-a.claude" = "true"
"guard-a.codex" = "true"
"hook-b.claude" = "true"
`

func oneGuardHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude/settings.json"), "{\n  \"model\": \"x\",\n  \"hooks\": {}\n}\n")
	writeScript(t, filepath.Join(home, ".agent/hooks/guard-a.sh"))
	return home
}

func genOnly(t *testing.T, home, units, h string, o GenOptions) HarnessResult {
	t.Helper()
	o.Home = home
	o.Only = setOf(h)
	rs, err := Gen(mustParse(t, units), twoMachines(), o)
	if err != nil {
		t.Fatal(err)
	}
	return byHarness(rs)[h]
}

// A symlinked harness file is written through the link: the link stays and
// its target gets the wiring.
func TestGenWritesThroughSymlink(t *testing.T) {
	home := oneGuardHome(t)
	real := filepath.Join(home, "dots/settings.json")
	writeFile(t, real, readFile(t, filepath.Join(home, ".claude/settings.json")))
	if err := os.Chmod(real, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".claude/settings.json")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if r := genOnly(t, home, oneGuard, "claude", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("claude: %s %s", r.Status, r.Reason)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", fi.Mode(), err)
	}
	if !strings.Contains(readFile(t, real), "guard-a.sh") {
		t.Fatal("the link target did not get the wiring")
	}
	if st, _ := os.Stat(real); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
}

// A harness config path must stay inside home, and a route file gen did
// not write is never overwritten.
func TestGenConfinesConfigPath(t *testing.T) {
	register(routeAdapter{name: "tool-r"})
	defer delete(registry, "tool-r")
	for _, c := range []struct{ config, want string }{
		{"~/../outside/route.tsv", "inside home"},
		{"/abs/route.tsv", "inside home"},
		{"~/.notes", "not a route file"},
	} {
		home := oneGuardHome(t)
		writeFile(t, filepath.Join(home, ".notes"), "# my notes\n")
		src := "schema = 1\n[harness.tool-r]\nconfig = \"" + c.config + "\"\n" + strings.TrimPrefix(oneGuard, "\nschema = 1\n") + "\"guard-a.tool-r\" = \"true\"\n"
		r := genOnly(t, home, src, "tool-r", GenOptions{})
		if r.Status != StatusRefused || !strings.Contains(r.Reason, c.want) {
			t.Errorf("%s: %s %s", c.config, r.Status, r.Reason)
		}
		if readFile(t, filepath.Join(home, ".notes")) != "# my notes\n" {
			t.Errorf("%s: .notes overwritten", c.config)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(home), "outside")); err == nil {
			t.Errorf("%s: wrote outside home", c.config)
		}
	}
}

// An MCP server name lands in a regex matcher, so it must be a plain name.
func TestParseRejectsBadServerName(t *testing.T) {
	for _, s := range []string{"a(b", "a|.*", "a b", "a.b"} {
		src := strings.Replace(oneGuard, `actions = ["shell", "file_write"]`, `actions = ["mcp_call:`+s+`"]`, 1)
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("server %q parsed", s)
		}
	}
	if _, err := Parse([]byte(strings.Replace(oneGuard, `"file_write"]`, `"file_write", "mcp_call:srv_a-1"]`, 1))); err != nil {
		t.Fatal(err)
	}
}

// --prune drops handlers no unit owns. It never drops a required unit's
// handler just because its cell for the harness went away.
func TestPruneKeepsRequiredWithoutCell(t *testing.T) {
	home := oneGuardHome(t)
	if r := genOnly(t, home, oneGuard, "claude", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("first: %s %s", r.Status, r.Reason)
	}
	noCell := strings.Replace(oneGuard, `"guard-a.claude" = "true"`+"\n", "", 1)
	r := genOnly(t, home, noCell, "claude", GenOptions{Prune: true})
	if r.Status != StatusRefused || !strings.Contains(r.Reason, "guard-a") {
		t.Fatalf("cell removed, --prune: %s %s", r.Status, r.Reason)
	}
	if r := genOnly(t, home, noCell, "claude", GenOptions{AllowDrop: true}); r.Status != StatusWritten {
		t.Fatalf("--allow-drop: %s %s", r.Status, r.Reason)
	}
}

// A required guard that would lose a tool or an event it covers live is a
// drop, even though its command stays.
func TestGenRefusesNarrowingRequired(t *testing.T) {
	home := oneGuardHome(t)
	if r := genOnly(t, home, oneGuard, "claude", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("first: %s %s", r.Status, r.Reason)
	}
	for name, src := range map[string]string{
		"tool":  strings.Replace(oneGuard, `actions = ["shell", "file_write"]`, `actions = ["shell"]`, 1),
		"event": strings.Replace(oneGuard, `on = ["PreToolUse"]`, `on = ["PermissionRequest"]`, 1),
	} {
		r := genOnly(t, home, src, "claude", GenOptions{DryRun: true})
		if r.Status != StatusRefused || !strings.Contains(r.Reason, "guard-a") {
			t.Errorf("%s narrowed: %s %s", name, r.Status, r.Reason)
		}
		if r := genOnly(t, home, src, "claude", GenOptions{DryRun: true, AllowDrop: true}); r.Status != StatusChange {
			t.Errorf("%s narrowed, --allow-drop: %s %s", name, r.Status, r.Reason)
		}
	}
	// Widening, regrouping and a timeout change are not drops.
	for name, src := range map[string]string{
		"widen":   strings.Replace(oneGuard, `actions = ["shell", "file_write"]`, `actions = ["shell", "file_write", "file_edit", "mcp_call:srv-a"]`, 1),
		"all":     strings.Replace(oneGuard, `actions = ["shell", "file_write"]`, `actions = []`, 1),
		"timeout": strings.Replace(oneGuard, `timeout = 10`, `timeout = 20`, 1),
	} {
		if r := genOnly(t, home, src, "claude", GenOptions{DryRun: true}); r.Status != StatusChange {
			t.Errorf("%s: %s %s", name, r.Status, r.Reason)
		}
	}
	// Adding a server to a server list is not a drop either.
	one := strings.Replace(oneGuard, `"file_write"]`, `"file_write", "mcp_call:srv-a"]`, 1)
	if r := genOnly(t, home, one, "claude", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("srv-a: %s %s", r.Status, r.Reason)
	}
	two := strings.Replace(oneGuard, `"file_write"]`, `"file_write", "mcp_call:srv-a", "mcp_call:srv-b"]`, 1)
	if r := genOnly(t, home, two, "claude", GenOptions{DryRun: true}); r.Status != StatusChange {
		t.Errorf("add a server: %s %s", r.Status, r.Reason)
	}
}

// A live mod list with no mod unit for Claude is not gen's to change; it
// must not wedge every later gen.
func TestGenKeepsUnownedModList(t *testing.T) {
	home := oneGuardHome(t)
	writeFile(t, filepath.Join(home, ".claude/settings.json"), `{"env":{"CLAUDE_CODE_PLUGIN_DIRS":"/x","A":"1"},"hooks":{}}`)
	r := genOnly(t, home, oneGuard, "claude", GenOptions{})
	if r.Status != StatusWritten {
		t.Fatalf("claude: %s %s", r.Status, r.Reason)
	}
	if !strings.Contains(readFile(t, filepath.Join(home, ".claude/settings.json")), `"CLAUDE_CODE_PLUGIN_DIRS":"/x"`) {
		t.Fatal("the unowned mod list changed")
	}
	if r := genOnly(t, home, oneGuard, "claude", GenOptions{}); r.Status != StatusUnchanged {
		t.Fatalf("second: %s %s", r.Status, r.Reason)
	}
}

// A route harness names Claude tools; a regex in match would never match
// one, so gen refuses it instead of routing nothing.
func TestRouteRefusesRegexMatch(t *testing.T) {
	register(routeAdapter{name: "tool-r"})
	defer delete(registry, "tool-r")
	home := oneGuardHome(t)
	src := "schema = 1\n[harness.tool-r]\nconfig = \"~/route.tsv\"\n" + strings.TrimPrefix(oneGuard, "\nschema = 1\n") + "\"guard-a.tool-r\" = \"true\"\n"
	src = strings.Replace(src, `timeout = 10`, "timeout = 10\nmatch = \"^mcp__(a|b)__.*\"", 1)
	r := genOnly(t, home, src, "tool-r", GenOptions{})
	if r.Status != StatusRefused {
		t.Fatalf("tool-r: %s %s", r.Status, r.Reason)
	}
	ok := strings.Replace(src, `"^mcp__(a|b)__.*"`, `"Bash|mcp__a__*"`, 1)
	if r := genOnly(t, home, ok, "tool-r", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("plain names: %s %s", r.Status, r.Reason)
	}
}

// --only with a harness no cell names is a usage error, not a silent no-op.
func TestGenOnlyUnknownHarness(t *testing.T) {
	home := oneGuardHome(t)
	units := filepath.Join(home, "units.toml")
	writeFile(t, units, oneGuard)
	t.Setenv("YADM_KIND", "")
	var out, errb bytes.Buffer
	code := run([]string{"gen", "--dry-run", "--home", home, "--units", units, "--only", "cluade"}, nil, &out, &errb, twoMachines())
	if code != 2 || !strings.Contains(errb.String(), "cluade") {
		t.Fatalf("exit %d: %s%s", code, out.String(), errb.String())
	}
}

// In check mode a relative --units still finds the staged copy.
func TestCheckModeRelativeUnits(t *testing.T) {
	home := genHome(t)
	staged := filepath.Join(t.TempDir(), "staged")
	writeFile(t, staged, strings.Replace(fixtureUnits, `"guard-a.claude" = "true"`, `"ghost.claude" = "true"`, 1))
	writeFile(t, filepath.Join(home, ".config/yadm-agents/units.toml"), fixtureUnits)
	req, _ := json.Marshal(map[string]any{"schema": 1, "kind": "check", "home": home,
		"staged": map[string]string{".config/yadm-agents/units.toml": staged}})
	t.Setenv("YADM_KIND", "check")
	t.Setenv("YADM_HOME", "")
	t.Setenv("YADM_AGENTS_UNITS", "")
	t.Chdir(home)
	var out, errb bytes.Buffer
	code := run([]string{"verify", "--offline", "--units", ".config/yadm-agents/units.toml"}, bytes.NewReader(req), &out, &errb, twoMachines())
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var resp extexec.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("response %q: %v", out.String(), err)
	}
	if resp.OK || !strings.Contains(resp.Message, "ghost") {
		t.Fatalf("verify read the live file, not the staged one: %+v", resp)
	}
}

// Going from a server list to every MCP tool widens; it is not a drop.
func TestGenServersToAllIsNotDrop(t *testing.T) {
	home := oneGuardHome(t)
	one := strings.Replace(oneGuard, `"file_write"]`, `"file_write", "mcp_call:srv-a"]`, 1)
	if r := genOnly(t, home, one, "claude", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("srv-a: %s %s", r.Status, r.Reason)
	}
	all := strings.Replace(oneGuard, `"file_write"]`, `"file_write", "mcp_call"]`, 1)
	if r := genOnly(t, home, all, "claude", GenOptions{DryRun: true}); r.Status != StatusChange {
		t.Errorf("servers to all: %s %s", r.Status, r.Reason)
	}
}

// A script path the shell would split or expand never reaches a harness
// unquoted: a space works everywhere, and quoting characters are refused.
func TestScriptPathQuoting(t *testing.T) {
	u := Resolved{Harness: "h", Script: "~/Application Support/g.sh", Args: []string{"x"}}
	if got := u.Command("E"); got != `[ -x "$HOME/Application Support/g.sh" ] || exit 0; exec "$HOME/Application Support/g.sh" x` {
		t.Fatalf("spaced = %s", got)
	}
	for _, s := range []string{`~/a"b.sh`, "~/a`id`.sh", "~/$(id).sh", `~/a\b.sh`, "~/a\nb.sh"} {
		src := strings.Replace(oneGuard, `script = "~/.agent/hooks/guard-a.sh"`, "script = '''"+s+"'''", 1)
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("script %q parsed", s)
		}
	}
}

// verify catches what gen would refuse to render, such as a regex match
// on a route harness.
func TestVerifyCatchesRouteRegex(t *testing.T) {
	src := "schema = 1\n[harness.opencode]\nconfig = \"~/route.tsv\"\n" + strings.TrimPrefix(oneGuard, "\nschema = 1\n") + "\"guard-a.opencode\" = \"true\"\n"
	src = strings.Replace(src, `timeout = 10`, "timeout = 10\nmatch = \"^Bash$\"", 1)
	home := oneGuardHome(t)
	fs := Verify(mustParse(t, src), nil, VerifyOptions{Home: home, Offline: true})
	if !hasErrors(fs) {
		t.Fatalf("findings: %+v", fs)
	}
}
