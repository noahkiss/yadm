package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// genHome builds a temp $HOME with the fixture's harness files and scripts.
func genHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude/settings.json"), settingsFixture)
	writeFile(t, filepath.Join(home, ".codex/config.toml"), codexFixture)
	for _, s := range []string{"guard-a.sh", "guard-b.sh", "logger.sh"} {
		writeScript(t, filepath.Join(home, ".agent/hooks", s))
	}
	return home
}

func byHarness(rs []HarnessResult) map[string]HarnessResult {
	m := map[string]HarnessResult{}
	for _, r := range rs {
		m[r.Harness] = r
	}
	return m
}

func TestGenWritesThenIsIdempotent(t *testing.T) {
	home := genHome(t)
	f := mustParse(t, fixtureUnits)
	ev := twoMachines()
	rs, err := Gen(f, ev, GenOptions{Home: home, Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	m := byHarness(rs)
	for _, h := range []string{"claude", "codex"} {
		if m[h].Status != StatusWritten {
			t.Fatalf("%s: %s %s", h, m[h].Status, m[h].Reason)
		}
	}
	// opencode wires logger through a plugin file and routes no guard here
	if m["opencode"].Status != StatusSkipped {
		t.Fatalf("opencode: %s %s", m["opencode"].Status, m["opencode"].Reason)
	}
	settings := readFile(t, filepath.Join(home, ".claude/settings.json"))
	if !strings.Contains(settings, `$HOME/.agent/hooks/logger.sh`) || strings.Contains(settings, "mod-two") {
		t.Fatalf("settings for host-a:\n%s", settings)
	}
	rs, _ = Gen(f, ev, GenOptions{Home: home})
	for _, r := range rs {
		if r.Status != StatusUnchanged && r.Status != StatusSkipped {
			t.Fatalf("second run %s: %s %s +%v -%v", r.Harness, r.Status, r.Reason, r.Added, r.Removed)
		}
	}
}

func TestGenDryRunWritesNothing(t *testing.T) {
	home := genHome(t)
	f := mustParse(t, fixtureUnits)
	rs, _ := Gen(f, twoMachines(), GenOptions{Home: home, DryRun: true, Prune: true})
	if byHarness(rs)["claude"].Status != StatusChange {
		t.Fatalf("claude: %+v", byHarness(rs)["claude"])
	}
	if readFile(t, filepath.Join(home, ".claude/settings.json")) != settingsFixture || readFile(t, filepath.Join(home, ".codex/config.toml")) != codexFixture {
		t.Fatal("dry run wrote a file")
	}
}

func TestGenRefusesForeignHandlers(t *testing.T) {
	home := genHome(t)
	f := mustParse(t, fixtureUnits)
	rs, _ := Gen(f, twoMachines(), GenOptions{Home: home, Only: setOf("codex")})
	r := byHarness(rs)["codex"]
	if r.Status != StatusRefused || len(r.Foreign) != 2 { // old-start and gone
		t.Fatalf("codex: %s %s %v", r.Status, r.Reason, r.Foreign)
	}
	if readFile(t, filepath.Join(home, ".codex/config.toml")) != codexFixture {
		t.Fatal("a refused harness was written")
	}
}

func TestGenRefusesToDropRequired(t *testing.T) {
	home := genHome(t)
	// guard-a is required and wired on host-b's live file, but host-b is
	// not type:work, so its codex cell is off.
	f := mustParse(t, strings.Replace(fixtureUnits, `"greeter.codex" = "type:work"`, `"greeter.codex" = "true"`, 1))
	ev := twoMachines()
	ev.this = "host-b"
	rs, _ := Gen(f, ev, GenOptions{Home: home, Only: setOf("codex"), Prune: true})
	r := byHarness(rs)["codex"]
	if r.Status != StatusRefused || !strings.Contains(r.Reason, "guard-a") {
		t.Fatalf("codex: %s %s", r.Status, r.Reason)
	}
}

func TestGenNeverEmpties(t *testing.T) {
	home := genHome(t)
	f := mustParse(t, fixtureUnits)
	ev := twoMachines()
	ev.this = "host-b"
	rs, _ := Gen(f, ev, GenOptions{Home: home, Only: setOf("codex"), Prune: true, AllowDrop: true})
	r := byHarness(rs)["codex"]
	if r.Status != StatusRefused || !strings.Contains(r.Reason, "no handler") {
		t.Fatalf("codex: %s %s", r.Status, r.Reason)
	}
}

func TestGenRefusesMissingRequiredScript(t *testing.T) {
	home := genHome(t)
	if err := os.Remove(filepath.Join(home, ".agent/hooks/guard-a.sh")); err != nil {
		t.Fatal(err)
	}
	rs, _ := Gen(mustParse(t, fixtureUnits), twoMachines(), GenOptions{Home: home, Prune: true})
	if r := byHarness(rs)["claude"]; r.Status != StatusRefused || !strings.Contains(r.Reason, "missing") {
		t.Fatalf("claude: %s %s", r.Status, r.Reason)
	}
}

func TestGenEvalErrorKeepsFile(t *testing.T) {
	home := genHome(t)
	f := mustParse(t, strings.Replace(fixtureUnits, `"logger.claude" = "type:work"`, `"logger.claude" = "type:nosuch"`, 1))
	rs, _ := Gen(f, twoMachines(), GenOptions{Home: home, Prune: true})
	if r := byHarness(rs)["claude"]; r.Status != StatusRefused {
		t.Fatalf("claude: %s", r.Status)
	}
	if readFile(t, filepath.Join(home, ".claude/settings.json")) != settingsFixture {
		t.Fatal("file changed after an eval error")
	}
}

func TestGenNeverCreatesAppConfig(t *testing.T) {
	home := genHome(t)
	if err := os.Remove(filepath.Join(home, ".codex/config.toml")); err != nil {
		t.Fatal(err)
	}
	rs, _ := Gen(mustParse(t, fixtureUnits), twoMachines(), GenOptions{Home: home, Prune: true})
	if r := byHarness(rs)["codex"]; r.Status != StatusSkipped {
		t.Fatalf("codex: %s", r.Status)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex/config.toml")); err == nil {
		t.Fatal("gen created an app's config")
	}
}

func TestGenCreatesRoute(t *testing.T) {
	home := genHome(t)
	src := fixtureUnits + `"guard-a.tool-r" = "true"` + "\n"
	register(routeAdapter{name: "tool-r"})
	defer delete(registry, "tool-r")
	rs, _ := Gen(mustParse(t, src), twoMachines(), GenOptions{Home: home, Only: setOf("tool-r")})
	r := byHarness(rs)["tool-r"]
	if r.Status != StatusWritten {
		t.Fatalf("tool-r: %s %s", r.Status, r.Reason)
	}
	got := readFile(t, filepath.Join(home, ".local/state/agents/route.tsv"))
	if !strings.Contains(got, "PreToolUse\tBash\tguard-a.sh\n") {
		t.Fatalf("route:\n%s", got)
	}
}

func TestGenAsUsesDelivery(t *testing.T) {
	home := genHome(t)
	ev := twoMachines()
	ev.delivered = map[string]map[string]bool{"host-b": setOf(append([]string{".claude/settings.json"}, fixtureScripts...)...)}
	rs, _ := Gen(mustParse(t, fixtureUnits), ev, GenOptions{Home: home, As: "host-b", Prune: true})
	m := byHarness(rs)
	if m["codex"].Status != StatusSkipped || !strings.Contains(m["codex"].Reason, "does not give host-b") {
		t.Fatalf("codex: %s %s", m["codex"].Status, m["codex"].Reason)
	}
	if m["claude"].Status != StatusChange {
		t.Fatalf("claude: %s %s", m["claude"].Status, m["claude"].Reason)
	}
	if readFile(t, filepath.Join(home, ".claude/settings.json")) != settingsFixture {
		t.Fatal("--as wrote a file")
	}
}

func TestGenRefusesUnsupportedEvent(t *testing.T) {
	home := genHome(t)
	src := strings.Replace(fixtureUnits, `on = ["SessionStart", "Stop"]`, `on = ["SessionStart", "Stop", "NoSuchEvent"]`, 1)
	rs, _ := Gen(mustParse(t, src), twoMachines(), GenOptions{Home: home, Prune: true})
	if r := byHarness(rs)["claude"]; r.Status != StatusRefused || !strings.Contains(r.Reason, "NoSuchEvent") {
		t.Fatalf("claude: %s %s", r.Status, r.Reason)
	}
}

func TestDiffRows(t *testing.T) {
	add, rm := diffRows([]string{"a", "b", "b"}, []string{"b", "c"})
	if strings.Join(add, ",") != "c" || strings.Join(rm, ",") != "a,b" {
		t.Fatalf("add %v rm %v", add, rm)
	}
}
