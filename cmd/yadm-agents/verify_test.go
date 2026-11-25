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

func findings(fs []Finding, level string) string {
	var out []string
	for _, f := range fs {
		if f.Level == level {
			out = append(out, f.Msg)
		}
	}
	return strings.Join(out, "\n")
}

func TestVerifyFixtureIsClean(t *testing.T) {
	home := genHome(t)
	fs := Verify(mustParse(t, fixtureUnits), twoMachines(), VerifyOptions{Home: home})
	if hasErrors(fs) {
		t.Fatalf("errors:\n%s", findings(fs, "error"))
	}
}

func TestVerifyCatches(t *testing.T) {
	home := genHome(t)
	cases := map[string]struct{ edit, want, level string }{
		"unknown unit":    {`"guard-a.claude" = "true"`, `"guard-a.claude" = "true"` + "\n" + `"ghost.claude" = "true"`, "error"},
		"unknown harness": {`"guard-a.claude" = "true"`, `"guard-a.claude" = "true"` + "\n" + `"guard-a.newharness" = "true"`, "warn"},
		"effect":          {`effect = "deny"` + "\nscript = \"~/.agent/hooks/guard-b.sh\"", `effect = "rewrite"` + "\nscript = \"~/.agent/hooks/guard-b.sh\"", "error"},
		"via":             {`via = "oc-logger"`, `via = "oc-nothing"`, "error"},
		"event":           {`on = ["PostToolUse"]`, `on = ["Interrupt"]`, "error"},
		"bad cell":        {`"logger.claude" = "type:work"`, `"logger.claude" = "type:nosuch"`, "error"},
		"unmapped":        {`note = "this harness fetches nothing"`, `note = ""`, "warn"},
	}
	for name, c := range cases {
		src := strings.Replace(fixtureUnits, c.edit, c.want, 1)
		if src == fixtureUnits {
			t.Fatalf("%s: edit did not apply", name)
		}
		fs := Verify(mustParse(t, src), twoMachines(), VerifyOptions{Home: home})
		if findings(fs, c.level) == "" {
			t.Errorf("%s: no %s; got %+v", name, c.level, fs)
		}
		if c.level == "warn" && hasErrors(fs) {
			t.Errorf("%s: a warning case raised an error: %s", name, findings(fs, "error"))
		}
	}
}

func TestVerifyRequiredScript(t *testing.T) {
	home := genHome(t)
	os.Remove(filepath.Join(home, ".agent/hooks/guard-a.sh"))
	fs := Verify(mustParse(t, fixtureUnits), twoMachines(), VerifyOptions{Home: home, Offline: true})
	if !strings.Contains(findings(fs, "error"), "guard-a") {
		t.Fatalf("missing required script not reported: %+v", fs)
	}
	// a staged script counts
	fs = Verify(mustParse(t, fixtureUnits), nil, VerifyOptions{Home: home, Offline: true, Staged: map[string]string{".agent/hooks/guard-a.sh": "/x"}})
	if hasErrors(fs) {
		t.Fatalf("staged script not seen: %+v", fs)
	}
}

// As a yadm check, verify reads the staged units file, answers with one
// response object and exits 0 so yadm reads ok from it.
func TestCheckMode(t *testing.T) {
	home := genHome(t)
	staged := filepath.Join(t.TempDir(), "staged")
	writeFile(t, staged, strings.Replace(fixtureUnits, `"guard-a.claude" = "true"`, `"ghost.claude" = "true"`, 1))
	writeFile(t, filepath.Join(home, ".config/yadm-agents/units.toml"), fixtureUnits)
	req, _ := json.Marshal(map[string]any{"schema": 1, "kind": "check", "home": home,
		"staged": map[string]string{".config/yadm-agents/units.toml": staged}})
	t.Setenv("YADM_KIND", "check")
	t.Setenv("YADM_HOME", "")
	t.Setenv("YADM_AGENTS_UNITS", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	var out, errb bytes.Buffer
	code := run(nil, bytes.NewReader(req), &out, &errb, twoMachines())
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var resp extexec.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("response %q: %v", out.String(), err)
	}
	if resp.OK || !strings.Contains(resp.Message, "ghost") {
		t.Fatalf("response = %+v", resp)
	}
}

func TestMatrix(t *testing.T) {
	ev := twoMachines()
	ev.delivered = map[string]map[string]bool{
		"host-a": {".config/opencode/plugins/logger.ts": true, ".agent/mods/mod-one/plugin.json": true},
		"host-b": {".agent/mods/mod-two/plugin.json": true},
	}
	f := mustParse(t, fixtureUnits)
	m, err := BuildMatrix(f, ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := m.unit("logger").Cells["claude"]
	if !logger.On["host-a"] || logger.On["host-b"] {
		t.Fatalf("logger.claude = %v", logger.On)
	}
	oc := m.unit("oc-logger").Cells["opencode"]
	if oc.Delivered["host-b"] || !oc.Delivered["host-a"] || !oc.On["host-b"] {
		t.Fatalf("oc-logger = %+v", oc)
	}
	table := m.Table()
	if !strings.Contains(table, "oc-logger") || !strings.Contains(table, "!") {
		t.Fatalf("table:\n%s", table)
	}
	par := m.Parity(f)
	if !strings.Contains(par, "guard-b.sh claude[mcp:srv-a,mcp:srv-b,shell,web] codex[mcp:srv-a,shell]") {
		t.Fatalf("parity:\n%s", par)
	}
	if !strings.Contains(par, "logger.sh claude[shell] opencode[via]") {
		t.Fatalf("parity:\n%s", par)
	}
	if _, err := m.JSON(); err != nil {
		t.Fatal(err)
	}
}
