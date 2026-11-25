package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
)

// With XDG_CONFIG_HOME away from ~/.config, the default units path is not
// the managed target. A check must fail loudly and name both paths rather
// than verify the live file in place of the staged one.
func TestCheckModeUnitsPathMismatch(t *testing.T) {
	home := genHome(t)
	xdg := t.TempDir()
	writeFile(t, filepath.Join(xdg, "yadm-agents/units.toml"), fixtureUnits) // clean live copy
	staged := filepath.Join(t.TempDir(), "staged")
	writeFile(t, staged, fixtureUnits)
	req, _ := json.Marshal(map[string]any{"schema": 1, "kind": "check", "home": home,
		"staged": map[string]string{".config/yadm-agents/units.toml": staged}})
	t.Setenv("YADM_KIND", "check")
	t.Setenv("YADM_HOME", "")
	t.Setenv("YADM_AGENTS_UNITS", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	var out, errb bytes.Buffer
	if code := run(nil, bytes.NewReader(req), &out, &errb, twoMachines()); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var resp extexec.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("response %q: %v", out.String(), err)
	}
	if resp.OK {
		t.Fatalf("a units path mismatch passed: %+v", resp)
	}
	for _, want := range []string{".config/yadm-agents/units.toml", filepath.Join(xdg, "yadm-agents/units.toml"), "XDG_CONFIG_HOME", "YADM_AGENTS_UNITS"} {
		if !strings.Contains(resp.Message, want) {
			t.Errorf("message lacks %q: %s", want, resp.Message)
		}
	}
}

// A check that runs for other staged paths (a script) reads the live
// units file; no units target is staged, so there is nothing to mismatch.
func TestCheckModeScriptOnlyCommit(t *testing.T) {
	home := genHome(t)
	writeFile(t, filepath.Join(home, ".config/yadm-agents/units.toml"), fixtureUnits)
	staged := filepath.Join(t.TempDir(), "staged")
	writeFile(t, staged, "#!/bin/sh\n")
	req, _ := json.Marshal(map[string]any{"schema": 1, "kind": "check", "home": home,
		"staged": map[string]string{".agent/hooks/guard-a.sh": staged}})
	t.Setenv("YADM_KIND", "check")
	t.Setenv("YADM_HOME", "")
	t.Setenv("YADM_AGENTS_UNITS", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	var out, errb bytes.Buffer
	run([]string{"verify", "--offline"}, bytes.NewReader(req), &out, &errb, twoMachines())
	var resp extexec.Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("response %q: %v", out.String(), err)
	}
	if !resp.OK {
		t.Fatalf("response = %+v", resp)
	}
}

// gen as a task with the same mismatch fails with the same message, not a
// bare "no such file".
func TestTaskModeUnitsPathMismatch(t *testing.T) {
	home := genHome(t)
	writeFile(t, filepath.Join(home, ".config/yadm-agents/units.toml"), fixtureUnits)
	xdg := t.TempDir()
	req, _ := json.Marshal(map[string]any{"schema": 1, "kind": "task", "home": home,
		"changed": []string{".config/yadm-agents/units.toml"}})
	t.Setenv("YADM_KIND", "task")
	t.Setenv("YADM_HOME", "")
	t.Setenv("YADM_AGENTS_UNITS", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	var out, errb bytes.Buffer
	code := run([]string{"gen"}, bytes.NewReader(req), &out, &errb, twoMachines())
	msg := out.String() + errb.String()
	if code == 0 && !strings.Contains(out.String(), `"ok":false`) {
		t.Fatalf("gen passed: %s", msg)
	}
	for _, want := range []string{".config/yadm-agents/units.toml", "XDG_CONFIG_HOME"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
}
