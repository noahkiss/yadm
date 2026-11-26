package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/model"
)

const guardA = `[ -x "$HOME/.agent/hooks/guard-a.sh" ] || exit 0; exec "$HOME/.agent/hooks/guard-a.sh"`

// The first gen after the switch meets each unit's plain command in the
// live file. It reads it as that unit, not a foreign handler and not a
// dropped required guard, and rewrites it in the guarded form.
func TestGenConvertsPlainToGuarded(t *testing.T) {
	home := genHome(t)
	// The Codex fixture's other handlers belong to no unit; keep only the
	// plain guard-a, unquoted as gen used to write it for Codex.
	writeFile(t, filepath.Join(home, ".codex/config.toml"), `model = "model-x"

[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "$HOME/.agent/hooks/guard-a.sh"
timeout = 10
`)
	f := mustParse(t, fixtureUnits)
	rs, err := Gen(f, twoMachines(), GenOptions{Home: home, Only: setOf("claude", "codex")})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"claude", "codex"} {
		if r := byHarness(rs)[h]; r.Status != StatusWritten {
			t.Fatalf("%s: %s %s foreign=%v", h, r.Status, r.Reason, r.Foreign)
		}
	}
	settings := readFile(t, filepath.Join(home, ".claude/settings.json"))
	if !strings.Contains(settings, `"[ -x \"$HOME/.agent/hooks/guard-a.sh\" ] || exit 0; exec \"$HOME/.agent/hooks/guard-a.sh\""`) ||
		strings.Contains(settings, `"command": "\"$HOME/.agent/hooks/guard-a.sh\""`) {
		t.Fatalf("settings:\n%s", settings)
	}
	codex := readFile(t, filepath.Join(home, ".codex/config.toml"))
	if !strings.Contains(codex, guardA) || strings.Contains(codex, "command = \"$HOME/") {
		t.Fatalf("codex:\n%s", codex)
	}
	// Codex keeps the live handler's position: guard-a stays first.
	if i, j := strings.Index(codex, "guard-a.sh"), strings.Index(codex, "guard-b.sh"); i < 0 || j < 0 || i > j {
		t.Fatalf("guard-a lost its position:\n%s", codex)
	}
	rs, _ = Gen(f, twoMachines(), GenOptions{Home: home, Only: setOf("claude", "codex")})
	for _, r := range rs {
		if r.Status != StatusUnchanged {
			t.Fatalf("second run %s: %s %s", r.Harness, r.Status, r.Reason)
		}
	}
}

// A required unit's script that is present but not executable would be
// skipped by the guard, so gen refuses it as it refuses a missing one.
func TestGenRefusesNonExecutableRequiredScript(t *testing.T) {
	home := genHome(t)
	if err := os.Chmod(filepath.Join(home, ".agent/hooks/guard-a.sh"), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, _ := Gen(mustParse(t, fixtureUnits), twoMachines(), GenOptions{Home: home, Only: setOf("claude")})
	if r := byHarness(rs)["claude"]; r.Status != StatusRefused || !strings.Contains(r.Reason, "not executable") {
		t.Fatalf("claude: %s %s", r.Status, r.Reason)
	}
}

// The guarded form keeps a missing script from failing tool calls, so the
// tripwire is where it shows: missing and not executable each get a loud line.
func TestTripwireReportsUnrunnableScript(t *testing.T) {
	for name, break_ := range map[string]func(string) error{
		"missing":        os.Remove,
		"not executable": func(p string) error { return os.Chmod(p, 0o644) },
	} {
		t.Run(name, func(t *testing.T) {
			home := genTripwireHome(t)
			if err := break_(filepath.Join(home, ".agent/hooks/guard-a.sh")); err != nil {
				t.Fatal(err)
			}
			out, code := tripwireRun(t, home)
			if code != 0 || !strings.Contains(out, tripPrefix) || !strings.Contains(out, "guard-a.sh is "+name) {
				t.Fatalf("exit %d, out %q", code, out)
			}
		})
	}
}

// gen runs as a yadm task after apply. Whatever apply has not written on
// this machine yet (a new script held, failed or not reached), gen never
// wires: a required unit refuses and keeps the live file, any other unit
// is left out with a warning. The apply that writes the script fires gen
// again, and that run wires it.
func TestGenTaskNeverWiresUnwrittenScript(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".claude/settings.json"), "{\n  \"hooks\": {}\n}\n")
	writeFile(t, filepath.Join(home, ".config/yadm-agents/units.toml"), fixtureUnits)
	t.Setenv("YADM_HOME", "")
	t.Setenv("YADM_AGENTS_UNITS", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("YADM_JSON", "")
	t.Setenv("YADM_KIND", string(extexec.KindTask))
	// Under the exec contract gen exits 0 and answers ok in the response.
	task := func(changed ...string) (bool, string) {
		t.Helper()
		req := extexec.Request{Schema: 1, Kind: extexec.KindTask, Name: "agents", Home: home, Trigger: "paths"}
		for _, c := range changed {
			req.Changed = append(req.Changed, model.Target(c))
		}
		b, _ := json.Marshal(req)
		var out, errb bytes.Buffer
		if code := run([]string{"gen", "--only", "claude"}, bytes.NewReader(b), &out, &errb, twoMachines()); code != 0 {
			t.Fatalf("task exit %d: %s%s", code, out.String(), errb.String())
		}
		var resp struct {
			OK bool `json:"ok"`
		}
		if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
			t.Fatalf("response %q: %v", out.String(), err)
		}
		return resp.OK, out.String() + errb.String()
	}
	settings := filepath.Join(home, ".claude/settings.json")

	// Apply wrote the units file and guard-a; guard-b and logger are not
	// here yet.
	writeScript(t, filepath.Join(home, ".agent/hooks/guard-a.sh"))
	if ok, out := task(".config/yadm-agents/units.toml", ".agent/hooks/guard-a.sh"); !ok {
		t.Fatalf("not ok: %s", out)
	} else if !strings.Contains(out, "guard-b") || !strings.Contains(out, "logger") {
		t.Fatalf("no warning for the unwritten scripts: %s", out)
	}
	live := readFile(t, settings)
	if !strings.Contains(live, "guard-a.sh") || strings.Contains(live, "guard-b.sh") || strings.Contains(live, "logger.sh") {
		t.Fatalf("settings wired a script apply has not written:\n%s", live)
	}

	// The next apply writes them; gen wires them.
	writeScript(t, filepath.Join(home, ".agent/hooks/guard-b.sh"))
	writeScript(t, filepath.Join(home, ".agent/hooks/logger.sh"))
	if ok, out := task(".agent/hooks/guard-b.sh", ".agent/hooks/logger.sh"); !ok {
		t.Fatalf("not ok: %s", out)
	}
	if live = readFile(t, settings); !strings.Contains(live, "guard-b.sh") || !strings.Contains(live, "logger.sh") {
		t.Fatalf("settings after the scripts landed:\n%s", live)
	}

	// A required script that apply has not written (removed here) refuses
	// the harness: the live file stays, and the tripwire says why.
	if err := os.Remove(filepath.Join(home, ".agent/hooks/guard-a.sh")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, ".config/yadm-agents/units.toml"), strings.Replace(fixtureUnits, `timeout = 10`, `timeout = 12`, 1))
	if ok, out := task(".config/yadm-agents/units.toml"); ok || !strings.Contains(out, "guard-a") {
		t.Fatalf("ok %v: %s", ok, out)
	}
	if readFile(t, settings) != live {
		t.Fatal("a refused gen changed the live file")
	}
	t.Setenv("YADM_KIND", "")
	if out, _ := tripwireRun(t, home); !strings.Contains(out, "guard-a") {
		t.Fatalf("tripwire: %q", out)
	}
}

// Under --as the manifest stands in for the other machine's disk: a
// script it does not deliver there is not wired there.
func TestGenAsSkipsUndeliveredScript(t *testing.T) {
	home := genHome(t)
	ev := twoMachines()
	ev.delivered["host-b"] = setOf(".claude/settings.json", ".agent/hooks/guard-a.sh")
	rs, _ := Gen(mustParse(t, fixtureUnits), ev, GenOptions{Home: home, As: "host-b", Only: setOf("claude"), Prune: true})
	r := byHarness(rs)["claude"]
	if r.Status != StatusChange || strings.Contains(strings.Join(r.Added, "\n"), "guard-b") ||
		!strings.Contains(strings.Join(r.Warnings, "\n"), "guard-b") {
		t.Fatalf("claude: %s %s +%v warnings %v", r.Status, r.Reason, r.Added, r.Warnings)
	}
	ev.delivered["host-b"] = setOf(".claude/settings.json")
	rs, _ = Gen(mustParse(t, fixtureUnits), ev, GenOptions{Home: home, As: "host-b", Only: setOf("claude"), Prune: true})
	if r := byHarness(rs)["claude"]; r.Status != StatusRefused || !strings.Contains(r.Reason, "not delivered to host-b") {
		t.Fatalf("claude: %s %s", r.Status, r.Reason)
	}
}

// verify refuses a wired cell whose script the manifest does not deliver
// to every machine where the cell is on, so wiring and script travel
// together. A cell that is off on a machine needs nothing there.
func TestVerifyScriptTravelsWithCell(t *testing.T) {
	home := genHome(t)
	f := mustParse(t, fixtureUnits)

	ev := twoMachines()
	delete(ev.delivered["host-b"], ".agent/hooks/guard-b.sh")
	msg := findings(Verify(f, ev, VerifyOptions{Home: home}), "error")
	if !strings.Contains(msg, `unit "guard-b" on claude`) || !strings.Contains(msg, "host-b") || !strings.Contains(msg, "does not deliver") {
		t.Fatalf("errors:\n%s", msg)
	}
	// guard-b.codex is on host-a only, which has the script.
	if strings.Contains(msg, `unit "guard-b" on codex`) {
		t.Fatalf("a cell off on host-b was checked there:\n%s", msg)
	}

	// logger.claude is on host-a only: host-b needs no logger script.
	ev = twoMachines()
	delete(ev.delivered["host-b"], ".agent/hooks/logger.sh")
	if fs := Verify(f, ev, VerifyOptions{Home: home}); hasErrors(fs) {
		t.Fatalf("errors:\n%s", findings(fs, "error"))
	}

	// A script outside home cannot travel with the wiring.
	src := strings.Replace(fixtureUnits, `script = "~/.agent/hooks/logger.sh"`, `script = "/opt/hooks/logger.sh"`, 1)
	if msg := findings(Verify(mustParse(t, src), twoMachines(), VerifyOptions{Home: home}), "error"); !strings.Contains(msg, "outside home") {
		t.Fatalf("errors:\n%s", msg)
	}

	// Offline skips it, as it skips every yadm query.
	ev = twoMachines()
	ev.delivered = map[string]map[string]bool{}
	if fs := Verify(f, ev, VerifyOptions{Home: home, Offline: true}); hasErrors(fs) {
		t.Fatalf("offline errors:\n%s", findings(fs, "error"))
	}
}

// As a commit check, a script tracked in the same commit as its cell is
// not in the last commit's manifest yet. When the check's globs match the
// script, the planned entry says where the commit sends it.
func TestCheckModeCountsScriptTrackedInSameCommit(t *testing.T) {
	home := genHome(t)
	writeFile(t, filepath.Join(home, ".config/yadm-agents/units.toml"), fixtureUnits)
	stagedUnits := filepath.Join(t.TempDir(), "units")
	writeFile(t, stagedUnits, fixtureUnits)
	t.Setenv("YADM_KIND", "check")
	t.Setenv("YADM_HOME", "")
	t.Setenv("YADM_AGENTS_UNITS", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	check := func(when *string) extexec.Response {
		t.Helper()
		ev := twoMachines()
		delete(ev.delivered["host-b"], ".agent/hooks/guard-b.sh") // new in this commit
		req := extexec.Request{Schema: 1, Kind: extexec.KindCheck, Home: home,
			Staged: map[model.Target]string{".config/yadm-agents/units.toml": stagedUnits}}
		if when != nil {
			req.Staged[".agent/hooks/guard-b.sh"] = filepath.Join(home, ".agent/hooks/guard-b.sh")
			req.Entries = map[model.Target]extexec.Entry{".agent/hooks/guard-b.sh": {Target: ".agent/hooks/*.sh", When: *when}}
		}
		b, _ := json.Marshal(req)
		var out, errb bytes.Buffer
		if code := run(nil, bytes.NewReader(b), &out, &errb, ev); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		var resp extexec.Response
		if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
			t.Fatalf("response %q: %v", out.String(), err)
		}
		return resp
	}
	if r := check(nil); r.OK || !strings.Contains(r.Message, "guard-b") {
		t.Fatalf("unstaged script: %+v", r)
	}
	all, workOnly := "", "type:work"
	if r := check(&all); !r.OK {
		t.Fatalf("staged for every machine: %+v", r)
	}
	if r := check(&workOnly); r.OK || !strings.Contains(r.Message, "host-b") {
		t.Fatalf("staged for host-a only: %+v", r)
	}
}
