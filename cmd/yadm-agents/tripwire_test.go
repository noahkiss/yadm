package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tripwireRun runs `yadm-agents tripwire` through run(), with an evaluator
// that fails the test if it is touched and stdin that fails if it is read.
func tripwireRun(t *testing.T, home string, args ...string) (string, int) {
	t.Helper()
	t.Setenv("YADM_KIND", "task") // even under the exec contract it reads no request
	ev := &fakeEval{}
	var out, errb bytes.Buffer
	code := run(append([]string{"tripwire", "--home", home}, args...), failReader{t}, &out, &errb, ev)
	if ev.calls != 0 {
		t.Fatalf("tripwire evaluated %d conditions", ev.calls)
	}
	if errb.Len() > 0 {
		t.Fatalf("stderr: %s", errb.String())
	}
	return out.String(), code
}

type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Fatal("tripwire read stdin")
	return 0, nil
}

// genTripwireHome runs gen once on the oneGuard fixture, so the state file
// holds the expected required set.
func genTripwireHome(t *testing.T) string {
	t.Helper()
	home := oneGuardHome(t)
	rs, err := Gen(mustParse(t, oneGuard), twoMachines(), GenOptions{Home: home, Only: setOf("claude")})
	if err != nil || byHarness(rs)["claude"].Status != StatusWritten {
		t.Fatalf("gen: %v %+v", err, rs)
	}
	return home
}

func TestTripwireQuietWhenWired(t *testing.T) {
	home := genTripwireHome(t)
	if out, code := tripwireRun(t, home); out != "" || code != 0 {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

// A required guard that leaves the live file, or loses a tool, is one loud
// line; exit stays 0 so the session starts.
func TestTripwireReportsMissingGuard(t *testing.T) {
	home := genTripwireHome(t)
	settings := filepath.Join(home, ".claude/settings.json")
	live := readFile(t, settings)

	writeFile(t, settings, "{\n  \"model\": \"x\",\n  \"hooks\": {}\n}\n")
	out, code := tripwireRun(t, home)
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.Contains(out, "REQUIRED GUARD MISSING") ||
		!strings.Contains(out, "guard-a") || !strings.Contains(out, "claude") {
		t.Fatalf("exit %d, out %q", code, out)
	}

	// narrowed: Bash stays, Write goes
	writeFile(t, settings, strings.Replace(live, `"Bash|Write"`, `"Bash"`, 1))
	if readFile(t, settings) == live {
		t.Fatalf("edit did not apply:\n%s", live)
	}
	if out, _ := tripwireRun(t, home); !strings.Contains(out, "guard-a") || !strings.Contains(out, "Write") {
		t.Fatalf("narrowed guard not reported: %q", out)
	}
}

func TestTripwireReportsMissingScript(t *testing.T) {
	home := genTripwireHome(t)
	os.Remove(filepath.Join(home, ".agent/hooks/guard-a.sh"))
	if out, _ := tripwireRun(t, home); !strings.Contains(out, "guard-a") || !strings.Contains(out, "guard-a.sh") {
		t.Fatalf("out %q", out)
	}
}

func TestTripwireNoState(t *testing.T) {
	home := oneGuardHome(t)
	out, code := tripwireRun(t, home)
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.Contains(out, "yadm-agents gen") {
		t.Fatalf("exit %d, out %q", code, out)
	}
	writeFile(t, statePath(home), "{not json")
	if out, code := tripwireRun(t, home); code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("corrupt state: exit %d, out %q", code, out)
	}
}

// --harness limits the check to the harness that calls it; a harness gen
// never planned is one line.
func TestTripwireHarnessFilter(t *testing.T) {
	home := genTripwireHome(t)
	writeFile(t, filepath.Join(home, ".claude/settings.json"), "{}\n")
	if out, _ := tripwireRun(t, home, "--harness", "claude"); !strings.Contains(out, "guard-a") {
		t.Fatalf("claude: %q", out)
	}
	if out, _ := tripwireRun(t, home, "--harness", "codex"); strings.Contains(out, "guard-a") || !strings.Contains(out, "codex") {
		t.Fatalf("codex: %q", out)
	}
}

// --format hook prints the SessionStart hook JSON: systemMessage for the
// user, additionalContext for the model; nothing when all is wired.
func TestTripwireHookFormat(t *testing.T) {
	home := genTripwireHome(t)
	if out, _ := tripwireRun(t, home, "--format", "hook"); out != "" {
		t.Fatalf("wired: %q", out)
	}
	writeFile(t, filepath.Join(home, ".claude/settings.json"), "{}\n")
	out, code := tripwireRun(t, home, "--format", "hook")
	var v struct {
		SystemMessage string `json:"systemMessage"`
		Specific      struct {
			Event   string `json:"hookEventName"`
			Context string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || code != 0 {
		t.Fatalf("exit %d, out %q: %v", code, out, err)
	}
	if !strings.Contains(v.SystemMessage, "guard-a") || v.Specific.Event != "SessionStart" || !strings.Contains(v.Specific.Context, "guard-a") {
		t.Fatalf("hook output = %+v", v)
	}
}

// A usage error never fails the session.
func TestTripwireBadFlagExitsZero(t *testing.T) {
	home := genTripwireHome(t)
	ev := &fakeEval{}
	var out, errb bytes.Buffer
	if code := run([]string{"tripwire", "--home", home, "--nope"}, failReader{t}, &out, &errb, ev); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// gen that refuses still records what this machine requires, so the
// tripwire reports the guard gen could not wire.
func TestTripwireAfterRefusedGen(t *testing.T) {
	home := oneGuardHome(t)
	writeFile(t, filepath.Join(home, ".claude/settings.json"),
		`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"someone-else"}]}]}}`+"\n")
	rs, _ := Gen(mustParse(t, oneGuard), twoMachines(), GenOptions{Home: home, Only: setOf("claude")})
	if r := byHarness(rs)["claude"]; r.Status != StatusRefused {
		t.Fatalf("claude: %s", r.Status)
	}
	if out, _ := tripwireRun(t, home); !strings.Contains(out, "guard-a") {
		t.Fatalf("out %q", out)
	}
}

// A gen that refuses before it knows the plan still leaves a mark the
// tripwire reports, even when the guards gen wired earlier are still in
// place. Otherwise a session starts with "all good" after a failed gen.
func TestTripwireReportsRefusalBeforePlan(t *testing.T) {
	home := genTripwireHome(t)
	bad := strings.Replace(oneGuard, "schema = 1\n", "schema = 1\n\n[harness.claude]\ntrusted_projects = [\"~/dev/x\"]\n", 1)
	if r := genOnly(t, home, bad, "claude", GenOptions{DryRun: true}); r.Status != StatusRefused {
		t.Fatalf("claude: %s", r.Status)
	}
	if out, _ := tripwireRun(t, home); out != "" {
		t.Fatalf("a dry run left a mark: %q", out)
	}
	if r := genOnly(t, home, bad, "claude", GenOptions{}); r.Status != StatusRefused {
		t.Fatalf("claude: %s", r.Status)
	}
	out, _ := tripwireRun(t, home, "--harness", "claude")
	if !strings.Contains(out, "gen refused claude") || !strings.Contains(out, "trusted_projects") {
		t.Fatalf("out %q", out)
	}
	// A gen that succeeds again clears it.
	if r := genOnly(t, home, oneGuard, "claude", GenOptions{}); r.Status == StatusRefused {
		t.Fatalf("claude: %s", r.Reason)
	}
	if out, _ := tripwireRun(t, home); out != "" {
		t.Fatalf("out %q", out)
	}
}

// A units file that does not load fails gen before any harness; the
// tripwire must say so rather than report the old wiring as fine.
func TestTripwireReportsGenLoadFailure(t *testing.T) {
	home := genTripwireHome(t)
	units := filepath.Join(home, ".config/yadm-agents/units.toml")
	writeFile(t, units, "schema = 1\n[[unit]\n")
	t.Setenv("YADM_KIND", "")
	var out, errb bytes.Buffer
	if code := run([]string{"gen", "--dry-run", "--home", home, "--units", units}, strings.NewReader(""), &out, &errb, twoMachines()); code == 0 {
		t.Fatal("gen loaded a broken units file")
	}
	if got, _ := tripwireRun(t, home); got != "" {
		t.Fatalf("a dry run left a mark: %q", got)
	}
	if code := run([]string{"gen", "--home", home, "--units", units}, strings.NewReader(""), &out, &errb, twoMachines()); code == 0 {
		t.Fatal("gen loaded a broken units file")
	}
	got, _ := tripwireRun(t, home, "--harness", "claude")
	if !strings.Contains(got, "gen failed") {
		t.Fatalf("out %q", got)
	}
	writeFile(t, units, oneGuard)
	if code := run([]string{"gen", "--home", home, "--units", units}, strings.NewReader(""), &out, &errb, twoMachines()); code != 0 {
		t.Fatalf("gen: %s %s", out.String(), errb.String())
	}
	if got, _ := tripwireRun(t, home); got != "" {
		t.Fatalf("out %q", got)
	}
}

// A refusal keeps the trust gen owned, so a later run can still take back
// what it wrote.
func TestRefusalKeepsOwnedTrust(t *testing.T) {
	home := trustHome(t)
	abs := filepath.Join(home, "dev/x")
	if r := genOnly(t, home, trustUnits("~/dev/x"), "codex", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("codex: %s %s", r.Status, r.Reason)
	}
	if r := genOnly(t, home, trustUnits("~/dev/x", "/elsewhere"), "codex", GenOptions{}); r.Status != StatusRefused {
		t.Fatalf("codex: %s", r.Status)
	}
	st, _ := readState(statePath(home))
	if o := st.Harness["codex"].Trusted; len(o) != 1 || o[0] != abs {
		t.Fatalf("owned = %v", o)
	}
}

// Text from the state and the live files reaches a terminal and a model.
// No control character survives, in either format, after decoding.
func TestTripwireStripsControlCharacters(t *testing.T) {
	home := t.TempDir()
	st := State{Schema: 1, Harness: map[string]HarnessState{"claude": {
		Target:   ".claude/set\x1b[2Jtings\n.json",
		Required: []Expected{{Unit: "guard-a", Handlers: []Handler{{Event: "PreToolUse", Matcher: "Bash", Command: "x"}}}},
	}}}
	if err := writeState(statePath(home), st); err != nil {
		t.Fatal(err)
	}
	text, _ := tripwireRun(t, home)
	hook, _ := tripwireRun(t, home, "--format", "hook")
	var msg struct {
		SystemMessage string `json:"systemMessage"`
		Hook          struct {
			Context string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(hook), &msg); err != nil {
		t.Fatalf("hook output is not JSON: %v\n%s", err, hook)
	}
	for _, s := range []string{strings.TrimSuffix(text, "\n"), msg.SystemMessage, msg.Hook.Context} {
		if s == "" {
			t.Fatal("no output")
		}
		for _, line := range strings.Split(s, "\n") {
			if !strings.HasPrefix(line, "yadm-agents: ") {
				t.Fatalf("a field broke a line: %q", s)
			}
		}
		if strings.ContainsAny(s, "\x1b\r\t\x00") {
			t.Fatalf("control character in %q", s)
		}
	}
}
