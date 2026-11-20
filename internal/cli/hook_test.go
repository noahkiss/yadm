package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// Hook payloads in the shapes Claude Code documents for its hook events
// (common fields plus each event's own). Paths are filled per test.
const (
	payloadWrite = `{
  "session_id": "%SESSION%",
  "transcript_path": "/tmp/transcripts/session.jsonl",
  "cwd": "%CWD%",
  "permission_mode": "default",
  "hook_event_name": "PostToolUse",
  "tool_name": "Write",
  "tool_input": {"file_path": "%FILE%", "content": "file content"},
  "tool_response": {"filePath": "%FILE%", "type": "create"},
  "tool_use_id": "toolu_01ABC123",
  "duration_ms": 12
}`
	payloadEdit = `{
  "session_id": "%SESSION%",
  "transcript_path": "/tmp/transcripts/session.jsonl",
  "cwd": "%CWD%",
  "permission_mode": "default",
  "hook_event_name": "PostToolUse",
  "tool_name": "Edit",
  "tool_input": {"file_path": "%FILE%", "old_string": "a", "new_string": "b", "replace_all": false},
  "tool_use_id": "toolu_01DEF456"
}`
	payloadStop = `{
  "session_id": "%SESSION%",
  "transcript_path": "/tmp/transcripts/session.jsonl",
  "cwd": "%CWD%",
  "permission_mode": "default",
  "hook_event_name": "Stop",
  "stop_hook_active": false,
  "last_assistant_message": "Done.",
  "background_tasks": [],
  "session_crons": []
}`
	payloadSubagentStop = `{
  "session_id": "%SESSION%",
  "transcript_path": "/tmp/transcripts/session.jsonl",
  "cwd": "%CWD%",
  "permission_mode": "default",
  "hook_event_name": "SubagentStop",
  "stop_hook_active": false,
  "agent_id": "%AGENT%",
  "agent_type": "Explore",
  "agent_transcript_path": "/tmp/transcripts/session/subagents/agent.jsonl",
  "last_assistant_message": "Analysis complete.",
  "background_tasks": [],
  "session_crons": []
}`
	payloadSessionStart = `{
  "session_id": "%SESSION%",
  "transcript_path": "/tmp/transcripts/session.jsonl",
  "cwd": "%CWD%",
  "hook_event_name": "SessionStart",
  "source": "startup",
  "model": "model-name"
}`
)

func payload(tmpl, session, cwd, file string) string {
	r := strings.NewReplacer("%SESSION%", session, "%CWD%", cwd, "%FILE%", file, "%AGENT%", "agent-0001")
	return r.Replace(tmpl)
}

// hookRun runs `yadm hook <event>` with stdin and returns its exit code,
// stdout and stderr.
func hookRun(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	saved := hooks.stdin
	hooks.stdin = func() io.Reader { return strings.NewReader(stdin) }
	defer func() { hooks.stdin = saved }()
	var out, errb bytes.Buffer
	code := Main(append([]string{"hook"}, args...), &out, &errb, "test")
	return code, out.String(), errb.String()
}

func verdictOf(t *testing.T, stdout string) Verdict {
	t.Helper()
	var v Verdict
	dec := json.NewDecoder(strings.NewReader(stdout))
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("hook stdout is not one verdict: %v\n%s", err, stdout)
	}
	if dec.More() {
		t.Fatalf("hook stdout holds more than one JSON value:\n%s", stdout)
	}
	if v.Schema != HookSchema {
		t.Fatalf("verdict schema %d", v.Schema)
	}
	return v
}

// TestHookInputShapes decodes every documented payload shape and the
// normalized fields, and round-trips a verdict.
func TestHookInputShapes(t *testing.T) {
	for _, c := range []struct {
		name, tmpl, event, path string
	}{
		{"write", payloadWrite, "PostToolUse", "/home/user/.config/x"},
		{"edit", payloadEdit, "PostToolUse", "/home/user/.config/x"},
		{"stop", payloadStop, "Stop", ""},
		{"subagent-stop", payloadSubagentStop, "SubagentStop", ""},
		{"session-start", payloadSessionStart, "SessionStart", ""},
	} {
		in, err := readHookInput(strings.NewReader(payload(c.tmpl, "s-1", "/home/user", "/home/user/.config/x")))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if in.HookEventName != c.event || in.SessionID != "s-1" || in.Cwd != "/home/user" || editedPath(in) != c.path {
			t.Fatalf("%s: %+v path %q", c.name, in, editedPath(in))
		}
		if c.name == "subagent-stop" && in.AgentID != "agent-0001" {
			t.Fatalf("agent id: %+v", in)
		}
		if c.name == "session-start" && in.Source != "startup" {
			t.Fatalf("source: %+v", in)
		}
	}
	// A relative path resolves against cwd; a shell action names no path.
	in, _ := readHookInput(strings.NewReader(`{"cwd":"/home/user","tool_input":{"file_path":".config/x"}}`))
	if editedPath(in) != "/home/user/.config/x" {
		t.Fatalf("relative path: %q", editedPath(in))
	}
	in, _ = readHookInput(strings.NewReader(`{"action":"shell","harness":"any-harness","tool_input":{"file_path":"/home/user/x","command":"ls"}}`))
	if editedPath(in) != "" || in.Harness != "any-harness" {
		t.Fatalf("shell action: %+v", in)
	}
	in, _ = readHookInput(strings.NewReader(`{"action":"file_edit","tool_input":{"notebook_path":"/home/user/n.ipynb"}}`))
	if editedPath(in) != "/home/user/n.ipynb" {
		t.Fatalf("notebook: %+v", in)
	}
	if _, err := readHookInput(strings.NewReader("not json")); err == nil {
		t.Fatal("bad stdin must fail")
	}

	v := Verdict{Schema: HookSchema, Event: HookStop, Decision: DecisionBlock, Reason: "r", Harness: "h",
		UpdatedInput: json.RawMessage(`{"file_path":"/x"}`), Packets: []Packet{{ID: "id", Kind: "conflict", Options: []Option{{Label: "l", Command: "c"}}}}}
	b, _ := json.Marshal(v)
	var back Verdict
	if err := json.Unmarshal(b, &back); err != nil || back.Decision != DecisionBlock || back.Packets[0].Options[0].Command != "c" || string(back.UpdatedInput) != `{"file_path":"/x"}` {
		t.Fatalf("round trip: %s %+v %v", b, back, err)
	}
	var keys map[string]any
	_ = json.Unmarshal(b, &keys)
	for _, k := range []string{"continue", "hookSpecificOutput", "suppressOutput"} {
		if _, ok := keys[k]; ok {
			t.Fatalf("verdict carries a harness-specific key %q", k)
		}
	}
}

const hookManifest = `schema = 1

[[file]]
target = ".config/tool/config"

[[file]]
target = ".config/tool/work-only"
when = "type:work"

[[root]]
path = ".config/tool"
`

func hookTree() map[string]string {
	return map[string]string{
		"fleet.toml":                   e2eFleet,
		"manifest.toml":                hookManifest,
		"files/.config/tool/config":    "color = blue\n",
		"files/.config/tool/work-only": "work\n",
	}
}

// hookMachine sets up a machine: init, apply, allow the owned root.
func hookMachine(t *testing.T, root, remote, dir, name string) machineDirs {
	t.Helper()
	m := useMachine(t, root, dir)
	yadmOK(t, "init", remote, "--machine", name, "--no-schedule")
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/tool")
	return m
}

// TestHookEditCommitsAndPeerReceives: an edit through the post-edit hook is
// committed and pushed within the call; the other machine receives it on
// its next sync.
func TestHookEditCommitsAndPeerReceives(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	hookMachine(t, root, remote, "b", "host-b")
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = green\n")
	code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-a", a.Home, file), HookPostEdit)
	if code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-edit on a clean edit: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	msg := git(t, a.Source, "log", "-1", "--format=%B", "main")
	for _, want := range []string{"update .config/tool/config", "Yadm-Auto: hook", "Yadm-Session: session-a", "Yadm-Tool: Edit", "Yadm-Scope: shared"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("commit message lacks %q:\n%s", want, msg)
		}
	}
	if local, pushed := git(t, a.Source, "rev-parse", "main"), git(t, remote, "rev-parse", "main"); local != pushed {
		t.Fatalf("the hook did not push: local %s remote %s", local, pushed)
	}

	b := useMachine(t, root, "b")
	yadmOK(t, "sync")
	if got := readFile(t, filepath.Join(b.Home, ".config/tool/config")); got != "color = green\n" {
		t.Fatalf("b after sync: %q", got)
	}
	// An edit outside every managed path and root is recorded, never committed.
	useMachine(t, root, "a")
	before := git(t, a.Source, "rev-parse", "main")
	other := filepath.Join(a.Home, ".config/elsewhere/file")
	writeFile(t, other, "x\n")
	if code, stdout, _ := hookRun(t, payload(payloadWrite, "session-a", a.Home, other), HookPostEdit); code != HookAllow || stdout != "" {
		t.Fatalf("unmanaged edit: exit %d %q", code, stdout)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("an unmanaged edit was committed")
	}
}

// TestHookStopBlocksUntilDefer: a new file in an owned root is a decision;
// stop blocks while it is open, passes after defer, and the share option
// commits it.
func TestHookStopBlocksUntilDefer(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/new.conf")
	writeFile(t, file, "fresh = 1\n")
	code, stdout, stderr := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("post-edit on a new file: exit %d\n%s\n%s", code, stdout, stderr)
	}
	v := verdictOf(t, stdout)
	if v.Decision != DecisionBlock || len(v.Packets) != 1 {
		t.Fatalf("verdict: %+v", v)
	}
	p := v.Packets[0]
	if p.Kind != "new_file" || p.Target != ".config/tool/new.conf" || p.Reaches == nil || len(p.Reaches.Machines) != 2 || len(p.Neighbours) == 0 || len(p.Suggested) != 1 || p.Suggested[0] != "work" {
		t.Fatalf("packet: %+v", p)
	}
	if len(p.Options) < 2 || p.Options[0].Command != "yadm commit .config/tool/new.conf" || !strings.HasPrefix(p.Options[len(p.Options)-1].Command, "yadm defer "+p.ID) {
		t.Fatalf("options: %+v", p.Options)
	}
	if !strings.Contains(stderr, "yadm defer "+p.ID) || !strings.Contains(stderr, "new_file") {
		t.Fatalf("stderr lacks the packet:\n%s", stderr)
	}

	// Stop blocks; a subagent that edited nothing stops freely.
	if code, _, stderr := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop); code != HookBlock || !strings.Contains(stderr, "1 decision(s)") {
		t.Fatalf("stop with an open decision: exit %d\n%s", code, stderr)
	}
	if code, stdout, stderr := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop, "--format", "text"); code != HookBlock || stdout != "" || !strings.Contains(stderr, "yadm defer") {
		t.Fatalf("text stop: exit %d stdout %q", code, stdout)
	}
	if code, _, _ := hookRun(t, payload(payloadSubagentStop, "session-s", a.Home, ""), HookStop); code != HookAllow {
		t.Fatalf("subagent stop: exit %d", code)
	}
	// Another session's stop does not block on this one's decision.
	if code, _, _ := hookRun(t, payload(payloadStop, "session-other", a.Home, ""), HookStop); code != HookAllow {
		t.Fatalf("other session's stop: exit %d", code)
	}

	// The defer escape, with the command the packet gave.
	if _, code, _ := yadm(t, "defer", p.ID); code != ExitUsage {
		t.Fatalf("defer without --reason: exit %d", code)
	}
	env := yadmOK(t, "defer", p.ID[:12], "--reason", "decide with the owner")
	if d := decode[Deferred](t, env.Data); d.ID != p.ID || d.Why != "decide with the owner" {
		t.Fatalf("defer: %+v", d)
	}
	if code, stdout, stderr := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop); code != HookAllow || stdout != "" {
		t.Fatalf("stop after defer: exit %d\n%s\n%s", code, stdout, stderr)
	}
	env = yadmOK(t, "review", "list")
	if ds := decode[map[string][]Deferred](t, env.Data)["deferred"]; len(ds) != 1 || ds[0].ID != p.ID {
		t.Fatalf("review list deferred: %+v", ds)
	}

	// The session-start summary names the deferred decision and stays short.
	code, stdout, _ = hookRun(t, payload(payloadSessionStart, "session-t", filepath.Join(a.Home, ".config/tool"), ""), HookSessionStart, "--format", "text")
	if code != HookAllow || !strings.Contains(stdout, "deferred") || strings.Count(stdout, "\n") > 10 {
		t.Fatalf("session-start: exit %d\n%s", code, stdout)
	}

	// The share option commits the file and settles the decision.
	yadmOK(t, strings.Fields(p.Options[0].Command)[1:]...)
	if out := git(t, a.Source, "ls-tree", "-r", "--name-only", "main"); !strings.Contains(out, "files/.config/tool/new.conf") {
		t.Fatalf("share did not commit:\n%s", out)
	}
	env = yadmOK(t, "review", "list")
	if ds := decode[map[string][]Deferred](t, env.Data)["deferred"]; len(ds) != 0 {
		t.Fatalf("a settled decision stays deferred: %+v", ds)
	}
}

// TestHookConflictPacket: two machines edit one file; the second hook's
// push meets the first edit, raises a conflict packet, and its "keep this
// edit" option commits and pushes over the incoming change.
func TestHookConflictPacket(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	b := hookMachine(t, root, remote, "b", "host-b")
	a := hookMachine(t, root, remote, "a", "host-a")

	fa := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, fa, "color = green\n")
	if code, _, stderr := hookRun(t, payload(payloadEdit, "session-a", a.Home, fa), HookPostEdit); code != HookAllow {
		t.Fatalf("a: exit %d %s", code, stderr)
	}

	useMachine(t, root, "b")
	fb := filepath.Join(b.Home, ".config/tool/config")
	writeFile(t, fb, "color = red\n")
	code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-b", b.Home, fb), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("b: exit %d\n%s\n%s", code, stdout, stderr)
	}
	v := verdictOf(t, stdout)
	var p *Packet
	for i := range v.Packets {
		if v.Packets[i].Kind == string(model.HoldConflict) {
			p = &v.Packets[i]
		}
	}
	if p == nil || p.Target != ".config/tool/config" || p.Diff == nil {
		t.Fatalf("no conflict packet: %+v", v.Packets)
	}
	var keep string
	for _, o := range p.Options {
		if strings.HasSuffix(o.Command, "--take target") {
			keep = o.Command
		}
	}
	if keep == "" {
		t.Fatalf("options: %+v", p.Options)
	}
	yadmOK(t, "hold", "show", p.ID)
	env := yadmOK(t, strings.Fields(keep)[1:]...)
	if cs := decode[struct{ Commits []string }](t, env.Data).Commits; len(cs) != 1 {
		t.Fatalf("resolve committed %v", cs)
	}
	if got := readFile(t, fb); got != "color = red\n" {
		t.Fatalf("b's edit lost: %q", got)
	}
	if code, _, stderr := hookRun(t, payload(payloadStop, "session-b", b.Home, ""), HookStop); code != HookAllow {
		t.Fatalf("stop after resolve: exit %d\n%s", code, stderr)
	}

	useMachine(t, root, "a")
	yadmOK(t, "sync")
	if got := readFile(t, fa); got != "color = red\n" {
		t.Fatalf("a after sync: %q", got)
	}
}

// TestHookSecrecy: a hook edit of an enclave file on a member commits it
// sealed; the plaintext reaches neither the hook's output, the session
// records, any repository, nor a non-member's $HOME.
func TestHookSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canaries := fx.AllCanaries()
	c := secrecytest.NewCanary(t, "personal-hook")
	canaries = append(canaries, c)

	bin := filepath.Join(root, "bin")
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "task", "allow")
	yadmOK(t, "apply")
	file := filepath.Join(a.Home, ".config/notes/private.md")
	writeFile(t, file, readFile(t, file)+c.String()+"\n")
	code, stdout, stderr := hookRun(t, payload(payloadWrite, "session-sec", a.Home, file), HookPostEdit)
	if code != HookAllow && code != HookBlock {
		t.Fatalf("post-edit: exit %d\n%s", code, stderr)
	}
	for _, x := range canaries {
		if strings.Contains(stdout, x.String()) || strings.Contains(stderr, x.String()) {
			t.Fatal("hook output carries enclave plaintext")
		}
	}
	if code == HookAllow {
		msg := git(t, a.Source, "log", "-1", "--format=%B", "main")
		if !strings.Contains(msg, "Yadm-Scope: personal") || !strings.Contains(msg, "Yadm-Auto: hook") {
			t.Fatalf("not a sealed hook commit:\n%s", msg)
		}
	}
	hookRun(t, payload(payloadStop, "session-sec", a.Home, ""), HookStop)
	secrecytest.AssertTreeClean(t, filepath.Join(a.State, "hooks"), canaries...)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "sync")
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)
}
