package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// payloadBash is a PostToolUse payload for a tool that names no file.
const payloadBash = `{
  "session_id": "%SESSION%",
  "cwd": "%CWD%",
  "hook_event_name": "PostToolUse",
  "tool_name": "Bash",
  "tool_input": {"command": "make test"},
  "tool_use_id": "toolu_01GHI789"
}`

// payloadSubagentBash is payloadBash from a subagent.
const payloadSubagentBash = `{
  "session_id": "%SESSION%",
  "cwd": "%CWD%",
  "hook_event_name": "PostToolUse",
  "agent_id": "%AGENT%",
  "tool_name": "Bash",
  "tool_input": {"command": "ls"},
  "tool_use_id": "toolu_01JKL012"
}`

// gatedHookTree is hookTree with a commit-gate check on the owned root
// that fails while flag exists.
func gatedHookTree(t *testing.T, root string) (map[string]string, string) {
	t.Helper()
	tools := filepath.Join(root, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	flag := filepath.Join(tools, "refuse")
	check := filepath.Join(tools, "check-terms")
	script := "#!/bin/sh\ncat >/dev/null\nif [ -f '" + flag + "' ]; then echo 'a banned term' >&2; exit 1; fi\nexit 0\n"
	if err := os.WriteFile(check, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	tree := hookTree()
	man := strings.Replace(hookManifest, "target = \".config/tool/config\"\n", "target = \".config/tool/config\"\nquiet = \"0s\"\n", 1)
	tree["manifest.toml"] = man + "\n[checks.terms]\npaths = [\".config/tool/**\"]\ncommand = [" + tomlQuote(check) + "]\n"
	return tree, flag
}

// TestHookGateRefusalBlocksEdit: post-edit runs the commit gate on the
// edited path within the call; a refusal blocks with the failed check's
// packet on stderr, where the harness shows it to the model.
func TestHookGateRefusalBlocksEdit(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree, flag := gatedHookTree(t, root)
	remote := seedRemote(t, root, tree)
	a := hookMachine(t, root, remote, "a", "host-a")
	yadmOK(t, "task", "allow", "terms")

	writeFile(t, flag, "")
	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = green\n")
	code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-g", a.Home, file), HookPostEdit, "--format", "text")
	if code != HookBlock || stdout != "" {
		t.Fatalf("post-edit on a refused edit: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "check_failed: .config/tool/config") || !strings.Contains(stderr, "yadm defer") {
		t.Fatalf("stderr lacks the check_failed packet:\n%s", stderr)
	}
}

// TestHookPostToolReportsLaterHold: a hold the timer raises on a path a
// session edited, after its post-edit returned, reaches that session at its
// next tool call through post-tool: once per hold, only to that session and
// to the agent that edited the path. stop still blocks on it.
func TestHookPostToolReportsLaterHold(t *testing.T) {
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
	yadmOK(t, "sync")

	useMachine(t, root, "b")
	// Nothing recorded yet: post-tool is silent and never fails.
	if code, stdout, stderr := hookRun(t, payload(payloadBash, "session-b", b.Home, ""), HookPostTool); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-tool before any edit: exit %d %q %q", code, stdout, stderr)
	}
	fb := filepath.Join(b.Home, ".config/tool/config")
	writeFile(t, fb, "color = red\n")
	if code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-b", b.Home, fb), HookPostEdit); code != HookAllow {
		t.Fatalf("b post-edit: exit %d\n%s\n%s", code, stdout, stderr)
	}
	yadm(t, "sync") // the timer meets a's edit: a conflict hold

	// A subagent that edited nothing is not told; another session is not told.
	if code, stdout, stderr := hookRun(t, payload(payloadSubagentBash, "session-b", b.Home, ""), HookPostTool, "--format", "text"); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("subagent post-tool: exit %d %q %q", code, stdout, stderr)
	}
	if code, stdout, stderr := hookRun(t, payload(payloadBash, "session-other", b.Home, ""), HookPostTool, "--format", "text"); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("other session's post-tool: exit %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr := hookRun(t, payload(payloadBash, "session-b", b.Home, ""), HookPostTool)
	if code != HookBlock {
		t.Fatalf("post-tool after the timer's hold: exit %d\n%s\n%s", code, stdout, stderr)
	}
	v := verdictOf(t, stdout)
	if v.Event != HookPostTool || len(v.Packets) != 1 || v.Packets[0].Kind != "conflict" || v.Packets[0].Target != ".config/tool/config" {
		t.Fatalf("verdict: %+v", v)
	}
	id := v.Packets[0].ID
	if !strings.Contains(stderr, "conflict: .config/tool/config") || !strings.Contains(stderr, "yadm hold resolve "+id) {
		t.Fatalf("stderr lacks the packet:\n%s", stderr)
	}
	// Told once: the next tool call, and the next edit elsewhere, are quiet.
	if code, stdout, stderr := hookRun(t, payload(payloadBash, "session-b", b.Home, ""), HookPostTool, "--format", "text"); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("second post-tool: exit %d %q %q", code, stdout, stderr)
	}
	other := filepath.Join(b.Home, ".config/elsewhere/file")
	writeFile(t, other, "x\n")
	if code, stdout, stderr := hookRun(t, payload(payloadWrite, "session-b", b.Home, other), HookPostEdit, "--format", "text"); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-edit elsewhere after being told: exit %d %q %q", code, stdout, stderr)
	}
	// stop still blocks until the decision is settled.
	if code, _, stderr := hookRun(t, payload(payloadStop, "session-b", b.Home, ""), HookStop); code != HookBlock || !strings.Contains(stderr, id) {
		t.Fatalf("stop: exit %d\n%s", code, stderr)
	}
}

// TestHookPostEditReportsHoldAfterBusyLock: post-edit leaves a path to the
// timer when a sync holds the lock. When the timer's gate then refuses it,
// the session's next edit of any file reports the hold, once.
func TestHookPostEditReportsHoldAfterBusyLock(t *testing.T) {
	hermetic(t)
	saved := hooks.hookWait
	hooks.hookWait = 100 * time.Millisecond
	defer func() { hooks.hookWait = saved }()
	root := t.TempDir()
	tree, flag := gatedHookTree(t, root)
	remote := seedRemote(t, root, tree)
	a := hookMachine(t, root, remote, "a", "host-a")
	yadmOK(t, "task", "allow", "terms")

	writeFile(t, flag, "")
	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = green\n")
	done := holdLock(t, a.State, time.Second)
	code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-l", a.Home, file), HookPostEdit, "--format", "text")
	<-done
	if code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-edit while a sync holds the lock: exit %d %q %q", code, stdout, stderr)
	}
	yadm(t, "sync", "--auto") // the timer captures the edit; the gate refuses it
	env := yadmOK(t, "hold", "list")
	if hs := decode[holdsOnly](t, env.Data).Holds; !hasReason(hs, "check_failed") {
		t.Fatalf("the timer raised no check_failed hold: %+v", hs)
	}

	other := filepath.Join(a.Home, ".config/elsewhere/file")
	writeFile(t, other, "x\n")
	code, stdout, stderr = hookRun(t, payload(payloadWrite, "session-l", a.Home, other), HookPostEdit, "--format", "text")
	if code != HookBlock || stdout != "" || !strings.Contains(stderr, "check_failed: .config/tool/config") {
		t.Fatalf("next post-edit after the timer's gate hold: exit %d %q\n%s", code, stdout, stderr)
	}
	if code, stdout, stderr := hookRun(t, payload(payloadBash, "session-l", a.Home, ""), HookPostTool, "--format", "text"); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-tool after post-edit told it: exit %d %q %q", code, stdout, stderr)
	}
	// An edit of the held file itself raises it again, as before.
	if code, _, stderr := hookRun(t, payload(payloadEdit, "session-l", a.Home, file), HookPostEdit, "--format", "text"); code != HookBlock || !strings.Contains(stderr, "check_failed") {
		t.Fatalf("post-edit of the held file: exit %d\n%s", code, stderr)
	}
	// Later timer ticks keep the hold's id: the session is not told again.
	yadm(t, "sync", "--auto")
	yadm(t, "sync", "--auto")
	if code, stdout, stderr := hookRun(t, payload(payloadBash, "session-l", a.Home, ""), HookPostTool, "--format", "text"); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-tool after more ticks: exit %d %q %q", code, stdout, stderr)
	}
	// Under a busy lock, post-edit still raises the decision open on its own path.
	done = holdLock(t, a.State, time.Second)
	code, _, stderr = hookRun(t, payload(payloadEdit, "session-m", a.Home, file), HookPostEdit, "--format", "text")
	<-done
	if code != HookBlock || !strings.Contains(stderr, "check_failed: .config/tool/config") {
		t.Fatalf("post-edit of the held file under a busy lock: exit %d\n%s", code, stderr)
	}
	// A deferred decision is not raised.
	env = yadmOK(t, "hold", "list")
	var id string
	for _, h := range decode[holdsOnly](t, env.Data).Holds {
		if h.Reason == "check_failed" {
			id = h.ID
		}
	}
	yadmOK(t, "defer", id, "--reason", "waits for the owner")
	if code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-n", a.Home, file), HookPostEdit, "--format", "text"); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-edit of a deferred hold: exit %d %q %q", code, stdout, stderr)
	}
}

func hasReason(hs []model.Hold, r model.HoldReason) bool {
	for _, h := range hs {
		if h.Reason == r {
			return true
		}
	}
	return false
}
