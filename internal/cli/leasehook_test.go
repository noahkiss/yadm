package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLeaseKeepsHooksOff: a leased path is the holder's. The post-edit hook
// of the editing session commits nothing, and the holder's named commit
// lands with its own subject. A stop hook in a session that recorded the
// path neither commits it nor blocks on it, and says who holds it.
func TestLeaseKeepsHooksOff(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	// 24h: the timer syncs below run hours ahead of the clock.
	yadmOK(t, "lease", "take", ".config/tool/config", "--holder", "agent-x", "--ttl", "24h")
	before := git(t, a.Source, "rev-parse", "main")

	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = half-edited\n")
	if code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-x", a.Home, file), HookPostEdit); code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-edit on a leased path: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("post-edit committed a leased path")
	}

	// The parent session also recorded the path; its stop leaves it alone.
	if code, _, _ := hookRun(t, payload(payloadEdit, "session-parent", a.Home, file), HookPostEdit); code != HookAllow {
		t.Fatalf("parent post-edit: exit %d", code)
	}
	code, stdout, stderr := hookRun(t, payload(payloadStop, "session-parent", a.Home, ""), HookStop)
	if code != HookAllow || stderr != "" {
		t.Fatalf("stop on a leased path: exit %d\n%s\n%s", code, stdout, stderr)
	}
	v := verdictOf(t, stdout)
	if v.Decision != DecisionAllow || len(v.Packets) != 0 || !strings.Contains(v.Context, "leased by agent-x until ") || !strings.Contains(v.Context, ".config/tool/config") {
		t.Fatalf("stop verdict: %+v", v)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("the stop hook committed a leased path")
	}

	// The timer leaves it too.
	timerSyncs(t)
	hooks.now = time.Now
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("the timer committed a leased path")
	}

	writeFile(t, file, "color = green\n")
	yadmOK(t, "commit", "-m", "tune the tool colour", "--no-push", ".config/tool/config")
	if msg := git(t, a.Source, "log", "-1", "--format=%B", "main"); !strings.HasPrefix(msg, "tune the tool colour\n") || !strings.Contains(msg, "Yadm-Auto: manual") {
		t.Fatalf("the holder's commit:\n%s", msg)
	}
	if n := git(t, a.Source, "rev-list", "--count", before+"..main"); n != "1" {
		t.Fatalf("%s commits since the lease, want the holder's one", n)
	}
}

// TestLeaseReleaseCommitsLeftovers: once the lease is released, the next
// stop hook commits what is still pending.
func TestLeaseReleaseCommitsLeftovers(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	yadmOK(t, "lease", "take", ".config/tool", "--holder", "agent-x", "--ttl", "60m")
	before := git(t, a.Source, "rev-parse", "main")
	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = red\n")
	hookRun(t, payload(payloadEdit, "session-x", a.Home, file), HookPostEdit)
	if code, _, _ := hookRun(t, payload(payloadStop, "session-x", a.Home, ""), HookStop); code != HookAllow {
		t.Fatalf("stop while leased: exit %d", code)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("a directory lease did not cover its file")
	}

	yadmOK(t, "lease", "release", "agent-x")
	code, stdout, stderr := hookRun(t, payload(payloadStop, "session-x", a.Home, ""), HookStop)
	if code != HookAllow || stdout != "" {
		t.Fatalf("stop after release: exit %d\n%s\n%s", code, stdout, stderr)
	}
	msg := git(t, a.Source, "log", "-1", "--format=%B", "main")
	if !strings.Contains(msg, "update .config/tool/config") || !strings.Contains(msg, "Yadm-Auto: stop") {
		t.Fatalf("leftover commit:\n%s", msg)
	}
}

// TestLeaseExpiredProtectsNothing: an expired lease no longer keeps the
// post-edit hook off its path.
func TestLeaseExpiredProtectsNothing(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	past := time.Now().Add(-2 * time.Hour)
	hooks.now = func() time.Time { return past }
	yadmOK(t, "lease", "take", ".config/tool/config", "--holder", "agent-x", "--ttl", "60m")
	hooks.now = time.Now

	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = green\n")
	if code, stdout, _ := hookRun(t, payload(payloadEdit, "session-x", a.Home, file), HookPostEdit); code != HookAllow || stdout != "" {
		t.Fatalf("post-edit: exit %d %q", code, stdout)
	}
	if msg := git(t, a.Source, "log", "-1", "--format=%B", "main"); !strings.Contains(msg, "Yadm-Auto: hook") {
		t.Fatalf("an expired lease kept the hook off:\n%s", msg)
	}
}

// TestLeaseNewFileRaisesNoDecision: a lease on a new file in an owned root
// suppresses its decision while the lease lives. After release, the stop
// hook raises it as usual.
func TestLeaseNewFileRaisesNoDecision(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	yadmOK(t, "lease", "take", ".config/tool/new.conf", "--holder", "agent-x", "--ttl", "60m")
	file := filepath.Join(a.Home, ".config/tool/new.conf")
	writeFile(t, file, "fresh = 1\n")
	if code, stdout, stderr := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit); code != HookAllow || stdout != "" {
		t.Fatalf("post-edit on a leased new file: exit %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, stderr := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop)
	if code != HookAllow || !strings.Contains(stdout, "leased by agent-x") {
		t.Fatalf("stop on a leased new file: exit %d\n%s\n%s", code, stdout, stderr)
	}
	env := yadmOK(t, "hold", "list")
	if strings.Contains(mustJSON(t, env.Data), "new.conf") {
		t.Fatalf("a leased new file is held: %+v", env.Data)
	}

	yadmOK(t, "lease", "release", "agent-x")
	if code, _, stderr := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop); code != HookBlock || !strings.Contains(stderr, "new_file") {
		t.Fatalf("stop after release: exit %d\n%s", code, stderr)
	}
}
