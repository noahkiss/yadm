package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/model"
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

// TestLeaseRepeatTakeKeepsEarlierPaths: a second take by the same holder
// adds to its lease, so the stop hook still leaves the first path alone.
func TestLeaseRepeatTakeKeepsEarlierPaths(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	yadmOK(t, "lease", "take", ".config/tool/config", "--holder", "agent-x", "--ttl", "60m")
	yadmOK(t, "lease", "take", ".config/tool/new.conf", "--holder", "agent-x", "--ttl", "60m")
	before := git(t, a.Source, "rev-parse", "main")
	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = red\n")
	hookRun(t, payload(payloadEdit, "session-p", a.Home, file), HookPostEdit)
	if code, stdout, _ := hookRun(t, payload(payloadStop, "session-p", a.Home, ""), HookStop); code != HookAllow || !strings.Contains(stdout, "leased by agent-x") {
		t.Fatalf("stop: exit %d %s", code, stdout)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("a repeat take dropped the first path's protection")
	}

	// A misspelled release drops nothing and says what still holds.
	env := yadmOK(t, "lease", "release", "agent-x", ".config/tool/config/")
	if k := decode[struct{ Kept []string }](t, env.Data).Kept; len(k) != 2 {
		t.Fatalf("kept after a misspelled release: %v", k)
	}

	// Releasing one path leaves the other leased; that one commits.
	env = yadmOK(t, "lease", "release", "agent-x", ".config/tool/config")
	if k := decode[struct{ Kept []string }](t, env.Data).Kept; len(k) != 1 || k[0] != ".config/tool/new.conf" {
		t.Fatalf("kept after a path release: %v", k)
	}
	if code, _, _ := hookRun(t, payload(payloadStop, "session-p", a.Home, ""), HookStop); code != HookAllow {
		t.Fatalf("stop after a path release: exit %d", code)
	}
	if msg := git(t, a.Source, "log", "-1", "--format=%B", "main"); !strings.Contains(msg, "update .config/tool/config") {
		t.Fatalf("the released path did not commit:\n%s", msg)
	}
	env = yadmOK(t, "lease", "list")
	if s := mustJSON(t, env.Data); !strings.Contains(s, "new.conf") || strings.Contains(s, "tool/config") {
		t.Fatalf("lease list after a path release: %s", s)
	}
}

// TestLeaseRaisesConflict: a lease holds back a path's commit, never a
// conflict on it. The stop hook and post-edit still raise the conflict.
func TestLeaseRaisesConflict(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	b := hookMachine(t, root, remote, "b", "host-b")
	a := hookMachine(t, root, remote, "a", "host-a")

	fa := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, fa, "color = green\n")
	hookRun(t, payload(payloadEdit, "session-a", a.Home, fa), HookPostEdit)
	yadmOK(t, "sync")

	useMachine(t, root, "b")
	fb := filepath.Join(b.Home, ".config/tool/config")
	writeFile(t, fb, "color = red\n")
	if code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-b", b.Home, fb), HookPostEdit); code != HookAllow {
		t.Fatalf("b post-edit: exit %d\n%s\n%s", code, stdout, stderr)
	}
	yadm(t, "sync") // meets a's edit: a conflict hold
	yadmOK(t, "lease", "take", ".config/tool", "--holder", "agent-x", "--ttl", "1h")

	hasConflict := func(v Verdict) bool {
		for _, p := range v.Packets {
			if p.Kind == string(model.HoldConflict) && p.Target == ".config/tool/config" {
				return true
			}
		}
		return false
	}
	code, stdout, stderr := hookRun(t, payload(payloadStop, "session-b", b.Home, ""), HookStop)
	if code != HookBlock {
		t.Fatalf("stop on a leased path with a conflict: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if v := verdictOf(t, stdout); !hasConflict(v) || !strings.Contains(v.Reason, "leased by agent-x") {
		t.Fatalf("stop verdict: %+v", v)
	}
	code, stdout, stderr = hookRun(t, payload(payloadEdit, "session-b", b.Home, fb), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("post-edit on a leased path with a conflict: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if v := verdictOf(t, stdout); !hasConflict(v) {
		t.Fatalf("post-edit verdict: %+v", v)
	}
}

// TestLeaseTTLCapped: a lease never outlives LeaseMax, so a crashed holder
// cannot keep a path uncommitted for long.
func TestLeaseTTLCapped(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	hookMachine(t, root, remote, "a", "host-a")

	start := time.Now()
	yadmOK(t, "lease", "take", ".config/tool", "--holder", "agent-x", "--ttl", "876000h")
	env := yadmOK(t, "lease", "list")
	ls := decode[struct {
		Leases []struct {
			Holder  string
			Expires time.Time
		}
	}](t, env.Data).Leases
	if len(ls) != 1 || ls[0].Expires.After(start.Add(LeaseMax+time.Minute)) {
		t.Fatalf("leases: %+v", ls)
	}
}

// TestLiveLeaseShown: a forgotten lease holds its paths back for up to a
// day, so yadm check lists each live lease as a passing item with its
// holder, paths and expiry, and session-start names it. A released lease
// is no longer shown.
func TestLiveLeaseShown(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	yadmOK(t, "lease", "take", ".config/tool/config", "--holder", "agent-x", "--ttl", "2h")

	leaseItems := func() []checkItem {
		env, _, _ := yadm(t, "check")
		var out []checkItem
		for _, c := range decode[map[string][]checkItem](t, env.Data)["checks"] {
			if c.Name == "lease" {
				out = append(out, c)
			}
		}
		return out
	}
	items := leaseItems()
	if len(items) != 1 || !items[0].OK || items[0].Warn || !strings.Contains(items[0].Detail, "agent-x holds .config/tool/config until ") ||
		!strings.Contains(items[0].Detail, "yadm lease release agent-x") {
		t.Fatalf("check lease items: %+v", items)
	}
	_, stdout, _ := hookRun(t, payload(payloadSessionStart, "session-t", a.Home, ""), HookSessionStart, "--format", "text")
	if !strings.Contains(stdout, "1 live lease(s)") || !strings.Contains(stdout, "agent-x holds .config/tool/config until ") {
		t.Fatalf("session start with a live lease:\n%s", stdout)
	}

	yadmOK(t, "lease", "release", "agent-x")
	if items := leaseItems(); len(items) != 0 {
		t.Fatalf("check lease items after release: %+v", items)
	}
	_, stdout, _ = hookRun(t, payload(payloadSessionStart, "session-t", a.Home, ""), HookSessionStart, "--format", "text")
	if strings.Contains(stdout, "lease") {
		t.Fatalf("session start after release:\n%s", stdout)
	}
}
