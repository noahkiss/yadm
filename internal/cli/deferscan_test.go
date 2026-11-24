package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// timerSyncs runs two scheduled syncs, each past the quiet period of the
// last, as the timer would over a few minutes.
func timerSyncs(t *testing.T) {
	t.Helper()
	for _, ahead := range []time.Duration{time.Hour, 2 * time.Hour} {
		at := time.Now().Add(ahead)
		hooks.now = func() time.Time { return at }
		yadmOK(t, "sync", "--auto", "--full")
	}
}

func deferredOf(t *testing.T) []Deferred {
	t.Helper()
	return decode[map[string][]Deferred](t, yadmOK(t, "review", "list").Data)["deferred"]
}

// TestDeferNewFileHoldsAgainstScan: a deferred new file in an owned root
// stays held and uncommitted through timer scans, and a commit that names
// it commits it and settles the defer.
func TestDeferNewFileHoldsAgainstScan(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/new.conf")
	writeFile(t, file, "fresh = 1\n")
	code, stdout, _ := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("post-edit on a new file: exit %d", code)
	}
	p := verdictOf(t, stdout).Packets[0]
	yadmOK(t, "defer", p.ID, "--reason", "decide with the owner")

	// The timer leaves it alone.
	before := git(t, a.Source, "rev-parse", "main")
	timerSyncs(t)
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatalf("the scan committed a deferred file:\n%s", git(t, a.Source, "log", "-1", "--format=%B", "main"))
	}
	if ds := deferredOf(t); len(ds) != 1 || ds[0].Target != ".config/tool/new.conf" || ds[0].Kind != "new_file" {
		t.Fatalf("deferred after the scan: %+v", ds)
	}

	writeFile(t, file, "fresh = 2\n")
	// A commit that names it commits it and settles the defer.
	yadmOK(t, "commit", ".config/tool/new.conf")
	if got := git(t, a.Source, "show", "main:files/.config/tool/new.conf"); got != "fresh = 2" {
		t.Fatalf("named commit: %q", got)
	}
	if b, err := os.ReadFile(filepath.Join(a.State, DeferredFile)); err != nil || strings.Contains(string(b), "new.conf") {
		t.Fatalf("deferred.json after the commit: %s %v", b, err)
	}
	// The file is managed now: the timer commits a later edit.
	writeFile(t, file, "fresh = 3\n")
	timerSyncs(t)
	if got := git(t, a.Source, "show", "main:files/.config/tool/new.conf"); got != "fresh = 3" {
		t.Fatalf("the timer did not commit a settled file: %q", got)
	}
}

// TestDeferNewFileSurvivesEdit: a defer covers the new file's path, so an
// edit through the hooks neither commits it nor raises the decision again.
// Removing the file settles it.
func TestDeferNewFileSurvivesEdit(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/new.conf")
	writeFile(t, file, "fresh = 1\n")
	code, stdout, _ := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("post-edit on a new file: exit %d", code)
	}
	p := verdictOf(t, stdout).Packets[0]
	yadmOK(t, "defer", p.ID, "--reason", "decide with the owner")
	before := git(t, a.Source, "rev-parse", "main")

	// A timer scan inside the quiet period commits nothing and keeps the
	// hold, so the review queue keeps the defer.
	yadmOK(t, "sync", "--auto", "--full")
	if ds := deferredOf(t); len(ds) != 1 {
		t.Fatalf("deferred after a quiet scan: %+v", ds)
	}
	hooks.now = func() time.Time { return time.Now().Add(time.Hour) }
	// An edit raises no new packet, and the stop hook stays clear.
	writeFile(t, file, "fresh = 2\n")
	if code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-s", a.Home, file), HookPostEdit); code != HookAllow || stdout != "" {
		t.Fatalf("post-edit after defer: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if code, stdout, stderr := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop); code != HookAllow || stdout != "" {
		t.Fatalf("stop after defer and edit: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("a hook committed a deferred file")
	}
	if ds := deferredOf(t); len(ds) != 1 {
		t.Fatalf("deferred after the edit: %+v", ds)
	}

	// Removing the file settles the decision.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	yadmOK(t, "sync", "--full", "--no-push")
	if ds := deferredOf(t); len(ds) != 0 {
		t.Fatalf("deferred after the file was removed: %+v", ds)
	}
	if hs := decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds; len(hs) != 0 {
		t.Fatalf("holds after the file was removed: %+v", hs)
	}

}

// TestDeferDriftedHoldsAgainstScan: a local edit meets an incoming change
// and apply holds it as drifted. Deferred, the timer's scan neither
// captures nor commits the edit.
func TestDeferDriftedHoldsAgainstScan(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	b := hookMachine(t, root, remote, "b", "host-b")
	writeFile(t, filepath.Join(b.Home, ".config/tool/config"), "color = red\n")
	yadmOK(t, "commit", ".config/tool/config")

	a := hookMachine(t, root, remote, "a", "host-a")
	_ = a
	useMachine(t, root, "b")
	writeFile(t, filepath.Join(b.Home, ".config/tool/config"), "color = green\n")
	yadmOK(t, "commit", ".config/tool/config")

	useMachine(t, root, "a")
	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = local\n")
	yadm(t, "sync")
	var h model.Hold
	for _, x := range decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds {
		if x.Target == ".config/tool/config" && x.Reason == model.HoldDrifted {
			h = x
		}
	}
	if h.ID == "" {
		t.Fatalf("no drifted hold: %+v", decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds)
	}
	yadmOK(t, "defer", h.ID, "--reason", "decide with the owner")

	before := git(t, a.Source, "rev-parse", "main")
	timerSyncs(t)
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatalf("the scan committed a deferred drift:\n%s", git(t, a.Source, "log", "-1", "--format=%B", "main"))
	}
	if ds := deferredOf(t); len(ds) != 1 || ds[0].ID != h.ID {
		t.Fatalf("deferred after the scan: %+v", ds)
	}
	if got := readFile(t, file); got != "color = local\n" {
		t.Fatalf("live file changed: %q", got)
	}
}

// TestDeferNewFileSettles: ignoring or retagging a deferred new file
// settles its defer.
func TestDeferNewFileSettles(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	for _, name := range []string{"ignored.conf", "retagged.conf"} {
		file := filepath.Join(a.Home, ".config/tool", name)
		writeFile(t, file, "fresh = 1\n")
		code, stdout, _ := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit)
		if code != HookBlock {
			t.Fatalf("post-edit on %s: exit %d", name, code)
		}
		yadmOK(t, "defer", verdictOf(t, stdout).Packets[0].ID, "--reason", "decide with the owner")
	}
	if ds := deferredOf(t); len(ds) != 2 {
		t.Fatalf("deferred: %+v", ds)
	}

	var ignore string
	for _, h := range decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds {
		if h.Target == ".config/tool/ignored.conf" {
			ignore = h.ID
		}
	}
	yadmOK(t, "hold", "ignore", ignore)
	yadmOK(t, "retag", ".config/tool/retagged.conf", "work")
	if got := git(t, a.Source, "show", "main:files/.config/tool/retagged.conf"); got != "fresh = 1" {
		t.Fatalf("retag did not commit: %q", got)
	}
	if ds := deferredOf(t); len(ds) != 0 {
		t.Fatalf("deferred after ignore and retag: %+v", ds)
	}
	before := git(t, a.Source, "rev-parse", "main")
	timerSyncs(t)
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("the scan committed an ignored file")
	}
}

// writeDeferred replaces deferred.json, as an earlier version or a record
// that outlived its hold leaves it.
func writeDeferred(t *testing.T, stateDir string, d map[string]Deferred) {
	t.Helper()
	if err := saveDeferred(stateDir, d); err != nil {
		t.Fatal(err)
	}
}

// TestStaleDeferDoesNotBlockScan: a record whose hold is gone does not stop
// the timer from committing a later change, even when a new hold appears on
// the same path and no session or review prunes the record. A path-keyed
// new-file record no longer covers the file once it is managed.
func TestStaleDeferDoesNotBlockScan(t *testing.T) {
	for name, rec := range map[string]map[string]Deferred{
		"hold id":  {"0123456789ab": {ID: "0123456789ab", Target: ".config/tool/config", Reason: model.HoldDrifted, Why: "old"}},
		"new file": {newFileKey(".config/tool/config"): {ID: "0123456789ab", Target: ".config/tool/config", Reason: model.HoldProtected, Kind: "new_file", Why: "old"}},
	} {
		t.Run(name, func(t *testing.T) {
			hermetic(t)
			root := t.TempDir()
			remote := seedRemote(t, root, hookTree())
			a := hookMachine(t, root, remote, "a", "host-a")
			writeDeferred(t, a.State, rec)

			// A deletion is protected: the timer holds it.
			file := filepath.Join(a.Home, ".config/tool/config")
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			timerSyncs(t)
			// The file comes back with a change: the timer commits it.
			writeFile(t, file, "color = teal\n")
			timerSyncs(t)
			if got := git(t, a.Source, "show", "main:files/.config/tool/config"); got != "color = teal" {
				t.Fatalf("a stale defer blocked the timer: %q", got)
			}
		})
	}
}

// TestDeferOldRecordHolds: a new file's defer that an earlier version keyed
// by hold id still holds against the timer, and deferring it again leaves
// one record.
func TestDeferOldRecordHolds(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/new.conf")
	writeFile(t, file, "fresh = 1\n")
	code, stdout, _ := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("post-edit on a new file: exit %d", code)
	}
	p := verdictOf(t, stdout).Packets[0]
	writeDeferred(t, a.State, map[string]Deferred{p.ID: {ID: p.ID, Target: ".config/tool/new.conf", Reason: model.HoldProtected, Why: "old"}})

	before := git(t, a.Source, "rev-parse", "main")
	timerSyncs(t)
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("the scan committed a file an old record deferred")
	}
	yadmOK(t, "defer", p.ID, "--reason", "again")
	if ds := deferredOf(t); len(ds) != 1 || ds[0].Kind != "new_file" {
		t.Fatalf("deferred after a second defer: %+v", ds)
	}
}

// TestUndecidedNewFileShared: a new file in an owned root that the hook held
// and nobody decided on is shared by the timer after its quiet period.
func TestUndecidedNewFileShared(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/new.conf")
	writeFile(t, file, "fresh = 1\n")
	if code, _, _ := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit); code != HookBlock {
		t.Fatalf("post-edit on a new file: exit %d", code)
	}
	timerSyncs(t)
	if got := git(t, a.Source, "show", "main:files/.config/tool/new.conf"); got != "fresh = 1" {
		t.Fatalf("the timer did not share an undecided new file: %q", got)
	}
}

// TestDeferExpires: a defer lasts --for, capped at DeferMax. Once it
// expires the stop hook and session start raise the decision again and
// check warns, while the timer still never commits the file.
func TestDeferExpires(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/new.conf")
	writeFile(t, file, "fresh = 1\n")
	code, stdout, _ := hookRun(t, payload(payloadWrite, "session-s", a.Home, file), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("post-edit on a new file: exit %d", code)
	}
	id := verdictOf(t, stdout).Packets[0].ID

	if _, code, _ := yadm(t, "defer", id, "--reason", "r", "--for", "0s"); code == ExitOK {
		t.Fatal("--for 0s was accepted")
	}
	type deferOut struct {
		Deferred
		Note string `json:"note"`
	}
	capped := decode[deferOut](t, yadmOK(t, "defer", id, "--reason", "r", "--for", "100h").Data)
	if got := capped.Until.Sub(capped.At); got != DeferMax || !strings.Contains(capped.Note, "capped") {
		t.Fatalf("--for 100h: lasts %s, note %q", got, capped.Note)
	}
	x := decode[deferOut](t, yadmOK(t, "defer", id, "--reason", "wait for the owner", "--for", "30m").Data)
	if got := x.Until.Sub(x.At); got != 30*time.Minute || !strings.Contains(x.Note, "comes back as an open decision") {
		t.Fatalf("--for 30m: lasts %s, note %q", got, x.Note)
	}

	// Inside its window the stop hook stays clear.
	if code, stdout, _ := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop); code != HookAllow {
		t.Fatalf("stop inside the defer: exit %d\n%s", code, stdout)
	}

	// Past it, the timer still commits nothing.
	before := git(t, a.Source, "rev-parse", "main")
	timerSyncs(t) // leaves the clock 2h ahead
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("the scan committed a file whose defer expired")
	}
	// The stop hook raises the decision again.
	code, stdout, _ = hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop)
	if code != HookBlock || len(verdictOf(t, stdout).Packets) != 1 {
		t.Fatalf("stop after the defer expired: exit %d\n%s", code, stdout)
	}
	// Session start names it.
	_, stdout, _ = hookRun(t, payload(payloadSessionStart, "session-t", a.Home, ""), HookSessionStart, "--format", "text")
	if !strings.Contains(stdout, "0 deferred decision(s) still waiting, 1 expired") {
		t.Fatalf("session start after the defer expired:\n%s", stdout)
	}
	// Check warns.
	env, _, _ := yadm(t, "check")
	warned := false
	for _, c := range decode[map[string][]checkItem](t, env.Data)["checks"] {
		if c.Name == "deferred" && c.Warn && strings.Contains(c.Detail, ".config/tool/new.conf") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("check did not warn on the expired defer: %+v", env.Data)
	}
}
