package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
)

// TestGateHoldOnRemovedRootFileClearsAtOnce: the timer's sync holds a new
// file in an owned root with check_failed when the gate refuses it. Once
// the file is deleted, `hold list`, `status` and the session-start hook no
// longer show the hold, before any sync; the next timer sync drops it from
// the state.
func TestGateHoldOnRemovedRootFileClearsAtOnce(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = hookManifest + `
[checks.scan]
paths = [".config/tool/job.toml"]
command = ["false"]
`
	remote := seedRemote(t, root, tree)
	a := hookMachine(t, root, remote, "a", "host-a")
	yadmOK(t, "task", "allow", "scan")

	const job = ".config/tool/job.toml"
	p := filepath.Join(a.Home, job)
	writeFile(t, p, "every = 1h\n")
	timerSyncs(t)

	listed := func(args ...string) []string {
		t.Helper()
		var out []string
		for _, h := range decode[holdsOnly](t, yadmOK(t, args...).Data).Holds {
			if h.Target == job {
				out = append(out, string(h.Reason))
			}
		}
		return out
	}
	inState := func() int {
		t.Helper()
		st, err := apply.FileStateDB(a.State).Load()
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, h := range st.Holds {
			if h.Target == job {
				n++
			}
		}
		return n
	}
	if got := listed("hold", "list"); len(got) != 1 || got[0] != "check_failed" {
		t.Fatalf("holds after the gate refused the new file: %v", got)
	}
	if st, err := apply.FileStateDB(a.State).Load(); err != nil {
		t.Fatal(err)
	} else if _, ok := st.Targets[job]; ok {
		t.Fatal("test setup: the held new file is managed")
	}

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if got := listed("hold", "list"); len(got) != 0 {
		t.Fatalf("hold list after the file was removed, before a sync: %v", got)
	}
	if got := listed("status"); len(got) != 0 {
		t.Fatalf("status after the file was removed, before a sync: %v", got)
	}
	if inState() != 1 {
		t.Fatal("a read command changed the state")
	}
	_, stdout, _ := hookRun(t, payload(payloadSessionStart, "session-t", a.Home, ""), HookSessionStart, "--format", "text")
	if strings.Contains(stdout, job) {
		t.Fatalf("session start names the hold on a removed file:\n%s", stdout)
	}
	timerSyncs(t)
	if n := inState(); n != 0 {
		t.Fatalf("%d holds on the removed file left in the state after a timer sync", n)
	}
}

// TestDeferSurvivesBriefRemoval: an editor that saves by removing the file
// and writing it again leaves it gone for a moment. A read command in that
// moment hides the hold, but the hold is still in the state, so the defer
// that covers it must stay: once the file is back, the stop hook still
// treats the decision as deferred.
func TestDeferSurvivesBriefRemoval(t *testing.T) {
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

	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	// Read commands in the window. (A sync in the window, such as the
	// session-start hook's, settles the hold itself; that is not a read.)
	yadmOK(t, "review", "list")
	yadm(t, "check")
	writeFile(t, file, "fresh = 2\n")

	if ds := deferredOf(t); len(ds) != 1 {
		t.Fatalf("deferred after the file came back: %+v", ds)
	}
	if code, stdout, stderr := hookRun(t, payload(payloadStop, "session-s", a.Home, ""), HookStop); code != HookAllow || stdout != "" {
		t.Fatalf("stop after the file came back: exit %d\n%s\n%s", code, stdout, stderr)
	}
}
