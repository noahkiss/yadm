package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

const keysManifest = `schema = 1

[[file]]
target = ".config/app/settings.json"
format = "json"
volatile = ["window"]
`

const keysSource = "{\n  \"theme\": \"dark\",\n  \"window\": 1\n}\n"

// takeTargetMachine seeds a source with a volatile entry, writes a live file
// yadm never wrote, sets the machine up with init and then setup (adopt or
// apply), and returns the one hold that leaves on the file.
func takeTargetMachine(t *testing.T, live, setup string, want model.HoldReason) (machineDirs, string, model.Hold) {
	t.Helper()
	root := t.TempDir()
	remote := seedRemote(t, root, map[string]string{
		"fleet.toml":                      e2eFleet,
		"manifest.toml":                   keysManifest,
		"files/.config/app/settings.json": keysSource,
	})
	a := useMachine(t, root, "a")
	writeFile(t, filepath.Join(a.Home, ".config/app/settings.json"), live)
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	args := []string{setup}
	if setup == "adopt" {
		args = append(args, "--no-schedule")
	}
	yadmOK(t, args...)
	hs := decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds
	if len(hs) != 1 || hs[0].Reason != want {
		t.Fatalf("after %s: want one %s hold, got %+v", setup, want, hs)
	}
	return a, remote, hs[0]
}

// assertOwned: no hold remains through a sync and an apply, and the live
// file is untouched.
func assertOwned(t *testing.T, a machineDirs, live string) {
	t.Helper()
	for _, args := range [][]string{{"sync"}, {"apply"}, {"hold", "list"}} {
		env := yadmOK(t, args...)
		if hs := decode[holdsOnly](t, env.Data).Holds; len(hs) != 0 {
			t.Fatalf("%v holds: %+v", args, hs)
		}
	}
	if got := readFile(t, filepath.Join(a.Home, ".config/app/settings.json")); got != live {
		t.Fatalf("live file changed: %q", got)
	}
}

// TestTakeTargetCapturesUnwrittenFile: adopt holds a file yadm never wrote
// that differs from the source only trivially (a trailing newline, a
// volatile key). Taking the target commits the live file as the new source
// through the entry's rules (the volatile key keeps the source's value) and
// records the target as managed: no needs_decision hold follows.
func TestTakeTargetCapturesUnwrittenFile(t *testing.T) {
	hermetic(t)
	live := "{\n  \"theme\": \"dark\",\n  \"window\": 7\n}"
	a, remote, h := takeTargetMachine(t, live, "adopt", model.HoldDrifted)
	before := git(t, a.Source, "rev-parse", "main")

	stdout, stderr, code := yadmRaw(t, "hold", "resolve", h.ID, "--take", "target")
	if code != ExitOK || !strings.Contains(stdout, "resolved .config/app/settings.json: committed ") {
		t.Fatalf("resolve: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if got := git(t, remote, "show", "main:files/.config/app/settings.json"); got != "{\n  \"theme\": \"dark\",\n  \"window\": 1\n}" {
		t.Fatalf("new source: %q", got)
	}
	if git(t, a.Source, "rev-parse", "main") == before {
		t.Fatal("main did not move")
	}
	assertOwned(t, a, live)
}

// TestTakeTargetOwnsWithoutCommit: apply holds a file yadm never wrote whose
// only difference is a volatile key. Taking the target has nothing to
// commit, and still records the target as managed.
func TestTakeTargetOwnsWithoutCommit(t *testing.T) {
	hermetic(t)
	live := "{\n  \"theme\": \"dark\",\n  \"window\": 7\n}\n"
	a, _, h := takeTargetMachine(t, live, "apply", model.HoldNeedsDecision)
	before := git(t, a.Source, "rev-parse", "main")

	env := yadmOK(t, "hold", "resolve", h.ID, "--take", "target")
	d := decode[struct {
		Commits []string     `json:"commits"`
		Holds   []model.Hold `json:"holds"`
	}](t, env.Data)
	if len(d.Commits) != 0 || len(d.Holds) != 0 {
		t.Fatalf("resolve: %+v", d)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("main moved with nothing to commit")
	}
	assertOwned(t, a, live)
}
