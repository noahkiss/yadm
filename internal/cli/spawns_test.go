package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitShim puts a `git` on PATH that logs one line per process and runs the
// real git. It returns a function that reports the number of spawns so far.
func gitShim(t *testing.T) func() int {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := fmt.Sprintf("#!/bin/sh\necho x >> '%s'\nexec '%s' \"$@\"\n", log, real)
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() int {
		b, err := os.ReadFile(log)
		if err != nil {
			return 0
		}
		return strings.Count(string(b), "\n")
	}
}

// postEditSpawns runs `yadm hook post-edit` on one edited file of a machine
// that manages n more files, and returns the git spawns and wall time.
func postEditSpawns(t *testing.T, n int) (int, time.Duration) {
	t.Helper()
	hermetic(t)
	count := gitShim(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = hookManifest + "\n[[file]]\ntarget = \".config/bulk/**\"\n"
	for i := 0; i < n; i++ {
		tree[fmt.Sprintf("files/.config/bulk/f%04d", i)] = fmt.Sprintf("file %d\n", i)
	}
	remote := seedRemote(t, root, tree)
	a := hookMachine(t, root, remote, "a", "host-a")
	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, fmt.Sprintf("color = green %d\n", n))
	before, start := count(), time.Now()
	code, stdout, stderr := hookRun(t, payload(payloadEdit, "session-a", a.Home, file), HookPostEdit)
	spawns, wall := count()-before, time.Since(start)
	if code != HookAllow || stdout != "" || stderr != "" {
		t.Fatalf("post-edit: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if local, pushed := git(t, a.Source, "rev-parse", "main"), git(t, remote, "rev-parse", "main"); local != pushed {
		t.Fatalf("the hook did not push")
	}
	return spawns, wall
}

// TestHookPostEditSpawnsFlat: the post-edit hook starts the same number of
// git processes whatever the number of managed files.
func TestHookPostEditSpawnsFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two machines with many files")
	}
	var small, large int
	var ws, wl time.Duration
	t.Run("small", func(t *testing.T) { small, ws = postEditSpawns(t, 20) })
	t.Run("large", func(t *testing.T) { large, wl = postEditSpawns(t, 400) })
	t.Logf("hook post-edit: n=20 %d spawns %s; n=400 %d spawns %s", small, ws.Round(time.Millisecond), large, wl.Round(time.Millisecond))
	if small == 0 || small != large {
		t.Errorf("hook post-edit: %d git spawns with 20 files, %d with 400", small, large)
	}
}
