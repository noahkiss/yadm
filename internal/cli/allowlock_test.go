package cli

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/sync"
)

// holdLock takes the sync lock in stateDir, as a running timer sync does,
// and releases it after d.
func holdLock(t *testing.T, stateDir string, d time.Duration) <-chan struct{} {
	t.Helper()
	release, err := sync.FileLock(stateDir).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		time.Sleep(d)
		release()
		close(done)
	}()
	return done
}

// TestAllowsWaitForTheLock: root allow and task allow are writers. While a
// sync holds the lock they wait for it, within the bound, instead of
// failing at once; past the bound they exit 4.
func TestAllowsWaitForTheLock(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = hookManifest + `
[tasks.hello]
on = [".config/tool/config"]
command = ["true"]
`
	remote := seedRemote(t, root, tree)
	m := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")

	for _, args := range [][]string{{"root", "allow", ".config/tool"}, {"task", "allow", "hello"}} {
		done := holdLock(t, m.State, 300*time.Millisecond)
		start := time.Now()
		env, code, _ := yadm(t, args...)
		if code != ExitOK && code != ExitAttention {
			t.Fatalf("yadm %v while a sync holds the lock: exit %d %+v", args, code, env.Error)
		}
		if waited := time.Since(start); waited < 250*time.Millisecond {
			t.Fatalf("yadm %v returned after %v: it did not wait for the lock", args, waited)
		}
		<-done
	}

	// Past the bound, the command exits 4 (locked).
	hooks.lockWait = 100 * time.Millisecond
	for _, args := range [][]string{{"root", "allow", ".config/tool"}, {"task", "allow", "hello"}} {
		done := holdLock(t, m.State, time.Second)
		env, code, _ := yadm(t, args...)
		<-done
		if code != ExitLocked {
			t.Fatalf("yadm %v past the lock bound: exit %d %+v", args, code, env.Error)
		}
	}
}

// TestAllowAppliesMainAfterTheWait: a sync that holds the lock may move
// main. root allow then applies the main it finds once it holds the lock,
// never the one it loaded before waiting.
func TestAllowAppliesMainAfterTheWait(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	m := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")

	release, err := sync.FileLock(m.State).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(400 * time.Millisecond)
		// What a sync does under the lock: main and the clone move.
		writeFile(t, filepath.Join(m.Source, "files/.config/tool/config"), "color = red\n")
		git(t, m.Source, "commit", "-q", "-am", "update .config/tool/config")
		release()
	}()
	yadmOK(t, "root", "allow", ".config/tool")
	<-done
	if got := readFile(t, filepath.Join(m.Home, ".config/tool/config")); got != "color = red\n" {
		t.Fatalf("root allow applied the main it loaded before the wait: %q", got)
	}
}
