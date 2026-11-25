package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/sync"
)

// TestLockWaitDefaults: an interactive command waits minutes for the sync
// lock, since a timer sync holds it while tasks run; the timer keeps its
// short wait, so ticks never stack up behind a long hold.
func TestLockWaitDefaults(t *testing.T) {
	if hooks.lockWait != sync.CommandLockTimeout || sync.CommandLockTimeout < 2*time.Minute {
		t.Fatalf("command lock wait %v, want sync.CommandLockTimeout (%v) of at least 2m", hooks.lockWait, sync.CommandLockTimeout)
	}
	m := &machineEnv{}
	if got := m.commandWait(); got != sync.CommandLockTimeout {
		t.Fatalf("commandWait %v", got)
	}
	if got := m.timerWait(); got != sync.LockTimeout {
		t.Fatalf("timerWait %v, want %v", got, sync.LockTimeout)
	}
	m.wait = &lockWait{d: 0, set: true}
	if m.commandWait() != 0 || m.timerWait() != 0 {
		t.Fatal("--lock-wait 0 does not reach the waits")
	}
}

// TestRetagWaitsForTheLock: while another process holds the sync lock, a
// retag waits for it within --lock-wait or $YADM_LOCK_WAIT, says once on
// stderr whom it waits for, and then commits. --lock-wait 0 does not wait.
func TestRetagWaitsForTheLock(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, variantTree())
	a := kitMachine(t, root, remote, "a", "host-a")
	// A default too short for the hold: only the override can carry the
	// command past it.
	hooks.lockWait = 100 * time.Millisecond

	writeFile(t, filepath.Join(a.Home, ".config/one.conf"), "one\n")
	done := holdLock(t, a.State, 600*time.Millisecond)
	start := time.Now()
	var out, errb bytes.Buffer
	code := Main([]string{"retag", ".config/one.conf", "work", "--lock-wait", "10s"}, &out, &errb, "test")
	<-done
	if code != ExitOK {
		t.Fatalf("retag --lock-wait 10s while a sync holds the lock: exit %d\n%s%s", code, out.String(), errb.String())
	}
	if waited := time.Since(start); waited < 500*time.Millisecond {
		t.Fatalf("retag returned after %v: it did not wait for the lock", waited)
	}
	if n := strings.Count(errb.String(), "yadm: waiting up to 10s for the yadm lock held by pid "); n != 1 {
		t.Fatalf("want one waiting line on stderr, got %d:\n%s", n, errb.String())
	}

	writeFile(t, filepath.Join(a.Home, ".config/two.conf"), "two\n")
	t.Setenv(LockWaitEnv, "10s")
	done = holdLock(t, a.State, 600*time.Millisecond)
	env, code, _ := yadm(t, "retag", ".config/two.conf", "work")
	<-done
	if code != ExitOK {
		t.Fatalf("retag with $%s=10s while a sync holds the lock: exit %d %+v", LockWaitEnv, code, env.Error)
	}

	head := git(t, a.Source, "rev-parse", "main")
	writeFile(t, filepath.Join(a.Home, ".config/three.conf"), "three\n")
	done = holdLock(t, a.State, 2*time.Second)
	start = time.Now()
	env, code, _ = yadm(t, "retag", ".config/three.conf", "work", "--lock-wait", "0")
	took := time.Since(start)
	<-done
	if code != ExitLocked || took > time.Second {
		t.Fatalf("retag --lock-wait 0: exit %d after %v %+v", code, took, env.Error)
	}
	if git(t, a.Source, "rev-parse", "main") != head {
		t.Fatal("a retag that did not get the lock committed")
	}

	t.Setenv(LockWaitEnv, "soon")
	if _, code, _ := yadm(t, "retag", ".config/three.conf", "work"); code != ExitUsage {
		t.Fatalf("a bad $%s: exit %d", LockWaitEnv, code)
	}
}

// TestReadOnlyCommandsSkipTheLock: why, managed, list, status, manifest and show
// read; they never wait for the sync lock a sync holds.
func TestReadOnlyCommandsSkipTheLock(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, variantTree())
	a := kitMachine(t, root, remote, "a", "host-a")
	done := holdLock(t, a.State, 4*time.Second)
	defer func() { <-done }()
	for _, args := range [][]string{
		{"why", ".config/tool/config"},
		{"managed", ".config/tool/config"},
		{"list"},
		{"status"},
		{"manifest"},
		{"show", ".config/tool/config"},
	} {
		start := time.Now()
		env, code, _ := yadm(t, args...)
		if code != ExitOK && code != ExitAttention {
			t.Fatalf("yadm %v while a sync holds the lock: exit %d %+v", args, code, env.Error)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("yadm %v took %v: it waited for the lock", args, d)
		}
	}
}

type retagAllData struct {
	Commit   string `json:"commit"`
	Retagged []struct {
		Target string `json:"target"`
		Source string `json:"source"`
		When   string `json:"when"`
	} `json:"retagged"`
}

// TestRetagSeveralPaths: retag takes several paths and commits them in one
// commit with one manifest edit. A refusal of any path commits nothing.
func TestRetagSeveralPaths(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, variantTree())
	a := kitMachine(t, root, remote, "a", "host-a")
	writeFile(t, filepath.Join(a.Home, ".config/extra.conf"), "extra\n")
	head := git(t, a.Source, "rev-parse", "main")

	for _, x := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"retag", ".config/tool/config", ".negated", "work"}, ExitUsage, "cannot replace the type terms"},
		{[]string{"retag", ".config/extra.conf", ".config/missing.conf", "work"}, ExitError, "not a regular file"},
		{[]string{"retag", ".config/tool/config", ".config/tool/config", "work"}, ExitUsage, "named twice"},
		{[]string{"retag", ".config/tool/config", ".config/extra.conf", "work", "--source", "files/.config/tool/config"}, ExitUsage, "--source"},
	} {
		env, code, _ := yadm(t, x.args...)
		if code != x.code || env.Error == nil || !strings.Contains(env.Error.Message, x.msg) {
			t.Errorf("yadm %v: exit %d %+v; want exit %d with %q", x.args, code, env.Error, x.code, x.msg)
		}
	}
	if git(t, a.Source, "rev-parse", "main") != head {
		t.Fatalf("a refused retag committed:\n%s", git(t, a.Source, "show", "main"))
	}

	env := yadmOK(t, "retag", ".config/tool/config", ".config/extra.conf", "work,home")
	d := decode[retagAllData](t, env.Data)
	if d.Commit == "" || len(d.Retagged) != 2 || d.Retagged[0].When != "type:work | type:home" || d.Retagged[1].Target != ".config/extra.conf" || d.Retagged[1].When != "type:work | type:home" {
		t.Fatalf("retag data: %+v", d)
	}
	if n := git(t, remote, "rev-list", "--count", head+"..main"); n != "1" {
		t.Fatalf("retag of two paths made %s commits", n)
	}
	if files := git(t, remote, "show", "--name-only", "--format=", "main"); files != "files/.config/extra.conf\nmanifest.toml" {
		t.Fatalf("retag commit files: %q", files)
	}
	man := git(t, remote, "show", "main:manifest.toml")
	if strings.Count(man, "type:work | type:home") != 2 || !strings.Contains(man, ".config/extra.conf") {
		t.Fatalf("manifest after retag:\n%s", man)
	}
	assertClean(t)
}

// TestRetagSeveralPathsIntoEnclaveSecrecy: a member retags two new files
// into its enclave in one call. The plaintext reaches neither a
// repository's object store nor a non-member's $HOME. A call that is
// refused, before the gate or by it for one path only, commits nothing
// and leaves no plaintext behind either.
func TestRetagSeveralPathsIntoEnclaveSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := secrecytest.NewCanary(t, "retag-several")

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	writeFile(t, filepath.Join(a.Home, ".config/private/one.txt"), "one "+canary.String()+"\n")
	writeFile(t, filepath.Join(a.Home, ".config/private/two.txt"), "two "+canary.String()+"\n")
	head := git(t, a.Source, "rev-parse", "main")

	env, code, out := yadm(t, "retag", ".config/private/one.txt", ".config/private/nope.txt", "personal", "--enclave", "personal")
	if code == ExitOK || env.Error == nil {
		t.Fatalf("retag with a missing path: exit %d", code)
	}
	if git(t, a.Source, "rev-parse", "main") != head {
		t.Fatal("a refused retag committed")
	}
	secrecytest.AssertRepoClean(t, a.Source, canary)

	// The fixture's check is not allowed here: the gate holds both paths.
	retag := func() (Envelope, int, []byte) {
		return yadm(t, "retag", ".config/private/one.txt", ".config/private/two.txt", "personal", "--enclave", "personal")
	}
	env, code, out1 := retag()
	if code != ExitAttention {
		t.Fatalf("retag past an untrusted check: exit %d %+v", code, env.Error)
	}
	// The check, allowed, refuses only two.txt: one.txt does not commit
	// without it.
	bin := t.TempDir()
	check := filepath.Join(bin, "secret-check")
	writeFile(t, check, "#!/bin/sh\nif grep -q two.txt; then exit 1; fi\nexit 0\n")
	if err := os.Chmod(check, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	yadmOK(t, "task", "allow", "no-private-keys")
	env, code, out2 := retag()
	if code != ExitAttention {
		t.Fatalf("retag with one path the gate refuses: exit %d %+v", code, env.Error)
	}
	if git(t, a.Source, "rev-parse", "main") != head {
		t.Fatalf("a retag the gate held in part committed:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}
	secrecytest.AssertRepoClean(t, a.Source, canary)

	writeFile(t, check, "#!/bin/sh\ncat >/dev/null\nexit 0\n")
	env, code, out3 := retag()
	if code != ExitOK {
		t.Fatalf("retag into the enclave: exit %d %+v %+v", code, env.Error, env.Data)
	}
	for _, o := range [][]byte{out, out1, out2, out3} {
		if bytes.Contains(o, canary.Bytes()) {
			t.Fatal("retag printed the plaintext")
		}
	}
	tree := git(t, remote, "ls-tree", "-r", "--name-only", "main")
	for _, p := range []string{"sealed/personal/.config/private/one.txt", "sealed/personal/.config/private/two.txt"} {
		if !strings.Contains(tree, p) {
			t.Fatalf("%s missing from the tree:\n%s", p, tree)
		}
	}
	if n := git(t, remote, "rev-list", "--count", head+"..main"); n != "1" {
		t.Fatalf("retag of two paths made %s commits", n)
	}

	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	secrecytest.AssertTreeClean(t, b.Home, canary)
	secrecytest.AssertRepoClean(t, b.Source, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)
}
