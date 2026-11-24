package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const trackManifest = hookManifest + `
[[file]]
target = ".config/globbed/*"

[[file]]
target = ".alias"
source = "files/.zshenv"
`

// TestTrack: track adds an entry and the file's source in one commit,
// pushes it, and another machine receives it on its next sync. It refuses
// a path an entry or an owned root covers, a new entry under a glob that
// covers the path (naming which), a path
// outside $HOME, a directory, and an unknown condition, and commits
// nothing then.
func TestTrack(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = trackManifest
	tree["files/.config/globbed/one"] = "g\n"
	tree["files/.zshenv"] = "alias\n"
	remote := seedRemote(t, root, tree)
	b := useMachine(t, root, "b")
	yadmOK(t, "init", remote, "--machine", "host-b", "--no-schedule")
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")
	yadmOK(t, "root", "allow", ".config/tool")

	writeFile(t, filepath.Join(a.Home, ".zshrc"), "export A=1\n")
	env, code, _ := yadm(t, "track", ".zshrc", "--when", "type:work")
	if code != ExitOK {
		t.Fatalf("track: exit %d %+v", code, env.Error)
	}
	d := decode[struct {
		Target, Source, Scope, Commit string
		Pushed                        bool
	}](t, env.Data)
	if d.Target != ".zshrc" || d.Source != "files/.zshrc" || d.Scope != "shared" || d.Commit == "" || !d.Pushed {
		t.Fatalf("track data: %+v", d)
	}
	if git(t, a.Source, "rev-parse", "main") != git(t, remote, "rev-parse", "main") {
		t.Fatal("track did not push")
	}
	if files := git(t, a.Source, "show", "--name-only", "--format=", d.Commit); files != "files/.zshrc\nmanifest.toml" {
		t.Fatalf("track commit files: %q", files)
	}
	if man := readFile(t, filepath.Join(a.Source, "manifest.toml")); !strings.Contains(man, "[[file]]\ntarget = '.zshrc'\nwhen = 'type:work'\n") {
		t.Fatalf("manifest:\n%s", man)
	}
	if env = yadmOK(t, "status"); len(decode[struct{ Holds []any }](t, env.Data).Holds) != 0 {
		t.Fatalf("holds after track: %+v", env.Data)
	}

	head := git(t, a.Source, "rev-parse", "main")
	if err := os.MkdirAll(filepath.Join(a.Home, ".config/dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(a.Home, ".config/tool/new"), "n\n")
	writeFile(t, filepath.Join(a.Home, ".config/globbed/two"), "g2\n")
	writeFile(t, filepath.Join(a.Home, ".other"), "o\n")
	writeFile(t, filepath.Join(a.Home, ".zshenv"), "mine\n")
	for _, c := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"track", ".zshrc"}, ExitUsage, "a manifest entry names it"},
		{[]string{"track", ".config/tool/new"}, ExitUsage, `owned root ".config/tool" covers it`},
		{[]string{"track", ".config/globbed/two", "--when", "type:work"}, ExitUsage, `glob entry ".config/globbed/*" covers it`},
		{[]string{"track", "/elsewhere/file"}, ExitUsage, "not under $HOME"},
		{[]string{"track", ".config/dir"}, ExitUsage, "directory"},
		{[]string{"track", ".zshenv"}, ExitUsage, `entry ".alias" already uses files/.zshenv`},
		{[]string{"track", ".missing"}, ExitUsage, "not a regular file"},
		{[]string{"track", ".other", "--when", "type:nope"}, ExitError, "nope"},
		{[]string{"track", ".other", "--enclave", "work"}, ExitError, "not an enclave type"},
		{[]string{"track", ".other", "--enclave", "nope"}, ExitError, "not an enclave type"},
	} {
		env, code, _ := yadm(t, c.args...)
		if code != c.code || env.Error == nil || !strings.Contains(env.Error.Message, c.msg) {
			t.Errorf("yadm %v: exit %d %+v, want exit %d with %q", c.args, code, env.Error, c.code, c.msg)
		}
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatal("a refused track committed")
	}

	// --no-push commits here only; the next sync pushes.
	writeFile(t, filepath.Join(a.Home, ".bashrc"), "export B=1\n")
	env = yadmOK(t, "track", ".bashrc", "--no-push")
	if decode[struct{ Pushed bool }](t, env.Data).Pushed || git(t, remote, "rev-parse", "main") != head {
		t.Fatal("track --no-push pushed")
	}
	yadmOK(t, "sync")
	if git(t, remote, "rev-parse", "main") != git(t, a.Source, "rev-parse", "main") {
		t.Fatal("the next sync did not push the tracked file")
	}

	useMachine(t, root, "b")
	yadmOK(t, "sync")
	if got := readFile(t, filepath.Join(b.Home, ".zshrc")); got != "export A=1\n" {
		t.Fatalf("host-b .zshrc: %q", got)
	}
	if got := readFile(t, filepath.Join(b.Home, ".bashrc")); got != "export B=1\n" {
		t.Fatalf("host-b .bashrc: %q", got)
	}
}

// TestTrackHeldByTheGate: when the commit gate holds the tracked file, the
// manifest entry does not land without it: nothing is committed.
func TestTrackHeldByTheGate(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = hookManifest + `
[checks.scan]
paths = [".gated"]
command = ["false"]
`
	remote := seedRemote(t, root, tree)
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")
	head := git(t, a.Source, "rev-parse", "main")

	writeFile(t, filepath.Join(a.Home, ".gated"), "g\n")
	env, code, _ := yadm(t, "track", ".gated")
	if code != ExitAttention {
		t.Fatalf("track held by the gate: exit %d %+v", code, env.Error)
	}
	hs := decode[struct {
		Holds []struct{ Target, Reason string }
	}](t, env.Data).Holds
	if len(hs) != 1 || hs[0].Target != ".gated" || hs[0].Reason != "task_untrusted" {
		t.Fatalf("holds: %+v", hs)
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatalf("a gate-held track committed:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}
	if got := git(t, remote, "rev-parse", "main"); got != head {
		t.Fatal("a gate-held track pushed")
	}
}

// TestGateHoldOnRemovedFileSettles: a track the gate refused leaves a
// check_failed hold on a file nothing manages. While the file exists, sync
// keeps the hold. Once the file is removed, the next sync drops it: there is
// nothing left to commit, and no command could settle it.
func TestGateHoldOnRemovedFileSettles(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = hookManifest + `
[checks.scan]
paths = [".gated"]
command = ["false"]
`
	remote := seedRemote(t, root, tree)
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")
	yadmOK(t, "task", "allow", "scan")

	p := filepath.Join(a.Home, ".gated")
	writeFile(t, p, "g\n")
	env, code, _ := yadm(t, "track", ".gated", "--when", "machine:host-a", "--no-push")
	if code != ExitAttention {
		t.Fatalf("track held by the gate: exit %d %+v", code, env.Error)
	}
	held := func() []string {
		var out []string
		hs := decode[struct {
			Holds []struct{ Target, Reason string }
		}](t, yadmOK(t, "hold", "list").Data)
		for _, h := range hs.Holds {
			if h.Target == ".gated" {
				out = append(out, h.Reason)
			}
		}
		return out
	}
	if got := held(); len(got) != 1 || got[0] != "check_failed" {
		t.Fatalf("holds after the refused track: %v", got)
	}
	yadmOK(t, "sync", "--no-push")
	if got := held(); len(got) != 1 {
		t.Fatalf("a sync dropped the gate hold on a file that still exists: %v", got)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	yadmOK(t, "sync", "--no-push")
	if got := held(); len(got) != 0 {
		t.Fatalf("holds after the file was removed: %v", got)
	}
}
