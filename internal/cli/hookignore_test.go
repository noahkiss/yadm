package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestHookNewFileIgnoreAndTrack: a new file's packet offers share, track
// for the neighbours' types, ignore and defer. Ignoring it silences the
// hooks for good; naming it in a commit tracks it again. The track option
// adds a manifest entry for the suggested types.
func TestHookNewFileIgnoreAndTrack(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	file := filepath.Join(a.Home, ".config/tool/local.conf")
	writeFile(t, file, "local = 1\n")
	code, stdout, stderr := hookRun(t, payload(payloadWrite, "session-i", a.Home, file), HookPostEdit)
	if code != HookBlock {
		t.Fatalf("post-edit: exit %d\n%s\n%s", code, stdout, stderr)
	}
	p := verdictOf(t, stdout).Packets[0]
	cmds := map[string]string{}
	for _, o := range p.Options {
		cmds[o.Label] = o.Command
	}
	if cmds["ignore it"] != "yadm hold ignore "+p.ID || cmds["track it for its neighbours' types"] != "yadm retag .config/tool/local.conf work" {
		t.Fatalf("options: %+v", p.Options)
	}

	yadmOK(t, strings.Fields(cmds["ignore it"])[1:]...)
	writeFile(t, file, "local = 2\n")
	if code, stdout, stderr := hookRun(t, payload(payloadWrite, "session-i", a.Home, file), HookPostEdit); code != HookAllow || stdout != "" {
		t.Fatalf("post-edit on an ignored file: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if code, _, stderr := hookRun(t, payload(payloadStop, "session-i", a.Home, ""), HookStop); code != HookAllow {
		t.Fatalf("stop with only an ignored file: exit %d\n%s", code, stderr)
	}
	if out := git(t, a.Source, "ls-tree", "-r", "--name-only", "main"); strings.Contains(out, "local.conf") {
		t.Fatal("an ignored file was committed by a hook")
	}

	// A second new file: track it for the neighbours' types.
	other := filepath.Join(a.Home, ".config/tool/shared.conf")
	writeFile(t, other, "shared = 1\n")
	_, stdout, _ = hookRun(t, payload(payloadWrite, "session-j", a.Home, other), HookPostEdit)
	q := verdictOf(t, stdout).Packets[0]
	var track string
	for _, o := range q.Options {
		if strings.HasPrefix(o.Command, "yadm retag ") {
			track = o.Command
		}
	}
	if track == "" {
		t.Fatalf("no track option: %+v", q.Options)
	}
	yadmOK(t, strings.Fields(track)[1:]...)
	out := git(t, a.Source, "show", "main:manifest.toml")
	if !strings.Contains(out, "shared.conf") || !strings.Contains(out, "type:work") {
		t.Fatalf("manifest after track:\n%s", out)
	}
	if out := git(t, a.Source, "ls-tree", "-r", "--name-only", "main"); !strings.Contains(out, "files/.config/tool/shared.conf") {
		t.Fatalf("tracked file not committed:\n%s", out)
	}

	// Naming the ignored file in a commit tracks it.
	yadmOK(t, "commit", ".config/tool/local.conf")
	if out := git(t, a.Source, "ls-tree", "-r", "--name-only", "main"); !strings.Contains(out, "files/.config/tool/local.conf") {
		t.Fatalf("named commit did not track the ignored file:\n%s", out)
	}
}
