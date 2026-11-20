package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func sec2Payload(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// H1: newlines in session_id, tool_name and intent must not add trailers.
func TestSec2HookTrailerInjection(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	file := filepath.Join(a.Home, ".config/tool/config")
	writeFile(t, file, "color = red\n")
	in := sec2Payload(t, map[string]any{
		"session_id": "s1\nMachine: m-evil\n\nYadm-Scope: personal",
		"cwd":        a.Home,
		"tool_name":  "Edit\r\nYadm-Auto: manual\nMachine: m-evil",
		"tool_input": map[string]any{"file_path": file},
		"intent":     "tidy\n\nMachine: m-evil\nYadm-Auto: manual\nYadm-Scope: personal",
	})
	code, _, stderr := hookRun(t, in, HookPostEdit)
	if code != HookAllow {
		t.Fatalf("exit %d %s", code, stderr)
	}
	raw := git(t, a.Source, "log", "-1", "--format=%B", "main")
	t.Logf("message:\n%s", raw)
	tr := git(t, a.Source, "log", "-1", "--format=%(trailers:only,unfold)", "main")
	t.Logf("trailers git sees:\n%s", tr)
	n := map[string]int{}
	for _, l := range strings.Split(tr, "\n") {
		k, v, _ := strings.Cut(l, ": ")
		n[k]++
		if k == "Machine" && strings.Contains(v, "evil") && !strings.HasPrefix(v, "m-") {
			t.Errorf("forged machine trailer %q", l)
		}
		if (k == "Machine" && v == "m-evil") || (k == "Yadm-Auto" && v == "manual") || (k == "Yadm-Scope" && v == "personal") {
			t.Errorf("injected trailer %q", l)
		}
	}
	if n["Machine"] != 1 || n["Yadm-Auto"] != 1 || n["Yadm-Scope"] != 1 {
		t.Errorf("trailer counts %v", n)
	}
}

// H2: paths that leave $HOME or name yadm's own directories are ignored.
func TestSec2HookPathsOutsideHome(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	before := git(t, a.Source, "rev-parse", "main")
	outside := filepath.Join(root, "outside.txt")
	writeFile(t, outside, "x\n")
	for _, c := range []struct{ cwd, file string }{
		{a.Home, "../../outside.txt"},
		{a.Home, outside},
		{a.Home, a.Home + "/.config/tool/../../../../outside.txt"},
		{a.Home, filepath.Join(a.Source, "manifest.toml")},
		{a.Home, filepath.Join(a.State, "state.json")},
		{"/", "etc/passwd"},
		{a.Home, a.Home + "/.config/tool/config\x00/../x"},
	} {
		in := sec2Payload(t, map[string]any{"session_id": "s", "cwd": c.cwd, "tool_name": "Write", "tool_input": map[string]any{"file_path": c.file}})
		code, stdout, stderr := hookRun(t, in, HookPostEdit)
		if code != HookAllow || stdout != "" {
			t.Errorf("%q: exit %d stdout %q stderr %q", c.file, code, stdout, stderr)
		}
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Error("a path outside $HOME was committed")
	}
	sess, _ := filepath.Glob(filepath.Join(a.State, "hooks", "sessions", "*.jsonl"))
	for _, s := range sess {
		b, _ := os.ReadFile(s)
		t.Logf("session record: %s", b)
		if strings.Contains(string(b), "outside") || strings.Contains(string(b), "passwd") || strings.Contains(string(b), "..") {
			t.Errorf("recorded a path outside $HOME: %s", b)
		}
	}
}

// H3: a managed target whose parent directory is a symlink to a directory
// outside $HOME. Capture reads through the link.
func TestSec2HookDirSymlinkOutsideHome(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	outside := filepath.Join(root, "private")
	writeFile(t, filepath.Join(outside, "config"), "SEC2-OUTSIDE-SECRET\n")
	dir := filepath.Join(a.Home, ".config/tool")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	in := sec2Payload(t, map[string]any{"session_id": "s", "cwd": a.Home, "tool_name": "Write", "tool_input": map[string]any{"file_path": filepath.Join(dir, "config")}})
	code, stdout, stderr := hookRun(t, in, HookPostEdit)
	t.Logf("exit %d stdout %q stderr %q", code, stdout, stderr)
	if got := git(t, remote, "show", "main:files/.config/tool/config"); strings.Contains(got, "SEC2-OUTSIDE-SECRET") {
		t.Errorf("a file outside $HOME was committed and pushed through a directory symlink: %q", got)
	}
}

// H4: a named-conditions include that is also a managed target. The
// manifest never auto-commits; does this file, which decides the same
// thing, auto-commit through an unattended hook?
func TestSec2HookAutoCommitsConditionsInclude(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = `schema = 1

[conditions]
include = ["files/.config/tool/conds.toml"]

[[file]]
target = ".config/tool/config"

[[file]]
target = ".config/tool/conds.toml"

[[file]]
target = ".config/tool/work-only"
when = "cond:tool.work"
`
	tree["files/.config/tool/conds.toml"] = "[conditions]\ntool.work = \"type:work\"\n"
	remote := seedRemote(t, root, tree)
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")
	file := filepath.Join(a.Home, ".config/tool/conds.toml")
	writeFile(t, file, "[conditions]\ntool.work = \"!type:work\"\n")
	in := sec2Payload(t, map[string]any{"session_id": "s", "cwd": a.Home, "tool_name": "Write", "tool_input": map[string]any{"file_path": file}})
	code, stdout, stderr := hookRun(t, in, HookPostEdit)
	t.Logf("exit %d stdout %q stderr %q", code, stdout, stderr)
	if got := git(t, remote, "show", "main:files/.config/tool/conds.toml"); strings.Contains(got, "!type:work") {
		t.Errorf("an unattended hook committed and pushed a change to named conditions: %q", got)
	}
}

// H5: the packet's `command` fields are built from the file name without
// quoting. An agent that runs the suggested command in a shell runs what
// the name says.
func TestSec2HookPacketCommandQuoting(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	file := filepath.Join(a.Home, ".config/tool/new;touch SEC2-INJECTED;.conf")
	writeFile(t, file, "x\n")
	in := sec2Payload(t, map[string]any{"session_id": "s", "cwd": a.Home, "tool_name": "Write", "tool_input": map[string]any{"file_path": file}})
	code, stdout, stderr := hookRun(t, in, HookPostEdit)
	if code != HookBlock {
		t.Fatalf("exit %d %s", code, stderr)
	}
	v := verdictOf(t, stdout)
	var cmds []string
	for _, p := range v.Packets {
		for _, o := range p.Options {
			cmds = append(cmds, o.Command)
		}
	}
	if len(cmds) == 0 {
		t.Fatal("no suggested commands")
	}
	// Run each suggestion in a shell where yadm only prints its arguments:
	// the file name must arrive as one argument and run nothing.
	sh := t.TempDir()
	named := false
	for _, c := range cmds {
		if strings.Contains(c, "<") {
			continue // a placeholder the agent fills in
		}
		cmd := exec.Command("sh", "-c", "yadm() { for a in \"$@\"; do printf '%s\\n' \"$a\"; done; }; "+c)
		cmd.Dir = sh
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("%s: %v", c, err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if l == ".config/tool/new;touch SEC2-INJECTED;.conf" {
				named = true
			}
		}
	}
	if _, err := os.Stat(filepath.Join(sh, "SEC2-INJECTED")); err == nil {
		t.Errorf("a suggested command ran the file name: %q", cmds)
	}
	if !named {
		t.Errorf("no suggested command passed the file name as one argument: %q", cmds)
	}
}

// A file name with a newline is never committed by a hook, and the hook
// stays silent.
func TestSec2HookControlCharacterName(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	before := git(t, a.Source, "rev-parse", "main")
	file := filepath.Join(a.Home, ".config/tool/new\nline.conf")
	writeFile(t, file, "x\n")
	in := sec2Payload(t, map[string]any{"session_id": "s", "cwd": a.Home, "tool_name": "Write", "tool_input": map[string]any{"file_path": file}})
	code, stdout, stderr := hookRun(t, in, HookPostEdit)
	if code != HookAllow || stdout != "" {
		t.Errorf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if git(t, a.Source, "rev-parse", "main") != before {
		t.Error("a file name with a newline was committed")
	}
}
