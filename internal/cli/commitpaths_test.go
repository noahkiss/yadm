package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommitRefusesUnmanagedPath: a named path that no manifest entry or
// owned root covers fails the whole commit, dry run included, and names
// the path. Managed paths, paths in an owned root, a directory above a
// managed target and a deleted managed file still commit.
func TestCommitRefusesUnmanagedPath(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	before := git(t, a.Source, "rev-parse", "main")

	writeFile(t, filepath.Join(a.Home, ".config/tool/config"), "color = red\n")
	writeFile(t, filepath.Join(a.Home, ".other/file"), "x\n")
	for _, args := range [][]string{
		{"commit", ".config/tool/config", ".other/file"},
		{"commit", "--dry-run", ".other/file", ".config/tool/config"},
	} {
		env, code, _ := yadm(t, args...)
		if code != ExitRefused || !strings.Contains(env.Error.Message, ".other/file") || strings.Contains(env.Error.Message, ".config/tool/config") {
			t.Fatalf("%v: exit %d %+v", args, code, env.Error)
		}
		if len(env.Next) != 1 || !strings.HasPrefix(env.Next[0], "yadm retag .other/file ") {
			t.Fatalf("%v: next %v", args, env.Next)
		}
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != before {
		t.Fatal("a refused commit moved main")
	}

	// Covered paths commit: a managed file by its directory, and a new file
	// in the owned root.
	writeFile(t, filepath.Join(a.Home, ".config/tool/new.conf"), "n = 1\n")
	yadmOK(t, "commit", ".config", ".config/tool/new.conf")
	tree := git(t, a.Source, "ls-tree", "-r", "--name-only", "main")
	if !strings.Contains(tree, "files/.config/tool/new.conf") || git(t, a.Source, "show", "main:files/.config/tool/config") != "color = red" {
		t.Fatalf("covered paths did not commit:\n%s", tree)
	}

	// A deleted managed file is still covered: the check passes it.
	if err := os.Remove(filepath.Join(a.Home, ".config/tool/config")); err != nil {
		t.Fatal(err)
	}
	if env, code, _ := yadm(t, "commit", "--dry-run", ".config/tool/config"); code == ExitRefused {
		t.Fatalf("a deleted managed file was refused: %+v", env.Error)
	}
}
