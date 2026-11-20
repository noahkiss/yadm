package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckGitDriversNeedAnAttribute: a global filter or merge driver that
// no attribute of the source clone assigns (git lfs install's filter.lfs.*)
// passes. It fails once a .gitattributes in the source, info/attributes or
// the global attributes file names it.
func TestCheckGitDriversNeedAnAttribute(t *testing.T) {
	hermetic(t)
	t.Setenv("GIT_ATTR_NOSYSTEM", "1")
	root := t.TempDir()
	remote := seedRemote(t, root, e2eTree())
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")

	global := filepath.Join(root, "gitconfig")
	writeFile(t, global, "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n[merge \"tool.x\"]\n\tdriver = true\n")
	t.Setenv("GIT_CONFIG_GLOBAL", global)

	drivers := func() checkItem {
		t.Helper()
		env, _, _ := yadm(t, "check")
		for _, c := range decode[map[string][]checkItem](t, env.Data)["checks"] {
			if c.Name == "git_drivers" {
				return c
			}
		}
		t.Fatal("no git_drivers check")
		return checkItem{}
	}
	if c := drivers(); !c.OK {
		t.Fatalf("unreferenced global drivers: %+v", c)
	}

	sources := []string{
		filepath.Join(a.Source, ".gitattributes"),
		filepath.Join(a.Source, "files", "sub", ".gitattributes"),
		filepath.Join(a.Source, ".git", "info", "attributes"),
		filepath.Join(a.Home, ".config", "git", "attributes"),
	}
	for _, f := range sources {
		writeFile(t, f, "# comment filter=nothing\n*.bin filter=lfs diff=lfs merge=tool.x -text\n")
		c := drivers()
		if c.OK || !strings.Contains(c.Detail, "filter.lfs.clean") || !strings.Contains(c.Detail, "merge.tool.x.driver") {
			t.Fatalf("%s names the drivers: %+v", f, c)
		}
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
		if c := drivers(); !c.OK {
			t.Fatalf("after removing %s: %+v", f, c)
		}
	}
}
