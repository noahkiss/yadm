package cli

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestCommitDryRunPlans: `yadm commit --dry-run` lists the commits the
// real commit would make, a new file in an owned root included, and
// commits nothing; the real commit then carries the same paths.
func TestCommitDryRunPlans(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	writeFile(t, filepath.Join(a.Home, ".config/tool/config"), "color = red\n")
	writeFile(t, filepath.Join(a.Home, ".config/tool/newfile"), "n\n")
	head := git(t, a.Source, "rev-parse", "main")

	type plan struct {
		Commits []string
		Planned []struct {
			Scope, Subject string
			Paths          []string
		}
	}
	for _, args := range [][]string{
		{"commit", "--dry-run"},
		{"commit", "--dry-run", ".config/tool/newfile", ".config/tool/config"},
	} {
		p := decode[plan](t, yadmOK(t, args...).Data)
		if len(p.Commits) != 0 || len(p.Planned) != 1 || p.Planned[0].Scope != "shared" || p.Planned[0].Subject != "update 2 files in .config/tool" ||
			!slices.Equal(p.Planned[0].Paths, []string{".config/tool/config", ".config/tool/newfile"}) {
			t.Fatalf("yadm %v: %+v", args, p)
		}
	}
	p := decode[plan](t, yadmOK(t, "commit", "--dry-run", ".config/tool/newfile").Data)
	if len(p.Planned) != 1 || !slices.Equal(p.Planned[0].Paths, []string{".config/tool/newfile"}) || p.Planned[0].Subject != "add .config/tool/newfile" {
		t.Fatalf("named new file: %+v", p)
	}
	if git(t, a.Source, "rev-parse", "main") != head {
		t.Fatal("a dry run committed")
	}
	yadmOK(t, "commit", "--no-push")
	if files := git(t, a.Source, "show", "--name-only", "--format=", "main"); files != "files/.config/tool/config\nfiles/.config/tool/newfile" {
		t.Fatalf("the real commit: %q", files)
	}
}
