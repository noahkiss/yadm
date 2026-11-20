package cli

import (
	"strings"
	"testing"
)

// `yadm git` refuses commands that move the source clone's HEAD: sync owns
// main and the recorded worktree head.
func TestGitPassthroughRefusesHeadMoving(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	before := git(t, a.Source, "rev-parse", "HEAD")
	for _, args := range [][]string{
		{"git", "checkout", "-q", "--detach", "HEAD"},
		{"git", "reset", "--hard", "HEAD"},
		{"git", "-c", "x.y=z", "pull", "-q"},
		{"git", "switch", "main"},
		{"git", "merge", "origin/main"},
		{"git", "rebase", "origin/main"},
	} {
		_, stderr, code := yadmRaw(t, args...)
		if code != ExitRefused || !strings.Contains(stderr, "yadm sync") {
			t.Errorf("%v: exit %d %q", args, code, stderr)
		}
	}
	if got := git(t, a.Source, "rev-parse", "HEAD"); got != before {
		t.Error("HEAD moved")
	}
	if _, stderr, code := yadmRaw(t, "git", "status", "--porcelain"); code != 0 {
		t.Errorf("status refused: %d %s", code, stderr)
	}
	for in, want := range map[string]string{"": "", "status": "status", "-C x pull": "pull", "--no-pager log": "log"} {
		if got := gitVerb(strings.Fields(in)); got != want {
			t.Errorf("gitVerb(%q) = %q, want %q", in, got, want)
		}
	}
}
