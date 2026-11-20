package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

// TestCommitAfterCloneCommitKeepsIndex: a commit made in the source clone
// with `yadm git commit` moves HEAD past the recorded worktree head. A
// later `yadm commit` must still leave the clone's index and worktree at
// the new HEAD, and the next sync must hold nothing.
func TestCommitAfterCloneCommitKeepsIndex(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")

	writeFile(t, filepath.Join(a.Source, "manifest.toml"), hookManifest+"\n")
	if _, stderr, code := yadmRaw(t, "git", "add", "manifest.toml"); code != 0 {
		t.Fatalf("git add: %d %s", code, stderr)
	}
	if _, stderr, code := yadmRaw(t, "git", "commit", "-q", "-m", "edit manifest"); code != 0 {
		t.Fatalf("git commit: %d %s", code, stderr)
	}

	writeFile(t, filepath.Join(a.Home, ".config/tool/config"), "color = red\n")
	env, code, _ := yadm(t, "commit", ".config/tool/config")
	if code != ExitOK {
		t.Fatalf("commit: exit %d %+v %+v", code, env.Error, env.Data)
	}
	if st := git(t, a.Source, "status", "--porcelain"); st != "" {
		t.Fatalf("source clone after commit:\n%s", st)
	}
	if got := git(t, a.Source, "show", "HEAD:files/.config/tool/config"); got != "color = red" {
		t.Fatalf("HEAD holds %q", got)
	}
	env = yadmOK(t, "sync")
	if hs := decode[holdsOnly](t, env.Data).Holds; len(hs) != 0 {
		t.Fatalf("sync after commit holds: %+v", hs)
	}
}

type holdsOnly struct {
	Holds []model.Hold `json:"holds"`
}

// TestSyncAfterCloneCommitKeepsIndex: after a sync takes a peer's commit,
// a raw `yadm git commit` moves HEAD past the recorded worktree head. The
// next sync replays it onto the peer's next commit; the clone's index must
// follow main, not keep the peer's earlier blobs behind HEAD.
func TestSyncAfterCloneCommitKeepsIndex(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	hookMachine(t, root, remote, "b", "host-b")
	a := hookMachine(t, root, remote, "a", "host-a")

	b := useMachine(t, root, "b")
	writeFile(t, filepath.Join(b.Home, ".config/tool/config"), "color = green\n")
	writeFile(t, filepath.Join(b.Home, ".config/tool/extra"), "extra\n")
	yadmOK(t, "commit", ".config/tool/config", ".config/tool/extra")

	useMachine(t, root, "a")
	yadmOK(t, "sync")
	if st := git(t, a.Source, "status", "--porcelain"); st != "" {
		t.Fatalf("source clone after taking the peer's commit:\n%s", st)
	}
	writeFile(t, filepath.Join(a.Source, "notes/new.txt"), "note\n")
	for _, args := range [][]string{{"git", "add", "notes/new.txt"}, {"git", "commit", "-q", "-m", "add a note"}} {
		if _, stderr, code := yadmRaw(t, args...); code != 0 {
			t.Fatalf("%v: %d %s", args, code, stderr)
		}
	}

	b = useMachine(t, root, "b")
	writeFile(t, filepath.Join(b.Home, ".config/tool/config"), "color = yellow\n")
	yadmOK(t, "commit", ".config/tool/config")

	useMachine(t, root, "a")
	env := yadmOK(t, "sync")
	if hs := decode[holdsOnly](t, env.Data).Holds; len(hs) != 0 {
		t.Fatalf("sync holds: %+v", hs)
	}
	if st := git(t, a.Source, "status", "--porcelain"); st != "" {
		t.Fatalf("source clone after sync:\n%s", st)
	}
	if got := readFile(t, filepath.Join(a.Home, ".config/tool/config")); got != "color = yellow\n" {
		t.Fatalf("target after sync: %q", got)
	}
}

// TestCommitRefusesDirtyClone: with a local edit in the source clone, a
// commit makes nothing and moves no ref, so no staged reverse diff appears.
// The hold's advice makes the clone clean, and the commit then lands.
func TestCommitRefusesDirtyClone(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	before := git(t, a.Source, "rev-parse", "main")

	writeFile(t, filepath.Join(a.Source, "fleet.toml"), e2eFleet+"\n")
	writeFile(t, filepath.Join(a.Home, ".config/tool/config"), "color = red\n")
	env, code, _ := yadm(t, "commit", ".config/tool/config")
	if code != ExitAttention {
		t.Fatalf("commit over a dirty clone: exit %d %+v", code, env.Data)
	}
	d := decode[struct {
		Commits []string     `json:"commits"`
		Holds   []model.Hold `json:"holds"`
	}](t, env.Data)
	if len(d.Commits) != 0 || len(d.Holds) != 1 || d.Holds[0].Reason != model.HoldSourceDirty {
		t.Fatalf("commit over a dirty clone: %+v", d)
	}
	if got := git(t, a.Source, "rev-parse", "main"); got != before {
		t.Fatal("main moved over a dirty clone")
	}
	if st := git(t, a.Source, "status", "--porcelain"); st != "M fleet.toml" {
		t.Fatalf("source clone: %q", st)
	}

	fix := d.Holds[0].Next[len(d.Holds[0].Next)-1]
	if !strings.HasPrefix(fix, "yadm git restore ") {
		t.Fatalf("advice: %v", d.Holds[0].Next)
	}
	if _, stderr, code := yadmRaw(t, strings.Fields(fix)[1:]...); code != 0 {
		t.Fatalf("%s: %d %s", fix, code, stderr)
	}
	env = yadmOK(t, "commit", ".config/tool/config")
	if hs := decode[holdsOnly](t, env.Data).Holds; len(hs) != 0 {
		t.Fatalf("commit after the advice holds: %+v", hs)
	}
	if st := git(t, a.Source, "status", "--porcelain"); st != "" {
		t.Fatalf("source clone after commit:\n%s", st)
	}
}
