package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `git checkout` in the source clone moved HEAD to a commit on main's
// history and left the clone clean there. The recorded worktree head is
// stale; SyncWorktree re-records HEAD and moves on instead of reporting
// staged edits.
func TestSyncWorktreeRecoversStaleHead(t *testing.T) {
	ctx := context.Background()
	_, a, b := seeded(t)
	mid := commitMain(t, a, "mid", change("files/.base", "base v2\n"))
	next := commitMain(t, a, "next", change("files/.base", "base v3\n"))
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}
	if err := b.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	old, _ := b.Head(ctx)
	rawGit(t, b.Dir(), "checkout", "-q", "--detach", string(mid))
	if err := b.UpdateRef(ctx, RefMain, next, old); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncWorktree(ctx, next); err != nil {
		t.Fatalf("stale head on main's history: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(b.Dir(), "files", ".base")); string(got) != "base v3\n" {
		t.Fatalf("worktree not moved: %q", got)
	}
	if ref := rawGit(t, b.Dir(), "symbolic-ref", "HEAD"); ref != RefMain {
		t.Fatalf("HEAD %s, want main", ref)
	}
	if st := rawGit(t, b.Dir(), "status", "--porcelain"); st != "" {
		t.Fatalf("status after recovery:\n%s", st)
	}
}

// HEAD on a commit yadm never reached (not on main's history) stays dirty.
func TestSyncWorktreeStaleHeadElsewhereIsDirty(t *testing.T) {
	ctx := context.Background()
	_, a, b := seeded(t)
	next := commitMain(t, a, "next", change("files/.base", "base v2\n"))
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}
	if err := b.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	old, _ := b.Head(ctx)
	if err := b.UpdateRef(ctx, RefMain, next, old); err != nil {
		t.Fatal(err)
	}
	// A side commit off the old head, never on main.
	rawGit(t, b.Dir(), "checkout", "-q", "--detach", string(old))
	os.WriteFile(filepath.Join(b.Dir(), "files", ".side"), []byte("side\n"), 0o644)
	rawGit(t, b.Dir(), "add", "files/.side")
	rawGit(t, b.Dir(), "-c", "user.name=x", "-c", "user.email=x@example.invalid", "commit", "-q", "-m", "side")
	err := b.SyncWorktree(ctx, next)
	if !errors.Is(err, ErrDirty) {
		t.Fatalf("HEAD off main: %v, want ErrDirty", err)
	}
	if !strings.Contains(rawGit(t, b.Dir(), "rev-parse", "--abbrev-ref", "HEAD"), "HEAD") {
		t.Fatal("HEAD was reattached")
	}
}
