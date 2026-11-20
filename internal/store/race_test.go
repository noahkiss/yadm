package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The remote moves main while it receives a push (another push landed in
// between). git reports "[remote rejected] (atomic transaction failed)" or
// "cannot lock ref ... is at X but expected Y": the same race as a
// non-fast-forward, so the sync loop retries it.
func TestPushServerSideRaceIsRejected(t *testing.T) {
	ctx := context.Background()
	remote, a, b := seeded(t)
	// A side commit on the remote that the hook moves main to.
	commitMain(t, a, "side", change("files/.side", "side\n"))
	if err := a.Push(ctx, []string{RefMain + ":refs/heads/side"}); err != nil {
		t.Fatal(err)
	}
	hook := "#!/bin/sh\nunset GIT_QUARANTINE_PATH\ngit update-ref refs/heads/main refs/heads/side\nexit 0\n"
	if err := os.WriteFile(filepath.Join(remote, "hooks", "pre-receive"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	commitMain(t, b, "b", change("files/.b", "b\n"))
	err := b.Push(ctx, []string{RefMain + ":" + RefMain})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("push = %v, want ErrRejected", err)
	}
	for _, c := range []struct{ out, errOut string }{
		{"!\trefs/heads/main:refs/heads/main\t[remote rejected] (atomic transaction failed)\n", ""},
		{"!\trefs/heads/main:refs/heads/main\t[remote rejected] (failed to update ref)\n", "error: cannot lock ref 'refs/heads/main': is at 1111 but expected 2222\n"},
	} {
		if !pushRejected(c.out, c.errOut) {
			t.Errorf("not a race: %q %q", c.out, c.errOut)
		}
	}
	if pushRejected("!\trefs/heads/main:refs/heads/main\t[remote rejected] (pre-receive hook declined)\n", "") {
		t.Error("a declined hook is not a race")
	}
}
