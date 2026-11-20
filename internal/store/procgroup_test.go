package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A git whose child keeps stdout open (as ssh does on a stalled fetch) must
// not outlive the caller's deadline by more than waitDelay.
func TestRunDeadlineKillsChildren(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "git")
	script := "#!/bin/sh\nsleep 60 &\nsleep 60\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := run(ctx, call{args: []string{"fetch"}, network: true})
	if err == nil {
		t.Fatal("run: want an error after the deadline")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("run returned after %s; the child kept it alive", d)
	}
}
