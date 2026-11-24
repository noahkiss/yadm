package reroot

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// TestPrunePin: a pinned bundle survives a prune even when its name sorts
// oldest (a clock that went back), and the last bundle is never deleted.
func TestPrunePin(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	var paths []string
	for i, h := range []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"} {
		p := filepath.Join(dir, BundleName(at.Add(time.Duration(i)*time.Hour), model.CommitID(h)))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	gone, err := Prune(dir, 1, paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 2 {
		t.Fatalf("deleted %d, want 2", len(gone))
	}
	left, _ := List(dir)
	if len(left) != 1 || left[0].Path != paths[0] {
		t.Fatalf("left %+v, want the pinned %s", left, paths[0])
	}
	if _, err := Prune(dir, 0); err == nil {
		t.Fatal("prune with keep 0 deleted the last bundle")
	}
}
