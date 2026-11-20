package apply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// A directory symlink above a target that points outside $HOME is left
// alone by adopt (dirLinks). Does adopt then write the target through it?
func TestSec2AdoptWritesThroughDirLinkOutsideHome(t *testing.T) {
	w := newWorld(t)
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(w.home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(w.home, ".config", "tool")); err != nil {
		t.Fatal(err)
	}
	c := w.commit(map[model.SourcePath]string{"files/.config/tool/config": "from the repository\n"},
		manifest.Entry{Target: ".config/tool/config"})
	res, err := w.eng.Adopt(context.Background(), c, AdoptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("action: %+v", actionOf(res, ".config/tool/config"))
	if b, err := os.ReadFile(filepath.Join(outside, "config")); err == nil {
		t.Errorf("adopt wrote outside $HOME through a directory symlink: %q", b)
	}
	// Plain apply does the same.
	outside2 := t.TempDir()
	w2 := newWorld(t)
	_ = os.MkdirAll(filepath.Join(w2.home, ".config"), 0o755)
	_ = os.Symlink(outside2, filepath.Join(w2.home, ".config", "tool"))
	c2 := w2.commit(map[model.SourcePath]string{"files/.config/tool/config": "from the repository\n"},
		manifest.Entry{Target: ".config/tool/config"})
	r := w2.apply(c2)
	if b, err := os.ReadFile(filepath.Join(outside2, "config")); err == nil {
		t.Errorf("apply wrote outside $HOME through a directory symlink: %q", b)
	}
	if h := holdFor(r.Holds, ".config/tool/config", model.HoldUncapturable); h == nil || !strings.Contains(h.Detail, "leaves $HOME") {
		t.Errorf("no hold naming the reason: %+v", r.Holds)
	}
}

// A managed target whose parent directory later becomes a link out of
// $HOME is never read by scan or capture.
func TestSec2CaptureThroughDirLinkOutsideHome(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.config/tool/config": "a\n"}, manifest.Entry{Target: ".config/tool/config"})
	w.apply(c)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "config"), []byte("OUTSIDE-SECRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(w.home, ".config", "tool")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	cp := scanCapture(t, w)
	for _, ch := range cp.Changes {
		if strings.Contains(string(ch.Blob), "OUTSIDE-SECRET") {
			t.Fatalf("captured a file outside $HOME at %s", ch.Path)
		}
	}
	if holdFor(cp.Holds, ".config/tool/config", model.HoldUncapturable) == nil {
		t.Fatalf("not held: %+v", cp.Holds)
	}
}
