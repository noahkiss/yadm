package apply

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// A directory under an accepted owned root becomes a link to a variant
// directory after the root's baseline walk. Adopt copies the link's files
// into a real directory; the copies join the baseline, so capture never
// takes them as new files of the root.
func TestSec2MaterializedCopiesJoinBaseline(t *testing.T) {
	canary := secrecytest.NewCanary(t, "file behind the link")
	w := newWorld(t)
	files := map[model.SourcePath]string{"files/.config/shell/aliases.sh": "a\n"}
	c := w.commit(files, manifest.Entry{Target: ".config/shell/aliases.sh"})
	w.plans[c].Roots = []manifest.Root{{Path: ".config"}}
	w.allowRoots(c)
	w.apply(c)

	variant := filepath.Join(w.home, "variants", "shell")
	if err := os.MkdirAll(variant, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(variant, "aliases.sh"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(variant, "local.sh"), canary.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := w.path(".config/shell")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(variant, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := w.eng.Adopt(context.Background(), c, AdoptOptions{}); err != nil {
		t.Fatal(err)
	}
	if li, err := os.Lstat(dir); err != nil || !li.IsDir() {
		t.Fatalf("not materialized: %v %v", li, err)
	}
	if _, ok := w.state().Baseline[".config/shell/local.sh"]; !ok {
		t.Fatalf("copy not in the baseline: %v", w.state().Baseline)
	}
	if cp := scanCapture(t, w); leakedIn(cp, canary) != nil {
		t.Fatal("a materialized copy was captured as a new file")
	}
}
