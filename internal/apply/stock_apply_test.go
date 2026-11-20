package apply

import (
	"os"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Apply takes over what adopt could not yet: a stock symlink whose content
// equals the render, and a read-only (0444) render with equal bytes. A
// differing link is still held, and so is a new keep entry over a link
// whose content differs from the source's own bytes.
func TestApplyTakesOverStockRenders(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{
		"files/.linked": "linked\n", "files/.readonly": "render\n", "files/.differs": "source\n",
		"files/.keyed.json": "{}\n", "files/.local.json": "{}\n",
	},
		manifest.Entry{Target: ".linked"}, manifest.Entry{Target: ".readonly"}, manifest.Entry{Target: ".differs"},
		manifest.Entry{Target: ".keyed.json", Format: manifest.FormatJSON, Keep: []string{"a"}},
		manifest.Entry{Target: ".local.json", Format: manifest.FormatJSON, Keep: []string{"a"}})
	w.write(".linked##class.home", "linked\n")
	mustSymlink(t, ".linked##class.home", w.path(".linked"))
	w.write(".differs##class.home", "other\n")
	mustSymlink(t, ".differs##class.home", w.path(".differs"))
	w.write(".keyed.json##class.home", "{}\n")
	mustSymlink(t, ".keyed.json##class.home", w.path(".keyed.json"))
	w.write(".local.json##class.home", "{\"b\": 1}\n")
	mustSymlink(t, ".local.json##class.home", w.path(".local.json"))
	w.write(".readonly", "render\n")
	if err := os.Chmod(w.path(".readonly"), 0o444); err != nil {
		t.Fatal(err)
	}
	r := w.apply(c)
	for _, tg := range []model.Target{".linked", ".readonly", ".keyed.json"} {
		if a := actionOf(r, tg); a.Kind != ActWrite {
			t.Errorf("%s: %+v", tg, a)
		}
		if li, err := os.Lstat(w.path(tg)); err != nil || !li.Mode().IsRegular() || li.Mode().Perm() != 0o644 {
			t.Errorf("%s not taken over: %v %v", tg, li, err)
		}
	}
	if w.read(".linked##class.home") != "linked\n" {
		t.Error("link target changed")
	}
	if holdFor(r.Holds, ".differs", model.HoldDrifted) == nil {
		t.Errorf("differing link not held: %+v", r.Holds)
	}
	if holdFor(r.Holds, ".local.json", model.HoldNeedsDecision) == nil {
		t.Errorf("keep entry over a link not held for a decision: %+v", r.Holds)
	}
}
