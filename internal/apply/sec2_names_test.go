package apply

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// A target whose name holds a control character (a glob or a root can
// expand to such a tree path) is held, never written or captured. Holds
// on other odd names suggest commands with the name shell-quoted.
func TestSec2ControlCharacterTargetsHeld(t *testing.T) {
	const bad model.Target = ".config/tool/new\nline.conf"
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/" + model.SourcePath(bad): "x\n"}, manifest.Entry{Target: bad})
	r := w.apply(c)
	if a := actionOf(r, bad); a.Kind != ActHold {
		t.Fatalf("applied: %+v", a)
	}
	h := holdFor(r.Holds, bad, model.HoldUncapturable)
	if h == nil || len(h.Next) != 1 {
		t.Fatalf("hold: %+v", r.Holds)
	}
	if _, err := os.Lstat(w.path(bad)); err == nil {
		t.Fatal("file with a newline in its name was written")
	}
	if _, err := w.eng.ResolveHold(context.Background(), h.ID, ResolveOptions{Take: "source"}); err == nil {
		t.Fatal("resolve wrote it")
	}

	// Capture of such a file holds it too.
	w.write(bad, "local\n")
	cp, err := w.eng.Capture(context.Background(), []Drift{{Target: bad, Kind: DriftNew, Scope: model.ScopeShared, Named: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 0 || holdFor(cp.Holds, bad, model.HoldUncapturable) == nil {
		t.Fatalf("captured: %+v %+v", cp.Changes, cp.Holds)
	}
}

func TestSec2HoldNextQuotesTarget(t *testing.T) {
	st := &State{}
	nowFixed := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	h := weakHold(st, nowFixed, ".config/tool/new;touch X;.conf", model.ScopeShared, nowFixed, "d")
	if !strings.HasPrefix(h.Next[0], "yadm protection allow '.config/tool/new;touch X;.conf'") {
		t.Fatalf("next: %q", h.Next)
	}
}
