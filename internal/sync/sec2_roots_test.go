package sync

import (
	"context"
	"os"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// Design 7.4: a new owned root does nothing on a machine until allowed
// there. That covers delivery too: its entry-less files reach $HOME only
// after `yadm root allow`, on the next apply.
func TestSec2UnallowedRootDeliversNothing(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	const tgt model.Target = ".config/newroot/x.conf"
	ch := sec2Manifest(t, A, func(s string) string { return s + "\n[[root]]\npath = \".config/newroot\"\n" })
	ch = append(ch, store.Change{Path: "files/.config/newroot/x.conf", Blob: []byte("pushed\n"), Mode: 0o100644})
	pushRaw(t, A, ch)
	r := B.sync()
	if _, err := os.Lstat(B.path(tgt)); err == nil {
		t.Fatal("a root that is not allowed delivered a file")
	}
	held := false
	for _, h := range r.Holds {
		if h.Target == ".config/newroot" && h.Reason == model.HoldRootUntrusted {
			held = true
		}
	}
	if !held {
		t.Errorf("no root_untrusted hold: %+v", r.Holds)
	}
	if err := B.eng.AllowRoot(context.Background(), B.main(), ".config/newroot"); err != nil {
		t.Fatal(err)
	}
	B.sync()
	if got := B.read(tgt); got != "pushed\n" {
		t.Fatalf("allowed root did not deliver: %q", got)
	}
}
