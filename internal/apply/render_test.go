package apply

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// TestRenderMatchesApply: Engine.Render returns the bytes apply writes, for
// a plain file, a template and a sealed file, writes nothing, and refuses
// an unplanned target and an enclave this machine cannot open.
func TestRenderMatchesApply(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, "personal")
	c := w.commit(map[model.SourcePath]string{
		"files/.plain":              "plain\n",
		"files/.tmpl":               "name={{ machine.name }}\n",
		"sealed/personal/.private":  "secret\n",
		"sealed/client/.clientfile": "client secret\n",
	},
		manifest.Entry{Target: ".plain"},
		manifest.Entry{Target: ".tmpl", Template: true},
		manifest.Entry{Target: ".private", Enclave: "personal"},
		manifest.Entry{Target: ".clientfile", Enclave: "client"},
	)
	snap, err := w.load(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[model.Target][]byte{}
	for _, tg := range []model.Target{".plain", ".tmpl", ".private"} {
		b, err := w.eng.Render(ctx, snap, tg, nil)
		if err != nil {
			t.Fatalf("%s: %v", tg, err)
		}
		got[tg] = b
		if _, err := os.Stat(w.path(tg)); err == nil {
			t.Fatalf("Render wrote %s", tg)
		}
	}
	if _, err := w.eng.Render(ctx, snap, ".clientfile", nil); !errors.Is(err, crypt.ErrNotMember) {
		t.Errorf("non-member render: %v", err)
	}
	if _, err := w.eng.Render(ctx, snap, ".nope", nil); !errors.Is(err, ErrNotPlanned) {
		t.Errorf("unplanned render: %v", err)
	}
	if _, err := w.eng.Apply(ctx, c, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	for tg, b := range got {
		if w.read(tg) != string(b) {
			t.Errorf("%s: render %q, apply wrote %q", tg, b, w.read(tg))
		}
	}
}
