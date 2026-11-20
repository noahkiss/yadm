package apply

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// A stock symlink into a `##` variant whose bytes equal a sealed keep or
// drop source is the stock layout, not evidence from the keep merge: it is
// taken over with no hold whether the machine joins the enclave before
// adopt or after it.
func TestStockLinkAtLocalKeysEntryTakenOver(t *testing.T) {
	const keep, drop model.Target = ".config/app/settings.json", ".config/tool/config.json"
	body := "{\n  \"theme\": \"dark\"\n}\n"
	files := map[model.SourcePath]string{
		"sealed/personal/.config/app/settings.json": body,
		"sealed/personal/.config/tool/config.json":  body,
	}
	entries := []manifest.Entry{
		{Target: keep, Enclave: "personal", Format: manifest.FormatJSON, Keep: []string{"theme"}},
		{Target: drop, Enclave: "personal", Format: manifest.FormatJSON, Drop: []string{"recent"}},
	}
	for _, joinFirst := range []bool{false, true} {
		name := "adopt then join"
		if joinFirst {
			name = "join then adopt"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			w.eng.Rules = pkgRules{}
			for _, tg := range []model.Target{keep, drop} {
				v := model.Target(string(tg) + "##class.home")
				w.write(v, body)
				mustSymlink(t, path.Base(string(v)), w.path(tg))
			}
			c := w.commit(files, entries...)
			join := func() { w.crypto.members["personal"] = true }
			if joinFirst {
				join()
			}
			res, err := w.eng.Adopt(ctx, c, AdoptOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Holds) != 0 {
				t.Fatalf("adopt holds: %+v", res.Holds)
			}
			if !joinFirst {
				join()
			}
			r := w.apply(c)
			if len(r.Holds) != 0 || len(w.state().Holds) != 0 {
				t.Fatalf("apply holds: %+v", r.Holds)
			}
			for _, tg := range []model.Target{keep, drop} {
				if li, err := os.Lstat(w.path(tg)); err != nil || !li.Mode().IsRegular() {
					t.Errorf("%s not taken over: %v %v", tg, li, err)
				}
				if _, ok := w.state().Targets[tg]; !ok {
					t.Errorf("%s not recorded as managed", tg)
				}
				if w.read(model.Target(string(tg)+"##class.home")) != body {
					t.Errorf("%s: link target changed", tg)
				}
			}
		})
	}
}

// A stock symlink to a `##` variant that differs from the source's own
// bytes, or that leaves $HOME, is still held for a decision at a keep entry.
func TestStockLinkAtLocalKeysEntryHeldWithoutEvidence(t *testing.T) {
	const tgt model.Target = ".config/app/creds.json"
	w := newWorld(t)
	w.eng.Rules = pkgRules{}
	c := w.commit(map[model.SourcePath]string{"files/.config/app/creds.json": "{}\n"},
		manifest.Entry{Target: tgt, Format: manifest.FormatJSON, Keep: []string{"managed"}})
	outside := t.TempDir() + "/creds.json"
	if err := os.WriteFile(outside, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(path.Dir(w.path(tgt)), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, w.path(tgt))
	r := w.apply(c)
	if holdFor(r.Holds, tgt, model.HoldNeedsDecision) == nil {
		t.Fatalf("link leaving $HOME not held: %+v", r.Holds)
	}

	if err := os.Remove(w.path(tgt)); err != nil {
		t.Fatal(err)
	}
	w.write(".config/app/creds.json##class.home", "{\"auth\": \"x\"}\n")
	mustSymlink(t, "creds.json##class.home", w.path(tgt))
	r = w.apply(c)
	if holdFor(r.Holds, tgt, model.HoldNeedsDecision) == nil {
		t.Fatalf("link differing from the source not held: %+v", r.Holds)
	}
	if _, ok := w.state().Targets[tgt]; ok {
		t.Fatal("recorded as managed")
	}
}
