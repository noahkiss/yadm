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

func TestResolveHoldTakeTargetOfUnmanagedFile(t *testing.T) {
	w := newWorld(t)
	w.write(".a", "local\n")
	c := w.commit(map[model.SourcePath]string{"files/.a": "repo\n"}, manifest.Entry{Target: ".a"})
	r, err := w.eng.Adopt(context.Background(), c, AdoptOptions{})
	if err != nil || len(r.Holds) != 1 {
		t.Fatalf("adopt: %+v %v", r, err)
	}
	res, err := w.eng.ResolveHold(context.Background(), r.Holds[0].ID, ResolveOptions{Take: "target"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Capture == nil || len(res.Capture.Changes) != 1 || string(res.Capture.Changes[0].Blob) != "local\n" {
		t.Fatalf("take target of an adopt hold: %+v", res)
	}
	if hs, _ := w.eng.Holds(context.Background()); len(hs) != 0 {
		t.Errorf("hold left: %+v", hs)
	}
}

func TestResolveHoldTakeTargetOfOrphan(t *testing.T) {
	w := newWorld(t)
	c1 := w.commit(map[model.SourcePath]string{"files/.a": "a\n"}, manifest.Entry{Target: ".a"})
	w.apply(c1)
	w.write(".a", "edited\n")
	r := w.apply(w.commit(nil))
	if len(r.Holds) != 1 {
		t.Fatalf("%+v", r)
	}
	if _, err := w.eng.ResolveHold(context.Background(), r.Holds[0].ID, ResolveOptions{Take: "target"}); err != nil {
		t.Fatal(err)
	}
	if w.read(".a") != "edited\n" {
		t.Error("orphan changed")
	}
	st := w.state()
	if _, ok := st.Targets[".a"]; ok || len(st.Holds) != 0 {
		t.Errorf("orphan still managed: %+v", st)
	}
}

// raceFS edits the target after the temp file is written, before the rename.
type raceFS struct{ osFS }

func (raceFS) BeforeRename(tmp, dst string) error {
	return os.WriteFile(dst, []byte("a concurrent edit\n"), 0o644)
}

func TestApplyHoldsTargetChangedDuringApply(t *testing.T) {
	w := newWorld(t)
	c1 := w.commit(map[model.SourcePath]string{"files/.a": "v1\n"}, manifest.Entry{Target: ".a"})
	w.apply(c1)
	w.eng.fs = raceFS{}
	r := w.apply(w.commit(map[model.SourcePath]string{"files/.a": "v2\n"}, manifest.Entry{Target: ".a"}))
	if a := actionOf(r, ".a"); a.Kind != ActHold || len(r.Holds) != 1 {
		t.Fatalf("%+v", r)
	}
	if w.read(".a") != "a concurrent edit\n" {
		t.Error("concurrent edit clobbered")
	}
	if temps, _ := filepath.Glob(filepath.Join(w.home, "..a"+tmpMarker+"*")); len(temps) != 0 {
		t.Errorf("temp left: %v", temps)
	}
}

func TestScanNestedRootsReportOnce(t *testing.T) {
	w := newWorld(t, "personal")
	c := w.commit(nil)
	w.plans[c].Roots = []manifest.Root{{Path: ".config"}, {Path: ".config/notes", Enclave: "personal"}}
	w.apply(c)
	w.write(".config/notes/n.md", "n\n")
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	if len(ds) != 1 || ds[0].Scope != "personal" {
		t.Fatalf("%+v", ds)
	}
}

func TestSecrecyRetagAndResealOutputIsSealed(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal", "client")
	man := "schema = 1\n\n[[file]]\ntarget = \".config/tool/key\"\nenclave = \"personal\"\n"
	tok, _ := w.crypto.SealValue("personal", "TOKEN", canary.Bytes())
	c := w.commit(map[model.SourcePath]string{
		"sealed/personal/.config/tool/key": canary.String(),
		"manifest.toml":                    man,
		"files/.env":                       "TOKEN=" + tok + "\n",
	},
		manifest.Entry{Target: ".config/tool/key", Enclave: "personal"},
		manifest.Entry{Target: ".env", Format: manifest.FormatText, Seal: map[string]model.EnclaveName{"TOKEN": "personal"}})

	cp, err := w.eng.Retag(context.Background(), ".config/tool/key", RetagOptions{Types: []model.TypeName{"client"}, Enclave: "client"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 3 {
		t.Fatalf("%+v", cp.Changes)
	}
	assertObjectsClean(t, cp.Changes, canary)

	// A new epoch: every sealed file and value reseals, and stays sealed.
	w.crypto.epoch = 2
	snap, _ := w.load(context.Background(), c)
	rs, err := w.eng.Reseal(context.Background(), snap, "personal")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[model.SourcePath]bool{}
	for _, ch := range rs.Changes {
		paths[ch.Path] = true
	}
	if !paths["sealed/personal/.config/tool/key"] || !paths["files/.env"] {
		t.Fatalf("reseal changes: %+v", rs.Changes)
	}
	assertObjectsClean(t, rs.Changes, canary)
}
