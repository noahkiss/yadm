package apply

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

func TestModeAccepted(t *testing.T) {
	cases := []struct {
		live, want fs.FileMode
		ok         bool
	}{
		{0o644, 0o644, true},
		{0o640, 0o644, true},  // umask 027 on a 0644 file
		{0o600, 0o644, true},  // stricter still
		{0o664, 0o644, false}, // group write is wider
		{0o755, 0o644, false}, // an execute bit is wider
		{0o750, 0o755, true},  // stricter, still executable by the owner
		{0o700, 0o755, true},  //
		{0o644, 0o755, false}, // loses the owner's execute bit: the script stops working
		{0o655, 0o755, false}, // the same, with others keeping theirs
		{0o600, 0o600, true},
		{0o640, 0o600, false},
	}
	for _, c := range cases {
		if got := ModeAccepted(c.live, c.want); got != c.ok {
			t.Errorf("ModeAccepted(%#o, %#o) = %v, want %v", c.live, c.want, got, c.ok)
		}
	}
}

// A managed file whose bytes match but whose mode is stricter than its
// entry wants is not drift: scan reports nothing, capture and apply hold
// nothing, and apply leaves the stricter mode alone. A wider mode, or one
// that drops the owner's execute bit from a script, still drifts and holds.
func TestStricterModeIsNotDrift(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	files := map[model.SourcePath]string{
		"files/.strict": "s\n", "files/.wide": "w\n",
		"files/.bin/narrow": "#!/bin/sh\n", "files/.bin/noexec": "#!/bin/sh\n",
	}
	c := w.commit(files,
		manifest.Entry{Target: ".strict"}, manifest.Entry{Target: ".wide"},
		manifest.Entry{Target: ".bin/narrow"}, manifest.Entry{Target: ".bin/noexec"})
	w.setMode(c, "files/.bin/narrow", gitModeExec)
	w.setMode(c, "files/.bin/noexec", gitModeExec)
	w.apply(c)

	chmod := map[model.Target]os.FileMode{".strict": 0o640, ".wide": 0o664, ".bin/narrow": 0o750, ".bin/noexec": 0o644}
	for tg, m := range chmod {
		if err := os.Chmod(w.path(tg), m); err != nil {
			t.Fatal(err)
		}
	}

	ds, err := w.eng.Scan(ctx, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	drifting := map[model.Target]bool{}
	for _, d := range ds {
		drifting[d.Target] = true
		if d.Kind != DriftMode {
			t.Errorf("%s: drift %q, want mode", d.Target, d.Kind)
		}
	}
	wantDrift := map[model.Target]bool{".wide": true, ".bin/noexec": true}
	for tg := range chmod {
		if drifting[tg] != wantDrift[tg] {
			t.Errorf("%s: drifting %v, want %v", tg, drifting[tg], wantDrift[tg])
		}
	}

	cp, err := w.eng.Capture(ctx, ds)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 0 {
		t.Errorf("a mode change captured source changes: %+v", cp.Changes)
	}
	res := w.apply(c)
	held := map[model.Target]bool{}
	for _, h := range res.Holds {
		held[h.Target] = true
	}
	for tg := range chmod {
		if held[tg] != wantDrift[tg] {
			t.Errorf("%s: held %v, want %v (holds %+v)", tg, held[tg], wantDrift[tg], res.Holds)
		}
	}
	// Apply never widens an accepted stricter mode.
	for _, tg := range []model.Target{".strict", ".bin/narrow"} {
		info, err := os.Stat(w.path(tg))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != chmod[tg] {
			t.Errorf("%s: apply changed mode to %#o, want %#o kept", tg, info.Mode().Perm(), chmod[tg])
		}
	}
	// It stays settled: a second scan finds nothing new on the strict files.
	ds, err = w.eng.Scan(ctx, ScanOptions{FullHash: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.Target == ".strict" || d.Target == ".bin/narrow" {
			t.Errorf("rescan: %s drifted: %+v", d.Target, d)
		}
	}
	if res := w.apply(c); len(res.Holds) != 2 {
		t.Errorf("second apply holds: %+v", res.Holds)
	}

	// New bytes are written with the entry's mode: a write replaces the
	// file, and the entry decides the mode of what apply writes.
	files["files/.strict"] = "s2\n"
	c2 := w.commit(files,
		manifest.Entry{Target: ".strict"}, manifest.Entry{Target: ".wide"},
		manifest.Entry{Target: ".bin/narrow"}, manifest.Entry{Target: ".bin/noexec"})
	w.setMode(c2, "files/.bin/narrow", gitModeExec)
	w.setMode(c2, "files/.bin/noexec", gitModeExec)
	w.apply(c2)
	if got := w.read(".strict"); got != "s2\n" {
		t.Fatalf(".strict = %q", got)
	}
	if info, _ := os.Stat(w.path(".strict")); info.Mode().Perm() != 0o644 {
		t.Errorf(".strict after a content write: mode %#o, want 0644", info.Mode().Perm())
	}
}

// A manifest that changes an entry's mode still changes the file's mode
// when the file is as last recorded, in either direction.
func TestManifestModeChangeStillApplies(t *testing.T) {
	w := newWorld(t)
	files := map[model.SourcePath]string{"files/.f": "f\n"}
	c := w.commit(files, manifest.Entry{Target: ".f", Mode: 0o600})
	w.apply(c)
	c2 := w.commit(files, manifest.Entry{Target: ".f", Mode: 0o644})
	if res := w.apply(c2); len(res.Holds) != 0 {
		t.Fatalf("holds: %+v", res.Holds)
	}
	if info, _ := os.Stat(w.path(".f")); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %#o, want 0644", info.Mode().Perm())
	}
}

// A file yadm never wrote, with the rendered bytes and a stricter mode, is
// taken over as it is by adopt and by apply; a wider one is held.
func TestStricterModeTakenOver(t *testing.T) {
	for _, adopt := range []bool{false, true} {
		w := newWorld(t)
		c := w.commit(map[model.SourcePath]string{"files/.s": "s\n", "files/.w": "w\n"},
			manifest.Entry{Target: ".s"}, manifest.Entry{Target: ".w"})
		w.write(".s", "s\n")
		w.write(".w", "w\n")
		os.Chmod(w.path(".s"), 0o640)
		os.Chmod(w.path(".w"), 0o666)
		var res Result
		var err error
		if adopt {
			res, err = w.eng.Adopt(context.Background(), c, AdoptOptions{})
		} else {
			res, err = w.eng.Apply(context.Background(), c, ApplyOptions{})
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Holds) != 1 || res.Holds[0].Target != ".w" {
			t.Errorf("adopt=%v: holds %+v, want only .w", adopt, res.Holds)
		}
		if _, ok := w.state().Targets[".s"]; !ok {
			t.Errorf("adopt=%v: .s not recorded", adopt)
		}
		if info, _ := os.Stat(w.path(".s")); info.Mode().Perm() != 0o640 {
			t.Errorf("adopt=%v: .s mode %#o, want 0640 kept", adopt, info.Mode().Perm())
		}
	}
}
