package apply

import (
	"context"
	"os"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Design 7.4 "Modes": an explicit mode may not grant a file with enclave
// plaintext a permission bit its source mode lacks. The existing test only
// covers a target under .ssh. This one uses a target outside .ssh/.gnupg.
func TestSec2EnclaveModeWidenedOutsidePrivateDir(t *testing.T) {
	w := newWorld(t, "personal")
	c := w.commit(map[model.SourcePath]string{"sealed/personal/.netrc": "secret\n"},
		manifest.Entry{Target: ".netrc", Enclave: "personal", Mode: 0o666})
	r := w.apply(c)
	a := actionOf(r, ".netrc")
	info, err := os.Stat(w.path(".netrc"))
	if err == nil {
		t.Logf("written with mode %v", info.Mode().Perm())
	}
	if a.Kind != ActHold {
		t.Fatalf("widened mode on an enclave file was applied: %+v", a)
	}
	if err == nil {
		t.Fatalf("held file was written (mode %v)", info.Mode().Perm())
	}
}

// An owner's explicit `mode = 0o600` on a sealed file is recorded at apply.
// A pusher who drops it (default 0644) or sets 0o644 widens the file; apply
// holds it until allowed here. Default modes still follow the source.
func TestSec2EnclaveModeWidenedAgainstState(t *testing.T) {
	files := map[model.SourcePath]string{"sealed/personal/.netrc": "secret\n", "files/.plain": "x\n"}
	owner := []manifest.Entry{{Target: ".netrc", Enclave: "personal", Mode: 0o600}, {Target: ".plain", Mode: 0o600}}
	for _, next := range []manifest.Entry{
		{Target: ".netrc", Enclave: "personal"},
		{Target: ".netrc", Enclave: "personal", Mode: 0o644},
	} {
		w := newWorld(t, "personal")
		w.apply(w.commit(files, owner...))
		if info, err := os.Stat(w.path(".netrc")); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("owner mode not applied: %v %v", info, err)
		}
		c := w.commit(files, next, manifest.Entry{Target: ".plain"})
		r := w.apply(c)
		if a := actionOf(r, ".netrc"); a.Kind != ActHold || holdFor(r.Holds, ".netrc", model.HoldSealGuard) == nil {
			t.Fatalf("%+v: pushed widening applied: %+v", next, a)
		}
		if info, _ := os.Stat(w.path(".netrc")); info.Mode().Perm() != 0o600 {
			t.Fatalf("%+v: mode changed to %v", next, info.Mode().Perm())
		}
		// A file without enclave plaintext follows the manifest.
		if info, _ := os.Stat(w.path(".plain")); info.Mode().Perm() != 0o644 {
			t.Fatalf("plain file mode %v", info.Mode().Perm())
		}
		if err := w.eng.AllowProtection(context.Background(), c, ".netrc"); err != nil {
			t.Fatal(err)
		}
		if a := actionOf(w.apply(c), ".netrc"); a.Kind == ActHold {
			t.Fatalf("%+v: allowed mode still held: %+v", next, a)
		}
		if info, _ := os.Stat(w.path(".netrc")); info.Mode().Perm() != 0o644 {
			t.Fatalf("%+v: allowed mode not written: %v", next, info.Mode().Perm())
		}
	}
	// Default modes follow the source: a first apply writes 0644.
	w := newWorld(t, "personal")
	w.apply(w.commit(files, manifest.Entry{Target: ".netrc", Enclave: "personal"}))
	if info, _ := os.Stat(w.path(".netrc")); info.Mode().Perm() != 0o644 {
		t.Fatalf("default mode %v", info.Mode().Perm())
	}
	// A source that gains the executable bit still sets the default mode.
	c := w.commit(files, manifest.Entry{Target: ".netrc", Enclave: "personal"})
	w.setMode(c, "sealed/personal/.netrc", gitModeExec)
	if a := actionOf(w.apply(c), ".netrc"); a.Kind == ActHold {
		t.Fatalf("default mode change held: %+v", a)
	}
	if info, _ := os.Stat(w.path(".netrc")); info.Mode().Perm() != 0o755 {
		t.Fatalf("default mode after exec bit %v", info.Mode().Perm())
	}
}
