package apply

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Target modes follow the source, sealed or not. Only .ssh and .gnupg are
// tightened, and an explicit mode always wins.
func TestTargetModesFollowSource(t *testing.T) {
	w := newWorld(t, "personal")
	c := w.commit(map[model.SourcePath]string{
		"files/.plain":                      "p\n",
		"files/.bin/tool":                   "#!/bin/sh\n",
		"sealed/personal/.notes":            "n\n",
		"sealed/personal/.bin/secret-tool":  "#!/bin/sh\n",
		"files/.ssh/config":                 "Host *\n",
		"sealed/personal/.ssh/known-script": "#!/bin/sh\n",
		"files/.gnupg/gpg.conf":             "g\n",
		"files/.ssh/explicit":               "e\n",
	},
		manifest.Entry{Target: ".plain"},
		manifest.Entry{Target: ".bin/tool"},
		manifest.Entry{Target: ".notes", Enclave: "personal"},
		manifest.Entry{Target: ".bin/secret-tool", Enclave: "personal"},
		manifest.Entry{Target: ".ssh/config"},
		manifest.Entry{Target: ".ssh/known-script", Enclave: "personal"},
		manifest.Entry{Target: ".gnupg/gpg.conf"},
		manifest.Entry{Target: ".ssh/explicit", Mode: 0o644},
	)
	w.setMode(c, "files/.bin/tool", gitModeExec)
	w.setMode(c, "sealed/personal/.bin/secret-tool", gitModeExec)
	w.setMode(c, "sealed/personal/.ssh/known-script", gitModeExec)
	w.apply(c)

	want := map[model.Target]os.FileMode{
		".plain":            0o644,
		".bin/tool":         0o755,
		".notes":            0o644,
		".bin/secret-tool":  0o755,
		".ssh/config":       0o600,
		".ssh/known-script": 0o700,
		".gnupg/gpg.conf":   0o600,
		".ssh/explicit":     0o644,
	}
	for tg, m := range want {
		info, err := os.Stat(w.path(tg))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != m {
			t.Errorf("%s: mode %#o, want %#o", tg, info.Mode().Perm(), m)
		}
	}
	for _, d := range []string{".ssh", ".gnupg"} {
		info, err := os.Stat(filepath.Join(w.home, d))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("%s: dir mode %#o, want 0700", d, info.Mode().Perm())
		}
	}
	if info, _ := os.Stat(filepath.Join(w.home, ".bin")); info.Mode().Perm() != 0o755 {
		t.Errorf(".bin: dir mode %#o", info.Mode().Perm())
	}

	// A captured sealed script keeps its executable bit in the source.
	w.write(".bin/secret-tool", "#!/bin/sh\necho hi\n")
	if err := os.Chmod(w.path(".bin/secret-tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, err := w.eng.Capture(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 1 || cp.Changes[0].Mode != gitModeExec {
		t.Fatalf("sealed exec capture: %+v", cp.Changes)
	}
}
