package importer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

func defaultSourceOr(e manifest.Entry) model.SourcePath {
	if e.Source != "" {
		return e.Source
	}
	return defaultSource(e)
}

// TestImportLinkIntoDirectoryAlternate: a tracked symlink that names a file
// inside a directory-level alternate (`dir##class.work/file`) reuses that
// file's source under the alternate's condition.
func TestImportLinkIntoDirectoryAlternate(t *testing.T) {
	hermetic(t)
	lf := buildLegacy(t, map[string]string{
		".config/kit##class.work/settings.conf": "work settings\n",
		".config/kit##class.work/sub/deep.conf": "deep\n",
	})
	links := map[string]string{
		".config/settings.conf": "kit##class.work/settings.conf",
		".config/kit-link":      "kit##class.work",
	}
	for from, to := range links {
		if err := os.Symlink(to, filepath.Join(lf.Dir, filepath.FromSlash(from))); err != nil {
			t.Fatal(err)
		}
	}
	gitT(t, lf.Dir, "add", "-A")
	gitT(t, lf.Dir, "-c", "user.name=Legacy", "-c", "user.email=legacy@example.invalid", "commit", "-q", "-m", "links")

	opts := testOptions(lf, filepath.Join(t.TempDir(), "source"), newFakeSealer())
	conv, err := convert(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(conv.Problems) > 0 {
		t.Fatalf("problems: %v", conv.Problems)
	}
	want := map[string]string{
		".config/settings.conf":          "files/.config/kit/settings.conf",
		".config/kit-link/settings.conf": "files/.config/kit/settings.conf",
		".config/kit-link/sub/deep.conf": "files/.config/kit/sub/deep.conf",
	}
	for target, src := range want {
		e := entryFor(t, conv, target)
		if string(defaultSourceOr(e)) != src {
			t.Errorf("%s: source %s, want %s", target, defaultSourceOr(e), src)
		}
		if !strings.Contains(e.When, "type:work") {
			t.Errorf("%s: when %q lacks the alternate's condition", target, e.When)
		}
	}
}
