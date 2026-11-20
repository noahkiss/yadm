package importer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestImportCustomCryptFilter: a transcrypt filter with a custom name is
// learned from the legacy repository's own config (a bare repository here),
// read without running it. A clone lacks that config: its marked files fail
// the import loudly until --crypt-filter names the filter.
func TestImportCustomCryptFilter(t *testing.T) {
	hermetic(t)
	lf := buildLegacy(t, map[string]string{".gitattributes": ".config/notes/** filter=vault diff=vault merge=vault\n"})
	root := t.TempDir()
	bare := filepath.Join(root, "bare.git")
	gitT(t, root, "clone", "-q", "--bare", lf.Dir, bare)
	// Never run: the importer only reads the config value.
	gitT(t, bare, "config", "filter.vault.smudge", `"$(git rev-parse --git-common-dir)"/crypt/transcrypt smudge`)
	gitT(t, bare, "config", "filter.vault.clean", `"$(git rev-parse --git-common-dir)"/crypt/transcrypt clean %f`)
	before := gitT(t, bare, "config", "--local", "--list")

	ctx := context.Background()
	opts := testOptions(lf, "", newFakeSealer())
	opts.Legacy = bare
	conv, err := convert(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(conv.Problems) > 0 {
		t.Fatalf("bare repository with the filter in its config: %v", conv.Problems)
	}
	sealed := 0
	for _, m := range conv.Mappings {
		if m.Sealed {
			sealed++
		}
	}
	if sealed == 0 {
		t.Fatal("no file was sealed")
	}
	if after := gitT(t, bare, "config", "--local", "--list"); after != before {
		t.Fatal("the import changed the legacy repository's config")
	}

	clone := filepath.Join(root, "clone")
	gitT(t, root, "clone", "-q", lf.Dir, clone)
	opts.Legacy = clone
	conv, err = convert(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	loud := false
	for _, p := range conv.Problems {
		if strings.HasPrefix(p.Path, ".config/notes/") && strings.Contains(p.Reason, "not marked with a transcrypt filter") {
			loud = true
		}
	}
	if !loud {
		t.Fatalf("a clone without the filter config must refuse: %v", conv.Problems)
	}
	opts.CryptFilters = []string{"vault"}
	conv, err = convert(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(conv.Problems) > 0 {
		t.Fatalf("clone with CryptFilters: %v", conv.Problems)
	}
}
