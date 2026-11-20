package fixture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func readTOML(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := toml.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return v
}

// TestShape checks the static fixture is self-consistent, independent of any
// package that is still a stub.
func TestShape(t *testing.T) {
	src := filepath.Join(Dir(), "source")
	fl := readTOML(t, filepath.Join(src, "fleet.toml"))
	types := fl["types"].(map[string]any)
	for id, raw := range fl["machines"].(map[string]any) {
		m := raw.(map[string]any)
		for _, ty := range m["types"].([]any) {
			if _, ok := types[ty.(string)]; !ok {
				t.Errorf("machine %s: unknown type %v", id, ty)
			}
		}
	}
	for e := range Members {
		if te, ok := types[string(e)].(map[string]any); !ok || te["enclave"] != true {
			t.Errorf("enclave %s is not declared as an enclave type", e)
		}
	}

	mf := readTOML(t, filepath.Join(src, "manifest.toml"))
	for _, raw := range mf["file"].([]any) {
		e := raw.(map[string]any)
		target := e["target"].(string)
		var p string
		switch {
		case e["source"] != nil:
			p = filepath.Join(src, e["source"].(string))
		case e["enclave"] != nil:
			p = filepath.Join(Dir(), "enclave-plain", e["enclave"].(string), target)
		default:
			p = filepath.Join(src, "files", target)
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("entry %s: source missing: %v", target, err)
		}
	}
	if _, err := os.Stat(filepath.Join(LegacyDir(), ".config", "yadm", "machines.tsv")); err != nil {
		t.Errorf("legacy fixture: %v", err)
	}
}

func TestBuild(t *testing.T) {
	f := Build(t) // skips until crypt is implemented
	if len(f.Identities) != 3 {
		t.Fatalf("identities: %d", len(f.Identities))
	}
}
