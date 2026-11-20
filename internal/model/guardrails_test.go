package model_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Guardrails that keep the core harness-agnostic and keep extensions on the
// small public surface docs/extensions.md describes.

// harnessNames lists coding-agent harnesses the core must never name. A
// harness belongs in an extension or in docs/hooks.md, never in internal/.
var harnessNames = []string{"claude", "codex", "opencode", "pi-agent", "cursor"}

// extensionImports lists the internal packages a cmd/yadm-* extension may import.
var extensionImports = []string{"cond", "rules", "extexec", "model", "render"}

// extensionExempt lists cmd/yadm-* directories that are not extensions.
var extensionExempt = map[string]string{
	"yadm-oracle": "a development harness that compares against a reference run; it ships with no release",
}

const modulePath = "github.com/noahkiss/yadm"

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatal("go.mod not found")
		}
		dir = up
	}
}

func TestNoHarnessNameInInternal(t *testing.T) {
	root := moduleRoot(t)
	re := regexp.MustCompile(`(?i)\b(` + strings.Join(quoteAll(harnessNames), "|") + `)\b`)
	self, err := filepath.Abs("guardrails_test.go")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if p == self {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range bytes.Split(b, []byte("\n")) {
			if m := re.Find(line); m != nil {
				rel, _ := filepath.Rel(root, p)
				t.Errorf("%s:%d names harness %q; the core stays harness-agnostic (only docs/hooks.md may name one)", rel, i+1, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = regexp.QuoteMeta(s)
	}
	return out
}

func TestExtensionImportBoundary(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-json", "./cmd/...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var pkg listedPackage
		if err := dec.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, pkg)
	}
	for _, v := range boundaryViolations(pkgs) {
		t.Error(v)
	}
}

type listedPackage struct {
	ImportPath string
	Imports    []string
}

// boundaryViolations lists every import of a cmd/yadm-* package outside
// extensionImports. Only direct imports count.
func boundaryViolations(pkgs []listedPackage) []string {
	allowed := map[string]bool{}
	for _, p := range extensionImports {
		allowed[modulePath+"/internal/"+p] = true
	}
	var out []string
	for _, pkg := range pkgs {
		rest, ok := strings.CutPrefix(pkg.ImportPath, modulePath+"/cmd/")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, "/") // cmd/yadm-x/sub counts as yadm-x
		if !strings.HasPrefix(name, "yadm-") || extensionExempt[name] != "" {
			continue
		}
		for _, imp := range pkg.Imports {
			if strings.HasPrefix(imp, modulePath+"/") && !allowed[imp] {
				out = append(out, pkg.ImportPath+" imports "+imp+"; an extension may import only internal/{"+strings.Join(extensionImports, ",")+"}")
			}
		}
	}
	return out
}

func TestBoundaryViolations(t *testing.T) {
	pkgs := []listedPackage{
		{ImportPath: modulePath + "/cmd/yadm", Imports: []string{modulePath + "/internal/cli"}},
		{ImportPath: modulePath + "/cmd/yadm-oracle", Imports: []string{modulePath + "/internal/oracle"}},
		{ImportPath: modulePath + "/cmd/yadm-good", Imports: []string{"os", modulePath + "/internal/cond", modulePath + "/internal/extexec"}},
		{ImportPath: modulePath + "/cmd/yadm-bad", Imports: []string{modulePath + "/internal/rules", modulePath + "/internal/store"}},
		{ImportPath: modulePath + "/cmd/yadm-good/gen", Imports: []string{modulePath + "/internal/crypt"}},
		{ImportPath: modulePath + "/cmd/yadm-oracle/sub", Imports: []string{modulePath + "/internal/oracle"}},
	}
	got := boundaryViolations(pkgs)
	if len(got) != 2 || !strings.Contains(got[0], "yadm-bad imports "+modulePath+"/internal/store") || !strings.Contains(got[1], "yadm-good/gen imports "+modulePath+"/internal/crypt") {
		t.Fatalf("violations = %q, want yadm-bad's store and yadm-good/gen's crypt imports", got)
	}
}
