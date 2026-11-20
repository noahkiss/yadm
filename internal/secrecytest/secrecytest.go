package secrecytest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Canary is a unique, random marker planted in enclave plaintext.
type Canary struct {
	Label string
	value []byte
}

// NewCanary returns a fresh canary. The label shows up in failure messages only.
func NewCanary(t testing.TB, label string) Canary {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return Canary{Label: label, value: []byte("YADM-CANARY-" + hex.EncodeToString(b))}
}

// Bytes returns the canary marker.
func (c Canary) Bytes() []byte { return c.value }

// String returns the canary marker.
func (c Canary) String() string { return string(c.value) }

// Finding is one place a canary was found.
type Finding struct {
	Canary string
	Where  string
}

// ScanTree returns every regular file under root whose bytes contain a canary.
// Symlinks are not followed.
func ScanTree(root string, canaries ...Canary) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, c := range canaries {
			if bytes.Contains(b, c.value) {
				out = append(out, Finding{Canary: c.Label, Where: p})
			}
		}
		return nil
	})
	return out, err
}

// ScanRepo returns every place in a git repository (bare or not) where a
// canary appears: any object (inflated), any ref name, the config, and any
// raw file under the git directory. The worktree of a non-bare repository is
// not scanned; use ScanTree for it.
func ScanRepo(repo string, canaries ...Canary) ([]Finding, error) {
	var out []Finding
	gitDir, err := gitOut(repo, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return nil, err
	}
	gitDir = strings.TrimSpace(gitDir)

	objs, err := gitOut(repo, "cat-file", "--batch-all-objects", "--batch", "--unordered")
	if err != nil {
		return nil, err
	}
	for _, c := range canaries {
		if bytes.Contains([]byte(objs), c.value) {
			out = append(out, Finding{Canary: c.Label, Where: repo + ": object store"})
		}
	}
	refs, err := gitOut(repo, "for-each-ref", "--format=%(refname)")
	if err != nil {
		return nil, err
	}
	for _, c := range canaries {
		if strings.Contains(refs, c.String()) {
			out = append(out, Finding{Canary: c.Label, Where: repo + ": ref names"})
		}
	}
	raw, err := ScanTree(gitDir, canaries...)
	if err != nil {
		return nil, err
	}
	out = append(out, raw...)
	return out, nil
}

// SecrecyConfigProblems lists repository settings that can leak plaintext into
// the object store: any diff.*.cachetextconv set to true, and any ref under
// refs/notes/textconv.
func SecrecyConfigProblems(repo string) ([]string, error) {
	var out []string
	cfg, _ := gitOut(repo, "config", "--get-regexp", `^diff\..*\.cachetextconv$`)
	for _, line := range strings.Split(strings.TrimSpace(cfg), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.EqualFold(f[1], "true") {
			out = append(out, "config "+f[0]+" = true")
		}
	}
	refs, err := gitOut(repo, "for-each-ref", "--format=%(refname)", "refs/notes/textconv")
	if err != nil {
		return nil, err
	}
	for _, r := range strings.Fields(refs) {
		out = append(out, "ref "+r)
	}
	return out, nil
}

// AssertTreeClean fails the test if any canary appears under root (a
// non-member's $HOME, a sandbox, a state directory).
func AssertTreeClean(t testing.TB, root string, canaries ...Canary) {
	t.Helper()
	f, err := ScanTree(root, canaries...)
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	for _, x := range f {
		t.Errorf("enclave %q plaintext reached %s", x.Canary, x.Where)
	}
}

// AssertRepoClean fails the test if any canary appears in the repository's
// object store, refs or git directory, or if the repository enables a
// plaintext-caching setting.
func AssertRepoClean(t testing.TB, repo string, canaries ...Canary) {
	t.Helper()
	f, err := ScanRepo(repo, canaries...)
	if err != nil {
		t.Fatalf("scan %s: %v", repo, err)
	}
	for _, x := range f {
		t.Errorf("enclave %q plaintext reached %s", x.Canary, x.Where)
	}
	p, err := SecrecyConfigProblems(repo)
	if err != nil {
		t.Fatalf("config %s: %v", repo, err)
	}
	for _, x := range p {
		t.Errorf("%s: plaintext-caching setting present: %s", repo, x)
	}
}

func gitOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	b, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return string(b), &gitError{args: args, stderr: string(ee.Stderr)}
		}
		return string(b), err
	}
	return string(b), nil
}

type gitError struct {
	args   []string
	stderr string
}

func (e *gitError) Error() string { return "git " + strings.Join(e.args, " ") + ": " + e.stderr }
