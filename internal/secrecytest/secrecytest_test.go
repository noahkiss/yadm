package secrecytest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, b)
	}
	return strings.TrimSpace(string(b))
}

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	return dir
}

func commitFile(t *testing.T, repo, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", name)
	git(t, repo, "commit", "-q", "-m", "add "+name)
}

func TestScanRepoFindsCompressedObjects(t *testing.T) {
	c := NewCanary(t, "enclave-a")
	repo := newRepo(t)
	commitFile(t, repo, "secret.txt", "token = "+c.String()+"\n")
	// Remove the worktree copy and the index so only the object store holds it.
	os.Remove(filepath.Join(repo, "secret.txt"))
	os.Remove(filepath.Join(repo, ".git", "index"))

	raw, err := ScanTree(filepath.Join(repo, ".git"), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Fatalf("expected zlib to hide the canary from a raw scan, got %v", raw)
	}
	f, err := ScanRepo(repo, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) == 0 {
		t.Fatal("ScanRepo missed a canary inside a loose object")
	}

	git(t, repo, "gc", "-q")
	f, err = ScanRepo(repo, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) == 0 {
		t.Fatal("ScanRepo missed a canary inside a pack")
	}
}

func TestScanRepoCleanRepo(t *testing.T) {
	c := NewCanary(t, "enclave-a")
	repo := newRepo(t)
	commitFile(t, repo, "public.txt", "nothing secret\n")
	AssertRepoClean(t, repo, c)
}

func TestScanTree(t *testing.T) {
	c := NewCanary(t, "enclave-a")
	other := NewCanary(t, "enclave-b")
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".config", "app"), 0o755)
	os.WriteFile(filepath.Join(home, ".config", "app", "x.json"), []byte(`{"k":"`+c.String()+`"}`), 0o600)
	f, err := ScanTree(home, c, other)
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Canary != "enclave-a" {
		t.Fatalf("findings: %v", f)
	}
}

func TestSecrecyConfigProblems(t *testing.T) {
	repo := newRepo(t)
	commitFile(t, repo, "a.txt", "a\n")
	if p, err := SecrecyConfigProblems(repo); err != nil || len(p) != 0 {
		t.Fatalf("clean repo: %v %v", p, err)
	}
	git(t, repo, "config", "diff.sealed.cachetextconv", "true")
	head := git(t, repo, "rev-parse", "HEAD")
	git(t, repo, "update-ref", "refs/notes/textconv/sealed", head)
	p, err := SecrecyConfigProblems(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 2 {
		t.Fatalf("want config and ref problems, got %v", p)
	}
}

func TestCanariesAreUnique(t *testing.T) {
	if NewCanary(t, "x").String() == NewCanary(t, "x").String() {
		t.Fatal("canaries repeat")
	}
}
