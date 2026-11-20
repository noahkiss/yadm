package crypt_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

var _ rules.Sealer = (*crypt.Set)(nil)

// git runs git hermetically: no user or system config, fixed identity, no signing.
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Env = append(os.Environ(),
		"HOME="+home, "XDG_CONFIG_HOME="+home,
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestSealedFixtureRepoIsClean commits the sealed fixture source tree, clones
// it bare, and proves no enclave canary reaches the tree, the object store or
// the clone, while members can still read every sealed part back.
func TestSealedFixtureRepoIsClean(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	f := fixture.Build(t)
	canaries := f.AllCanaries()

	// Positive controls: the canaries really are inside the sealed parts.
	set := &crypt.Set{Rings: f.Rings}
	blob, err := os.ReadFile(filepath.Join(f.Root, "sealed", "personal", ".config", "notes", "private.md"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := f.Rings["personal"].OpenFile(blob)
	if err != nil || !bytes.Contains(pt, f.Canaries["personal"].Bytes()) {
		t.Fatalf("member cannot read the sealed file back: %v", err)
	}
	blob, _ = os.ReadFile(filepath.Join(f.Root, "sealed", "client", ".config", "client-tool", "token"))
	if pt, err := f.Rings["client"].OpenFile(blob); err != nil || !bytes.Contains(pt, f.Canaries["client"].Bytes()) {
		t.Fatalf("client file: %v", err)
	}
	settings, _ := os.ReadFile(filepath.Join(f.Root, "files", ".config", "editor", "settings.json"))
	tok := regexp.MustCompile(`yadm:1:[^"]+`).Find(settings)
	if pt, err := set.OpenValue("personal", "sync.token", string(tok)); err != nil || !bytes.Contains(pt, f.Canaries["personal"].Bytes()) {
		t.Fatalf("sealed value: %v", err)
	}
	sshcfg, _ := os.ReadFile(filepath.Join(f.Root, "files", ".ssh", "config"))
	rtok := regexp.MustCompile(`yadm:sealed 1 \d+ \S+`).Find(sshcfg)
	if pt, err := set.OpenRegion("personal", "hosts", string(rtok)); err != nil || !bytes.Contains(pt, f.Canaries["personal"].Bytes()) {
		t.Fatalf("sealed region: %v", err)
	}

	// A non-member loads the same logs and can open nothing.
	logs := map[model.EnclaveName][]crypt.LogEntry{}
	for e, l := range f.Logs {
		logs[e] = l
	}
	outsider, loads, err := crypt.LoadSet(logs, crypt.FilePins(t.TempDir()), f.Identities[fixture.HostB])
	if err != nil {
		t.Fatal(err)
	}
	for e, l := range loads {
		if l.Err != nil || l.Member || outsider.CanOpen(e) {
			t.Fatalf("non-member load of %s: %+v", e, l)
		}
	}
	if _, err := outsider.OpenValue("personal", "sync.token", string(tok)); !errors.Is(err, crypt.ErrNotMember) {
		t.Fatalf("non-member opened a value: %v", err)
	}
	// HostC is a member of client only: its ring must not open personal data.
	if _, err := crypt.Open(f.Logs["personal"][len(f.Logs["personal"])-1], f.Identities[fixture.HostC]); !errors.Is(err, crypt.ErrNotMember) {
		t.Fatalf("client member opened personal: %v", err)
	}

	// The tree, the repository and a bare clone hold no canary.
	secrecytest.AssertTreeClean(t, f.Root, canaries...)
	git(t, f.Root, "init", "-q")
	git(t, f.Root, "add", "-A")
	git(t, f.Root, "commit", "-q", "-m", "fixture")
	bare := filepath.Join(t.TempDir(), "remote.git")
	git(t, f.Root, "clone", "-q", "--bare", f.Root, bare)
	secrecytest.AssertRepoClean(t, f.Root, canaries...)
	secrecytest.AssertRepoClean(t, bare, canaries...)

	// Control: the scan would have caught plaintext in the store.
	leak := t.TempDir()
	git(t, leak, "init", "-q")
	os.WriteFile(filepath.Join(leak, "x"), pt, 0o644)
	git(t, leak, "add", "-A")
	git(t, leak, "commit", "-q", "-m", "leak")
	if found, err := secrecytest.ScanRepo(leak, canaries...); err != nil || len(found) == 0 {
		t.Fatalf("scan control found nothing: %v", err)
	}
}
