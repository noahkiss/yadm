package cli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// transcryptBlob writes plaintext the way transcrypt's clean filter does:
// base64 of "Salted__", the salt and AES-256-CBC (EVP_BytesToKey, MD5).
func transcryptBlob(pt []byte, password string, salt [8]byte) []byte {
	var kv, prev []byte
	for len(kv) < 48 {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		h.Write(salt[:])
		prev = h.Sum(nil)
		kv = append(kv, prev...)
	}
	block, _ := aes.NewCipher(kv[:32])
	n := aes.BlockSize - len(pt)%aes.BlockSize
	padded := append(append([]byte{}, pt...), bytes.Repeat([]byte{byte(n)}, n)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, kv[32:48]).CryptBlocks(ct, padded)
	return []byte(base64.StdEncoding.EncodeToString(append(append([]byte("Salted__"), salt[:]...), ct...)) + "\n")
}

// TestImportSealsThroughCLI runs a sealing import through Main. Until the
// importer passes source paths to its Sealer it must refuse cleanly; then the output
// holds the enclave's key log on top of the import commit, a clean worktree,
// and no plaintext anywhere.
func TestImportSealsThroughCLI(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, e2eTree())
	useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")

	c := secrecytest.NewCanary(t, "personal")
	legacy := filepath.Join(root, "legacy")
	git(t, root, "init", "-q", "-b", "main", legacy)
	writeFile(t, filepath.Join(legacy, ".gitattributes"), ".config/secret.txt filter=crypt diff=crypt merge=crypt -text\n")
	writeFile(t, filepath.Join(legacy, ".config/secret.txt"), string(transcryptBlob(append(c.Bytes(), '\n'), "pw", [8]byte{1, 2, 3, 4, 5, 6, 7, 8})))
	writeFile(t, filepath.Join(legacy, ".profile"), "export A=1\n")
	git(t, legacy, "add", "-A")
	git(t, legacy, "commit", "-q", "-m", "legacy")
	t.Setenv("LEGACY_PW", "pw")

	out := filepath.Join(root, "out")
	env, code, raw := yadm(t, "import", legacy, "--output", out, "--password-env", "LEGACY_PW", "--default-enclave", "personal", "--new-recovery", filepath.Join(root, "recovery"))
	if code != ExitOK {
		t.Fatalf("import: exit %d\n%s", code, raw)
	}
	if strings.Contains(string(raw), c.String()) {
		t.Fatal("the import output printed plaintext")
	}
	d := decode[importData](t, env.Data)
	if d.KeyLogs["personal"] == "" || d.Commit == "" {
		t.Fatalf("import data: %+v", d)
	}
	if head := git(t, out, "rev-parse", "HEAD"); head != string(d.Commit) {
		t.Fatalf("branch at %s, report says %s", head, d.Commit)
	}
	if st := git(t, out, "status", "--porcelain"); st != "" {
		t.Fatalf("output worktree is not clean:\n%s", st)
	}
	b, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(string(crypt.LogPath("personal", 1)))))
	if err != nil {
		t.Fatal(err)
	}
	le, err := crypt.ParseLogEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := crypt.PinOf(le)
	if _, err := crypt.VerifyLog([]crypt.LogEntry{le}, &pin); err != nil {
		t.Fatal(err)
	}
	if fp, _ := crypt.Fingerprint(le); fp != d.KeyLogs["personal"] {
		t.Fatalf("fingerprint %s, report %s", fp, d.KeyLogs["personal"])
	}
	sealed := false
	for _, m := range d.Mappings {
		if m.Sealed && strings.HasPrefix(string(m.Source), "sealed/personal/") {
			sealed = true
		}
	}
	if !sealed {
		t.Fatalf("no sealed mapping: %+v", d.Mappings)
	}
	// The member (this machine) opens the sealed file at its source path.
	p, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypt.LoadIdentity(p.State)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := crypt.Open(le, id)
	if err != nil {
		t.Fatal(err)
	}
	src := "sealed/personal/.config/secret.txt"
	blob, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(src)))
	if err != nil {
		t.Fatal(err)
	}
	if !crypt.IsSealedFile(blob) {
		t.Fatal("sealed source is not a sealed container")
	}
	pt, err := ring.OpenFile(model.SourcePath(src), blob)
	if err != nil || string(pt) != string(c.Bytes())+"\n" {
		t.Fatalf("member cannot open the imported file: %v", err)
	}
	secrecytest.AssertRepoClean(t, out, c)
	secrecytest.AssertTreeClean(t, out, c)
}

// TestImportCryptFilterFlag: a file marked with a custom transcrypt filter
// that the legacy config does not declare refuses the import; with
// --crypt-filter it is treated as encrypted (here it then needs the
// password, which the dry run does not give).
func TestImportCryptFilterFlag(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy")
	git(t, root, "init", "-q", "-b", "main", legacy)
	writeFile(t, filepath.Join(legacy, ".gitattributes"), ".config/secret.txt filter=vault diff=vault merge=vault -text\n")
	writeFile(t, filepath.Join(legacy, ".config/secret.txt"), string(transcryptBlob([]byte("s\n"), "pw", [8]byte{1, 2, 3, 4, 5, 6, 7, 8})))
	git(t, legacy, "add", "-A")
	git(t, legacy, "commit", "-q", "-m", "legacy")

	_, code, raw := yadm(t, "import", legacy, "--dry-run")
	if code == ExitOK || !strings.Contains(string(raw), "not marked with a transcrypt filter") {
		t.Fatalf("unknown crypt filter: exit %d\n%s", code, raw)
	}
	_, code, raw = yadm(t, "import", legacy, "--dry-run", "--crypt-filter", "other", "--crypt-filter", "vault")
	if code == ExitOK || strings.Contains(string(raw), "not marked with a transcrypt filter") || !strings.Contains(string(raw), "password") {
		t.Fatalf("--crypt-filter vault: exit %d\n%s", code, raw)
	}
}

// TestImportStripFilterFlag: a legacy strip filter without --filters fails
// the import; with a filters file it becomes the entry's rules.
func TestImportStripFilterFlag(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy")
	git(t, root, "init", "-q", "-b", "main", legacy)
	writeFile(t, filepath.Join(legacy, ".gitattributes"), ".config/app/settings.json filter=strip-runtime\n")
	writeFile(t, filepath.Join(legacy, ".config/app/settings.json"), "{\n  \"theme\": \"dark\"\n}\n")
	git(t, legacy, "add", "-A")
	git(t, legacy, "commit", "-q", "-m", "legacy")

	_, code, raw := yadm(t, "import", legacy, "--dry-run")
	if code == ExitOK || !strings.Contains(string(raw), "strip-runtime") {
		t.Fatalf("unmapped strip filter: exit %d\n%s", code, raw)
	}
	ff := filepath.Join(root, "filters.toml")
	writeFile(t, ff, "[filters.strip-runtime.paths.\".config/app/settings.json\"]\ndrop = [\"model\"]\n")
	out := filepath.Join(root, "out")
	if _, code, raw := yadm(t, "import", legacy, "--output", out, "--filters", ff); code != ExitOK {
		t.Fatalf("import: exit %d\n%s", code, raw)
	}
	b, err := os.ReadFile(filepath.Join(out, "manifest.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `format = "json"`) || !strings.Contains(string(b), `drop = ["model"]`) {
		t.Fatalf("manifest lacks the strip rule:\n%s", b)
	}
	if _, code, _ := yadm(t, "import", legacy, "--dry-run", "--filters", filepath.Join(root, "missing.toml")); code != ExitUsage {
		t.Fatalf("missing filters file: exit %d", code)
	}
}

// TestCheckFlagsGitConfig: check fails the secrecy item on a textconv cache
// and the drivers item on a filter or merge driver in git config.
func TestCheckFlagsGitConfig(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, e2eTree())
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")
	git(t, a.Source, "config", "filter.x.smudge", "cat")
	git(t, a.Source, "config", "merge.y.driver", "true")
	git(t, a.Source, "config", "diff.z.cachetextconv", "true")
	env, code, _ := yadm(t, "check")
	if code != ExitError {
		t.Fatalf("check: exit %d", code)
	}
	items := map[string]checkItem{}
	for _, c := range decode[map[string][]checkItem](t, env.Data)["checks"] {
		items[c.Name] = c
	}
	if c := items["secrecy_config"]; c.OK || !strings.Contains(c.Detail, "diff.z.cachetextconv") {
		t.Fatalf("secrecy_config: %+v", c)
	}
	if c := items["git_drivers"]; c.OK || !strings.Contains(c.Detail, "filter.x.smudge") || !strings.Contains(c.Detail, "merge.y.driver") {
		t.Fatalf("git_drivers: %+v", c)
	}
	if !items["identity"].OK || !items["manifest"].OK {
		t.Fatalf("checks: %+v", items)
	}
}
