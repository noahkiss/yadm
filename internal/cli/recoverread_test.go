package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

const privateNotes = ".config/notes/private.md"

// recoverWorld is the no-member case: a plain clone of the fixture remote,
// no "yadm init", and the recovery identity restored into a 0700 directory.
type recoverWorld struct {
	root, remote, clone, recDir string
	fx                          *fixture.Fixture
}

func newRecoverWorld(t *testing.T) *recoverWorld {
	t.Helper()
	hermetic(t)
	w := &recoverWorld{root: t.TempDir(), fx: fixture.Build(t)}
	useMachine(t, w.root, "fresh") // $HOME and every XDG directory inside the test
	w.remote = fixtureRemote(t, w.root, w.fx)
	w.clone = filepath.Join(w.root, "clone")
	git(t, w.root, "clone", "-q", w.remote, w.clone)
	w.recDir = filepath.Join(w.root, "offline", "rec")
	if err := w.fx.Recovery.Save(w.recDir); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *recoverWorld) key() string { return filepath.Join(w.recDir, crypt.AgeIdentityFile) }

// recoverArgs builds a recover command line against the clone.
func (w *recoverWorld) recoverArgs(enc, key, out string, extra ...string) []string {
	return append([]string{"enclave", "recover", enc, "--read-only", "--identity", key, "--out", out, "--repo", w.clone}, extra...)
}

// commitClone writes files into the clone (nil content deletes) and commits.
func commitClone(t *testing.T, clone string, files map[string][]byte, msg string) {
	t.Helper()
	for p, b := range files {
		full := filepath.Join(clone, filepath.FromSlash(p))
		if b == nil {
			if err := os.RemoveAll(full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, clone, "add", "-A")
	git(t, clone, "commit", "-q", "-m", msg)
}

// treeState records every file and directory under dirs (mode, size and
// hash), so a test can prove a command wrote nothing there.
func treeState(t *testing.T, skip string, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if skip != "" && (p == skip || strings.HasPrefix(p, skip+string(filepath.Separator))) {
				return filepath.SkipDir
			}
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			v := fi.Mode().String() // a directory's size changes with its entries, which are recorded
			if fi.Mode().IsRegular() {
				v += fmt.Sprintf(" %d", fi.Size())
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				h := sha256.Sum256(b)
				v += " " + hex.EncodeToString(h[:])
			}
			out[p] = v
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func sameState(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	for p, v := range after {
		if before[p] != v {
			t.Errorf("%s: %s changed or appeared: %q -> %q", what, p, before[p], v)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("%s: %s disappeared", what, p)
		}
	}
}

func assertNoOut(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("a refused recover created %s", out)
	}
}

// TestRecoverReadRoundTrip: with no member machine and no init, the
// recovery identity reads the enclave's sealed files into a new 0700
// directory, files 0600. It writes nothing else: the clone with its .git,
// the remote, $HOME and the identity directory stay byte for byte, and the
// canary reaches no repository and no $HOME. --expect anchors the log;
// paths, stdin and --out - work.
func TestRecoverReadRoundTrip(t *testing.T) {
	w := newRecoverWorld(t)
	c := w.fx.Canaries["personal"]
	home, _ := os.UserHomeDir()
	out := filepath.Join(w.root, "plain", "personal")
	before := treeState(t, "", w.clone, w.remote, home, w.recDir)

	env := yadmOK(t, w.recoverArgs("personal", w.key(), out)...)
	d := decode[recoverData](t, env.Data)
	root, _ := crypt.Fingerprint(w.fx.Logs["personal"][0])
	if d.Anchored || d.Root != root || len(d.Files) != 1 || d.Files[0] != privateNotes || d.Out != out {
		t.Fatalf("data: %+v", d)
	}
	got := readFile(t, filepath.Join(out, filepath.FromSlash(privateNotes)))
	if !strings.Contains(got, c.String()) || !strings.HasPrefix(got, "# Private notes") {
		t.Fatalf("plaintext: %q", got)
	}
	for _, p := range []string{out, filepath.Join(out, ".config"), filepath.Join(out, ".config", "notes")} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(out, filepath.FromSlash(privateNotes))); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", fi.Mode())
	}
	if strings.Contains(fmt.Sprint(env.Data), c.String()) {
		t.Fatal("the JSON envelope carries plaintext")
	}
	sameState(t, "recover", before, treeState(t, "", w.clone, w.remote, home, w.recDir))
	for _, r := range []string{w.clone, w.remote} {
		secrecytest.AssertRepoClean(t, r, w.fx.AllCanaries()...)
	}
	secrecytest.AssertTreeClean(t, home, w.fx.AllCanaries()...)
	// Only the named enclave's files are written.
	secrecytest.AssertTreeClean(t, out, w.fx.Canaries["client"])

	// --expect with entry 1's fingerprint anchors the log; a path selects.
	out2 := filepath.Join(w.root, "plain", "anchored")
	env = yadmOK(t, w.recoverArgs("personal", w.key(), out2, "--expect", strings.ToUpper(root), "~/.config/notes")...)
	if d := decode[recoverData](t, env.Data); !d.Anchored || len(d.Files) != 1 {
		t.Fatalf("anchored: %+v", d)
	}
	if _, code, _ := yadm(t, w.recoverArgs("personal", w.key(), filepath.Join(w.root, "plain", "none"), ".config/missing")...); code == ExitOK {
		t.Fatal("a path that matches no sealed file succeeded")
	}
	assertNoOut(t, filepath.Join(w.root, "plain", "none"))

	// The key from stdin, the file to stdout; the human text warns when the
	// log is not anchored.
	key, err := os.ReadFile(w.key())
	if err != nil {
		t.Fatal(err)
	}
	saved := hooks.stdin
	t.Cleanup(func() { hooks.stdin = saved })
	hooks.stdin = func() io.Reader { return bytes.NewReader(key) }
	stdout, stderr, code := yadmRaw(t, w.recoverArgs("personal", "-", "-", privateNotes)...)
	if code != ExitOK || stdout != got || !strings.Contains(stderr, "not anchored") {
		t.Fatalf("stdout: exit %d %q stderr %q", code, stdout, stderr)
	}
	hooks.stdin = func() io.Reader { return bytes.NewReader(key) }
	if _, code, _ := yadm(t, w.recoverArgs("personal", "-", "-")...); code != ExitOK {
		t.Fatalf("--out - with the enclave's only file: exit %d", code)
	}
	sameState(t, "recover to stdout", before, treeState(t, "", w.clone, w.remote, home, w.recDir))
}

// TestRecoverReadRefusals: recover needs --read-only, and refuses a wrong
// or loose identity, another enclave's recovery identity, a member's key,
// and an --out that exists or lies in the clone or yadm's directories. A
// refusal creates nothing.
func TestRecoverReadRefusals(t *testing.T) {
	w := newRecoverWorld(t)
	out := filepath.Join(w.root, "plain")

	args := []string{"enclave", "recover", "personal", "--identity", w.key(), "--out", out, "--repo", w.clone}
	if env, code, _ := yadm(t, args...); code != ExitNotImplemented || !strings.Contains(env.Error.Message, "--read-only") {
		t.Fatalf("without --read-only: exit %d %+v", code, env.Error)
	}
	assertNoOut(t, out)

	// A second enclave with its own recovery identity.
	vrec, err := crypt.GenerateIdentity(crypt.RecoveryMachine)
	if err != nil {
		t.Fatal(err)
	}
	vhead, vring, err := crypt.Create("vault", w.fx.Identities[fixture.HostA], vrec.Member(), crypt.MemPins())
	if err != nil {
		t.Fatal(err)
	}
	vlog, err := crypt.MarshalLogEntry(vhead)
	if err != nil {
		t.Fatal(err)
	}
	vct, err := vring.SealFile("sealed/vault/.vault/key", []byte("vault secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	commitClone(t, w.clone, map[string][]byte{string(crypt.LogPath("vault", 1)): vlog, "sealed/vault/.vault/key": vct}, "vault")
	vdir := filepath.Join(w.root, "offline", "vault")
	if err := vrec.Save(vdir); err != nil {
		t.Fatal(err)
	}
	vkey := filepath.Join(vdir, crypt.AgeIdentityFile)
	yadmOK(t, w.recoverArgs("vault", vkey, filepath.Join(w.root, "vault-out"))...)
	if got := readFile(t, filepath.Join(w.root, "vault-out", ".vault", "key")); got != "vault secret\n" {
		t.Fatalf("vault: %q", got)
	}

	memberDir := filepath.Join(w.root, "offline", "member")
	if err := w.fx.Identities[fixture.HostA].Save(memberDir); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, enc, key string }{
		{"personal's identity on vault", "vault", w.key()},
		{"vault's identity on personal", "personal", vkey},
		{"a member's key", "personal", filepath.Join(memberDir, crypt.AgeIdentityFile)},
	} {
		if env, code, _ := yadm(t, w.recoverArgs(c.enc, c.key, out)...); code != ExitRefused {
			t.Fatalf("%s: exit %d %+v", c.name, code, env.Error)
		}
		assertNoOut(t, out)
	}
	if err := os.Chmod(w.key(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code, _ := yadm(t, w.recoverArgs("personal", w.key(), out)...); code != ExitRefused {
		t.Fatalf("a world-readable identity: exit %d", code)
	}
	assertNoOut(t, out)
	if err := os.Chmod(w.key(), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{filepath.Join(w.clone, "plain"), filepath.Join(w.clone, ".git", "plain"), filepath.Join(p.State, "plain"), filepath.Join(w.root, "vault-out")} {
		if env, code, _ := yadm(t, w.recoverArgs("personal", w.key(), bad)...); code != ExitUsage {
			t.Fatalf("--out %s: exit %d %+v", bad, code, env.Error)
		}
	}
	assertNoOut(t, filepath.Join(w.clone, "plain"))
	if _, code, _ := yadm(t, w.recoverArgs("personal", w.key(), out, "../escape")...); code != ExitUsage {
		t.Fatalf("a path outside $HOME: exit %d", code)
	}
	if _, code, _ := yadm(t, "enclave", "recover", "personal", "--read-only", "--out", out, "--repo", w.clone); code != ExitUsage {
		t.Fatalf("no --identity: exit %d", code)
	}
	assertNoOut(t, out)
	secrecytest.AssertRepoClean(t, w.clone, w.fx.AllCanaries()...)
}

// TestRecoverReadForgedLog: a writer replaces the key log with its own,
// naming the genuine recovery recipient and wrapping keys it chose. The
// genuine sealed files never open under those keys, so recover writes
// nothing, even when the writer also replaced some of the files. When it
// replaced every file, the read succeeds but reports itself not anchored,
// and --expect with the genuine fingerprint refuses it.
func TestRecoverReadForgedLog(t *testing.T) {
	w := newRecoverWorld(t)
	genuineRoot, _ := crypt.Fingerprint(w.fx.Logs["personal"][0])
	second := ".config/notes/second.md"
	ct2, err := w.fx.Rings["personal"].SealFile(model.SourcePath("sealed/personal/"+second), []byte("second "+w.fx.Canaries["personal"].String()+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	commitClone(t, w.clone, map[string][]byte{"sealed/personal/" + second: ct2}, "second sealed file")

	x, err := crypt.GenerateIdentity("m-attacker")
	if err != nil {
		t.Fatal(err)
	}
	forged, xring, err := crypt.Create("personal", x, w.fx.Recovery.Member(), crypt.MemPins())
	if err != nil {
		t.Fatal(err)
	}
	flog, err := crypt.MarshalLogEntry(forged)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"keys/personal": nil}
	commitClone(t, w.clone, files, "drop the log")
	commitClone(t, w.clone, map[string][]byte{string(crypt.LogPath("personal", 1)): flog}, "forged log")

	out := filepath.Join(w.root, "plain")
	env, code, _ := yadm(t, w.recoverArgs("personal", w.key(), out)...)
	if code != ExitRefused || !strings.Contains(env.Error.Message, "nothing was written") {
		t.Fatalf("forged log, genuine files: exit %d %+v", code, env.Error)
	}
	assertNoOut(t, out)

	evil, err := xring.SealFile(model.SourcePath("sealed/personal/"+privateNotes), []byte("attacker guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	commitClone(t, w.clone, map[string][]byte{"sealed/personal/" + privateNotes: evil}, "replace one file")
	if _, code, _ := yadm(t, w.recoverArgs("personal", w.key(), out)...); code != ExitRefused {
		t.Fatalf("forged log, one genuine file left: exit %d", code)
	}
	assertNoOut(t, out)
	// Naming only the replaced file is the attack a writer can win
	// without a pin: the output says it is not anchored.
	env = yadmOK(t, w.recoverArgs("personal", w.key(), out, privateNotes)...)
	if d := decode[recoverData](t, env.Data); d.Anchored {
		t.Fatalf("a forged read claims to be anchored: %+v", d)
	}
	if env, code, _ := yadm(t, w.recoverArgs("personal", w.key(), filepath.Join(w.root, "anchored"), "--expect", genuineRoot, privateNotes)...); code != ExitRefused {
		t.Fatalf("--expect on a forged log: exit %d %+v", code, env.Error)
	}
	assertNoOut(t, filepath.Join(w.root, "anchored"))
	secrecytest.AssertRepoClean(t, w.clone, w.fx.AllCanaries()...)
}

// TestRecoverReadManagedOut: on a set-up machine, --out inside $HOME must
// hold no path the manifest manages; elsewhere in $HOME it works, and the
// source clone and state directory stay unchanged.
func TestRecoverReadManagedOut(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	recDir := filepath.Join(root, "offline", "rec")
	if err := fx.Recovery.Save(recDir); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(recDir, crypt.AgeIdentityFile)
	managed := filepath.Join(b.Home, ".config", "shell", "rec")
	if env, code, _ := yadm(t, "enclave", "recover", "personal", "--read-only", "--identity", key, "--out", managed); code != ExitUsage || !strings.Contains(env.Error.Message, "manages") {
		t.Fatalf("managed --out: exit %d %+v", code, env.Error)
	}
	assertNoOut(t, managed)
	out := filepath.Join(b.Home, "recovered")
	before := treeState(t, out, b.Home, b.Source, b.State)
	yadmOK(t, "enclave", "recover", "personal", "--read-only", "--identity", key, "--out", out)
	if !strings.Contains(readFile(t, filepath.Join(out, filepath.FromSlash(privateNotes))), fx.Canaries["personal"].String()) {
		t.Fatal("no plaintext in --out")
	}
	sameState(t, "set-up machine", before, treeState(t, out, b.Home, b.Source, b.State))
	secrecytest.AssertRepoClean(t, b.Source, fx.AllCanaries()...)
	secrecytest.AssertRepoClean(t, remote, fx.AllCanaries()...)
}

// TestRecoverReadNewMachine: a machine set up with "yadm init" after every
// member is gone, not in fleet.toml and pinned to nothing, cannot load its
// manifest, so recover refuses an --out inside its $HOME and reads into one
// outside it, from its own source clone.
func TestRecoverReadNewMachine(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	m := useMachine(t, root, "newhost")
	yadmOK(t, "init", remote, "--machine", "host-new", "--no-schedule")
	recDir := filepath.Join(root, "offline", "rec")
	if err := fx.Recovery.Save(recDir); err != nil {
		t.Fatal(err)
	}
	root1, _ := crypt.Fingerprint(fx.Logs["personal"][0])
	key := filepath.Join(recDir, crypt.AgeIdentityFile)
	inHome := filepath.Join(m.Home, "personal-plain")
	if env, code, _ := yadm(t, "enclave", "recover", "personal", "--read-only", "--identity", key, "--out", inHome); code == ExitOK || !strings.Contains(env.Error.Message, "outside $HOME") {
		t.Fatalf("--out in $HOME without a manifest: exit %d %+v", code, env.Error)
	}
	assertNoOut(t, inHome)
	out := filepath.Join(root, "plain")
	before := treeState(t, "", m.Home)
	env := yadmOK(t, "enclave", "recover", "personal", "--read-only", "--identity", key, "--expect", root1, "--out", out)
	want, _ := filepath.EvalSymlinks(m.Source)
	if d := decode[recoverData](t, env.Data); !d.Anchored || d.Repo != want {
		t.Fatalf("data: %+v", d)
	}
	if !strings.Contains(readFile(t, filepath.Join(out, filepath.FromSlash(privateNotes))), fx.Canaries["personal"].String()) {
		t.Fatal("no plaintext in --out")
	}
	sameState(t, "new machine", before, treeState(t, "", m.Home))
	secrecytest.AssertRepoClean(t, m.Source, fx.AllCanaries()...)
	secrecytest.AssertRepoClean(t, remote, fx.AllCanaries()...)
}
