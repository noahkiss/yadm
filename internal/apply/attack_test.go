package apply

// Regression tests for attacks found in a security review. The attacker is
// a machine with push access that is not a member of "personal"; it edits
// only manifest.toml, or plants sealed blobs. The victim is a member. Before
// the fixes, each attack staged plaintext for commit or delivered forged
// content.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

func scanCapture(t *testing.T, w *world) Capture {
	t.Helper()
	ds, err := w.eng.Scan(context.Background(), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := w.eng.Capture(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func leakedIn(cp Capture, c secrecytest.Canary) *store.Change {
	for i, ch := range cp.Changes {
		if bytes.Contains(ch.Blob, c.Bytes()) {
			return &cp.Changes[i]
		}
	}
	return nil
}

func holdFor(hs []model.Hold, t model.Target, r model.HoldReason) *model.Hold {
	for i, h := range hs {
		if h.Target == t && h.Reason == r {
			return &hs[i]
		}
	}
	return nil
}

// useRealCrypto makes the world use package rules and a real crypt.Set.
func useRealCrypto(t *testing.T, w *world, set *crypt.Set) {
	t.Helper()
	real := SetCrypto(set)
	w.eng.Rules = pkgRules{}
	w.eng.LoadSnapshot = func(ctx context.Context, rev model.CommitID) (*Snapshot, error) {
		s, err := w.load(ctx, rev)
		if s != nil {
			s.Crypto = real
		}
		return s, err
	}
}

func realRing(t *testing.T) (*crypt.Keyring, crypt.LogEntry, *crypt.Identity, crypt.PinStore) {
	t.Helper()
	id, err := crypt.GenerateIdentity("m-test01")
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := crypt.GenerateIdentity(crypt.RecoveryMachine)
	pins := crypt.MemPins()
	head, ring, err := crypt.Create("personal", id, rec.Member(), pins)
	if err != nil {
		t.Fatal(err)
	}
	return ring, head, id, pins
}

// commitRaw records a commit whose files are stored as given: sealed/
// blobs are not sealed again.
func (w *world) commitRaw(files map[model.SourcePath][]byte, entries ...manifest.Entry) model.CommitID {
	w.n++
	id := model.CommitID(fmt.Sprintf("%040d", w.n))
	tree := map[model.SourcePath][]byte{}
	for p, b := range files {
		tree[p] = b
		w.st.blobs[blobID(b)] = b
	}
	w.st.commits[id] = tree
	w.st.head = id
	w.plans[id] = &manifest.Manifest{Schema: 1, Entries: entries}
	return id
}

// A pusher adds a plain [[root]] over ~/.ssh. Nothing is captured until the
// user allows the root, and a file that was there before is never captured.
func TestAttackNewPlainRoot(t *testing.T) {
	canary := secrecytest.NewCanary(t, "ssh-key")
	w := newWorld(t, "personal")
	files := map[model.SourcePath]string{"files/.config/shell/aliases.sh": "a\n"}
	w.apply(w.commit(files, manifest.Entry{Target: aliases}))
	w.write(".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n"+canary.String()+"\n")

	c2 := w.commit(files, manifest.Entry{Target: aliases})
	w.plans[c2].Roots = []manifest.Root{{Path: ".ssh"}}
	r := w.apply(c2)
	if holdFor(r.Holds, ".ssh", model.HoldRootUntrusted) == nil {
		t.Fatalf("no root hold: %+v", r.Holds)
	}
	if cp := scanCapture(t, w); leakedIn(cp, canary) != nil || len(cp.Changes) != 0 {
		t.Fatalf("captured under an unallowed root: %+v", cp.Paths)
	}

	// The user allows the root: the key that predates it is still never
	// captured; a file written afterwards is.
	w.allowRoots(c2)
	r = w.apply(c2)
	if holdFor(r.Holds, ".ssh", model.HoldRootUntrusted) != nil || holdFor(w.state().Holds, ".ssh", model.HoldRootUntrusted) != nil {
		t.Fatalf("root hold not cleared: %+v", w.state().Holds)
	}
	w.write(".ssh/known_hosts", "host-a ssh-ed25519 AAAA\n")
	cp := scanCapture(t, w)
	if leakedIn(cp, canary) != nil {
		t.Fatal("a file that predates its root was captured")
	}
	if len(cp.Changes) != 1 || cp.Changes[0].Path != "files/.ssh/known_hosts" {
		t.Fatalf("new file under an allowed root: %+v", cp.Paths)
	}
}

// A pusher strips `enclave` from an enclave root, or points it at another
// enclave. The accepted root keeps sealing for its enclave.
func TestAttackRootEnclaveStripped(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal", "client")
	files := map[model.SourcePath]string{"files/.config/shell/aliases.sh": "a\n"}
	c1 := w.commit(files, manifest.Entry{Target: aliases})
	w.plans[c1].Roots = []manifest.Root{{Path: ".secrets", Enclave: "personal"}}
	w.allowRoots(c1)
	w.apply(c1)

	for _, enc := range []model.EnclaveName{"", "client"} {
		c := w.commit(files, manifest.Entry{Target: aliases})
		w.plans[c].Roots = []manifest.Root{{Path: ".secrets", Enclave: enc}}
		r := w.apply(c)
		if holdFor(r.Holds, ".secrets", model.HoldRootUntrusted) == nil {
			t.Fatalf("enclave %q: no root hold", enc)
		}
		name := model.Target(".secrets/one-" + string(enc))
		w.write(name, "first "+canary.String())
		cp := scanCapture(t, w)
		if ch := leakedIn(cp, canary); ch != nil {
			t.Fatalf("enclave %q: plaintext staged at %s", enc, ch.Path)
		}
		want := model.SourcePath("sealed/personal/" + string(name))
		found := false
		for _, ch := range cp.Changes {
			if ch.Path == want {
				found = true
			}
			if strings.HasPrefix(string(ch.Path), "sealed/client/") || strings.HasPrefix(string(ch.Path), "files/.secrets/") {
				t.Fatalf("enclave %q: staged at %s", enc, ch.Path)
			}
		}
		if !found {
			t.Fatalf("enclave %q: not sealed for personal: %+v", enc, cp.Paths)
		}
		w.apply(c) // the capture is not committed; keep the state current
		os.Remove(w.path(name))
	}
}

// A pusher removes a nested enclave root inside a plain one. Without a
// local allow the enclave root stays, so its new files never fall to the
// plain root.
func TestAttackNestedEnclaveRootRemoved(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal")
	c1 := w.commit(nil)
	w.plans[c1].Roots = []manifest.Root{{Path: ".config"}, {Path: ".config/notes", Enclave: "personal"}}
	w.allowRoots(c1)
	w.apply(c1)
	c2 := w.commit(nil)
	w.plans[c2].Roots = []manifest.Root{{Path: ".config"}}
	r := w.apply(c2)
	if holdFor(r.Holds, ".config/notes", model.HoldRootUntrusted) == nil {
		t.Fatalf("no hold for the removed enclave root: %+v", r.Holds)
	}
	w.write(".config/notes/n.md", canary.String())
	cp := scanCapture(t, w)
	if ch := leakedIn(cp, canary); ch != nil {
		t.Fatalf("staged in plaintext at %s", ch.Path)
	}
	if len(cp.Changes) != 1 || cp.Changes[0].Path != "sealed/personal/.config/notes/n.md" {
		t.Fatalf("not sealed: %+v", cp.Paths)
	}
	// Allowing the removal lets it go.
	if err := w.eng.AllowRoot(context.Background(), c2, ".config/notes"); err != nil {
		t.Fatal(err)
	}
	w.apply(c2)
	if len(w.state().Roots) != 1 {
		t.Fatalf("removal not applied: %+v", w.state().Roots)
	}
}

// A protected target leaves the plan and is deleted; when the app writes it
// again inside a plain root, it is not captured.
func TestAttackProtectedTargetLeavesPlan(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal")
	files := map[model.SourcePath]string{"sealed/personal/.config/app/token": "t1\n"}
	c1 := w.commit(files, manifest.Entry{Target: ".config/app/token", Enclave: "personal"})
	w.plans[c1].Roots = []manifest.Root{{Path: ".config"}}
	w.allowRoots(c1)
	w.apply(c1)
	c2 := w.commit(files) // the entry is gone
	w.plans[c2].Roots = []manifest.Root{{Path: ".config"}}
	if a := actionOf(w.apply(c2), ".config/app/token"); a.Kind != ActDelete {
		t.Fatalf("not deleted: %+v", a)
	}
	w.write(".config/app/token", canary.String())
	if ch := leakedIn(scanCapture(t, w), canary); ch != nil {
		t.Fatalf("recreated protected file staged in plaintext at %s", ch.Path)
	}
}

// MergeSealed opens both sides under the current epoch only, so a merge
// never reseals an old-epoch forgery under the current epoch.
func TestAttackMergeDoesNotLaunderOldEpoch(t *testing.T) {
	ring1, head, id, pins := realRing(t)
	_, ring2, err := ring1.Rotate(head, id, pins)
	if err != nil {
		t.Fatal(err)
	}
	const p model.SourcePath = "sealed/personal/.netrc"
	w := newWorld(t, "personal")
	useRealCrypto(t, w, &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": ring2}})
	base, _ := ring2.SealFile(p, []byte("a\nb\nc\n"))
	good, _ := ring2.SealFile(p, []byte("a\nb\nc\nd\n"))
	forged, _ := ring1.SealFile(p, []byte("evil\na\nb\nc\n"))
	for _, b := range [][]byte{base, good, forged} {
		w.st.blobs[blobID(b)] = b
	}
	snap, err := w.eng.LoadSnapshot(context.Background(), w.commitRaw(map[model.SourcePath][]byte{p: base}, manifest.Entry{Target: ".netrc", Enclave: "personal"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []store.Conflict{
		{Path: p, Base: blobID(base), Ours: blobID(base), Theirs: blobID(forged)},
		{Path: p, Base: blobID(base), Ours: blobID(forged), Theirs: blobID(base)},
		{Path: p, Base: blobID(base), Ours: blobID(forged), Theirs: blobID(good)},
	} {
		ch, h, err := w.eng.MergeSealed(context.Background(), snap, c)
		if err != nil || ch != nil || h == nil || h.Reason != model.HoldConflict {
			t.Fatalf("forged side merged: change %v hold %+v err %v", ch != nil, h, err)
		}
	}
}

// A pusher drops the `seal` rule of a structured file while the victim's
// copy has a pending edit. Apply and capture hold the file until the user
// allows the weaker protection.
func TestAttackSealRuleDropped(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal")
	ring, _, _, _ := realRing(t)
	useRealCrypto(t, w, &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": ring}})
	tok, err := ring.SealValue(crypt.PartName("files/settings.json", "sync.token"), canary.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	src := "{\n  \"theme\": \"dark\",\n  \"sync\": { \"token\": \"" + tok + "\" }\n}\n"
	files := map[model.SourcePath]string{"files/settings.json": src}
	sealed := manifest.Entry{Target: "settings.json", Format: manifest.FormatJSON, Seal: map[string]model.EnclaveName{"sync.token": "personal"}}
	w.apply(w.commit(files, sealed))
	if !strings.Contains(w.read("settings.json"), canary.String()) {
		t.Fatal("member did not get the plaintext")
	}
	w.write("settings.json", strings.Replace(w.read("settings.json"), "dark", "light", 1))

	plain := manifest.Entry{Target: "settings.json", Format: manifest.FormatJSON}
	c2 := w.commit(files, plain)
	r := w.apply(c2)
	if a := actionOf(r, "settings.json"); a.Kind != ActHold {
		t.Fatalf("apply: %+v", a)
	}
	cp := scanCapture(t, w)
	if ch := leakedIn(cp, canary); ch != nil {
		t.Fatalf("sealed value staged in plaintext at %s", ch.Path)
	}
	h := holdFor(cp.Holds, "settings.json", model.HoldSealGuard)
	if h == nil || !strings.Contains(h.Detail, "seal sync.token was dropped") {
		t.Fatalf("no seal_guard hold: %+v", cp.Holds)
	}
	if st := w.state(); st.Targets["settings.json"].Seal["sync.token"] != "personal" {
		t.Fatalf("recorded protection lost: %+v", st.Targets["settings.json"])
	}
	// Resolving by taking the source does not get around it.
	if _, err := w.eng.ResolveHold(context.Background(), h.ID, ResolveOptions{Take: "source"}); err == nil {
		t.Fatal("take source applied the weaker spec")
	}

	// Without a pending edit, apply holds too: it never adopts the weaker
	// spec on its own.
	w2 := newWorld(t, "personal")
	useRealCrypto(t, w2, &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": ring}})
	w2.apply(w2.commit(files, sealed))
	c := w2.commit(files, plain)
	if a := actionOf(w2.apply(c), "settings.json"); a.Kind != ActHold {
		t.Fatalf("clean target, weaker spec: %+v", a)
	}
	// Once the user allows it, the new spec applies and is recorded.
	if err := w2.eng.AllowProtection(context.Background(), c, "settings.json"); err != nil {
		t.Fatal(err)
	}
	if a := actionOf(w2.apply(c), "settings.json"); a.Kind == ActHold {
		t.Fatalf("allowed spec still held: %+v", a)
	}
	if st := w2.state(); len(st.Targets["settings.json"].Seal) != 0 {
		t.Fatalf("allowed spec not recorded: %+v", st.Targets["settings.json"])
	}
}

// The same with `regions = true` dropped.
func TestAttackRegionsDropped(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal")
	ring, _, _, _ := realRing(t)
	useRealCrypto(t, w, &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": ring}})
	tok, err := ring.SealRegion(crypt.PartName("files/.ssh/config", "hosts"), []byte("Host private-box\n  IdentityFile "+canary.String()+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	src := "Host *\n  Compression yes\n# yadm:seal personal hosts\n# " + tok + "\n# yadm:end\n"
	files := map[model.SourcePath]string{"files/.ssh/config": src}
	w.apply(w.commit(files, manifest.Entry{Target: ".ssh/config", Regions: true}))
	if !strings.Contains(w.read(".ssh/config"), canary.String()) {
		t.Fatal("member did not get the region")
	}
	w.write(".ssh/config", strings.Replace(w.read(".ssh/config"), "Compression yes", "Compression no", 1))
	w.apply(w.commit(files, manifest.Entry{Target: ".ssh/config"}))
	cp := scanCapture(t, w)
	if ch := leakedIn(cp, canary); ch != nil {
		t.Fatalf("sealed region staged in plaintext at %s", ch.Path)
	}
	if h := holdFor(cp.Holds, ".ssh/config", model.HoldSealGuard); h == nil || !strings.Contains(h.Detail, "regions were turned off") {
		t.Fatalf("no seal_guard hold: %+v", cp.Holds)
	}
}

// Control: moving a whole sealed file to files/ was already held.
func TestAttackWholeFileDowngradeIsHeld(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal")
	w.apply(w.commit(map[model.SourcePath]string{"sealed/personal/.netrc": "v1 " + canary.String()}, manifest.Entry{Target: ".netrc", Enclave: "personal"}))
	w.write(".netrc", "v2 "+canary.String())
	w.apply(w.commit(map[model.SourcePath]string{"files/.netrc": "attacker\n"}, manifest.Entry{Target: ".netrc"}))
	cp := scanCapture(t, w)
	if ch := leakedIn(cp, canary); ch != nil {
		t.Fatalf("leak at %s", ch.Path)
	}
	if len(cp.Holds) == 0 {
		t.Fatal("not held")
	}
	// A hold resolved by keeping the target drops the file from management;
	// a later plain root over it never captures it.
	c3 := w.commit(map[model.SourcePath]string{"files/x": "x\n"}, manifest.Entry{Target: "x"})
	w.plans[c3].Roots = []manifest.Root{{Path: "."}}
	w.allowRoots(c3)
	w.apply(c3)
	st := w.state()
	for _, h := range st.Holds {
		if h.Target == ".netrc" {
			if _, err := w.eng.ResolveHold(context.Background(), h.ID, ResolveOptions{Take: "target"}); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			break
		}
	}
	if ch := leakedIn(scanCapture(t, w), canary); ch != nil {
		t.Fatalf("after resolve, staged in plaintext at %s", ch.Path)
	}
}

// A removed member still holds the old epoch key and plants a blob sealed
// under it. Apply holds the target: content new to this machine opens only
// under the current epoch.
func TestAttackOldEpochBlobHeld(t *testing.T) {
	ring1, head, id, pins := realRing(t)
	_, ring2, err := ring1.Rotate(head, id, pins)
	if err != nil {
		t.Fatal(err)
	}
	const p model.SourcePath = "sealed/personal/.netrc"
	entry := manifest.Entry{Target: ".netrc", Enclave: "personal"}
	honest, _ := ring2.SealFile(p, []byte("v2\n"))
	forged, _ := ring1.SealFile(p, []byte("machine attacker.invalid\n"))

	w := newWorld(t, "personal")
	useRealCrypto(t, w, &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": ring2}})
	w.apply(w.commitRaw(map[model.SourcePath][]byte{p: honest}, entry))
	if w.read(".netrc") != "v2\n" {
		t.Fatal("honest blob not applied")
	}
	r := w.apply(w.commitRaw(map[model.SourcePath][]byte{p: forged}, entry))
	if a := actionOf(r, ".netrc"); a.Kind != ActHold || holdFor(r.Holds, ".netrc", model.HoldSealGuard) == nil {
		t.Fatalf("forged old-epoch blob: %+v", a)
	}
	if w.read(".netrc") != "v2\n" {
		t.Fatal("forged content delivered")
	}
	// A new machine is held too.
	w2 := newWorld(t, "personal")
	useRealCrypto(t, w2, &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": ring2}})
	if a := actionOf(w2.apply(w2.commitRaw(map[model.SourcePath][]byte{p: forged}, entry)), ".netrc"); a.Kind != ActHold {
		t.Fatalf("new machine: %+v", a)
	}
	// A blob moved to another path does not open and is held, not fatal.
	moved := manifest.Entry{Target: ".pgpass", Enclave: "personal"}
	if a := actionOf(w2.apply(w2.commitRaw(map[model.SourcePath][]byte{"sealed/personal/.pgpass": honest}, moved)), ".pgpass"); a.Kind != ActHold {
		t.Fatalf("moved blob: %+v", a)
	}
}

// A pusher may not widen an enclave file's mode; the default modes stay.
func TestAttackEnclaveModeWidened(t *testing.T) {
	w := newWorld(t, "personal")
	files := map[model.SourcePath]string{"sealed/personal/.ssh/id_ed25519": "key\n", "sealed/personal/.netrc": "n\n"}
	c := w.commit(files,
		manifest.Entry{Target: ".ssh/id_ed25519", Enclave: "personal", Mode: 0o644},
		manifest.Entry{Target: ".netrc", Enclave: "personal"})
	r := w.apply(c)
	if a := actionOf(r, ".ssh/id_ed25519"); a.Kind != ActHold {
		t.Fatalf("widened mode applied: %+v", a)
	}
	if _, err := os.Stat(w.path(".ssh/id_ed25519")); err == nil {
		t.Fatal("file written")
	}
	info, err := os.Stat(w.path(".netrc"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("default mode changed: %v %v", info, err)
	}
	// A narrower explicit mode is fine.
	c2 := w.commit(files,
		manifest.Entry{Target: ".ssh/id_ed25519", Enclave: "personal", Mode: 0o400},
		manifest.Entry{Target: ".netrc", Enclave: "personal"})
	if a := actionOf(w.apply(c2), ".ssh/id_ed25519"); a.Kind != ActWrite {
		t.Fatalf("narrow mode: %+v", a)
	}
}

// Backups of enclave plaintext live apart and go when this machine leaves
// the enclave; a refused key log prunes nothing.
func TestAttackBackupsPrunedOnRemoval(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	w := newWorld(t, "personal")
	w.apply(w.commit(map[model.SourcePath]string{"sealed/personal/.netrc": "v1 " + canary.String() + "\n", "files/.a": "a1\n"},
		manifest.Entry{Target: ".netrc", Enclave: "personal"}, manifest.Entry{Target: ".a"}))
	w.tick(1)
	w.apply(w.commit(map[model.SourcePath]string{"sealed/personal/.netrc": "v2\n", "files/.a": "a2\n"},
		manifest.Entry{Target: ".netrc", Enclave: "personal"}, manifest.Entry{Target: ".a"}))
	encBackups, _ := filepath.Glob(filepath.Join(w.stateDir, "backup", "enclave", "personal", "*", ".netrc"))
	plainBackups, _ := filepath.Glob(filepath.Join(w.stateDir, "backup", "*", ".a"))
	if len(encBackups) != 1 || len(plainBackups) != 1 {
		t.Fatalf("backups: enclave %v plain %v", encBackups, plainBackups)
	}
	if m, _ := filepath.Glob(filepath.Join(w.stateDir, "backup", "*", ".netrc")); len(m) != 0 {
		t.Fatalf("enclave plaintext in the shared backup: %v", m)
	}

	// A refused log prunes nothing.
	w.eng.pruneBackups(w.clock, map[model.EnclaveName]crypt.EnclaveLoad{"personal": {Err: crypt.ErrBadSignature}}, nil)
	if _, err := os.Stat(encBackups[0]); err != nil {
		t.Fatal("refused log pruned a backup")
	}
	// A verified head that no longer lists this machine prunes them.
	w.eng.pruneBackups(w.clock, map[model.EnclaveName]crypt.EnclaveLoad{"personal": {Member: false}}, nil)
	if _, err := os.Stat(encBackups[0]); err == nil {
		t.Fatal("backup kept after removal")
	}
	secrecytest.AssertTreeClean(t, filepath.Join(w.stateDir, "backup"), canary)
	if _, err := os.Stat(plainBackups[0]); err != nil {
		t.Fatal("shared backup pruned")
	}
}

// Reseal reaches templates and glob entries.
func TestAttackResealCoversTemplatesAndGlobs(t *testing.T) {
	w := newWorld(t, "personal")
	tok, _ := w.crypto.SealValue("personal", "TOKEN", []byte("s"))
	c := w.commit(map[model.SourcePath]string{
		"files/.config/tool/a.env": "TOKEN=" + tok + "\n",
		"files/.config/tool/b.env": "TOKEN=" + tok + "\n",
		"files/.tmpl.env":          "TOKEN=" + tok + "\nNAME={{ machine.name }}\n",
	},
		manifest.Entry{Target: ".config/tool/*", Seal: map[string]model.EnclaveName{"TOKEN": "personal"}},
		manifest.Entry{Target: ".tmpl.env", Template: true, Seal: map[string]model.EnclaveName{"TOKEN": "personal"}})
	snap, err := w.load(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	w.crypto.epoch = 1
	snap.Crypto = w.crypto
	cp, err := w.eng.Reseal(context.Background(), snap, "personal")
	if err != nil {
		t.Fatal(err)
	}
	got := map[model.SourcePath]bool{}
	for _, ch := range cp.Changes {
		got[ch.Path] = true
	}
	for _, p := range []model.SourcePath{"files/.config/tool/a.env", "files/.config/tool/b.env", "files/.tmpl.env"} {
		if !got[p] {
			t.Errorf("%s not resealed: %+v", p, cp.Paths)
		}
	}
}
