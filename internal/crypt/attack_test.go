package crypt

// Regression tests for attacks found in a security review. Each test names
// the attack it replays; before the fixes, each attack succeeded.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

// attackWorld: A creates "personal" and adds B and C. Each machine has its
// own pin store; B and C joined at entry 3.
type attackWorld struct {
	a, b, c, rec *Identity
	pa, pb, pc   PinStore
	e1, e2, e3   LogEntry
	ka           *Keyring
}

func newAttackWorld(t *testing.T) *attackWorld {
	t.Helper()
	w := &attackWorld{a: ident(t, hostA), b: ident(t, hostB), c: ident(t, hostC), rec: ident(t, RecoveryMachine),
		pa: MemPins(), pb: MemPins(), pc: MemPins()}
	var err error
	if w.e1, w.ka, err = Create("personal", w.a, w.rec.Member(), w.pa); err != nil {
		t.Fatal(err)
	}
	if w.e2, err = w.ka.Add(w.e1, w.b.Member(), w.a, w.pa); err != nil {
		t.Fatal(err)
	}
	if w.e3, err = w.ka.Add(w.e2, w.c.Member(), w.a, w.pa); err != nil {
		t.Fatal(err)
	}
	fp, _ := Fingerprint(w.e3)
	for _, p := range []PinStore{w.pb, w.pc} {
		if _, err := Join([]LogEntry{w.e1, w.e2, w.e3}, fp, p); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func one(es ...LogEntry) map[model.EnclaveName][]LogEntry {
	return map[model.EnclaveName][]LogEntry{"personal": es}
}

// A removed member signs a competing entry 4 on entry 3. Crypt alone cannot
// tell it from the honest entry 4 for a machine pinned at 3; sync refuses
// the commit that replaces keys/personal/000004.toml, using
// CheckLogAppendOnly against the previous tree's log.
func TestAttackRemovedMemberForksKeyLog(t *testing.T) {
	w := newAttackWorld(t)
	e4, _, err := w.ka.Remove(w.e3, hostB, w.a, w.pa)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := Open(w.e3, w.b)
	if err != nil {
		t.Fatal(err)
	}
	f4, _, err := kb.Rotate(w.e3, w.b, w.pb)
	if err != nil {
		t.Fatal(err)
	}
	honest := []LogEntry{w.e1, w.e2, w.e3, e4}
	forked := []LogEntry{w.e1, w.e2, w.e3, f4}
	if err := CheckLogAppendOnly(honest, forked); !errors.Is(err, ErrRewritten) {
		t.Fatalf("fork replacing entry 4: %v", err)
	}
	if err := CheckLogAppendOnly(honest, honest[:3]); !errors.Is(err, ErrRewritten) {
		t.Fatalf("truncation: %v", err)
	}
	if err := CheckLogAppendOnly(honest[:3], honest); err != nil {
		t.Fatalf("honest append refused: %v", err)
	}
	resigned := e4
	resigned.Sig = append([]byte{}, e4.Sig...)
	resigned.Sig[0] ^= 1
	if err := CheckLogAppendOnly(honest, []LogEntry{w.e1, w.e2, w.e3, resigned}); !errors.Is(err, ErrRewritten) {
		t.Fatalf("changed signature: %v", err)
	}
	// A machine that pinned the honest entry 4 refuses the fork.
	p := pinnedAt(t, e4)
	if _, loads, _ := LoadSet(one(forked...), p, w.c); !errors.Is(loads["personal"].Err, ErrBrokenChain) {
		t.Fatalf("pinned machine accepted the fork: %+v", loads["personal"])
	}
}

// The write path refuses a head past the pin: the writer must load (verify
// and pin) the chain first, so its entry descends from its pin.
func TestAttackWriteOnUnverifiedHead(t *testing.T) {
	w := newAttackWorld(t)
	kb, _ := Open(w.e3, w.b)
	f4, err := kb.Add(w.e3, ident(t, "m-ffffff").Member(), w.b, pinnedAt(t, w.e3))
	if err != nil {
		t.Fatal(err)
	}
	// C is pinned at 2 and handed f4 as the head with no chain.
	pc := pinnedAt(t, w.e2)
	kc, _ := Open(w.e3, w.c)
	if _, err := kc.Add(f4, ident(t, "m-dddddd").Member(), w.c, pc); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("write on a head past the pin: %v", err)
	}
	// Unpinned member writes are refused.
	if _, err := w.ka.Add(w.e3, ident(t, "m-dddddd").Member(), w.a, MemPins()); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("unpinned write: %v", err)
	}
}

// A removed member keeps the old epoch keys and forges content under them.
// Fresh content under an old epoch opens only through History; after the
// retire entry, the signed min_epoch refuses it for delivery everywhere.
func TestAttackRemovedMemberForgesUnderOldEpoch(t *testing.T) {
	w := newAttackWorld(t)
	kb, err := Open(w.e3, w.b)
	if err != nil {
		t.Fatal(err)
	}
	e4, k4, err := w.ka.Remove(w.e3, hostB, w.a, w.pa)
	if err != nil {
		t.Fatal(err)
	}
	const at model.SourcePath = "sealed/personal/.ssh/authorized_keys"
	evil := []byte("ssh-ed25519 AAAA attacker-key\n")
	ct, _ := kb.SealFile(at, evil)
	vname := PartName("files/settings.json", "sync.token")
	tok, _ := kb.SealValue(vname, evil)
	rname := PartName("files/.ssh/config", "hosts")
	rtok, _ := kb.SealRegion(rname, evil)

	set, loads, _ := LoadSet(one(w.e1, w.e2, w.e3, e4), w.pc, w.c)
	if loads["personal"].Err != nil {
		t.Fatal(loads["personal"].Err)
	}
	strict := set.Strict()
	if _, err := strict.OpenFile("personal", at, ct); !errors.Is(err, ErrRetiredEpoch) {
		t.Fatalf("strict file: %v", err)
	}
	if _, err := strict.OpenValue("personal", vname, tok); !errors.Is(err, ErrRetiredEpoch) {
		t.Fatalf("strict value: %v", err)
	}
	if _, err := strict.OpenRegion("personal", rname, rtok); !errors.Is(err, ErrRetiredEpoch) {
		t.Fatalf("strict region: %v", err)
	}

	// The reseal lands; a member retires epoch 1.
	e5, err := k4.Retire(e4, w.a, w.pa)
	if err != nil {
		t.Fatal(err)
	}
	if e5.MinEpoch != 2 || e5.Epoch != 2 {
		t.Fatalf("retire: %+v", e5)
	}
	set, loads, _ = LoadSet(one(w.e1, w.e2, w.e3, e4, e5), w.pc, w.c)
	if loads["personal"].Err != nil {
		t.Fatal(loads["personal"].Err)
	}
	if _, err := set.OpenFile("personal", at, ct); !errors.Is(err, ErrRetiredEpoch) {
		t.Fatalf("file under a retired epoch: %v", err)
	}
	if _, err := set.OpenValue("personal", vname, tok); !errors.Is(err, ErrRetiredEpoch) {
		t.Fatalf("value under a retired epoch: %v", err)
	}
	if _, err := set.OpenRegion("personal", rname, rtok); !errors.Is(err, ErrRetiredEpoch) {
		t.Fatalf("region under a retired epoch: %v", err)
	}
	if got, err := set.History().OpenFile("personal", at, ct); err != nil || !bytes.Equal(got, evil) {
		t.Fatalf("history open: %v", err)
	}
	fresh, _ := set.SealFile("personal", at, []byte("current"))
	if got, err := set.OpenFile("personal", at, fresh); err != nil || string(got) != "current" {
		t.Fatalf("current epoch: %q %v", got, err)
	}

	// min_epoch is signed: lowering it again, or raising it outside retire, fails.
	k5 := set.Rings["personal"]
	e6, _, err := k5.Rotate(e5, w.a, w.pa)
	if err != nil {
		t.Fatal(err)
	}
	low := e6
	low.MinEpoch = 1
	low = resign(t, low, w.a, hostA)
	if _, err := VerifyLog([]LogEntry{w.e1, w.e2, w.e3, e4, e5, low}, nil); !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("lowered min_epoch: %v", err)
	}
}

// A signer swaps the key of an earlier epoch inside Wrapped. The key
// commitments refuse it: in VerifyLog when the signer commits to the new
// key, and in Open when it keeps the old commitments.
func TestAttackSignerReplacesOldEpochKeys(t *testing.T) {
	w := newAttackWorld(t)
	old, _ := w.ka.SealFile("sealed/personal/x", []byte("sealed under the real epoch 1 key"))
	kb, _ := Open(w.e3, w.b)
	bad := kb.clone()
	bad.keys[1] = bytes.Repeat([]byte{0x42}, EpochKeySize)

	// Through the write helper: the entry commits to the swapped key.
	f4, _, err := bad.Rotate(w.e3, w.b, pinnedAt(t, w.e3))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLog([]LogEntry{w.e1, w.e2, w.e3, f4}, nil); !errors.Is(err, ErrInvalidLog) {
		t.Fatalf("changed commitment: %v", err)
	}

	// By hand: keep the honest commitments, wrap the swapped keys.
	honest, _, err := kb.Rotate(w.e3, w.b, pinnedAt(t, w.e3))
	if err != nil {
		t.Fatal(err)
	}
	forged := honest
	bad.Current, bad.keys[2] = 2, bytes.Repeat([]byte{0x43}, EpochKeySize)
	if forged.Wrapped, err = bad.wrap(append(append([]Member{}, forged.Members...), forged.Recovery)); err != nil {
		t.Fatal(err)
	}
	forged.KeyCommits = append(append([]string{}, w.e3.KeyCommits...), KeyCommit("personal", 2, bad.keys[2]))
	forged = resign(t, forged, w.b, hostB)
	set, loads, _ := LoadSet(one(w.e1, w.e2, w.e3, forged), w.pc, w.c)
	if !errors.Is(loads["personal"].Err, ErrInvalidLog) || set.CanOpen("personal") {
		t.Fatalf("swapped wrapped key accepted: %+v", loads["personal"])
	}
	// The honest rotate still opens the old file.
	set, loads, _ = LoadSet(one(w.e1, w.e2, w.e3, honest), w.pc, w.c)
	if loads["personal"].Err != nil {
		t.Fatal(loads["personal"].Err)
	}
	if _, err := set.History().OpenFile("personal", "sealed/personal/x", old); err != nil {
		t.Fatal(err)
	}
}

// The recovery identity signs only recover and set-recovery; set-recovery
// replaces a leaked recovery identity.
func TestAttackRecoveryIdentityPowers(t *testing.T) {
	w := newAttackWorld(t)
	kr, err := Open(w.e3, w.rec)
	if err != nil {
		t.Fatal(err)
	}
	mallory := ident(t, "m-mallory")
	if _, err := kr.Add(w.e3, mallory.Member(), w.rec, MemPins()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("write side: recovery add: %v", err)
	}
	// Hand-built recovery-signed add.
	prev, _ := Fingerprint(w.e3)
	add := LogEntry{Enclave: "personal", Seq: 4, Prev: prev, Epoch: 1, MinEpoch: 1, Op: OpAdd, Subject: mallory.Machine,
		Members: append(append([]Member{}, w.e3.Members...), mallory.Member()), Recovery: w.e3.Recovery,
		KeyCommits: w.e3.KeyCommits, Wrapped: w.e3.Wrapped}
	add = resign(t, add, w.rec, RecoveryMachine)
	if _, loads, _ := LoadSet(one(w.e1, w.e2, w.e3, add), w.pc, w.c); !errors.Is(loads["personal"].Err, ErrBadSignature) {
		t.Fatalf("recovery-signed add: %+v", loads["personal"])
	}
	// Recovery-signed rotate and retire are refused too.
	for _, op := range []Op{OpRotate, OpRemove, OpRetire} {
		e := add
		e.Op, e.Subject, e.Members = op, "", w.e3.Members
		e = resign(t, e, w.rec, RecoveryMachine)
		if _, err := VerifyLog([]LogEntry{w.e1, w.e2, w.e3, e}, nil); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("recovery-signed %s: %v", op, err)
		}
	}

	// set-recovery by the old recovery identity.
	rec2 := ident(t, RecoveryMachine)
	e4, err := SetRecovery(w.e3, w.rec, rec2.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	set, loads, _ := LoadSet(one(w.e1, w.e2, w.e3, e4), w.pc, w.c)
	if loads["personal"].Err != nil || !set.CanOpen("personal") {
		t.Fatalf("set-recovery refused: %+v", loads["personal"])
	}
	if _, err := Open(e4, rec2); err != nil {
		t.Fatalf("new recovery cannot open: %v", err)
	}
	// The old recovery identity is now powerless.
	if _, _, err := Recover(e4, w.rec, []Member{mallory.Member()}, MemPins()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("old recovery recovers: %v", err)
	}
	p4, _ := Fingerprint(e4)
	rec := LogEntry{Enclave: "personal", Seq: 5, Prev: p4, Epoch: 2, MinEpoch: 1, Op: OpRecover,
		Members: []Member{mallory.Member()}, Recovery: e4.Recovery, KeyCommits: nextCommits(e4), Wrapped: e4.Wrapped}
	rec = resign(t, rec, w.rec, RecoveryMachine)
	if _, err := VerifyLog([]LogEntry{w.e1, w.e2, w.e3, e4, rec}, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("old recovery signs recover: %v", err)
	}
	// A member cannot sign set-recovery.
	byMember := e4
	byMember = resign(t, byMember, w.a, hostA)
	if _, err := VerifyLog([]LogEntry{w.e1, w.e2, w.e3, byMember}, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("member-signed set-recovery: %v", err)
	}
}

// LoadIdentity follows no symlink and refuses a state directory others can
// enter.
func TestAttackIdentityFileChecks(t *testing.T) {
	id := ident(t, "m-a")
	t.Run("symlinked key files", func(t *testing.T) {
		dir, elsewhere := t.TempDir(), t.TempDir()
		if err := id.Save(elsewhere); err != nil {
			t.Fatal(err)
		}
		os.Chmod(dir, 0o700)
		for _, n := range []string{AgeIdentityFile, SigningKeyFile} {
			if err := os.Symlink(filepath.Join(elsewhere, n), filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := LoadIdentity(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("symlinked key files: %v", err)
		}
	})
	t.Run("open state directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := id.Save(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIdentity(dir); err != nil {
			t.Fatal(err)
		}
		for _, m := range []os.FileMode{0o777, 0o755, 0o710} {
			os.Chmod(dir, m)
			if _, err := LoadIdentity(dir); err == nil {
				t.Fatalf("state directory %o accepted", m)
			}
		}
		os.Chmod(dir, 0o700)
	})
}

// A whole-file blob is bound to its source path; a pusher who moves it to
// another path gets a file that fails to open.
func TestAttackSealedBlobMovedToAnotherPath(t *testing.T) {
	w := newAttackWorld(t)
	blob, err := w.ka.SealFile("sealed/personal/.netrc", []byte("machine example.invalid password hunter2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ka.OpenFile("sealed/personal/.netrc", blob); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ka.OpenFile("sealed/personal/.config/motd", blob); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("moved blob: %v", err)
	}
	// A version-1 container (no path in the AD) is refused.
	v1 := append([]byte{}, blob...)
	v1[len(FileMagic)] = 1
	if _, err := w.ka.OpenFile("sealed/personal/.netrc", v1); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("v1 container: %v", err)
	}
	if _, err := w.ka.SealFile("", []byte("x")); err == nil {
		t.Fatal("sealed without a path")
	}
	// Equal content at two paths gives two blobs.
	a, _ := w.ka.SealFile("sealed/personal/a", []byte("same"))
	b, _ := w.ka.SealFile("sealed/personal/b", []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("cross-path equality still visible")
	}
	// Values and regions bind file and concrete key.
	tok, _ := w.ka.SealValue(PartName("files/a.json", "servers.prod.token"), []byte("s"))
	for _, name := range []string{PartName("files/a.json", "servers.evil.token"), PartName("files/b.json", "servers.prod.token")} {
		if _, err := w.ka.OpenValue(name, tok); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("value opened as %q: %v", name, err)
		}
	}
}

// Encodings are strict: one entry, token or key has one spelling.
func TestAttackStrictEncodings(t *testing.T) {
	w := newAttackWorld(t)
	b, err := MarshalLogEntry(w.e3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLogEntry(b); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]string{
		"comment":      "# note\n" + string(b),
		"spacing":      strings.Replace(string(b), "seq = 3", "seq =  3", 1),
		"no min_epoch": strings.Replace(string(b), "min_epoch = 1\n", "", 1),
	} {
		if _, err := ParseLogEntry([]byte(mut)); err == nil {
			t.Errorf("%s: non-canonical entry parsed", name)
		}
	}
	// A sign_key with non-zero padding bits decodes non-strictly to the same key.
	m := w.a.Member()
	raw, _ := base64.StdEncoding.DecodeString(m.SignKey)
	if len(raw) != ed25519.PublicKeySize {
		t.Fatal("key size")
	}
	enc := []byte(m.SignKey)
	last := enc[len(enc)-2] // "xx=" form: the char before '=' carries 2 spare bits
	enc[len(enc)-2] = nonStrict(last)
	m.SignKey = string(enc)
	if _, err := m.publicKey(); err == nil {
		t.Error("non-strict sign_key accepted")
	}
	// A value token whose base64 has spare bits set is refused.
	tok, _ := w.ka.SealValue("p", []byte("x"))
	vt, _ := ParseValueToken(tok)
	body := base64.RawURLEncoding.EncodeToString(vt.Body)
	if len(vt.Body)%3 != 0 {
		bb := []byte(body)
		bb[len(bb)-1] = nonStrictURL(bb[len(bb)-1])
		if _, ok := ParseValueToken(strings.TrimSuffix(tok, body) + string(bb)); ok {
			t.Error("non-strict token body accepted")
		}
	}
}

// nonStrict flips the lowest bit of a standard base64 character, which in
// the last position before padding only touches spare bits.
func nonStrict(c byte) byte {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alpha, c)
	return alpha[i^1]
}

func nonStrictURL(c byte) byte {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alpha, c)
	return alpha[i^1]
}

// The not-pinned message never prints a fingerprint from the local log.
func TestAttackNotPinnedShowsNoLocalFingerprint(t *testing.T) {
	w := newAttackWorld(t)
	_, loads, _ := LoadSet(one(w.e1, w.e2, w.e3), MemPins(), w.b)
	err := loads["personal"].Err
	if !errors.Is(err, ErrNotPinned) {
		t.Fatal(err)
	}
	for _, e := range []LogEntry{w.e1, w.e2, w.e3} {
		fp, _ := Fingerprint(e)
		if strings.Contains(err.Error(), fp) {
			t.Fatalf("message shows a local fingerprint: %v", err)
		}
	}
}

func TestParseLogPath(t *testing.T) {
	if e, n, ok := ParseLogPath(LogPath("personal", 12)); !ok || e != "personal" || n != 12 {
		t.Fatalf("%v %v %v", e, n, ok)
	}
	for _, p := range []model.SourcePath{"keys/personal/12.toml", "keys/personal/000000.toml", "keys/a/b/000001.toml", "files/keys/personal/000001.toml", "keys/personal/000001.txt"} {
		if _, _, ok := ParseLogPath(p); ok {
			t.Errorf("%s parsed", p)
		}
	}
}
