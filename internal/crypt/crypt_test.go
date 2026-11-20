package crypt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/noahkiss/yadm/internal/model"
)

const (
	hostA model.MachineID = "m-aaaaaa"
	hostB model.MachineID = "m-bbbbbb"
	hostC model.MachineID = "m-cccccc"
	evil  model.MachineID = "m-eeeeee"
)

func ident(t *testing.T, m model.MachineID) *Identity {
	t.Helper()
	id, err := GenerateIdentity(m)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// world is a small enclave history used by most tests.
type world struct {
	a, b, c, outsider, rec *Identity
	log                    []LogEntry
	ring                   *Keyring // hostA's keyring at the head
}

// newWorld builds: 1 create(A), 2 add(B), 3 add(C).
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{a: ident(t, hostA), b: ident(t, hostB), c: ident(t, hostC), outsider: ident(t, evil), rec: ident(t, RecoveryMachine)}
	e1, k, err := Create("personal", w.a, w.rec.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	e2, err := k.Add(e1, w.b.Member(), w.a, pinnedAt(t, e1))
	if err != nil {
		t.Fatal(err)
	}
	e3, err := k.Add(e2, w.c.Member(), w.b, pinnedAt(t, e2)) // any member may sign
	if err != nil {
		t.Fatal(err)
	}
	w.log = []LogEntry{e1, e2, e3}
	w.ring = k
	return w
}

func (w *world) head() LogEntry { return w.log[len(w.log)-1] }

// resign signs e with key as if by the machine named in e.Signer. It is how an
// attacker builds an entry past the write-side checks.
func resign(t *testing.T, e LogEntry, key *Identity, claimed model.MachineID) LogEntry {
	t.Helper()
	e.Signer = claimed
	msg, err := SignedBytes(e)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = ed25519.Sign(key.sign, msg)
	return e
}

// pinnedAt returns a PinStore pinned at e, as a member has after loading a
// log whose head is e.
func pinnedAt(t *testing.T, e LogEntry) PinStore {
	t.Helper()
	p := MemPins()
	if err := p.Set(e.Enclave, *mustPin(t, e)); err != nil {
		t.Fatal(err)
	}
	return p
}

// nextCommits is head's key commitments plus one for a made-up next epoch
// key, for entries built by hand past the write-side checks.
func nextCommits(head LogEntry) []string {
	return append(append([]string{}, head.KeyCommits...), KeyCommit(head.Enclave, head.Epoch+1, make([]byte, EpochKeySize)))
}

func mustPin(t *testing.T, e LogEntry) *Pin {
	t.Helper()
	p, err := PinOf(e)
	if err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestIdentitySaveLoad(t *testing.T) {
	dir := t.TempDir()
	id := ident(t, hostA)
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{AgeIdentityFile, SigningKeyFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %o", f, fi.Mode().Perm())
		}
	}
	got, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Machine != hostA || got.Member() != id.Member() {
		t.Fatalf("round trip: %+v vs %+v", got.Member(), id.Member())
	}
	// The age file stays a valid age identity file.
	f, _ := os.Open(filepath.Join(dir, AgeIdentityFile))
	ids, err := age.ParseIdentities(f)
	f.Close()
	if err != nil || len(ids) != 1 {
		t.Fatalf("age identity file: %v", err)
	}

	t.Run("refuses group-readable key", func(t *testing.T) {
		if err := os.Chmod(filepath.Join(dir, SigningKeyFile), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIdentity(dir); err == nil {
			t.Fatal("loaded a 0644 signing key")
		}
		os.Chmod(filepath.Join(dir, SigningKeyFile), 0o600)
	})
	t.Run("refuses mismatched machine", func(t *testing.T) {
		other := t.TempDir()
		if err := ident(t, hostB).Save(other); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join(other, SigningKeyFile))
		os.WriteFile(filepath.Join(dir, SigningKeyFile), b, 0o600)
		if _, err := LoadIdentity(dir); err == nil {
			t.Fatal("loaded identity files of two machines")
		}
	})
	t.Run("missing", func(t *testing.T) {
		empty := t.TempDir()
		os.Chmod(empty, 0o700)
		if _, err := LoadIdentity(empty); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("want not-exist, got %v", err)
		}
	})
}

func TestEntryCodec(t *testing.T) {
	w := newWorld(t)
	for _, e := range w.log {
		b, err := MarshalLogEntry(e)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParseLogEntry(b)
		if err != nil {
			t.Fatalf("parse:\n%s\n%v", b, err)
		}
		s1, _ := SignedBytes(e)
		s2, _ := SignedBytes(p)
		if !bytes.Equal(s1, s2) {
			t.Fatalf("signed bytes differ after round trip:\n%s\n%s", s1, s2)
		}
		b2, _ := MarshalLogEntry(p)
		if !bytes.Equal(b, b2) {
			t.Fatal("marshal is not stable")
		}
		if bytes.Contains(s1, []byte(`sig = ""`)) == false {
			t.Fatal("signed bytes must carry an empty sig")
		}
	}
	// Entries parsed from files verify.
	var parsed []LogEntry
	for _, e := range w.log {
		b, _ := MarshalLogEntry(e)
		p, _ := ParseLogEntry(b)
		parsed = append(parsed, p)
	}
	if _, err := VerifyLog(parsed, nil); err != nil {
		t.Fatal(err)
	}
	// Strict decoding.
	b, _ := MarshalLogEntry(w.log[0])
	if _, err := ParseLogEntry(append(b, []byte("extra = 1\n")...)); err == nil {
		t.Error("accepted an unknown field")
	}
	// Quoting.
	q, _ := tomlString("a\"b\\c\n")
	if q != `"a\"b\\c\u000A"` {
		t.Errorf("quote: %s", q)
	}
	if LogPath("personal", 7) != "keys/personal/000007.toml" {
		t.Error(LogPath("personal", 7))
	}
}

func TestLifecycleVerifies(t *testing.T) {
	w := newWorld(t)
	e4, k4, err := w.ring.Rotate(w.head(), w.c, pinnedAt(t, w.head()))
	if err != nil {
		t.Fatal(err)
	}
	e5, k5, err := k4.Remove(e4, hostB, w.a, pinnedAt(t, e4))
	if err != nil {
		t.Fatal(err)
	}
	e6, k6, err := Recover(e5, w.rec, []Member{w.c.Member()}, MemPins())
	if err != nil {
		t.Fatal(err)
	}
	log := append(w.log, e4, e5, e6)
	head, err := VerifyLog(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 6 || head.Epoch != 4 || k5.Current != 3 || k6.Current != 4 {
		t.Fatalf("head %d epoch %d", head.Seq, head.Epoch)
	}
	for _, e := range log {
		if _, err := VerifyLog(log, mustPin(t, e)); err != nil {
			t.Fatalf("pin at %d: %v", e.Seq, err)
		}
	}
	// C opens the recovered head and reads data sealed at every epoch.
	kc, err := Open(e6, w.c)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := w.ring.SealFile(tp, []byte("epoch one"))
	if pt, err := kc.OpenFile(tp, old); err != nil || string(pt) != "epoch one" {
		t.Fatalf("open old epoch: %q %v", pt, err)
	}
	// The recovery identity can open any head.
	if _, err := Open(e6, w.rec); err != nil {
		t.Fatal(err)
	}
	// The remaining members get the same keys.
	ka, err := Open(e5, w.a)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := ka.SealValue("k", []byte("v"))
	y, _ := k5.SealValue("k", []byte("v"))
	if x != y {
		t.Fatal("members disagree on the epoch key")
	}
}

func TestForgedEntryRejected(t *testing.T) {
	w := newWorld(t)
	head := w.head()
	prev, _ := Fingerprint(head)
	addEvil := LogEntry{
		Enclave: head.Enclave, Seq: head.Seq + 1, Prev: prev, Epoch: head.Epoch, Op: OpAdd,
		Subject: evil, Members: append(append([]Member{}, head.Members...), w.outsider.Member()),
		Recovery: head.Recovery, Wrapped: head.Wrapped, MinEpoch: head.MinEpoch, KeyCommits: head.KeyCommits,
	}
	cases := map[string]LogEntry{
		// A non-member signs as itself.
		"outsider signs as itself": resign(t, addEvil, w.outsider, evil),
		// A non-member claims a member's id but has only its own key.
		"outsider claims a member id": resign(t, addEvil, w.outsider, hostA),
		// A non-member claims to be the recovery identity.
		"outsider claims recovery": resign(t, addEvil, w.outsider, RecoveryMachine),
	}
	// A non-member substitutes its key for hostA's in the new member list and
	// signs as hostA with that key: the signer key must come from the
	// previous entry, so this fails too.
	swapped := addEvil
	swapped.Op, swapped.Subject = OpRotate, ""
	swapped.Epoch, swapped.KeyCommits = head.Epoch+1, nextCommits(head)
	swapped.Members = append([]Member{}, head.Members...)
	fake := w.outsider.Member()
	fake.Machine = hostA
	swapped.Members[0] = fake
	cases["key substitution"] = resign(t, swapped, w.outsider, hostA)
	// A valid entry tampered with after signing.
	tampered := w.log[1]
	tampered.Members = append(append([]Member{}, tampered.Members...), w.outsider.Member())
	cases["tampered after signing"] = tampered

	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			log := append(append([]LogEntry{}, w.log...), e)
			if name == "tampered after signing" {
				log = []LogEntry{w.log[0], e}
			}
			if _, err := VerifyLog(log, nil); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("want ErrBadSignature, got %v", err)
			}
		})
	}

	t.Run("member cannot sign recover", func(t *testing.T) {
		e := addEvil
		e.Op, e.Subject, e.Epoch, e.KeyCommits = OpRecover, "", head.Epoch+1, nextCommits(head)
		e = resign(t, e, w.a, hostA)
		if _, err := VerifyLog(append(append([]LogEntry{}, w.log...), e), nil); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
	})
	t.Run("member cannot smuggle a second member into add", func(t *testing.T) {
		e := addEvil
		e.Subject = "m-dddddd"
		e = resign(t, e, w.a, hostA)
		if _, err := VerifyLog(append(append([]LogEntry{}, w.log...), e), nil); !errors.Is(err, ErrInvalidLog) {
			t.Fatalf("want ErrInvalidLog, got %v", err)
		}
	})
	t.Run("member cannot change the recovery identity", func(t *testing.T) {
		e := addEvil
		e.Op, e.Subject, e.Epoch, e.Members, e.KeyCommits = OpRotate, "", head.Epoch+1, head.Members, nextCommits(head)
		e.Recovery = w.outsider.Member()
		e.Recovery.Machine = RecoveryMachine
		e = resign(t, e, w.a, hostA)
		if _, err := VerifyLog(append(append([]LogEntry{}, w.log...), e), nil); !errors.Is(err, ErrInvalidLog) {
			t.Fatalf("want ErrInvalidLog, got %v", err)
		}
	})
	t.Run("removed member cannot sign", func(t *testing.T) {
		e4, k4, err := w.ring.Remove(head, hostB, w.a, pinnedAt(t, head))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := k4.Rotate(e4, w.b, pinnedAt(t, e4)); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("write side: want ErrBadSignature, got %v", err)
		}
		p4, _ := Fingerprint(e4)
		e5 := LogEntry{Enclave: e4.Enclave, Seq: 5, Prev: p4, Epoch: e4.Epoch + 1, Op: OpRotate,
			Members: e4.Members, Recovery: e4.Recovery, Wrapped: e4.Wrapped, MinEpoch: e4.MinEpoch, KeyCommits: nextCommits(e4)}
		e5 = resign(t, e5, w.b, hostB)
		if _, err := VerifyLog(append(append([]LogEntry{}, w.log...), e4, e5), nil); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
	})
	t.Run("write side refuses a non-member", func(t *testing.T) {
		if _, err := w.ring.Add(head, w.outsider.Member(), w.outsider, pinnedAt(t, head)); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
		if _, _, err := Recover(head, w.outsider, []Member{w.outsider.Member()}, MemPins()); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("recover: want ErrBadSignature, got %v", err)
		}
	})
	t.Run("forged create", func(t *testing.T) {
		e1 := w.log[0]
		e1 = resign(t, e1, w.outsider, hostA)
		if _, err := VerifyLog([]LogEntry{e1}, nil); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got %v", err)
		}
	})
	t.Run("member named recovery", func(t *testing.T) {
		m := w.outsider.Member()
		m.Machine = RecoveryMachine
		e := addEvil
		e.Subject, e.Members = RecoveryMachine, append(append([]Member{}, head.Members...), m)
		e = resign(t, e, w.a, hostA)
		if _, err := VerifyLog(append(append([]LogEntry{}, w.log...), e), nil); !errors.Is(err, ErrInvalidLog) {
			t.Fatalf("want ErrInvalidLog, got %v", err)
		}
	})
}

func TestPinRejectsReplayAndTruncation(t *testing.T) {
	w := newWorld(t)
	pin := mustPin(t, w.head())

	t.Run("truncated", func(t *testing.T) {
		if _, err := VerifyLog(w.log[:2], pin); !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("want ErrBrokenChain, got %v", err)
		}
	})
	t.Run("replayed entry", func(t *testing.T) {
		replay := append(append([]LogEntry{}, w.log...), w.log[1])
		if _, err := VerifyLog(replay, pin); !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("want ErrBrokenChain, got %v", err)
		}
	})
	t.Run("fork by a real member", func(t *testing.T) {
		// A validly signed alternative entry 3: the chain verifies on its
		// own, but not against the pin.
		k, err := Open(w.log[1], w.a)
		if err != nil {
			t.Fatal(err)
		}
		alt, _, err := k.Rotate(w.log[1], w.a, pinnedAt(t, w.log[1]))
		if err != nil {
			t.Fatal(err)
		}
		fork := []LogEntry{w.log[0], w.log[1], alt}
		if _, err := VerifyLog(fork, nil); err != nil {
			t.Fatalf("fork should verify without a pin: %v", err)
		}
		if _, err := VerifyLog(fork, pin); !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("want ErrBrokenChain, got %v", err)
		}
	})
	t.Run("reordered", func(t *testing.T) {
		if _, err := VerifyLog([]LogEntry{w.log[0], w.log[2], w.log[1]}, nil); !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("want ErrBrokenChain, got %v", err)
		}
	})
	t.Run("join", func(t *testing.T) {
		pins := FilePins(t.TempDir())
		fp, _ := Fingerprint(w.log[2])
		if _, err := Join(w.log, strings.Repeat("0", 64), pins); !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("unknown fingerprint: %v", err)
		}
		if p, _ := pins.Get("personal"); p != nil {
			t.Fatal("failed join wrote a pin")
		}
		head, err := Join(w.log, strings.ToUpper(fp), pins)
		if err != nil || head.Seq != 3 {
			t.Fatalf("join: %v", err)
		}
		if p, _ := pins.Get("personal"); p == nil || p.Seq != 3 || p.Hash != fp {
			t.Fatalf("pin: %+v", p)
		}
		// A later join on a fork that does not contain the pin fails.
		k, _ := Open(w.log[1], w.a)
		alt, _, _ := k.Rotate(w.log[1], w.a, pinnedAt(t, w.log[1]))
		fork := []LogEntry{w.log[0], w.log[1], alt}
		afp, _ := Fingerprint(alt)
		if _, err := Join(fork, afp, pins); !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("fork join: want ErrBrokenChain, got %v", err)
		}
	})
}

func TestWrongADFails(t *testing.T) {
	w := newWorld(t)
	k := w.ring

	t.Run("value key path", func(t *testing.T) {
		tok, err := k.SealValue("sync.token", []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		if pt, err := k.OpenValue("sync.token", tok); err != nil || string(pt) != "secret" {
			t.Fatalf("round trip: %q %v", pt, err)
		}
		if _, err := k.OpenValue("sync.other", tok); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("moved token: %v", err)
		}
	})
	t.Run("region label", func(t *testing.T) {
		tok, err := k.SealRegion("hosts", []byte("Host x\n"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, RegionPrefix+"1 ") {
			t.Fatalf("token %q", tok)
		}
		if pt, err := k.OpenRegion("hosts", tok); err != nil || string(pt) != "Host x\n" {
			t.Fatalf("round trip: %q %v", pt, err)
		}
		if _, err := k.OpenRegion("other", tok); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("moved region: %v", err)
		}
	})
	t.Run("value vs region purpose", func(t *testing.T) {
		tok, _ := k.SealValue("hosts", []byte("x"))
		vt, _ := ParseValueToken(tok)
		rtok := RegionPrefix + "1 " + base64Std(vt.Body)
		if _, err := k.OpenRegion("hosts", rtok); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("value body opened as region: %v", err)
		}
	})
	t.Run("other enclave", func(t *testing.T) {
		_, other, err := Create("work", w.a, w.rec.Member(), MemPins())
		if err != nil {
			t.Fatal(err)
		}
		tok, _ := k.SealValue("p", []byte("x"))
		if _, err := other.OpenValue("p", tok); !errors.Is(err, ErrNotMember) {
			t.Fatalf("other ring: %v", err)
		}
		// Relabel the token's enclave: different subkey and AD.
		relabeled := strings.Replace(tok, ":personal:", ":work:", 1)
		if _, err := other.OpenValue("p", relabeled); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("relabeled: %v", err)
		}
		blob, _ := k.SealFile(tp, []byte("file"))
		if _, err := other.OpenFile(tp, blob); !errors.Is(err, ErrNotMember) {
			t.Fatalf("file other ring: %v", err)
		}
	})
	t.Run("epoch", func(t *testing.T) {
		_, k2, err := k.Rotate(w.head(), w.a, pinnedAt(t, w.head()))
		if err != nil {
			t.Fatal(err)
		}
		tok, _ := k2.SealValue("p", []byte("x"))
		if !strings.Contains(tok, ":personal:2:") {
			t.Fatalf("token %q", tok)
		}
		older := strings.Replace(tok, ":personal:2:", ":personal:1:", 1)
		if _, err := k2.OpenValue("p", older); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("known other epoch: %v", err)
		}
		unknown := strings.Replace(tok, ":personal:2:", ":personal:9:", 1)
		if _, err := k2.OpenValue("p", unknown); !errors.Is(err, ErrUnknownEpoch) {
			t.Fatalf("unknown epoch: %v", err)
		}
		blob, _ := k2.SealFile(tp, []byte("file"))
		h := fileHeader("personal", 2)
		bad := append(fileHeader("personal", 1), blob[len(h):]...)
		if _, err := k2.OpenFile(tp, bad); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("file epoch: %v", err)
		}
		rtok, _ := k2.SealRegion("l", []byte("b"))
		if _, err := k2.OpenRegion("l", strings.Replace(rtok, " 2 ", " 1 ", 1)); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("region epoch: %v", err)
		}
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		blob, _ := k.SealFile(tp, []byte("file body"))
		blob[len(blob)-1] ^= 1
		if _, err := k.OpenFile(tp, blob); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("tampered: %v", err)
		}
	})
	t.Run("not sealed", func(t *testing.T) {
		if _, err := k.OpenFile(tp, []byte("plain")); !errors.Is(err, ErrNotSealed) {
			t.Fatal(err)
		}
		if _, err := k.OpenFile(tp, []byte(FileMagic+"\x02")); !errors.Is(err, ErrNotSealed) {
			t.Fatal(err)
		}
		if _, err := k.OpenValue("p", "plain"); !errors.Is(err, ErrNotSealed) {
			t.Fatal(err)
		}
		if _, err := k.OpenRegion("p", "yadm:sealed 1 x y"); !errors.Is(err, ErrNotSealed) {
			t.Fatal(err)
		}
	})
}

func TestDeterminism(t *testing.T) {
	w := newWorld(t)
	kb, err := Open(w.head(), w.b)
	if err != nil {
		t.Fatal(err)
	}
	for _, pt := range [][]byte{[]byte("same plaintext"), {}} {
		f1, _ := w.ring.SealFile(tp, pt)
		f2, _ := w.ring.SealFile(tp, pt)
		f3, _ := kb.SealFile(tp, pt) // another member converges on the same blob
		if !bytes.Equal(f1, f2) || !bytes.Equal(f1, f3) {
			t.Fatal("file sealing is not deterministic")
		}
		if got, err := kb.OpenFile(tp, f1); err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("open: %q %v", got, err)
		}
		v1, _ := w.ring.SealValue("a.b", pt)
		v2, _ := kb.SealValue("a.b", pt)
		r1, _ := w.ring.SealRegion("l", pt)
		r2, _ := kb.SealRegion("l", pt)
		if v1 != v2 || r1 != r2 {
			t.Fatal("value or region sealing is not deterministic")
		}
	}
	// An add keeps the epoch, so blobs do not churn.
	before, _ := w.ring.SealFile(tp, []byte("x"))
	kc, _ := Open(w.head(), w.c)
	after, _ := kc.SealFile(tp, []byte("x"))
	if !bytes.Equal(before, after) {
		t.Fatal("add changed the sealing key")
	}
	// The container does not carry the path: same bytes under any name.
	if !IsSealedFile(before) {
		t.Fatal("IsSealedFile")
	}
}

func TestRemovedMemberCannotOpenNewData(t *testing.T) {
	w := newWorld(t)
	kb, err := Open(w.head(), w.b) // hostB's ring before removal
	if err != nil {
		t.Fatal(err)
	}
	oldBlob, _ := w.ring.SealFile(tp, []byte("before removal"))

	e4, k4, err := w.ring.Remove(w.head(), hostB, w.a, pinnedAt(t, w.head()))
	if err != nil {
		t.Fatal(err)
	}
	if e4.Epoch != 2 || k4.Current != 2 {
		t.Fatalf("epoch %d", e4.Epoch)
	}
	newBlob, _ := k4.SealFile(tp, []byte("after removal"))
	newTok, _ := k4.SealValue("p", []byte("after"))
	newReg, _ := k4.SealRegion("l", []byte("after"))

	// The new head is not wrapped to hostB: a raw age unwrap fails.
	if _, err := age.Decrypt(bytes.NewReader(e4.Wrapped), w.b.age); err == nil {
		t.Fatal("removed member unwrapped the new head")
	}
	if _, err := Open(e4, w.b); !errors.Is(err, ErrNotMember) {
		t.Fatalf("Open: %v", err)
	}
	// hostB's old ring has no key for the new epoch.
	if _, err := kb.OpenFile(tp, newBlob); !errors.Is(err, ErrUnknownEpoch) {
		t.Fatalf("file: %v", err)
	}
	if _, err := kb.OpenValue("p", newTok); !errors.Is(err, ErrUnknownEpoch) {
		t.Fatalf("value: %v", err)
	}
	if _, err := kb.OpenRegion("l", newReg); !errors.Is(err, ErrUnknownEpoch) {
		t.Fatalf("region: %v", err)
	}
	// As designed, it keeps what it had.
	if pt, err := kb.OpenFile(tp, oldBlob); err != nil || string(pt) != "before removal" {
		t.Fatalf("old data: %v", err)
	}
	// Remaining members open both.
	kc, err := Open(e4, w.c)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{oldBlob, newBlob} {
		if _, err := kc.OpenFile(tp, b); err != nil {
			t.Fatal(err)
		}
	}
	// A removed member listed in LoadSet is reported as a non-member.
	pins := FilePins(t.TempDir())
	pins.Set("personal", *mustPin(t, w.head()))
	set, loads, _ := LoadSet(map[model.EnclaveName][]LogEntry{"personal": append(w.log, e4)}, pins, w.b)
	if set.CanOpen("personal") || loads["personal"].Member || loads["personal"].Err != nil {
		t.Fatalf("load: %+v", loads["personal"])
	}
}

func TestLoadSet(t *testing.T) {
	wp := newWorld(t)
	// A second enclave, created by hostA too.
	c1, ck, err := Create("client", wp.a, wp.rec.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	logs := map[model.EnclaveName][]LogEntry{"personal": wp.log, "client": {c1}}

	stateDir := t.TempDir()
	pins := FilePins(stateDir)
	pins.Set("personal", *mustPin(t, wp.log[0]))
	pins.Set("client", *mustPin(t, c1))

	set, loads, err := LoadSet(logs, pins, wp.a)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []model.EnclaveName{"personal", "client"} {
		if loads[e].Err != nil || !loads[e].Member || !set.CanOpen(e) {
			t.Fatalf("%s: %+v", e, loads[e])
		}
	}
	if p, _ := pins.Get("personal"); p.Seq != 3 {
		t.Fatalf("pin not advanced: %+v", p)
	}
	tok, _ := ck.SealValue("x", []byte("v"))
	if pt, err := set.OpenValue("client", "x", tok); err != nil || string(pt) != "v" {
		t.Fatal(err)
	}

	t.Run("one bad log refuses only its enclave", func(t *testing.T) {
		bad := append([]LogEntry{}, wp.log...)
		bad[2].Members = append(append([]Member{}, bad[2].Members...), wp.outsider.Member())
		set, loads, err := LoadSet(map[model.EnclaveName][]LogEntry{"personal": bad, "client": {c1}}, pins, wp.a)
		if err != nil {
			t.Fatal(err)
		}
		if loads["personal"].Err == nil || set.CanOpen("personal") {
			t.Fatal("tampered enclave loaded")
		}
		if loads["client"].Err != nil || !set.CanOpen("client") {
			t.Fatalf("client refused: %v", loads["client"].Err)
		}
		if p, _ := pins.Get("personal"); p.Seq != 3 {
			t.Fatal("refused enclave moved its pin")
		}
		if _, err := set.SealValue("personal", "x", []byte("v")); !errors.Is(err, ErrNotMember) {
			t.Fatal("sealed for a refused enclave")
		}
	})
	t.Run("rollback against the pin is refused", func(t *testing.T) {
		_, loads, _ := LoadSet(map[model.EnclaveName][]LogEntry{"personal": wp.log[:2]}, pins, wp.a)
		if !errors.Is(loads["personal"].Err, ErrBrokenChain) {
			t.Fatalf("want ErrBrokenChain, got %v", loads["personal"].Err)
		}
	})
	t.Run("entry for another enclave", func(t *testing.T) {
		_, loads, _ := LoadSet(map[model.EnclaveName][]LogEntry{"client": wp.log}, FilePins(t.TempDir()), nil)
		if loads["client"].Err == nil {
			t.Fatal("accepted a log filed under the wrong enclave")
		}
	})
	t.Run("listed but unpinned opens nothing", func(t *testing.T) {
		set, loads, _ := LoadSet(logs, FilePins(t.TempDir()), wp.b)
		if !errors.Is(loads["personal"].Err, ErrNotPinned) || set.CanOpen("personal") {
			t.Fatalf("personal: %+v", loads["personal"])
		}
		if loads["client"].Err != nil || loads["client"].Member {
			t.Fatalf("client: %+v", loads["client"])
		}
	})
	t.Run("nil identity verifies only", func(t *testing.T) {
		set, loads, err := LoadSet(logs, nil, nil)
		if err != nil || len(set.Rings) != 0 || loads["personal"].Head.Seq != 3 {
			t.Fatalf("%v %+v", err, loads)
		}
		if _, _, err := LoadSet(nil, pins, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("non-member with pin advances", func(t *testing.T) {
		pins := FilePins(t.TempDir())
		pins.Set("personal", *mustPin(t, wp.log[0]))
		_, loads, _ := LoadSet(logs, pins, wp.outsider)
		if loads["personal"].Member || loads["personal"].Err != nil {
			t.Fatalf("%+v", loads["personal"])
		}
		if p, _ := pins.Get("personal"); p.Seq != 3 {
			t.Fatal("pin not advanced")
		}
	})
}

// TestWritesPin proves the acting machine pins every entry it writes, so it
// never needs a join, and that its pin refuses writes on a stale head.
func TestWritesPin(t *testing.T) {
	a, b, rec := ident(t, hostA), ident(t, hostB), ident(t, RecoveryMachine)
	pins := FilePins(t.TempDir())
	e1, k, err := Create("personal", a, rec.Member(), pins)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := pins.Get("personal"); p == nil || *p != *mustPin(t, e1) {
		t.Fatalf("create did not pin: %+v", p)
	}
	if _, _, err := Create("personal", a, rec.Member(), pins); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("second create on a pinned enclave: %v", err)
	}
	e2, err := k.Add(e1, b.Member(), a, pins)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := pins.Get("personal"); p.Seq != 2 {
		t.Fatalf("add did not pin: %+v", p)
	}
	// The creator loads without a join.
	set, loads, _ := LoadSet(map[model.EnclaveName][]LogEntry{"personal": {e1, e2}}, pins, a)
	if loads["personal"].Err != nil || !set.CanOpen("personal") {
		t.Fatalf("creator load: %+v", loads["personal"])
	}
	// A write on a head behind the pin is refused and leaves the pin alone.
	if _, _, err := k.Rotate(e1, a, pins); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("stale head: %v", err)
	}
	if p, _ := pins.Get("personal"); p.Seq != 2 {
		t.Fatalf("refused write moved the pin: %+v", p)
	}
	// A different entry at the pinned seq is refused.
	alt := e2
	alt.Subject = "m-other"
	if _, _, err := k.Rotate(alt, a, pins); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("forked head: %v", err)
	}
	e3, _, err := k.Rotate(e2, a, pins)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := pins.Get("personal"); *p != *mustPin(t, e3) {
		t.Fatal("rotate did not pin")
	}
	if _, _, err := Create("work", a, rec.Member(), nil); err == nil {
		t.Fatal("write without a PinStore")
	}
	// hostB is listed but never pinned: the error names the enclave and the join step.
	_, loads, _ = LoadSet(map[model.EnclaveName][]LogEntry{"personal": {e1, e2, e3}}, FilePins(t.TempDir()), b)
	msg := loads["personal"].Err.Error()
	if !errors.Is(loads["personal"].Err, ErrNotPinned) || !strings.Contains(msg, "yadm enclave join personal --expect") || !strings.Contains(msg, "enclave personal") {
		t.Fatalf("not actionable: %v", msg)
	}
}

func TestFilePins(t *testing.T) {
	dir := t.TempDir()
	p := FilePins(dir)
	if got, err := p.Get("personal"); got != nil || err != nil {
		t.Fatalf("%v %v", got, err)
	}
	want := Pin{Seq: 2, Hash: strings.Repeat("ab", 32)}
	if err := p.Set("personal", want); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Get("personal"); err != nil || *got != want {
		t.Fatalf("%v %v", got, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "pins", "personal"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", fi.Mode().Perm())
	}
	for _, bad := range []model.EnclaveName{"", "..", "a/b"} {
		if err := p.Set(bad, want); err == nil {
			t.Errorf("accepted enclave name %q", bad)
		}
	}
}

func TestHiddenNamesIsStub(t *testing.T) {
	if _, err := (HiddenNames{}).Stored(".x"); !errors.Is(err, model.ErrNotImplemented) {
		t.Fatal(err)
	}
	if s, _ := (PlainNames{}).Stored(".x/y"); s != ".x/y" {
		t.Fatal(s)
	}
}

func TestParseValueToken(t *testing.T) {
	w := newWorld(t)
	tok, _ := w.ring.SealValue("p", []byte("x"))
	vt, ok := ParseValueToken(tok)
	if !ok || vt.Enclave != "personal" || vt.Epoch != 1 {
		t.Fatalf("%+v %v", vt, ok)
	}
	for _, bad := range []string{"", "yadm:1:", "yadm:1:personal:0:AAAA", "yadm:1:personal:01:" + tok[len(tok)-24:], "yadm:2:personal:1:AAAA"} {
		if _, ok := ParseValueToken(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// tp is the source path test containers are bound to.
const tp model.SourcePath = "sealed/personal/x"

// fileSealer is the path-bound whole-file contract *Set offers.
var _ interface {
	SealFile(model.EnclaveName, model.SourcePath, []byte) ([]byte, error)
	OpenFile(model.EnclaveName, model.SourcePath, []byte) ([]byte, error)
} = (*Set)(nil)

func TestSetSealFile(t *testing.T) {
	wp := newWorld(t)
	_, ck, err := Create("client", wp.a, wp.rec.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	set := &Set{Rings: map[model.EnclaveName]*Keyring{"personal": wp.ring, "client": ck}}
	ct, err := set.SealFile("personal", tp, []byte("canary-body"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("canary-body")) || !IsSealedFile(ct) {
		t.Fatal("not sealed")
	}
	if pt, err := set.OpenFile("personal", tp, ct); err != nil || string(pt) != "canary-body" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := set.OpenFile("client", tp, ct); err == nil {
		t.Fatal("opened a personal container as client")
	}
	if _, err := set.SealFile("other", tp, []byte("x")); !errors.Is(err, ErrNotMember) {
		t.Fatalf("seal for unknown enclave: %v", err)
	}
	var none *Set
	if _, err := none.SealFile("personal", tp, []byte("x")); !errors.Is(err, ErrNotMember) {
		t.Fatalf("nil set: %v", err)
	}
	if _, err := none.OpenFile("personal", tp, ct); !errors.Is(err, ErrNotMember) {
		t.Fatalf("nil set open: %v", err)
	}
}
