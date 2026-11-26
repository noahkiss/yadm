package crypt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

func recoveryKeyOf(t *testing.T, id *Identity) *RecoveryKey {
	t.Helper()
	k, err := ParseRecoveryKey([]byte(machineComment + string(id.Machine) + "\n" + id.age.String() + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestOpenRecoveryRoundTrip: the recovery key alone opens a verified head
// and reads a file a member sealed, at every epoch the head carries.
func TestOpenRecoveryRoundTrip(t *testing.T) {
	a, rec := ident(t, hostA), ident(t, RecoveryMachine)
	e1, k1, err := Create("personal", a, rec.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	pins := MemPins()
	if err := pins.Set("personal", *mustPin(t, e1)); err != nil {
		t.Fatal(err)
	}
	e2, k2, err := k1.Rotate(e1, a, pins)
	if err != nil {
		t.Fatal(err)
	}
	head, err := VerifyLog([]LogEntry{e1, e2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := model.SourcePath("sealed/personal/.config/notes/private.md")
	ct, err := k2.SealFile(p, []byte("restore guide\n"))
	if err != nil {
		t.Fatal(err)
	}
	old, err := k1.SealFile(p, []byte("epoch one\n"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := OpenRecovery(head, recoveryKeyOf(t, rec))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := k.OpenFile(p, ct); err != nil || string(pt) != "restore guide\n" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if pt, err := k.OpenFile(p, old); err != nil || string(pt) != "epoch one\n" {
		t.Fatalf("open epoch 1 before retire: %q %v", pt, err)
	}
	if _, err := k.OpenFile("sealed/personal/elsewhere", ct); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("a blob at another path opened: %v", err)
	}
}

// TestOpenRecoveryCrossEnclave: one enclave's recovery key opens no other
// enclave, and a member's age key is no recovery key.
func TestOpenRecoveryCrossEnclave(t *testing.T) {
	a := ident(t, hostA)
	recP, recW := ident(t, RecoveryMachine), ident(t, RecoveryMachine)
	hp, _, err := Create("personal", a, recP.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	hw, _, err := Create("work", a, recW.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecovery(hw, recoveryKeyOf(t, recP)); !errors.Is(err, ErrNotMember) {
		t.Fatalf("personal's recovery key opened work: %v", err)
	}
	if _, err := OpenRecovery(hp, recoveryKeyOf(t, recW)); !errors.Is(err, ErrNotMember) {
		t.Fatalf("work's recovery key opened personal: %v", err)
	}
	// A head that claims another key's recipient still fails to unwrap.
	forged := hw
	forged.Recovery.Recipient = recP.Member().Recipient
	if _, err := OpenRecovery(forged, recoveryKeyOf(t, recP)); !errors.Is(err, ErrNotMember) {
		t.Fatalf("a relabeled head opened: %v", err)
	}
	// A member's identity file is refused as a recovery key.
	if _, err := ParseRecoveryKey([]byte(machineComment + string(hostA) + "\n" + a.age.String() + "\n")); err == nil {
		t.Fatal("a member's key parsed as a recovery key")
	}
}

// TestOpenRecoveryForgedLog: a writer forges a whole key log that names the
// genuine recovery recipient and wraps keys of its own. The chain verifies
// without a pin and the recovery key opens it, but ciphertext sealed under
// the genuine keys at an existing path never opens to anything. With the
// genuine fingerprint as the pin, the forged log is refused outright.
func TestOpenRecoveryForgedLog(t *testing.T) {
	a, x, rec := ident(t, hostA), ident(t, "m-attacker"), ident(t, RecoveryMachine)
	genuine, gk, err := Create("personal", a, rec.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	p := model.SourcePath("sealed/personal/.config/notes/private.md")
	ct, err := gk.SealFile(p, []byte("genuine\n"))
	if err != nil {
		t.Fatal(err)
	}
	forged, xk, err := Create("personal", x, rec.Member(), MemPins())
	if err != nil {
		t.Fatal(err)
	}
	head, err := VerifyLog([]LogEntry{forged}, nil)
	if err != nil {
		t.Fatalf("a forged log should verify without a pin: %v", err)
	}
	k, err := OpenRecovery(head, recoveryKeyOf(t, rec))
	if err != nil {
		t.Fatalf("the recovery key should open the forged head: %v", err)
	}
	if pt, err := k.OpenFile(p, ct); !errors.Is(err, ErrAuthFailed) || pt != nil {
		t.Fatalf("genuine ciphertext opened under forged keys: %q %v", pt, err)
	}
	// The attacker's own ciphertext opens under its keys: only a pin tells
	// the forged log apart.
	evil, err := xk.SealFile(p, []byte("attacker\n"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := k.OpenFile(p, evil); err != nil || string(pt) != "attacker\n" {
		t.Fatalf("control: %q %v", pt, err)
	}
	pin := mustPin(t, genuine)
	if _, err := VerifyLog([]LogEntry{forged}, pin); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("a forged log passed the genuine pin: %v", err)
	}
}

// TestRecoveryKeyFile: LoadRecoveryKey takes new-recovery's file and
// refuses one with group or other access or behind a symlink; the parser
// takes a bare key line and never quotes a malformed key.
func TestRecoveryKeyFile(t *testing.T) {
	rec := ident(t, RecoveryMachine)
	dir := t.TempDir()
	if err := rec.Save(dir); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, AgeIdentityFile)
	k, err := LoadRecoveryKey(p)
	if err != nil || k.Recipient() != rec.Member().Recipient {
		t.Fatalf("load: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryKey(link); err == nil {
		t.Fatal("loaded a key through a symlink")
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecoveryKey(p); err == nil {
		t.Fatal("loaded a group-readable key")
	}
	if k, err := ParseRecoveryKey([]byte("\n  " + rec.age.String() + "  \n")); err != nil || k.Recipient() != rec.Member().Recipient {
		t.Fatalf("bare key: %v", err)
	}
	bad := "AGE-SECRET-KEY-1" + strings.Repeat("Q", 58) // built at run time: a malformed key, not a secret
	if _, err := ParseRecoveryKey([]byte(bad)); err == nil || strings.Contains(err.Error(), "QQQQ") {
		t.Fatalf("malformed key: %v", err)
	}
	if _, err := ParseRecoveryKey([]byte(rec.age.String() + "\n" + rec.age.String() + "\n")); err == nil {
		t.Fatal("two key lines parsed")
	}
}
