package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
)

// landEntryFirst makes another process on this machine append a key-log
// entry, through the same write path, after the command has checked its
// own entry and before it commits: the window a lock wait opens.
func landEntryFirst(t *testing.T, enc model.EnclaveName, build func(m *machineEnv) entryBuild) *crypt.LogEntry {
	t.Helper()
	landed := new(crypt.LogEntry)
	hooks.beforeCommit = func(ctx context.Context) {
		hooks.beforeCommit = nil
		m, err := requireIdentity(ctx)
		if err != nil {
			t.Errorf("other process: %v", err)
			return
		}
		d, e, _, err := m.writeEntry(ctx, "test", enc, "enclave "+string(enc)+": other process", build(m))
		if err != nil || d.Commit == "" {
			t.Errorf("other process: commit %q %v", d.Commit, err)
		}
		*landed = e
	}
	return landed
}

// addBuild adds member to enc, as `enclave add` does.
func addBuild(enc model.EnclaveName, member crypt.Member) func(m *machineEnv) entryBuild {
	return func(m *machineEnv) entryBuild {
		return func(context.Context) (crypt.LogEntry, *apply.Capture, error) {
			ring, head, err := ringFor(m, enc)
			if err != nil {
				return crypt.LogEntry{}, nil, err
			}
			e, err := ring.Add(head, member, m.id, m.pendingPins())
			return e, nil, err
		}
	}
}

// assertLogKeeps fails unless the key log of enc on main verifies, holds
// the other process's entry unchanged at its seq, and ends with the
// command's entry right after it.
func assertLogKeeps(t *testing.T, source string, enc model.EnclaveName, other *crypt.LogEntry, op crypt.Op) []crypt.LogEntry {
	t.Helper()
	log := keyLogAt(t, source, string(enc))
	if _, err := crypt.VerifyLog(log, nil); err != nil {
		t.Fatalf("key log of %s: %v", enc, err)
	}
	if other.Seq == 0 || int(other.Seq) > len(log) {
		t.Fatalf("the other process's entry (seq %d) is missing from a log of %d", other.Seq, len(log))
	}
	want, _ := crypt.Fingerprint(*other)
	if got, _ := crypt.Fingerprint(log[other.Seq-1]); got != want {
		t.Fatalf("seq %d of %s was overwritten: now %s %s", other.Seq, enc, log[other.Seq-1].Op, log[other.Seq-1].Subject)
	}
	if last := log[len(log)-1]; last.Seq != other.Seq+1 || last.Op != op {
		t.Fatalf("the command's entry: seq %d %s (other at seq %d)", last.Seq, last.Op, other.Seq)
	}
	return log
}

// freshMember is a new machine's public keys.
func freshMember(t *testing.T, id model.MachineID) crypt.Member {
	t.Helper()
	x, err := crypt.GenerateIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	return x.Member()
}

// TestEnclaveWritesExtendAConcurrentEntry: while enclave add and remove
// wait for the lock, another process appends a key-log entry. Each command
// then appends after it; no entry is lost, overwritten or forked. (Retire
// writes through the same path; remove ends with one.)
func TestEnclaveWritesExtendAConcurrentEntry(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	passGate(t)
	hb := fx.Identities[fixture.HostB].Member()
	hc := fx.Identities[fixture.HostC].Member()
	const enc = model.EnclaveName("personal")

	other := landEntryFirst(t, enc, addBuild(enc, hc))
	yadmOK(t, "enclave", "add", "host-b", "--enclave", "personal", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
	log := assertLogKeeps(t, a.Source, enc, other, crypt.OpAdd)
	if _, ok := memberOf(log[len(log)-1], fixture.HostC); !ok {
		t.Fatal("the add dropped the member the other process added")
	}

	other = landEntryFirst(t, enc, addBuild(enc, freshMember(t, "m-eeeeee000001")))
	env, code, _ := yadm(t, "enclave", "remove", "host-c", "--enclave", "personal", "--confirm")
	if code != ExitOK && code != ExitAttention {
		t.Fatalf("remove: exit %d %+v", code, env.Error)
	}
	log = keyLogAt(t, a.Source, string(enc))
	if _, err := crypt.VerifyLog(log, nil); err != nil {
		t.Fatalf("key log after remove: %v", err)
	}
	want, _ := crypt.Fingerprint(*other)
	if got, _ := crypt.Fingerprint(log[other.Seq-1]); got != want || len(log) <= int(other.Seq) || log[other.Seq].Op != crypt.OpRemove {
		t.Fatalf("remove did not extend the other process's entry at seq %d (log of %d)", other.Seq, len(log))
	}
	if _, ok := memberOf(log[other.Seq], "m-eeeeee000001"); !ok {
		t.Fatal("the remove dropped the member the other process added")
	}
	yadmOK(t, "enclave", "verify")
}

// TestEnclaveCreateAndSetRecoveryRace: a create that finds another
// process's create landed meanwhile is refused and leaves that log alone;
// a set-recovery extends a concurrent entry.
func TestEnclaveCreateAndSetRecoveryRace(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, map[string]string{
		"fleet.toml":                goldenFleet,
		"manifest.toml":             e2eManifest,
		"files/.config/tool/config": "color = blue\n",
	})
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	const enc = model.EnclaveName("vault")
	rec, err := crypt.GenerateIdentity(crypt.RecoveryMachine)
	if err != nil {
		t.Fatal(err)
	}
	recDir := filepath.Join(root, "offline", "rec")
	if err := os.MkdirAll(recDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rec.Save(recDir); err != nil {
		t.Fatal(err)
	}

	other := landEntryFirst(t, enc, func(m *machineEnv) entryBuild {
		return func(context.Context) (crypt.LogEntry, *apply.Capture, error) {
			e, _, err := crypt.Create(enc, m.id, rec.Member(), m.pendingPins())
			return e, nil, err
		}
	})
	if _, code, _ := yadm(t, "enclave", "create", "vault", "--new-recovery", filepath.Join(root, "offline", "second")); code == ExitOK {
		t.Fatal("a second create over a concurrent one succeeded")
	}
	log := keyLogAt(t, a.Source, string(enc))
	want, _ := crypt.Fingerprint(*other)
	if got, _ := crypt.Fingerprint(log[0]); len(log) != 1 || got != want {
		t.Fatalf("the concurrent create was overwritten: %d entries", len(log))
	}

	other = landEntryFirst(t, enc, addBuild(enc, freshMember(t, "m-eeeeee000002")))
	yadmOK(t, "enclave", "set-recovery", "--enclave", "vault", "--recovery-dir", recDir, "--new-recovery", filepath.Join(root, "offline", "rec-2"))
	assertLogKeeps(t, a.Source, enc, other, crypt.OpSetRecovery)
}
