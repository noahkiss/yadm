package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

// fixtureRemote commits the fixture source tree and pushes it to a bare remote.
func fixtureRemote(t *testing.T, root string, fx *fixture.Fixture) string {
	t.Helper()
	remote := filepath.Join(root, "remote.git")
	git(t, root, "init", "-q", "--bare", "-b", "main", remote)
	git(t, fx.Root, "init", "-q", "-b", "main")
	git(t, fx.Root, "add", "-A")
	git(t, fx.Root, "commit", "-q", "-m", "fixture")
	git(t, fx.Root, "push", "-q", remote, "main")
	return remote
}

// fixtureMachine sets up one fixture machine the way init does, with the
// fixture's identity, and pins the enclaves it is a member of when pin is set.
func fixtureMachine(t *testing.T, root, remote string, fx *fixture.Fixture, id model.MachineID, pin bool) machineDirs {
	t.Helper()
	m := useMachine(t, root, string(id))
	if _, err := store.Clone(context.Background(), remote, m.Source, m.State); err != nil {
		t.Fatal(err)
	}
	if err := fx.Identities[id].Save(m.State); err != nil {
		t.Fatal(err)
	}
	if err := fleet.SaveIdentity(identityPath(m.Paths), fleet.Identity{Machine: id, Remote: remote}); err != nil {
		t.Fatal(err)
	}
	if pin {
		pins := crypt.FilePins(m.State)
		for e, members := range fixture.Members {
			for _, mid := range members {
				if mid != id {
					continue
				}
				p, err := crypt.PinOf(fx.Logs[e][len(fx.Logs[e])-1])
				if err != nil {
					t.Fatal(err)
				}
				if err := pins.Set(e, p); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return m
}

// TestSecrecyThroughCLI applies, diffs, shows and lists as a non-member and
// a member, and removes a member through `enclave remove`: no enclave
// plaintext reaches a non-member's $HOME, its stdout, or any repository.
func TestSecrecyThroughCLI(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canaries := fx.AllCanaries()

	// host-b (work) is in no enclave.
	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	// Edit a target with a sealed region so diff has something to show.
	sshCfg := filepath.Join(b.Home, ".ssh/config")
	writeFile(t, sshCfg, readFile(t, sshCfg)+"# local edit\n")
	env, _, _ := yadm(t, "diff", ".ssh/config")
	if fs := decode[map[string][]fileDiff](t, env.Data)["files"]; len(fs) != 1 || !strings.Contains(fs[0].Diff, "+# local edit") {
		t.Fatalf("non-member diff: %+v", fs)
	}
	for _, args := range [][]string{{"diff", ".ssh/config", ".config/editor/settings.json"}, {"diff"}, {"hold", "list"}, {"machine"}, {"status"}, {"log"}, {"enclave", "list"}, {"check"}} {
		_, _, out := yadm(t, args...)
		for _, c := range canaries {
			if strings.Contains(string(out), c.String()) {
				t.Fatalf("yadm %v on a non-member printed %s plaintext", args, c.Label)
			}
		}
	}
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)

	// host-a is the only member of personal.
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	env = yadmOK(t, "apply")
	if s := mustJSON(t, env.Data); !strings.Contains(s, ".config/notes/private.md") {
		t.Fatalf("member apply did not deliver the sealed file: %s", s)
	}
	env = yadmOK(t, "machine")
	if md := decode[machineData](t, env.Data); len(md.Enclaves.Opened) != 1 || md.Enclaves.Opened[0] != "personal" {
		t.Fatalf("enclaves: %+v", md.Enclaves)
	}

	// Add host-b to personal, then remove it again: the remove reseals under a
	// new epoch and nothing leaks into either repository.
	hb := fx.Identities[fixture.HostB].Member()
	env = yadmOK(t, "enclave", "add", "host-b", "--enclave", "personal", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
	added := decode[entryData](t, env.Data)
	if added.Op != crypt.OpAdd || added.Seq != 2 || added.Fingerprint == "" {
		t.Fatalf("add: %+v", added)
	}
	if _, code, _ := yadm(t, "enclave", "remove", "host-b", "--enclave", "personal"); code != ExitUsage {
		t.Fatalf("remove without --confirm: exit %d", code)
	}
	env = yadmOK(t, "enclave", "remove", "host-b", "--enclave", "personal", "--confirm")
	removed := decode[entryData](t, env.Data)
	if removed.Op != crypt.OpRemove || removed.Epoch != 2 || len(removed.Resealed) == 0 {
		t.Fatalf("remove: %+v", removed)
	}
	env = yadmOK(t, "enclave", "verify")
	if _, _, err := yadmRawPush(t); err != nil {
		t.Fatal(err)
	}
	yadmOK(t, "apply")
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
}

func yadmRawPush(t *testing.T) (string, string, error) {
	t.Helper()
	out, stderr, code := yadmRaw(t, "git", "push", "-q", "origin", "main")
	if code != 0 {
		t.Fatalf("push: exit %d %s", code, stderr)
	}
	return out, stderr, nil
}

// TestEnclaveJoinRefusals: join needs --expect (exit 2), and a wrong
// fingerprint or a tampered log is refused (exit 6).
func TestEnclaveJoinRefusals(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)

	// host-c is a member of client but has not pinned it.
	fixtureMachine(t, root, remote, fx, fixture.HostC, false)
	env, code, _ := yadm(t, "enclave", "verify")
	if code != ExitRefused || !strings.Contains(env.Error.Message, "client") {
		t.Fatalf("verify unpinned member: exit %d %+v", code, env.Error)
	}
	if env, code, _ := yadm(t, "enclave", "join", "client"); code != ExitUsage || len(env.Next) == 0 {
		t.Fatalf("join without --expect: exit %d", code)
	}
	if _, code, _ := yadm(t, "enclave", "join", "client", "--expect", strings.Repeat("0", 64)); code != ExitRefused {
		t.Fatalf("join with a wrong fingerprint: exit %d", code)
	}
	logs := fx.Logs["client"]
	fp, err := crypt.Fingerprint(logs[len(logs)-1])
	if err != nil {
		t.Fatal(err)
	}
	env = yadmOK(t, "enclave", "join", "client", "--expect", fp)
	if d := decode[map[string]any](t, env.Data); d["member"] != true {
		t.Fatalf("join: %+v", d)
	}
	yadmOK(t, "enclave", "verify")
	env = yadmOK(t, "machine")
	if md := decode[machineData](t, env.Data); len(md.Enclaves.Opened) != 1 || md.Enclaves.Opened[0] != "client" {
		t.Fatalf("after join: %+v", md.Enclaves)
	}
}

// TestImportSealerSecrecy: the cli's import sealer creates a valid key log,
// seals in memory, and the commit it adds holds no plaintext.
func TestImportSealerSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	c := secrecytest.NewCanary(t, "personal")
	by, err := crypt.GenerateIdentity("m-test00000001")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := crypt.GenerateIdentity(crypt.RecoveryMachine)
	if err != nil {
		t.Fatal(err)
	}
	s := newImportSealer(by, rec.Member())
	sealed, err := s.SealFile("personal", c.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !crypt.IsSealedFile(sealed) || strings.Contains(string(sealed), c.String()) {
		t.Fatal("sealer returned plaintext")
	}
	repo := seedRemote(t, root, map[string]string{"README": "x\n"})
	work := filepath.Join(root, "seed")
	parent := model.CommitID(git(t, work, "rev-parse", "HEAD"))
	r, err := store.Open(work, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	changes, fps, err := s.changes()
	if err != nil {
		t.Fatal(err)
	}
	ch := append(changes, store.Change{Path: "sealed/personal/.secret", Blob: sealed, Mode: 0o100644})
	id, err := r.CommitPaths(context.Background(), parent, ch, store.Message{Subject: "t"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.ReadPath(context.Background(), id, crypt.LogPath("personal", 1))
	if err != nil {
		t.Fatal(err)
	}
	le, err := crypt.ParseLogEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := crypt.PinOf(le)
	if _, err := crypt.VerifyLog([]crypt.LogEntry{le}, &pin); err != nil {
		t.Fatalf("key log: %v", err)
	}
	if fps["personal"] == "" {
		t.Fatal("no fingerprint")
	}
	ring, err := crypt.Open(le, by)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := ring.OpenFile(sealed); err != nil || string(pt) != string(c.Bytes()) {
		t.Fatalf("open: %v", err)
	}
	secrecytest.AssertRepoClean(t, work, c)
	secrecytest.AssertRepoClean(t, repo, c)
}
