package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// TestEnclaveRemoveHeldByGate: when the commit gate holds the reseal (here
// its check is not allowed on this machine), remove commits nothing: no
// key-log entry, no pin move, no epoch change, and members keep opening
// the enclave with no seal_guard hold. Once the gate passes, remove lands
// the entry, the reseal and the retire together.
func TestEnclaveRemoveHeldByGate(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := fx.Canaries["personal"]

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	hb := fx.Identities[fixture.HostB].Member()
	yadmOK(t, "enclave", "add", "host-b", "--enclave", "personal", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)

	head := git(t, a.Source, "rev-parse", "main")
	remoteHead := git(t, remote, "rev-parse", "main")
	pins := crypt.FilePins(a.State)
	pinBefore, err := pins.Get("personal")
	if err != nil || pinBefore == nil {
		t.Fatalf("pin: %v %v", pinBefore, err)
	}

	env, code, raw := yadm(t, "enclave", "remove", "host-b", "--enclave", "personal", "--confirm")
	if code != ExitError || env.Error == nil {
		t.Fatalf("remove with a held reseal: exit %d %+v", code, env.Error)
	}
	for _, want := range []string{"did not commit", ".config/notes/private.md", "unchanged"} {
		if !strings.Contains(env.Error.Message, want) {
			t.Fatalf("remove message lacks %q: %s", want, env.Error.Message)
		}
	}
	if strings.Contains(env.Error.Message, ".config/shell") {
		t.Fatalf("remove names a hold that is not part of the reseal: %s", env.Error.Message)
	}
	if strings.Contains(string(raw), canary.String()) {
		t.Fatal("remove printed enclave plaintext")
	}
	if now := git(t, a.Source, "rev-parse", "main"); now != head {
		t.Fatal("a held remove committed")
	}
	if now := git(t, remote, "rev-parse", "main"); now != remoteHead {
		t.Fatal("a held remove pushed")
	}
	if out := git(t, a.Source, "ls-tree", "--name-only", "main", "keys/personal/"); strings.Count(out, ".toml") != 2 {
		t.Fatalf("key log changed: %s", out)
	}
	if pinAfter, _ := pins.Get("personal"); pinAfter == nil || *pinAfter != *pinBefore {
		t.Fatalf("pin moved: %v -> %v", pinBefore, pinAfter)
	}
	env = yadmOK(t, "enclave", "list")
	for _, e := range decode[map[string][]enclaveInfo](t, env.Data)["enclaves"] {
		if e.Enclave == "personal" && (e.Epoch != 1 || e.Seq != 2) {
			t.Fatalf("enclave changed: %+v", e)
		}
	}
	noSealGuard(t)
	if !strings.Contains(readFile(t, filepath.Join(a.Home, ".config/notes/private.md")), canary.String()) {
		t.Fatal("the member lost its enclave file")
	}

	// With the gate passing, remove lands whole and retires the old epoch.
	passGate(t)
	env = yadmOK(t, "enclave", "remove", "host-b", "--enclave", "personal", "--confirm")
	if d := decode[entryData](t, env.Data); d.Epoch != 2 || len(d.Resealed) == 0 || d.Commit == "" {
		t.Fatalf("remove: %+v", d)
	}
	for _, n := range env.Next {
		if strings.Contains(n, "enclave retire") {
			t.Fatalf("remove left the old epoch open: %v", env.Next)
		}
	}
	noSealGuard(t)
	if !strings.Contains(readFile(t, filepath.Join(a.Home, ".config/notes/private.md")), canary.String()) {
		t.Fatal("the member cannot open the resealed file")
	}
	secrecytest.AssertRepoClean(t, a.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)
}

// noSealGuard applies and fails on any seal_guard hold.
func noSealGuard(t *testing.T) {
	t.Helper()
	env, _, _ := yadm(t, "apply")
	for _, h := range decode[struct{ Holds []model.Hold }](t, env.Data).Holds {
		if h.Reason == model.HoldSealGuard {
			t.Fatalf("seal_guard hold on %s: %s", h.Target, h.Detail)
		}
	}
}
