package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// TestMain keeps the join-code KDF cheap here; crypt's known-answer test
// covers the production cost.
func TestMain(m *testing.M) {
	restore := crypt.SetJoinCodeCostForTest(crypt.JoinCodeCost{Time: 1, Memory: 64, Threads: 1})
	code := m.Run()
	restore()
	os.Exit(code)
}

// TestEnclaveJoinCode: host-a adds host-b to personal and prints a join
// code. On host-b a malformed code is a usage error; a wrong code, or the
// code of another entry, is refused and pins nothing, and apply and sync
// after it leave no personal plaintext in host-b's $HOME or object store.
// The right code, typed in lower case without the dash, pins.
func TestEnclaveJoinCode(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := fx.Canaries["personal"]

	fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	hb := fx.Identities[fixture.HostB].Member()
	env := yadmOK(t, "enclave", "add", "host-b", "--enclave", "personal", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
	added := decode[entryData](t, env.Data)
	want, err := crypt.JoinCode(added.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if added.JoinCode != want || len(env.Next) < 2 || !strings.Contains(env.Next[1], "--code "+want) {
		t.Fatalf("add: code %q (want %q), next %v", added.JoinCode, want, env.Next)
	}
	if out, _, _ := yadmRaw(t, "--json=false", "enclave", "add", "--help"); !strings.Contains(out, "join code") {
		t.Fatalf("add --help does not mention the join code:\n%s", out)
	}
	createFP, err := crypt.Fingerprint(fx.Logs["personal"][0])
	if err != nil {
		t.Fatal(err)
	}
	createCode, err := crypt.JoinCode(createFP)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "0000-0000"
	if want == wrong {
		wrong = "0000-0001"
	}

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, false)
	yadmOK(t, "sync")
	pinned := func() bool {
		t.Helper()
		p, err := crypt.FilePins(b.State).Get("personal")
		if err != nil {
			t.Fatal(err)
		}
		return p != nil
	}
	if _, code, _ := yadm(t, "enclave", "join", "personal", "--code", "ABC"); code != ExitUsage {
		t.Fatalf("malformed code: exit %d", code)
	}
	if _, code, _ := yadm(t, "enclave", "join", "personal", "--code", want, "--expect", added.Fingerprint); code != ExitUsage {
		t.Fatalf("--code with --expect: exit %d", code)
	}
	for _, c := range []string{wrong, createCode} {
		env, code, raw := yadm(t, "enclave", "join", "personal", "--code", c)
		if code != ExitRefused {
			t.Fatalf("join --code %s: exit %d %+v", c, code, env.Error)
		}
		if strings.Contains(string(raw), want) {
			t.Fatal("a refused join printed the code of the local entry")
		}
		if pinned() {
			t.Fatalf("join --code %s pinned", c)
		}
	}
	yadm(t, "apply")
	yadm(t, "sync")
	if pinned() {
		t.Fatal("apply or sync after a refused join pinned")
	}
	// .ssh/config carries a personal region; host-b gets the file without it.
	if s := readFile(t, filepath.Join(b.Home, ".ssh/config")); s == "" {
		t.Fatal("apply after a refused join did not deliver the shared file")
	}
	secrecytest.AssertTreeClean(t, b.Home, canary)
	secrecytest.AssertRepoClean(t, b.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)

	typed := strings.ToLower(strings.ReplaceAll(want, "-", ""))
	env = yadmOK(t, "enclave", "join", "personal", "--code", typed)
	if d := decode[map[string]any](t, env.Data); d["member"] != true {
		t.Fatalf("join: %+v", d)
	}
	if !pinned() {
		t.Fatal("join with the right code did not pin")
	}
	yadmOK(t, "apply")
	// The control: the code was what kept personal off host-b.
	if s := readFile(t, filepath.Join(b.Home, ".ssh/config")); !strings.Contains(s, canary.String()) {
		t.Fatal("member apply after join did not deliver the personal region")
	}
}
