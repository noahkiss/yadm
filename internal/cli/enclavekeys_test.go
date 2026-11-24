package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// TestEnclaveNewRecovery: a machine that is not initialized generates a
// recovery identity with new-recovery. The directory and files are private,
// and a machine of the type creates the enclave with only the public half.
// The saved identity signs a set-recovery the CLI accepts and a recover
// entry the key log verifies. new-recovery refuses an existing directory and
// one inside the source or state directory, and writes nothing then.
func TestEnclaveNewRecovery(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, map[string]string{
		"fleet.toml":                goldenFleet,
		"manifest.toml":             e2eManifest,
		"files/.config/tool/config": "color = blue\n",
	})

	// A fresh machine: no init, no membership.
	useMachine(t, root, "keygen")
	dir := filepath.Join(root, "offline", "vault-recovery")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	env := yadmOK(t, "enclave", "new-recovery", dir, "--enclave", "vault")
	d := decode[map[string]string](t, env.Data)
	if d["dir"] != dir || !strings.HasPrefix(d["recipient"], "age1") || d["sign_key"] == "" {
		t.Fatalf("new-recovery: %+v", d)
	}
	wantCreate := "yadm enclave create vault --recovery-recipient " + d["recipient"] + " --recovery-sign-key " + d["sign_key"]
	if d["create"] != wantCreate || !strings.Contains(strings.Join(env.Next, "\n"), "password manager") {
		t.Fatalf("create %q next %v", d["create"], env.Next)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode: %v %v", fi, err)
	}
	for _, f := range []string{crypt.AgeIdentityFile, crypt.SigningKeyFile} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode: %v %v", f, fi, err)
		}
	}
	if out, _, _ := yadmRaw(t, "--json=false", "enclave", "new-recovery", "--help"); !strings.Contains(out, "password manager") || !strings.Contains(out, "delete") {
		t.Fatalf("help does not say to store it offline and delete it:\n%s", out)
	}
	rec, err := crypt.LoadIdentity(dir)
	if err != nil || rec.Member().Recipient != d["recipient"] || rec.Member().SignKey != d["sign_key"] {
		t.Fatalf("saved identity: %v", err)
	}

	// Refusals write nothing.
	before := listDir(t, dir)
	if _, code, _ := yadm(t, "enclave", "new-recovery", dir); code != ExitUsage {
		t.Fatalf("existing dir: exit %d", code)
	}
	if after := listDir(t, dir); after != before {
		t.Fatalf("a refused new-recovery changed %s: %s -> %s", dir, before, after)
	}
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	for _, bad := range []string{filepath.Join(a.State, "rec"), filepath.Join(a.Source, "rec"), filepath.Join(a.Config, "rec")} {
		if _, code, _ := yadm(t, "enclave", "new-recovery", bad); code != ExitUsage {
			t.Fatalf("new-recovery %s: exit %d", bad, code)
		}
		if _, err := os.Stat(bad); !os.IsNotExist(err) {
			t.Fatalf("a refused new-recovery created %s", bad)
		}
	}

	// The creator takes only the public half.
	env = yadmOK(t, "enclave", "create", "vault", "--recovery-recipient", d["recipient"], "--recovery-sign-key", d["sign_key"])
	if r := decode[entryData](t, env.Data); r.Recovery != "" || r.Seq != 1 {
		t.Fatalf("create: %+v", r)
	}
	entries := keyLogAt(t, a.Source, "vault")
	if len(entries) != 1 || entries[0].Recovery.Recipient != d["recipient"] || entries[0].Recovery.SignKey != d["sign_key"] {
		t.Fatalf("key log recovery: %+v", entries)
	}

	// The identity signs a recover entry that verifies, and opens the head.
	fresh, err := crypt.GenerateIdentity("m-ffffff")
	if err != nil {
		t.Fatal(err)
	}
	re, _, err := crypt.Recover(entries[0], rec, []crypt.Member{fresh.Member()}, crypt.MemPins())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypt.VerifyLog(append(entries, re), nil); err != nil {
		t.Fatalf("recover entry: %v", err)
	}
	// And the CLI accepts it as the current recovery identity.
	next := filepath.Join(root, "offline", "vault-recovery-2")
	env = yadmOK(t, "enclave", "set-recovery", "--enclave", "vault", "--recovery-dir", dir, "--new-recovery", next)
	if r := decode[entryData](t, env.Data); r.Op != crypt.OpSetRecovery || r.Recovery != next {
		t.Fatalf("set-recovery: %+v", r)
	}
	// --new-recovery refuses an existing directory too.
	if _, code, _ := yadm(t, "enclave", "set-recovery", "--enclave", "vault", "--recovery-dir", next, "--new-recovery", dir); code != ExitUsage {
		t.Fatalf("--new-recovery over an existing dir: exit %d", code)
	}
	if got, err := crypt.LoadIdentity(dir); err != nil || got.Member() != rec.Member() {
		t.Fatal("--new-recovery overwrote a recovery identity")
	}
}

func listDir(t *testing.T, dir string) string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.Name() + " " + readFile(t, filepath.Join(dir, e.Name())) + "\n")
	}
	return b.String()
}

// keyLogAt parses an enclave's key-log entries at the source clone's main.
func keyLogAt(t *testing.T, source, enclave string) []crypt.LogEntry {
	t.Helper()
	var out []crypt.LogEntry
	for _, p := range strings.Fields(git(t, source, "ls-tree", "-r", "--name-only", "main", "keys/"+enclave+"/")) {
		e, err := crypt.ParseLogEntry([]byte(git(t, source, "show", "main:"+p) + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out = append(out, e)
	}
	return out
}

// TestEnclaveAddVouchedKeys: enclave add leaves out --recipient and
// --sign-key only when a key log this machine has pinned vouches for the
// keys through a trusted signer.
//
//   - host-c (client) has not pinned personal, where host-a is listed: it
//     must pass the flags, and a refused add commits nothing.
//   - host-a adds host-b to personal with flags, then (after joining client
//     on demand) adds host-b to client without them: host-a signed the
//     personal entry that introduced host-b's keys.
//   - A personal entry signed by a machine that is no member of the target
//     enclave vouches for nothing, and a refused add leaks no plaintext.
func TestEnclaveAddVouchedKeys(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := fx.Canaries["client"]
	passBin(t)

	c := fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	head := git(t, c.Source, "rev-parse", "main")
	env, code, raw := yadm(t, "enclave", "add", "host-a", "--enclave", "client")
	if code != ExitUsage || !strings.Contains(env.Error.Message, "--recipient") || len(env.Next) == 0 || !strings.Contains(env.Next[0], "yadm machine") {
		t.Fatalf("add from an unpinned log: exit %d %+v %v", code, env.Error, env.Next)
	}
	ha := fx.Identities[fixture.HostA].Member()
	if strings.Contains(string(raw), ha.Recipient) {
		t.Fatal("a refused add printed keys read from an unpinned log")
	}
	if now := git(t, c.Source, "rev-parse", "main"); now != head {
		t.Fatal("a refused add committed")
	}
	if _, code, _ := yadm(t, "enclave", "add", "host-a", "--enclave", "client", "--recipient", ha.Recipient); code != ExitUsage {
		t.Fatalf("--recipient alone: exit %d", code)
	}
	env = yadmOK(t, "enclave", "add", "host-a", "--enclave", "client", "--recipient", ha.Recipient, "--sign-key", ha.SignKey)
	added := decode[entryData](t, env.Data)
	if added.KeysFrom != "flags" {
		t.Fatalf("keys_from: %q", added.KeysFrom)
	}
	yadmRawPush(t)

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "enclave", "on-demand", "client")
	yadmOK(t, "enclave", "join", "client", "--expect", added.Fingerprint)
	hb := fx.Identities[fixture.HostB].Member()
	yadmOK(t, "enclave", "add", "host-b", "--enclave", "personal", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
	env = yadmOK(t, "enclave", "add", string(fixture.HostB), "--enclave", "client")
	d := decode[entryData](t, env.Data)
	if !strings.HasPrefix(d.KeysFrom, "personal seq ") {
		t.Fatalf("keys_from: %q", d.KeysFrom)
	}
	entries := keyLogAt(t, a.Source, "client")
	last := entries[len(entries)-1]
	if got, ok := memberOf(last, fixture.HostB); !ok || got != hb {
		t.Fatalf("client add of host-b: %+v", last.Members)
	}
	secrecytest.AssertTreeClean(t, a.Home, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)
}

// TestEnclaveAddUntrustedSigner: a key pair introduced into a pinned log by
// a signer that is neither this machine nor a member of the target enclave
// vouches for nothing. host-c adds a made-up machine to client; host-a
// (member of personal and client) can add it to personal only with flags.
func TestEnclaveAddUntrustedSigner(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := fx.Canaries["personal"]
	passBin(t)

	// host-a joins client (host-c adds it), so host-a pins client.
	fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	ha := fx.Identities[fixture.HostA].Member()
	fp := decode[entryData](t, yadmOK(t, "enclave", "add", "host-a", "--enclave", "client", "--recipient", ha.Recipient, "--sign-key", ha.SignKey).Data).Fingerprint
	// host-c, no personal member, introduces keys for a machine into client.
	stranger, err := crypt.GenerateIdentity("m-zzzzzz")
	if err != nil {
		t.Fatal(err)
	}
	sm := stranger.Member()
	yadmOK(t, "enclave", "add", "m-zzzzzz", "--enclave", "client", "--recipient", sm.Recipient, "--sign-key", sm.SignKey)
	yadmRawPush(t)

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "enclave", "on-demand", "client")
	yadmOK(t, "enclave", "join", "client", "--expect", fp)
	yadmOK(t, "sync")
	head := git(t, a.Source, "rev-parse", "main")
	if env, code, _ := yadm(t, "enclave", "add", "m-zzzzzz", "--enclave", "personal"); code != ExitUsage {
		t.Fatalf("add vouched by an outside signer: exit %d %+v", code, env.Error)
	}
	if now := git(t, a.Source, "rev-parse", "main"); now != head {
		t.Fatal("a refused add committed")
	}
	got := keyLogAt(t, a.Source, "personal")
	if len(got) != len(fx.Logs["personal"]) {
		t.Fatalf("personal key log grew to %d entries", len(got))
	}
	// The stranger's key opens nothing of personal.
	if _, err := crypt.Open(got[len(got)-1], stranger); err == nil {
		t.Fatal("the stranger opens personal")
	}
	yadmOK(t, "sync")
	secrecytest.AssertRepoClean(t, a.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)
}

func memberOf(e crypt.LogEntry, id model.MachineID) (crypt.Member, bool) {
	for _, m := range e.Members {
		if m.Machine == id {
			return m, true
		}
	}
	return crypt.Member{}, false
}

// passBin puts a passing secret-check stub on PATH for the fixture's gate.
func passBin(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestEnclaveAddSignerByKey: a signer counts by its signing key, not its id.
// A personal member lists host-c's id in personal under keys it holds, then
// signs a stranger's add with them. host-c's id is a client member, but
// under other keys, so host-a's add to client without flags is refused,
// commits nothing, and the stranger opens nothing of client.
func TestEnclaveAddSignerByKey(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	passBin(t)

	fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	ha := fx.Identities[fixture.HostA].Member()
	fp := decode[entryData](t, yadmOK(t, "enclave", "add", "host-a", "--enclave", "client", "--recipient", ha.Recipient, "--sign-key", ha.SignKey).Data).Fingerprint
	yadmRawPush(t)

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "enclave", "on-demand", "client")
	yadmOK(t, "enclave", "join", "client", "--expect", fp)
	fakeC, err := crypt.GenerateIdentity(fixture.HostC)
	if err != nil {
		t.Fatal(err)
	}
	fc := fakeC.Member()
	yadmOK(t, "enclave", "add", string(fixture.HostC), "--enclave", "personal", "--recipient", fc.Recipient, "--sign-key", fc.SignKey)

	// The impostor signs the stranger's add to personal.
	stranger, err := crypt.GenerateIdentity("m-zzzzzz")
	if err != nil {
		t.Fatal(err)
	}
	log := keyLogAt(t, a.Source, "personal")
	head := log[len(log)-1]
	ring, err := crypt.Open(head, fakeC)
	if err != nil {
		t.Fatal(err)
	}
	pins := crypt.MemPins()
	pin, err := crypt.PinOf(head)
	if err != nil {
		t.Fatal(err)
	}
	if err := pins.Set("personal", pin); err != nil {
		t.Fatal(err)
	}
	forged, err := ring.Add(head, stranger.Member(), fakeC, pins)
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypt.MarshalLogEntry(forged)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(a.Source, string(crypt.LogPath("personal", forged.Seq))), string(b))
	git(t, a.Source, "add", "-A")
	git(t, a.Source, "commit", "-q", "-m", "enclave personal: add m-zzzzzz")
	yadmOK(t, "enclave", "verify")

	before := git(t, a.Source, "rev-parse", "main")
	if env, code, _ := yadm(t, "enclave", "add", "m-zzzzzz", "--enclave", "client"); code != ExitUsage {
		t.Fatalf("add vouched by a same-id impostor: exit %d %+v", code, env.Error)
	}
	if now := git(t, a.Source, "rev-parse", "main"); now != before {
		t.Fatal("a refused add committed")
	}
	cl := keyLogAt(t, a.Source, "client")
	if _, err := crypt.Open(cl[len(cl)-1], stranger); err == nil {
		t.Fatal("the stranger opens client")
	}
}

// vouchSetup: host-c adds host-a to client; host-a joins client on demand.
// host-a then pins both personal (member) and client.
func vouchSetup(t *testing.T) (root, remote string, fx *fixture.Fixture, a machineDirs) {
	t.Helper()
	hermetic(t)
	root = t.TempDir()
	fx = fixture.Build(t)
	remote = fixtureRemote(t, root, fx)
	passBin(t)
	fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	ha := fx.Identities[fixture.HostA].Member()
	fp := decode[entryData](t, yadmOK(t, "enclave", "add", "host-a", "--enclave", "client", "--recipient", ha.Recipient, "--sign-key", ha.SignKey).Data).Fingerprint
	yadmRawPush(t)
	a = fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "enclave", "on-demand", "client")
	yadmOK(t, "enclave", "join", "client", "--expect", fp)
	return root, remote, fx, a
}

// TestEnclaveAddVouchedNameBinding: without key flags, a fleet name selects
// the keys, and fleet.toml is writable by any writer. host-a honestly adds
// another machine (m-zzzzzz) to personal. A writer then points the fleet
// name host-b at m-zzzzzz. "add host-b" without flags must not wrap client
// to m-zzzzzz: it asks for the machine id or the flags.
func TestEnclaveAddVouchedNameBinding(t *testing.T) {
	_, _, fx, a := vouchSetup(t)
	canary := fx.Canaries["client"]
	x, err := crypt.GenerateIdentity("m-zzzzzz")
	if err != nil {
		t.Fatal(err)
	}
	xm := x.Member()
	yadmOK(t, "enclave", "add", "m-zzzzzz", "--enclave", "personal", "--recipient", xm.Recipient, "--sign-key", xm.SignKey)

	fl := readFile(t, filepath.Join(a.Source, "fleet.toml"))
	fl = strings.Replace(fl, `name = "host-b"`, `name = "host-b-old"`, 1)
	fl = strings.Replace(fl, `nicknames = ["desk-b"]`, `nicknames = []`, 1)
	fl += "\n[machines.m-zzzzzz]\nname = \"host-b\"\ntypes = [\"work\"]\nos = \"linux\"\narch = \"amd64\"\n"
	writeFile(t, filepath.Join(a.Source, "fleet.toml"), fl)
	git(t, a.Source, "add", "-A")
	git(t, a.Source, "commit", "-q", "-m", "fleet: rename")

	before := git(t, a.Source, "rev-parse", "main")
	if env, code, _ := yadm(t, "enclave", "add", "host-b", "--enclave", "client"); code != ExitUsage {
		t.Fatalf("add by a fleet name without flags: exit %d %+v", code, env.Error)
	}
	if now := git(t, a.Source, "rev-parse", "main"); now != before {
		t.Fatal("a refused add committed")
	}
	cl := keyLogAt(t, a.Source, "client")
	if _, err := crypt.Open(cl[len(cl)-1], x); err == nil {
		t.Fatal("the renamed machine opens client")
	}
	secrecytest.AssertRepoClean(t, a.Source, canary)
}

// TestEnclaveAddVouchedAfterRemove: a machine that the target enclave's own
// log once removed is re-added only with the flags, never from a vouching
// log.
func TestEnclaveAddVouchedAfterRemove(t *testing.T) {
	_, _, fx, a := vouchSetup(t)
	hb := fx.Identities[fixture.HostB].Member()
	yadmOK(t, "enclave", "add", "host-b", "--enclave", "client", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
	env := yadmOK(t, "enclave", "add", string(fixture.HostB), "--enclave", "personal")
	if d := decode[entryData](t, env.Data); !strings.HasPrefix(d.KeysFrom, "client seq ") {
		t.Fatalf("keys_from: %q", d.KeysFrom)
	}
	passGate(t)
	yadmOK(t, "enclave", "remove", "host-b", "--enclave", "personal", "--confirm")
	before := git(t, a.Source, "rev-parse", "main")
	if env, code, _ := yadm(t, "enclave", "add", string(fixture.HostB), "--enclave", "personal"); code != ExitUsage {
		t.Fatalf("re-add after remove without flags: exit %d %+v", code, env.Error)
	}
	if now := git(t, a.Source, "rev-parse", "main"); now != before {
		t.Fatal("a refused add committed")
	}
	yadmOK(t, "enclave", "add", "host-b", "--enclave", "personal", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
}

// TestPickVouched: an add without flags takes the vouching keys only when
// every verified pinned log that lists the machine agrees, a log with an
// untrusted signer included, and the target enclave never listed it.
func TestPickVouched(t *testing.T) {
	k1 := vouch{member: crypt.Member{Machine: "m-x", Recipient: "age1one", SignKey: "s1"}, from: "personal seq 3"}
	k2 := vouch{member: crypt.Member{Machine: "m-x", Recipient: "age1two", SignKey: "s2"}, from: "client seq 4"}
	if v, err := pickVouched("m-x", []vouch{k1}, []vouch{k1}, false); err != nil || v != k1 {
		t.Fatalf("agreeing: %+v %v", v, err)
	}
	for name, c := range map[string]struct {
		vouched, listed []vouch
		removed         bool
	}{
		"none":         {nil, []vouch{k2}, false},
		"disagreement": {[]vouch{k1}, []vouch{k1, k2}, false},
		"removed":      {[]vouch{k1}, []vouch{k1}, true},
	} {
		if _, err := pickVouched("m-x", c.vouched, c.listed, c.removed); !errors.Is(err, errUsage) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
