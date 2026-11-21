package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// checkNamed returns the check items of one name whose detail mentions sub.
func checkNamed(t *testing.T, env Envelope, name, sub string) []checkItem {
	t.Helper()
	var out []checkItem
	for _, c := range decode[map[string][]checkItem](t, env.Data)["checks"] {
		if c.Name == name && strings.Contains(c.Detail, sub) {
			out = append(out, c)
		}
	}
	return out
}

// TestOnDemandTransitionSecrecy: a member that delivered an enclave's whole
// file, sealed value and region, then marks the enclave on demand, has
// none of its plaintext left in $HOME, backups or the state after the next
// apply, and nothing reaches any object store. The plaintext still prints
// on stdout through show, and only there.
func TestOnDemandTransitionSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := fx.Canaries["personal"]

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	notes := filepath.Join(a.Home, ".config/notes/private.md")
	if !strings.Contains(readFile(t, notes), canary.String()) {
		t.Fatal("member apply did not deliver the sealed file")
	}
	for _, p := range []string{".config/editor/settings.json", ".ssh/config"} {
		if !strings.Contains(readFile(t, filepath.Join(a.Home, p)), canary.String()) {
			t.Fatalf("member apply did not deliver the sealed value or region in %s", p)
		}
	}

	if _, code, _ := yadm(t, "enclave", "on-demand", "no-such-enclave"); code != ExitUsage {
		t.Fatalf("on-demand for an unknown enclave: exit %d", code)
	}
	yadmOK(t, "enclave", "on-demand", "personal")
	id, err := fleet.LoadIdentity(identityPath(a.Paths))
	if err != nil || !id.IsOnDemand("personal") {
		t.Fatalf("machine.toml: %+v %v", id, err)
	}
	yadmOK(t, "apply")

	if _, err := os.Stat(notes); !os.IsNotExist(err) {
		t.Fatalf("the on-demand whole file is still in $HOME: %v", err)
	}
	// $HOME holds the state directory (state.json, backup/) and the source
	// clone: one scan covers them all.
	secrecytest.AssertTreeClean(t, a.Home, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)
	// A second apply keeps it that way, and the shared files stay managed.
	yadmOK(t, "apply")
	secrecytest.AssertTreeClean(t, a.Home, canary)
	if s := readFile(t, filepath.Join(a.Home, ".config/editor/settings.json")); !strings.Contains(s, "editor") {
		t.Fatalf("settings.json lost its shared keys: %s", s)
	}

	// Stdout is the one outlet.
	out, _, code := yadmRaw(t, "show", ".config/notes/private.md")
	if code != ExitOK || !strings.Contains(out, canary.String()) {
		t.Fatalf("show: exit %d, canary on stdout: %v", code, strings.Contains(out, canary.String()))
	}
	env := yadmOK(t, "show", ".ssh/config")
	if d := decode[showData](t, env.Data); !strings.Contains(d.Content, canary.String()) || d.Machine != fixture.HostA {
		t.Fatalf("show region: %+v", d)
	}
	secrecytest.AssertTreeClean(t, a.Home, canary)

	// Other commands keep it off stdout: diff points at show.
	env, _, raw := yadm(t, "diff", ".config/notes/private.md")
	if strings.Contains(string(raw), canary.String()) {
		t.Fatal("diff printed on-demand plaintext")
	}
	if fs := decode[map[string][]fileDiff](t, env.Data)["files"]; len(fs) != 1 || !strings.Contains(fs[0].Skipped, "yadm show") {
		t.Fatalf("diff: %+v", fs)
	}
	for _, args := range [][]string{{"status"}, {"machine"}, {"enclave", "list"}, {"check"}, {"hold", "list"}} {
		if _, _, out := yadm(t, args...); strings.Contains(string(out), canary.String()) {
			t.Fatalf("yadm %v printed on-demand plaintext", args)
		}
	}
	env = yadmOK(t, "machine")
	if md := decode[machineData](t, env.Data); len(md.Enclaves.OnDemand) != 1 || len(md.Enclaves.Opened) != 0 {
		t.Fatalf("machine enclaves: %+v", md.Enclaves)
	}
	env, _, _ = yadm(t, "check")
	if c := checkNamed(t, env, "on_demand", "personal"); len(c) != 1 || !c[0].OK {
		t.Fatalf("check on_demand: %+v", c)
	}

	// Track refuses to seal for an on-demand enclave: it never captures.
	writeFile(t, filepath.Join(a.Home, ".config/notes/new.md"), canary.String()+"\n")
	if _, code, _ := yadm(t, "track", ".config/notes/new.md", "--enclave", "personal"); code == ExitOK {
		t.Fatal("track sealed a new file for an on-demand enclave")
	}
	if err := os.Remove(filepath.Join(a.Home, ".config/notes/new.md")); err != nil {
		t.Fatal(err)
	}
	secrecytest.AssertTreeClean(t, a.Home, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)

	// Clearing the mark delivers the enclave again.
	yadmOK(t, "enclave", "on-demand", "personal", "--off")
	yadmOK(t, "apply")
	if !strings.Contains(readFile(t, notes), canary.String()) {
		t.Fatal("clearing on-demand did not deliver the file again")
	}
}

// TestOnDemandMemberOfOtherEnclave is the fleet the setting is for: a
// personal machine joins a work machine's enclave as a full key-log member
// and marks it on demand before it joins. The enclave's plaintext never
// reaches its $HOME, state, backups or any object store; show --as prints
// the file as the work machine receives it; and check on both machines
// reports the membership without a type mismatch.
func TestOnDemandMemberOfOtherEnclave(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := fx.Canaries["client"]
	// The fixture's commit gate runs secret-check; a stub passes it.
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// host-c, the client machine, adds host-a to client.
	c := fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	yadmOK(t, "apply")
	// It seals a client region into the shared .ssh/config, which host-a
	// receives too: without on-demand, host-a would get it as a member.
	sshCfg := filepath.Join(c.Home, ".ssh/config")
	writeFile(t, sshCfg, readFile(t, sshCfg)+"# yadm:seal client client-hosts\nHost client-box\n  # "+canary.String()+"\n# yadm:end\n")
	yadmOK(t, "task", "allow")
	if d := decode[map[string]any](t, yadmOK(t, "commit", ".ssh/config", "-m", "client hosts").Data); len(d["commits"].([]any)) != 1 {
		t.Fatalf("commit: %+v", d)
	}
	secrecytest.AssertRepoClean(t, c.Source, canary)
	ha := fx.Identities[fixture.HostA].Member()
	env := yadmOK(t, "enclave", "add", "host-a", "--enclave", "client", "--recipient", ha.Recipient, "--sign-key", ha.SignKey)
	fp := decode[entryData](t, env.Data).Fingerprint
	yadmRawPush(t)
	// host-a has not said it reads client on demand yet: a mismatch.
	env, _, _ = yadm(t, "check")
	if m := checkNamed(t, env, "membership", "client:"); len(m) != 1 || m[0].OK {
		t.Fatalf("host-c check before host-a publishes: %+v", m)
	}

	// host-a marks client on demand, then joins.
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "enclave", "on-demand", "client")
	yadmOK(t, "enclave", "join", "client", "--expect", fp)
	yadmOK(t, "apply")
	yadmOK(t, "sync")
	secrecytest.AssertTreeClean(t, a.Home, canary)
	if s := readFile(t, filepath.Join(a.Home, ".ssh/config")); !strings.Contains(s, "git.example.invalid") {
		t.Fatalf("host-a lost the shared part of .ssh/config: %s", s)
	}
	// show prints the region on stdout, for host-a itself and for host-c.
	for _, args := range [][]string{{"show", ".ssh/config", "--as", "host-c"}, {"show", ".ssh/config"}} {
		if out, _, code := yadmRaw(t, args...); code != ExitOK || !strings.Contains(out, canary.String()) {
			t.Fatalf("yadm %v: exit %d, canary on stdout: %v", args, code, strings.Contains(out, canary.String()))
		}
	}
	secrecytest.AssertTreeClean(t, a.Home, canary)

	env = yadmOK(t, "enclave", "list")
	for _, e := range decode[map[string][]enclaveInfo](t, env.Data)["enclaves"] {
		if e.Enclave == "client" && (!e.Member || !e.OnDemand) {
			t.Fatalf("enclave list client: %+v", e)
		}
	}
	out, _, code := yadmRaw(t, "show", ".config/client-tool/token", "--as", "host-c")
	if code != ExitOK || !strings.Contains(out, canary.String()) {
		t.Fatalf("show --as host-c: exit %d, canary on stdout: %v", code, strings.Contains(out, canary.String()))
	}
	// host-a's own plan does not hold the file; host-b is no client member.
	if _, code, raw := yadm(t, "show", ".config/client-tool/token"); code == ExitOK || strings.Contains(string(raw), canary.String()) {
		t.Fatalf("show as host-a: exit %d", code)
	}
	if _, code, raw := yadm(t, "show", ".config/client-tool/token", "--as", "host-b"); code == ExitOK || strings.Contains(string(raw), canary.String()) {
		t.Fatalf("show --as host-b: exit %d", code)
	}
	// A plain file renders with the other machine's facts.
	env = yadmOK(t, "show", ".config/work/proxy.conf", "--as", "host-b")
	if d := decode[showData](t, env.Data); !strings.Contains(d.Content, "proxy.example.invalid") {
		t.Fatalf("show --as host-b proxy.conf: %+v", d)
	}
	env, _, _ = yadm(t, "check")
	if m := checkNamed(t, env, "membership", "client:"); len(m) != 1 || !m[0].OK || !strings.Contains(m[0].Detail, "host-a (on demand)") {
		t.Fatalf("host-a check: %+v", m)
	}
	secrecytest.AssertTreeClean(t, a.Home, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)

	// host-c reads host-a's published on-demand state.
	useMachine(t, root, string(fixture.HostC))
	yadmOK(t, "sync")
	env, _, _ = yadm(t, "check")
	if m := checkNamed(t, env, "membership", "client:"); len(m) != 1 || !m[0].OK || !strings.Contains(m[0].Detail, "host-c (type)") {
		t.Fatalf("host-c check after host-a publishes: %+v", m)
	}
	secrecytest.AssertRepoClean(t, c.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)
}

// TestOnDemandUnknownNameFailsCheck: a misspelled on-demand name protects
// nothing, so check fails on it.
func TestOnDemandUnknownNameFailsCheck(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	if err := fleet.SaveIdentity(identityPath(a.Paths), fleet.Identity{Machine: fixture.HostA, Remote: remote, OnDemand: []model.EnclaveName{"persnal"}}); err != nil {
		t.Fatal(err)
	}
	env, _, _ := yadm(t, "check")
	if c := checkNamed(t, env, "on_demand", "persnal"); len(c) != 1 || c[0].OK {
		t.Fatalf("check: %+v", c)
	}
}
