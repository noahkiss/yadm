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

// passGate puts a passing secret-check stub on PATH, for the fixture's
// commit-gate check, and allows every definition on the current machine.
func passGate(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	yadmOK(t, "task", "allow")
}

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
	head := git(t, a.Source, "rev-parse", "main")
	writeFile(t, filepath.Join(a.Home, ".config/notes/new.md"), canary.String()+"\n")
	if env, code, _ := yadm(t, "track", ".config/notes/new.md", "--enclave", "personal"); code != ExitRefused || !strings.Contains(env.Error.Message, "member on demand only") || strings.Contains(env.Error.Message, "not a member") {
		t.Fatalf("track for an on-demand enclave: exit %d %+v", code, env.Error)
	}
	if now := git(t, a.Source, "rev-parse", "main"); now != head {
		t.Fatal("track committed for an on-demand enclave")
	}
	if err := os.Remove(filepath.Join(a.Home, ".config/notes/new.md")); err != nil {
		t.Fatal(err)
	}
	secrecytest.AssertTreeClean(t, a.Home, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)

	// An on-demand member adds members like any member. It refuses a
	// remove, whose reseal would need the commit gate to read the
	// enclave's plaintext on this machine, and writes no entry.
	hb := fx.Identities[fixture.HostB].Member()
	yadmOK(t, "enclave", "add", "host-b", "--enclave", "personal", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
	head = git(t, a.Source, "rev-parse", "main")
	if env, code, _ := yadm(t, "enclave", "remove", "host-b", "--enclave", "personal", "--confirm"); code != ExitRefused || len(env.Next) == 0 {
		t.Fatalf("remove on an on-demand member: exit %d %+v", code, env.Error)
	}
	if now := git(t, a.Source, "rev-parse", "main"); now != head {
		t.Fatal("a refused remove committed")
	}
	yadmOK(t, "apply")
	secrecytest.AssertTreeClean(t, a.Home, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)

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
	// Text output reads the on-demand membership as membership.
	for _, args := range [][]string{{"machine"}, {"enclave", "list"}} {
		out, _, code := yadmRaw(t, append([]string{"--json=false"}, args...)...)
		if code != ExitOK || !strings.Contains(out, "member (on demand)") || strings.Contains(out, "client: not a member") {
			t.Fatalf("yadm %v text:\n%s", args, out)
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

// TestShowAsRendersPeerHome: a template that reads {{ home }} and
// {{ user }} renders for another machine with the home and user that
// machine published in its status record. Here an on-demand member prints
// a peer's sealed template, and --source prints the opened template
// unrendered. Both go to stdout only: the enclave's plaintext reaches
// neither the member's $HOME and state nor any object store. A machine that
// published neither renders with $HOME and $USER placeholders, and the
// output says so.
func TestShowAsRendersPeerHome(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	canary := fx.Canaries["client"]
	const tmplSrc = "sealed/client/.config/client-tool/env.tmpl"
	blob, err := fx.Rings["client"].SealFile(tmplSrc, []byte("home={{ home }}\nuser={{ user }}\nsecret="+canary.String()+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(fx.Root, filepath.FromSlash(tmplSrc)), string(blob))
	mp := filepath.Join(fx.Root, "manifest.toml")
	writeFile(t, mp, readFile(t, mp)+"\n[[file]]\ntarget = \".config/client-tool/env\"\nsource = \""+tmplSrc+"\"\nenclave = \"client\"\nwhen = \"type:client\"\ntemplate = true\n")
	remote := fixtureRemote(t, root, fx)
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// host-c, a client member, publishes its home and user, and adds host-a.
	t.Setenv("USER", "user-c")
	c := fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	yadmOK(t, "apply")
	yadmOK(t, "task", "allow")
	ha := fx.Identities[fixture.HostA].Member()
	env := yadmOK(t, "enclave", "add", "host-a", "--enclave", "client", "--recipient", ha.Recipient, "--sign-key", ha.SignKey)
	fp := decode[entryData](t, env.Data).Fingerprint
	yadmOK(t, "sync")

	// host-a reads client on demand.
	t.Setenv("USER", "user-a")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "enclave", "on-demand", "client")
	yadmOK(t, "enclave", "join", "client", "--expect", fp)
	yadmOK(t, "apply")
	yadmOK(t, "sync")

	env, code, _ := yadm(t, "show", ".config/client-tool/env", "--as", "host-c")
	if code != ExitOK {
		t.Fatalf("show --as host-c: exit %d %+v", code, env.Error)
	}
	d := decode[showData](t, env.Data)
	want := "home=" + c.Home + "\nuser=user-c\nsecret=" + canary.String() + "\n"
	if d.Content != want || d.HomeFrom != homePublished {
		t.Fatalf("show --as host-c: home_from %q, content %q", d.HomeFrom, d.Content)
	}
	out, _, code := yadmRaw(t, "show", ".config/client-tool/env", "--as", "host-c")
	if code != ExitOK || out != want {
		t.Fatalf("show --as host-c text: exit %d %q", code, out)
	}
	out, _, code = yadmRaw(t, "show", "--source", ".config/client-tool/env", "--as", "host-c")
	if code != ExitOK || out != "home={{ home }}\nuser={{ user }}\nsecret="+canary.String()+"\n" {
		t.Fatalf("show --source --as host-c: exit %d %q", code, out)
	}

	// host-b never synced: it published no home, so the render uses
	// placeholders and says so.
	env = yadmOK(t, "show", ".gitconfig", "--as", "host-b")
	if d := decode[showData](t, env.Data); d.HomeFrom != homePlaceholder || !strings.Contains(d.Content, "excludesfile = $HOME/.config/git/ignore") {
		t.Fatalf("show --as host-b: %+v", d)
	}
	if _, stderr, code := yadmRaw(t, "show", ".gitconfig", "--as", "host-b"); code != ExitOK || !strings.Contains(stderr, "print as $HOME and $USER") {
		t.Fatalf("show --as host-b text: exit %d, stderr %q", code, stderr)
	}
	// This machine renders with its own.
	env = yadmOK(t, "show", ".gitconfig")
	if d := decode[showData](t, env.Data); d.HomeFrom != homeLocal || !strings.Contains(d.Content, "excludesfile = "+a.Home+"/.config/git/ignore") {
		t.Fatalf("show as host-a: %+v", d)
	}

	secrecytest.AssertTreeClean(t, a.Home, canary)
	secrecytest.AssertRepoClean(t, a.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)
}
