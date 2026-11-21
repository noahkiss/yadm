package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// restrictedCheck writes a check script that logs each request to log and
// passes only when the request gives a staged target a when or an enclave:
// a directory where every file must be restricted.
func restrictedCheck(t *testing.T, dir, log string) string {
	t.Helper()
	p := filepath.Join(dir, "check-restricted")
	script := "#!/bin/sh\nreq=$(cat)\nprintf '%s\\n' \"$req\" >> '" + log + "'\n" +
		"printf '%s' \"$req\" | grep -q '\"when\":\"[^\"]' && exit 0\n" +
		"printf '%s' \"$req\" | grep -q '\"enclave\":\"[^\"]' && exit 0\n" +
		"echo 'unrestricted file in a restricted directory' >&2\nexit 1\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTrackGateSeesPlannedEntry: the commit gate's request gives each
// staged target the entry it has once the commit lands, so a check that
// requires a when or an enclave passes a track that adds one and holds a
// track that does not. The request carries no plaintext, and the sealed
// file reaches neither a repository nor the non-member.
func TestTrackGateSeesPlannedEntry(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	tools := filepath.Join(root, "tools")
	if err := os.MkdirAll(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(tools, "requests.log")
	check := restrictedCheck(t, tools, log)
	mp := filepath.Join(fx.Root, "manifest.toml")
	man := readFile(t, mp)
	old := "[checks.no-private-keys]\npaths = [\"**\"]\ncommand = [\"secret-check\", \"--stdin-json\"]\n"
	if !strings.Contains(man, old) {
		t.Fatal("fixture manifest changed: no check to replace")
	}
	man = strings.Replace(man, old, "[checks.restricted]\npaths = [\".config/restricted/**\"]\ncommand = ["+tomlQuote(check)+"]\n", 1)
	writeFile(t, mp, man)
	remote := fixtureRemote(t, root, fx)
	canary := secrecytest.NewCanary(t, "gate-entry")
	canaries := append(fx.AllCanaries(), canary)

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	yadmOK(t, "task", "allow", "restricted")

	// (1) A new file with --when and --enclave passes the check.
	const sealedT = ".config/restricted/token"
	writeFile(t, filepath.Join(a.Home, sealedT), "token = "+canary.String()+"\n")
	env, code, out := yadm(t, "track", sealedT, "--when", "type:personal", "--enclave", "personal")
	if code != ExitOK {
		t.Fatalf("track --when --enclave: exit %d %+v %+v", code, env.Error, env.Data)
	}
	d := decode[struct {
		Commit string
		Holds  []any
	}](t, env.Data)
	if d.Commit == "" || len(d.Holds) != 0 {
		t.Fatalf("track data: %+v", d)
	}
	if files := git(t, a.Source, "show", "--name-only", "--format=", d.Commit); files != "manifest.toml\nsealed/personal/"+sealedT {
		t.Fatalf("track commit files: %q", files)
	}
	if strings.Contains(string(out), canary.String()) {
		t.Fatal("track printed the plaintext")
	}
	reqs := readFile(t, log)
	want := `"entries":{"` + sealedT + `":{"target":"` + sealedT + `","source":"sealed/personal/` + sealedT + `","when":"type:personal","enclave":"personal"}}`
	if !strings.Contains(reqs, want) {
		t.Fatalf("request lacks the planned entry %s:\n%s", want, reqs)
	}

	// A when that is false on this machine still counts: it is the entry as written.
	const workT = ".config/restricted/work-only"
	writeFile(t, filepath.Join(a.Home, workT), "w\n")
	if env, code, _ = yadm(t, "track", workT, "--when", "type:work", "--no-push"); code != ExitOK {
		t.Fatalf("track --when type:work: exit %d %+v %+v", code, env.Error, env.Data)
	}

	// (2) Without --when or --enclave the check holds it, and nothing commits.
	head := git(t, a.Source, "rev-parse", "main")
	const openT = ".config/restricted/open"
	writeFile(t, filepath.Join(a.Home, openT), "o\n")
	env, code, _ = yadm(t, "track", openT)
	if code != ExitAttention {
		t.Fatalf("track unrestricted: exit %d %+v", code, env.Error)
	}
	if hs := decode[holdsOnly](t, env.Data).Holds; len(hs) != 1 || string(hs[0].Target) != openT || hs[0].Reason != "check_failed" {
		t.Fatalf("holds: %+v", hs)
	}
	if git(t, a.Source, "rev-parse", "main") != head {
		t.Fatal("a held track committed")
	}
	reqs = readFile(t, log)
	want = `"entries":{"` + openT + `":{"target":"` + openT + `","source":"files/` + openT + `","when":"","enclave":""}}`
	if !strings.Contains(reqs, want) {
		t.Fatalf("request lacks the unrestricted entry %s:\n%s", want, reqs)
	}

	// (3) No request carried plaintext, and nothing leaked.
	if strings.Contains(reqs, canary.String()) {
		t.Fatal("a check request carried staged plaintext")
	}
	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	if _, err := os.Stat(filepath.Join(b.Home, sealedT)); err == nil {
		t.Fatal("the non-member received the sealed file")
	}
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertTreeClean(t, tools, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)
}

// tomlQuote quotes s as a TOML literal string; s holds no single quote.
func tomlQuote(s string) string { return "'" + s + "'" }
