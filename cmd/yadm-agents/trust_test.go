package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// trustCodex is a Codex config with a project the owner trusted by hand.
const trustCodex = `model = "model-x"

[projects."/opt/elsewhere"]
trust_level = "trusted"

[mcp_servers.srv-a]
command = "srv-a"
`

func trustUnits(paths ...string) string {
	var q []string
	for _, p := range paths {
		q = append(q, `"`+p+`"`)
	}
	return strings.Replace(oneGuard, "schema = 1\n", "schema = 1\n\n[harness.codex]\ntrusted_projects = ["+strings.Join(q, ", ")+"]\n", 1)
}

func trustHome(t *testing.T) string {
	t.Helper()
	home := oneGuardHome(t)
	writeFile(t, filepath.Join(home, ".codex/config.toml"), trustCodex)
	return home
}

// projectTrust reads every projects.<path>.trust_level from a Codex config.
func projectTrust(t *testing.T, home string) map[string]string {
	t.Helper()
	var doc struct {
		Projects map[string]map[string]any `toml:"projects"`
	}
	if err := toml.Unmarshal([]byte(readFile(t, filepath.Join(home, ".codex/config.toml"))), &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for p, v := range doc.Projects {
		s, _ := v["trust_level"].(string)
		out[p] = s
	}
	return out
}

func TestParseRejectsRelativeTrust(t *testing.T) {
	if _, err := Parse([]byte(trustUnits("dev/x"))); err == nil || !strings.Contains(err.Error(), "trusted_projects") {
		t.Fatalf("err = %v", err)
	}
}

func TestGenRefusesTrustOutsideHome(t *testing.T) {
	for _, p := range []string{"/opt/elsewhere", "~/../x", "~/"} {
		home := trustHome(t)
		r := genOnly(t, home, trustUnits(p), "codex", GenOptions{})
		if r.Status != StatusRefused || !strings.Contains(r.Reason, "trusted_projects") {
			t.Errorf("%s: %s %s", p, r.Status, r.Reason)
		}
		if got := readFile(t, filepath.Join(home, ".codex/config.toml")); got != trustCodex {
			t.Errorf("%s: config changed:\n%s", p, got)
		}
	}
}

// gen writes trust for exactly the listed paths, owns what it wrote, and
// removes it once the path leaves the list. The hand-trusted project and
// every other key stay.
func TestGenOwnsCodexTrust(t *testing.T) {
	home := trustHome(t)
	listed := "~/dev/my proj.v2"
	abs := filepath.Join(home, "dev/my proj.v2")
	r := genOnly(t, home, trustUnits(listed), "codex", GenOptions{})
	if r.Status != StatusWritten {
		t.Fatalf("codex: %s %s", r.Status, r.Reason)
	}
	got := projectTrust(t, home)
	if got[abs] != "trusted" || got["/opt/elsewhere"] != "trusted" || len(got) != 2 {
		t.Fatalf("projects = %v", got)
	}
	cfg := readFile(t, filepath.Join(home, ".codex/config.toml"))
	if !strings.Contains(cfg, "[mcp_servers.srv-a]") || !strings.Contains(cfg, `model = "model-x"`) {
		t.Fatalf("lost a key:\n%s", cfg)
	}
	st, err := readState(statePath(home))
	if err != nil {
		t.Fatal(err)
	}
	if o := st.Harness["codex"].Trusted; len(o) != 1 || o[0] != abs {
		t.Fatalf("owned = %v", o)
	}
	if r := genOnly(t, home, trustUnits(listed), "codex", GenOptions{}); r.Status != StatusUnchanged {
		t.Fatalf("second run: %s %s +%v -%v", r.Status, r.Reason, r.Added, r.Removed)
	}

	r = genOnly(t, home, trustUnits(), "codex", GenOptions{})
	if r.Status != StatusWritten {
		t.Fatalf("unlist: %s %s", r.Status, r.Reason)
	}
	got = projectTrust(t, home)
	if _, ok := got[abs]; ok || got["/opt/elsewhere"] != "trusted" {
		t.Fatalf("after unlist, projects = %v\n%s", got, readFile(t, filepath.Join(home, ".codex/config.toml")))
	}
	st, _ = readState(statePath(home))
	if o := st.Harness["codex"].Trusted; len(o) != 0 {
		t.Fatalf("still owns %v", o)
	}
}

// A project trusted before gen listed it is not gen's: unlisting it later
// leaves it alone.
func TestGenNeverRemovesTrustItDidNotWrite(t *testing.T) {
	home := oneGuardHome(t)
	abs := filepath.Join(home, "dev/x")
	writeFile(t, filepath.Join(home, ".codex/config.toml"), trustCodex+"\n[projects.\""+abs+"\"]\ntrust_level = \"trusted\"\n")
	if r := genOnly(t, home, trustUnits("~/dev/x"), "codex", GenOptions{}); r.Status == StatusRefused {
		t.Fatalf("codex: %s", r.Reason)
	}
	if st, _ := readState(statePath(home)); len(st.Harness["codex"].Trusted) != 0 {
		t.Fatalf("adopted a hand-written entry: %v", st.Harness["codex"].Trusted)
	}
	if r := genOnly(t, home, trustUnits(), "codex", GenOptions{}); r.Status == StatusRefused {
		t.Fatalf("codex: %s", r.Reason)
	}
	if got := projectTrust(t, home); got[abs] != "trusted" {
		t.Fatalf("removed a hand-written entry: %v", got)
	}
}

// A dry run plans trust but records no ownership.
func TestGenDryRunOwnsNothing(t *testing.T) {
	home := trustHome(t)
	r := genOnly(t, home, trustUnits("~/dev/x"), "codex", GenOptions{DryRun: true})
	if r.Status != StatusChange {
		t.Fatalf("codex: %s %s", r.Status, r.Reason)
	}
	if _, err := readState(statePath(home)); err == nil {
		t.Fatal("a dry run wrote state")
	}
}

func TestVerifyTrustOnlyOnCodex(t *testing.T) {
	src := strings.Replace(oneGuard, "schema = 1\n", "schema = 1\n\n[harness.claude]\ntrusted_projects = [\"~/dev/x\"]\n", 1)
	fs := Verify(mustParse(t, src), nil, VerifyOptions{Home: oneGuardHome(t), Offline: true})
	if !strings.Contains(findings(fs, "error"), "trusted_projects") {
		t.Fatalf("findings: %+v", fs)
	}
}
