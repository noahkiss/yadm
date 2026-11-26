package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// routeOrderUnits has a guard marked first that the file lists last.
const routeOrderUnits = `
schema = 1

[harness.tool-r]
config = "~/.local/state/agents/route.tsv"

[[unit]]
name = "guard-b"
kind = "guard"
effect = "deny"
script = "~/.agent/hooks/guard-b.sh"
on = ["PreToolUse"]
actions = ["shell", "file_write"]

[[unit]]
name = "guard-a"
kind = "guard"
first = true
effect = "deny"
script = "~/.agent/hooks/guard-a.sh"
on = ["PreToolUse"]
actions = ["shell"]

[conditions]
"guard-a.tool-r" = "true"
"guard-b.tool-r" = "true"
`

// A unit marked first leads every route list it is on, whatever its place
// in the units file.
func TestFirstLeadsRouteList(t *testing.T) {
	register(routeAdapter{name: "tool-r"})
	defer delete(registry, "tool-r")
	home := genHome(t)
	rs, _ := Gen(mustParse(t, routeOrderUnits), twoMachines(), GenOptions{Home: home, Only: setOf("tool-r")})
	if r := byHarness(rs)["tool-r"]; r.Status != StatusWritten {
		t.Fatalf("tool-r: %s %s", r.Status, r.Reason)
	}
	got := readFile(t, filepath.Join(home, ".local/state/agents/route.tsv"))
	if !strings.Contains(got, "PreToolUse\tBash\tguard-a.sh guard-b.sh\n") {
		t.Fatalf("guard-a does not lead the Bash list:\n%s", got)
	}
	if !strings.Contains(got, "PreToolUse\tWrite\tguard-b.sh\n") {
		t.Fatalf("route:\n%s", got)
	}
	fs := Verify(mustParse(t, routeOrderUnits), twoMachines(), VerifyOptions{Home: home, Offline: true})
	if w := findings(fs, "warn"); strings.Contains(w, "first") {
		t.Fatalf("a lone first unit warned: %s", w)
	}
}

// Two units marked first on one list cannot both lead: verify warns and
// names the one that does not.
func TestVerifyWarnsFirstNotLeading(t *testing.T) {
	register(routeAdapter{name: "tool-r"})
	defer delete(registry, "tool-r")
	home := genHome(t)
	src := strings.Replace(routeOrderUnits, "name = \"guard-b\"\nkind = \"guard\"", "name = \"guard-b\"\nkind = \"guard\"\nfirst = true", 1)
	if src == routeOrderUnits {
		t.Fatal("edit did not apply")
	}
	fs := Verify(mustParse(t, src), twoMachines(), VerifyOptions{Home: home, Offline: true})
	w := findings(fs, "warn")
	if !strings.Contains(w, `"guard-a"`) || !strings.Contains(w, "PreToolUse Bash") || strings.Contains(w, "Write") {
		t.Fatalf("warnings:\n%s", w)
	}
	if hasErrors(fs) {
		t.Fatalf("errors: %s", findings(fs, "error"))
	}
}

// A unit marked first after it was wired moves to the front on the next gen.
func TestFirstReordersWiredList(t *testing.T) {
	register(routeAdapter{name: "tool-r"})
	defer delete(registry, "tool-r")
	home := genHome(t)
	plain := strings.Replace(routeOrderUnits, "first = true\n", "", 1)
	if r := genOnly(t, home, plain, "tool-r", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("tool-r: %s %s", r.Status, r.Reason)
	}
	if r := genOnly(t, home, routeOrderUnits, "tool-r", GenOptions{}); r.Status != StatusWritten {
		t.Fatalf("tool-r: %s %s", r.Status, r.Reason)
	}
	if got := readFile(t, filepath.Join(home, ".local/state/agents/route.tsv")); !strings.Contains(got, "PreToolUse\tBash\tguard-a.sh guard-b.sh\n") {
		t.Fatalf("route:\n%s", got)
	}
}
