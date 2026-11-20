package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/secrecytest"
)

const synthFleet = `schema = 1

[types.home]
enclave = true

[types.corp]

[machines.m-aaaaaa000001]
name = "host-a"
types = ["home"]
os = "darwin"
arch = "arm64"

[machines.m-bbbbbb000002]
name = "host-b"
types = ["home"]
os = "linux"
arch = "amd64"

[machines.m-cccccc000003]
name = "host-c"
types = ["corp"]
os = "darwin"
arch = "arm64"
`

const synthManifest = `schema = 1

[defaults]
quiet = "2m"

[[file]]
target = ".config/shell/aliases.sh"

[[file]]
target = ".config/shell/env.sh"

[[file]]
target = ".config/packages/Brewfile"

[[file]]
target = ".config/app/settings.json"
format = "json"
drop = ["volatile"]

[[root]]
path = ".config/private"
enclave = "home"
when = "type:home"

[[root]]
path = ".config/drop"
`

const synthSealed = ".config/private/notes.md"

// pushSourceEdit clones the remote, lets edit change the worktree, commits
// and pushes: a manual source edit by any writer.
func pushSourceEdit(t testing.TB, w *World, msg string, edit func(dir string)) {
	t.Helper()
	dir, err := os.MkdirTemp(w.Root, "edit-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	w.Git("", "clone", "-q", w.Remote, dir)
	edit(dir)
	w.Git(dir, "add", "-A")
	w.Git(dir, "commit", "-q", "-m", msg)
	w.Git(dir, "push", "-q", "origin", "main")
}

func writeFiles(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		fp := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// synthWorld builds the three-machine synthetic fleet through the binary:
// host-a creates the home enclave and seals a file with a canary, host-b
// joins with --expect, host-c (corp) never joins.
func synthWorld(t *testing.T) (*World, []*Machine, secrecytest.Canary) {
	w := NewWorld(t)
	seed := filepath.Join(w.Root, "seed")
	w.Git("", "init", "-q", "-b", "main", seed)
	writeFiles(t, seed, map[string]string{
		"fleet.toml":                      synthFleet,
		"manifest.toml":                   synthManifest,
		"files/.config/shell/aliases.sh":  "alias ll='ls -l'\n",
		"files/.config/shell/env.sh":      "export EDITOR=editor-one\n",
		"files/.config/packages/Brewfile": "brew \"git\"\n",
		"files/.config/app/settings.json": "{\n  \"theme\": \"dark\"\n}\n",
	})
	w.Git(seed, "add", "-A")
	w.Git(seed, "commit", "-q", "-m", "seed")
	w.Git(seed, "push", "-q", w.Remote, "main")

	a, b, c := w.NewMachine("host-a", "user"), w.NewMachine("host-b", "user"), w.NewMachine("host-c", "user")
	for _, m := range []*Machine{a, b, c} {
		if r := m.Init(m.Name); r.Code != 0 {
			t.Fatalf("%s: init: %s", m.Name, r.Err())
		}
	}
	a.OK("enclave", "create", "home", "--new-recovery", filepath.Join(w.Root, "recovery"))
	for _, m := range []*Machine{a, b, c} {
		m.OK("root", "allow", ".config/drop")
	}
	a.OK("root", "allow", ".config/private")
	canary := secrecytest.NewCanary(t, "home-setup")
	a.WriteHome(synthSealed, []byte("notes\n"+canary.String()+"\n"), 0)
	a.OK("commit", synthSealed)
	// A committed file in an owned root gets no manifest entry; a writer
	// adds one by hand so the file becomes a managed, sealed target.
	pushSourceEdit(t, w, "manage notes", func(dir string) {
		f, _ := os.OpenFile(filepath.Join(dir, "manifest.toml"), os.O_APPEND|os.O_WRONLY, 0)
		_, _ = f.WriteString("\n[[file]]\ntarget = \"" + synthSealed + "\"\nenclave = \"home\"\nwhen = \"type:home\"\n")
		_ = f.Close()
	})
	r := a.OK("enclave", "add", "host-b", "--enclave", "home", "--recipient", b.Recipient, "--sign-key", b.SignKey)
	var add struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := r.Decode(&add); err != nil || add.Fingerprint == "" {
		t.Fatalf("enclave add: %v", err)
	}
	a.OK("sync")
	b.OK("sync")
	b.OK("enclave", "join", "home", "--expect", add.Fingerprint)
	b.OK("root", "allow", ".config/private")
	for _, m := range []*Machine{a, b, c} {
		m.OK("sync")
	}
	return w, []*Machine{a, b, c}, canary
}

// TestSyntheticFleet: setup, delivery and secrecy on the synthetic fleet.
func TestSyntheticFleet(t *testing.T) {
	w, ms, canary := synthWorld(t)
	a, b, c := ms[0], ms[1], ms[2]
	for _, m := range []*Machine{a, b} {
		got, ok := m.ReadHome(synthSealed)
		if !ok || !bytes.Contains(got, canary.Bytes()) {
			t.Errorf("%s: sealed file not delivered to a member (present=%v)", m.Name, ok)
		}
	}
	if _, ok := c.ReadHome(synthSealed); ok {
		t.Errorf("host-c (corp) received the sealed file")
	}
	secrecytest.AssertTreeClean(t, c.Root, canary)
	secrecytest.AssertRepoClean(t, w.Remote, canary)
	for _, m := range ms {
		secrecytest.AssertRepoClean(t, m.Source, canary)
	}
	if calls := w.UnitCalls(); len(calls) > 0 {
		t.Logf("unit shim calls: %d", len(calls))
	}
}

// TestSyntheticSoak runs the multi-machine soak on the synthetic fleet.
func TestSyntheticSoak(t *testing.T) {
	if os.Getenv("YADM_E2E_SOAK") == "" {
		t.Skip("set YADM_E2E_SOAK=1 to run the multi-machine soak")
	}
	w, ms, canary := synthWorld(t)
	spec := SoakSpec{
		Machines: ms,
		Members:  map[string]bool{"host-a": true, "host-b": true},
		Enclave:  "home",
		Shared:   []string{".config/shell/aliases.sh", ".config/shell/env.sh"},
		Union:    ".config/packages/Brewfile",
		JSON:     ".config/app/settings.json",
		Sealed:   []string{synthSealed},
		Root:     ".config/drop",
		Rounds:   soakRounds(6),
		Seed:     soakSeed(),
		Canaries: []secrecytest.Canary{canary},
	}
	rep := Soak(t, w, spec)
	t.Logf("soak: %s", rep)
	reportSoak(t, rep)
}

func reportSoak(t *testing.T, rep SoakReport) {
	t.Helper()
	show := func(name string, xs []string) {
		if len(xs) == 0 {
			return
		}
		n := len(xs)
		if n > 15 {
			xs = xs[:15]
		}
		t.Errorf("%s: %d\n  %s", name, n, strings.Join(xs, "\n  "))
	}
	show("lost edits", rep.Lost)
	show("unexplained holds", rep.Unexplained)
	show("diverged", rep.Diverged)
	show("command errors", rep.CommandErrors)
	show("plaintext leaks", rep.Leaks)
	if rep.VolatileLeaks > 0 {
		t.Errorf("volatile JSON keys reached git %d times", rep.VolatileLeaks)
	}
	if rep.NewFilesStuck > 0 {
		t.Errorf("%d new owned-root files were committed but never reached a peer", rep.NewFilesStuck)
	}
}
