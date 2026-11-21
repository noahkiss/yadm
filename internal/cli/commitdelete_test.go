package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// kitFiles are six plain entries under one directory, as a tool's install
// directory would be.
var kitFiles = []string{"README.md", "cutover.sh", "hooks/a.json", "hooks/b.py", "c.py", "d.sh"}

const kitDir = ".local/share/kit"

// kitTree is a source with the six kit entries, a comment on one of them,
// and an unrelated entry that must survive every edit.
func kitTree() map[string]string {
	var man strings.Builder
	man.WriteString("schema = 1\n\n[[file]]\ntarget = \".config/tool/config\"\n")
	tree := map[string]string{"fleet.toml": e2eFleet, "files/.config/tool/config": "color = blue\n"}
	for i, p := range kitFiles {
		if i == 2 {
			man.WriteString("\n# the kit's hooks\n")
		} else {
			man.WriteString("\n")
		}
		man.WriteString("[[file]]\ntarget = \"" + kitDir + "/" + p + "\"\n")
		tree["files/"+kitDir+"/"+p] = p + " v1\n"
	}
	man.WriteString("\n[[file]]\ntarget = \".config/tool/last\"\n")
	tree["files/.config/tool/last"] = "last\n"
	tree["manifest.toml"] = man.String()
	return tree
}

func kitTargets(ps ...string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = kitDir + "/" + p
	}
	return out
}

type commitsOnly struct {
	Commits []string `json:"commits"`
}

// kitMachine sets up a machine: init and apply.
func kitMachine(t *testing.T, root, remote, dir, name string) machineDirs {
	t.Helper()
	m := useMachine(t, root, dir)
	yadmOK(t, "init", remote, "--machine", name, "--no-schedule")
	yadmOK(t, "apply")
	return m
}

// holdsOn returns the holds whose target is one of ts.
func holdsOn(hs []model.Hold, ts []string) []model.Hold {
	var out []model.Hold
	for _, h := range hs {
		for _, t := range ts {
			if string(h.Target) == t {
				out = append(out, h)
			}
		}
	}
	return out
}

// TestCommitDeletedDirectory: a deleted directory of plain entries is held
// by the timer as a protected deletion, and the hold's advice, `yadm
// commit <path>`, commits it: the source files and their manifest entries
// go in one commit, the holds clear, and the peer deletes its unchanged
// copies on its next sync while it holds the one it edited.
func TestCommitDeletedDirectory(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, kitTree())
	b := kitMachine(t, root, remote, "b", "host-b")
	writeFile(t, filepath.Join(b.Home, kitDir, "hooks/b.py"), "b.py edited on b\n")
	a := kitMachine(t, root, remote, "a", "host-a")
	for _, p := range kitFiles {
		if got := readFile(t, filepath.Join(a.Home, kitDir, p)); got != p+" v1\n" {
			t.Fatalf("apply on a: %s = %q", p, got)
		}
	}

	// Steps 2 and 3: the directory goes; the timer holds each file.
	if err := os.RemoveAll(filepath.Join(a.Home, kitDir)); err != nil {
		t.Fatal(err)
	}
	env := yadmOK(t, "sync", "--auto", "--full")
	all := kitTargets(kitFiles...)
	var protected []model.Hold
	for _, h := range holdsOn(decode[holdsOnly](t, env.Data).Holds, all) {
		if h.Reason == model.HoldProtected {
			protected = append(protected, h)
		}
	}
	if len(protected) != len(kitFiles) {
		t.Fatalf("want %d protected deletion holds, got %+v", len(kitFiles), protected)
	}
	for _, h := range protected {
		if !strings.Contains(h.Detail, "deletion") || !strings.Contains(strings.Join(h.Next, "\n"), "yadm commit "+string(h.Target)) {
			t.Fatalf("hold advice: %+v", h)
		}
	}

	// Resolving a protected hold points at the commit by name.
	if env, code, _ := yadm(t, "hold", "resolve", protected[0].ID, "--take", "target"); code == ExitOK || !strings.Contains(env.Error.Message, "yadm commit "+string(protected[0].Target)) {
		t.Fatalf("resolve a protected hold: exit %d %+v", code, env.Error)
	}

	// Step 4, one path: its entry and source go; the others stay.
	env, code, _ := yadm(t, "commit", "-m", "remove the kit readme", all[0])
	if code != ExitAttention && code != ExitOK {
		t.Fatalf("commit one deletion: exit %d %+v", code, env.Error)
	}
	if cs := decode[commitsOnly](t, env.Data).Commits; len(cs) != 1 {
		t.Fatalf("commit one deletion: commits %v", cs)
	}
	man := git(t, remote, "show", "main:manifest.toml")
	if strings.Contains(man, all[0]) || !strings.Contains(man, all[1]) {
		t.Fatalf("manifest after one deletion:\n%s", man)
	}
	tree := git(t, remote, "ls-tree", "-r", "--name-only", "main")
	if strings.Contains(tree, "files/"+all[0]) || !strings.Contains(tree, "files/"+all[1]) {
		t.Fatalf("tree after one deletion:\n%s", tree)
	}

	// Step 4, the rest in one commit.
	env = yadmOK(t, "commit", "-m", "remove the kit", all[1], all[2], all[3], all[4], all[5])
	if cs := decode[commitsOnly](t, env.Data).Commits; len(cs) != 1 {
		t.Fatalf("commit five deletions: commits %v", cs)
	}
	if hs := holdsOn(decode[holdsOnly](t, env.Data).Holds, all); len(hs) != 0 {
		t.Fatalf("holds left after the commit: %+v", hs)
	}
	man = git(t, remote, "show", "main:manifest.toml")
	want := "schema = 1\n\n[[file]]\ntarget = \".config/tool/config\"\n\n[[file]]\ntarget = \".config/tool/last\""
	if man != want {
		t.Fatalf("manifest after the deletions:\n%s\nwant:\n%s", man, want)
	}
	tree = git(t, remote, "ls-tree", "-r", "--name-only", "main")
	if strings.Contains(tree, kitDir) {
		t.Fatalf("kit sources remain:\n%s", tree)
	}
	env, code, _ = yadm(t, "sync")
	if code != ExitOK {
		t.Fatalf("sync after the deletions: exit %d %+v %+v", code, env.Error, env.Data)
	}

	// The peer deletes what it had unchanged and holds what it edited.
	useMachine(t, root, "b")
	env, _, _ = yadm(t, "sync")
	for _, p := range kitFiles {
		_, err := os.Stat(filepath.Join(b.Home, kitDir, p))
		if p == "hooks/b.py" {
			if err != nil {
				t.Fatalf("b lost its edited %s: %v", p, err)
			}
			continue
		}
		if !os.IsNotExist(err) {
			t.Fatalf("b kept %s: %v", p, err)
		}
	}
	hs := holdsOn(decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds, all)
	if len(hs) != 1 || hs[0].Target != model.Target(kitDir+"/hooks/b.py") || hs[0].Reason != model.HoldDrifted {
		t.Fatalf("b holds: %+v", hs)
	}
	if got := readFile(t, filepath.Join(b.Home, kitDir, "hooks/b.py")); got != "b.py edited on b\n" {
		t.Fatalf("b's edit changed: %q", got)
	}
}

// TestResolveTakeTargetCommitsDeletion: taking the target of the drifted
// hold on a deleted file commits the deletion the same way.
func TestResolveTakeTargetCommitsDeletion(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, kitTree())
	a := kitMachine(t, root, remote, "a", "host-a")
	target := kitDir + "/c.py"
	if err := os.Remove(filepath.Join(a.Home, target)); err != nil {
		t.Fatal(err)
	}
	yadmOK(t, "sync", "--auto", "--full")
	var id string
	for _, h := range decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds {
		if string(h.Target) == target && h.Reason == model.HoldDrifted {
			id = h.ID
		}
	}
	if id == "" {
		t.Fatal("no drifted hold on the deleted file")
	}
	env, code, _ := yadm(t, "hold", "resolve", id, "--take", "target")
	if code != ExitOK {
		t.Fatalf("resolve: exit %d %+v", code, env.Error)
	}
	if man := git(t, remote, "show", "main:manifest.toml"); strings.Contains(man, target) {
		t.Fatalf("entry stayed:\n%s", man)
	}
	if hs := holdsOn(decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds, []string{target}); len(hs) != 0 {
		t.Fatalf("holds stayed: %+v", hs)
	}
}

// TestCommitDeletionSharedSourceRefused: when another entry (here, for
// another machine) reads the same source, the deletion is refused and
// nothing is committed, so no machine loses its source.
func TestCommitDeletionSharedSourceRefused(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, map[string]string{
		"fleet.toml":                e2eFleet,
		"manifest.toml":             "schema = 1\n\n[[file]]\ntarget = \".config/tool/config\"\nwhen = \"machine:host-a\"\n\n[[file]]\ntarget = \".config/tool/config\"\nwhen = \"machine:host-b\"\nmode = 0o600\n",
		"files/.config/tool/config": "color = blue\n",
	})
	a := kitMachine(t, root, remote, "a", "host-a")
	before := git(t, remote, "rev-parse", "main")
	if err := os.Remove(filepath.Join(a.Home, ".config/tool/config")); err != nil {
		t.Fatal(err)
	}
	env, code, _ := yadm(t, "commit", ".config/tool/config")
	if code != ExitError || !strings.Contains(env.Error.Message, "also reads its source") {
		t.Fatalf("exit %d %+v", code, env.Error)
	}
	if git(t, remote, "rev-parse", "main") != before || git(t, a.Source, "rev-parse", "main") != before {
		t.Fatal("a refused deletion moved main")
	}
}

// TestStaleHoldsDropAfterRemoteRemoval: when another clone removes the
// entries and sources of files this machine holds as deletions, the next
// sync drops those holds: nothing manages the targets any more.
func TestStaleHoldsDropAfterRemoteRemoval(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, kitTree())
	a := kitMachine(t, root, remote, "a", "host-a")
	if err := os.RemoveAll(filepath.Join(a.Home, kitDir)); err != nil {
		t.Fatal(err)
	}
	env := yadmOK(t, "sync", "--auto", "--full")
	all := kitTargets(kitFiles...)
	if hs := holdsOn(decode[holdsOnly](t, env.Data).Holds, all); len(hs) < len(kitFiles) {
		t.Fatalf("want deletion holds, got %+v", hs)
	}

	// A raw commit elsewhere removes the six entries and their sources.
	work := filepath.Join(root, "other")
	git(t, root, "clone", "-q", remote, work)
	man := "schema = 1\n\n[[file]]\ntarget = \".config/tool/config\"\n\n[[file]]\ntarget = \".config/tool/last\"\n"
	writeFile(t, filepath.Join(work, "manifest.toml"), man)
	git(t, work, "rm", "-q", "-r", "files/"+kitDir)
	git(t, work, "commit", "-q", "-am", "drop the kit")
	git(t, work, "push", "-q", "origin", "main")

	env, code, _ := yadm(t, "sync")
	if code != ExitOK {
		t.Fatalf("sync: exit %d %+v", code, env.Error)
	}
	if hs := holdsOn(decode[holdsOnly](t, env.Data).Holds, all); len(hs) != 0 {
		t.Fatalf("stale holds kept: %+v", hs)
	}
	if hs := holdsOn(decode[holdsOnly](t, yadmOK(t, "hold", "list").Data).Holds, all); len(hs) != 0 {
		t.Fatalf("hold list keeps stale holds: %+v", hs)
	}
}

// TestCommitSealedDeletionSecrecy: a member commits the deletion of a
// sealed file. The entry and the ciphertext go; no step writes the
// plaintext into any repository or onto the non-member.
func TestCommitSealedDeletionSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canaries := fx.AllCanaries()
	const private = ".config/notes/private.md"

	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	if _, err := os.Stat(filepath.Join(a.Home, private)); err != nil {
		t.Fatalf("member did not receive the sealed file: %v", err)
	}
	if err := os.Remove(filepath.Join(a.Home, private)); err != nil {
		t.Fatal(err)
	}
	yadmOK(t, "sync", "--auto", "--full")
	env, code, out := yadm(t, "commit", private)
	if code != ExitOK && code != ExitAttention {
		t.Fatalf("commit sealed deletion: exit %d %+v", code, env.Error)
	}
	if cs := decode[commitsOnly](t, env.Data).Commits; len(cs) != 1 {
		t.Fatalf("commit sealed deletion: commits %v", cs)
	}
	for _, c := range canaries {
		if strings.Contains(string(out), c.String()) {
			t.Fatalf("commit printed %s plaintext", c.Label)
		}
	}
	if man := git(t, remote, "show", "main:manifest.toml"); strings.Contains(man, private) {
		t.Fatalf("the sealed entry stayed:\n%s", man)
	}
	if tree := git(t, remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(tree, "sealed/personal/"+private) {
		t.Fatalf("the sealed source stayed:\n%s", tree)
	}

	useMachine(t, root, string(fixture.HostB))
	yadmOK(t, "sync")
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	secrecytest.AssertRepoClean(t, b.Source, canaries...)
	secrecytest.AssertRepoClean(t, a.Source, canaries...)
	secrecytest.AssertRepoClean(t, remote, canaries...)
}
