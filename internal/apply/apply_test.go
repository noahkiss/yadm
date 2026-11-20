package apply

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

const aliases model.Target = ".config/shell/aliases.sh"

func TestFileStateDBRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db := FileStateDB(dir)
	st, err := db.Load()
	if err != nil || st == nil || st.Targets == nil {
		t.Fatalf("empty load: %v %v", st, err)
	}
	st.Machine = "m-test01"
	st.Targets[aliases] = TargetState{Source: "files/x", Written: "abc", Mode: 0o644}
	if err := db.Save(st); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state mode %v, want 0600", info.Mode().Perm())
	}
	got, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[aliases].Written != "abc" || got.Machine != "m-test01" {
		t.Errorf("round trip lost data: %+v", got)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("state dir holds %d entries, want only %s", len(ents), StateFile)
	}
}

func TestFileStateDBRefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, StateFile), []byte(`{"schema": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FileStateDB(dir).Load(); err == nil {
		t.Fatal("want an error for a newer schema")
	}
}

func TestApplyWritesAndRecords(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.config/shell/aliases.sh": "alias ll='ls -l'\n", "files/bin/tool": "#!/bin/sh\n"},
		manifest.Entry{Target: aliases}, manifest.Entry{Target: "bin/tool"}, manifest.Entry{Target: ".netrc", Source: "files/bin/tool", Mode: 0o600})
	w.setMode(c, "files/bin/tool", gitModeExec)
	r := w.apply(c)
	if a := actionOf(r, aliases); a.Kind != ActWrite {
		t.Fatalf("aliases: %+v", a)
	}
	if got := w.read(aliases); got != "alias ll='ls -l'\n" {
		t.Errorf("content %q", got)
	}
	for tgt, want := range map[model.Target]fs.FileMode{aliases: 0o644, "bin/tool": 0o755, ".netrc": 0o600} {
		info, _ := os.Stat(w.path(tgt))
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", tgt, info.Mode().Perm(), want)
		}
	}
	st := w.state()
	if st.Applied != c || !st.FirstApplyDone || st.RenderContext == nil {
		t.Errorf("state not updated: applied=%s first=%v", st.Applied, st.FirstApplyDone)
	}
	if ts := st.Targets[aliases]; ts.Written != hashOf([]byte("alias ll='ls -l'\n")) || ts.SourceBlob == "" {
		t.Errorf("target state: %+v", ts)
	}
	if len(r.Holds) != 0 {
		t.Errorf("holds: %+v", r.Holds)
	}
}

func TestApplyUnchangedTargetNotRewritten(t *testing.T) {
	w := newWorld(t)
	files := map[model.SourcePath]string{"files/.config/shell/aliases.sh": "one\n", "files/.b": "b1\n"}
	c1 := w.commit(files, manifest.Entry{Target: aliases}, manifest.Entry{Target: ".b"})
	w.apply(c1)
	before := w.id(aliases)
	time.Sleep(20 * time.Millisecond)

	// Same rev again, then a new rev that changes only another file.
	r := w.apply(c1)
	if a := actionOf(r, aliases); a.Kind != ActSkip {
		t.Fatalf("second apply: %+v", a)
	}
	files["files/.b"] = "b2\n"
	c2 := w.commit(files, manifest.Entry{Target: aliases}, manifest.Entry{Target: ".b"})
	r = w.apply(c2)
	if a := actionOf(r, aliases); a.Kind != ActSkip {
		t.Fatalf("third apply: %+v", a)
	}
	if a := actionOf(r, ".b"); a.Kind != ActWrite {
		t.Fatalf(".b: %+v", a)
	}
	if after := w.id(aliases); after != before {
		t.Errorf("unchanged target rewritten: before %+v after %+v", before, after)
	}
}

func TestApplyHoldsDriftAndNeverClobbers(t *testing.T) {
	w := newWorld(t)
	c1 := w.commit(map[model.SourcePath]string{"files/.config/shell/aliases.sh": "v1\n"}, manifest.Entry{Target: aliases})
	w.apply(c1)
	w.tick(time.Minute)
	w.write(aliases, "hand edit\n")
	if _, err := w.eng.Scan(context.Background(), ScanOptions{}); err != nil {
		t.Fatal(err)
	}
	w.tick(3 * time.Hour)
	c2 := w.commit(map[model.SourcePath]string{"files/.config/shell/aliases.sh": "v2\n"}, manifest.Entry{Target: aliases})
	r := w.apply(c2)
	if got := w.read(aliases); got != "hand edit\n" {
		t.Fatalf("drifted target clobbered: %q", got)
	}
	if len(r.Holds) != 1 || r.Holds[0].Reason != model.HoldDrifted || r.Holds[0].Target != aliases {
		t.Fatalf("holds: %+v", r.Holds)
	}
	h := r.Holds[0]
	if !h.Since.Equal(time.Date(2030, 1, 1, 12, 1, 0, 0, time.UTC)) {
		t.Errorf("since %v, want the scan's first sighting", h.Since)
	}
	if !strings.Contains(h.Detail, "3h0m0s ago") {
		t.Errorf("detail lacks the age: %q", h.Detail)
	}
	if h.ID == "" || h.ID != HoldID(h) {
		t.Errorf("hold id %q", h.ID)
	}
	// The hold is stable across applies and listed by Holds.
	w.tick(time.Hour)
	r2 := w.apply(c2)
	if len(r2.Holds) != 1 || r2.Holds[0].ID != h.ID {
		t.Errorf("hold id changed: %+v", r2.Holds)
	}
	hs, err := w.eng.Holds(context.Background())
	if err != nil || len(hs) != 1 || hs[0].ID != h.ID {
		t.Errorf("Holds: %+v %v", hs, err)
	}
	// Backups are empty: nothing was replaced.
	if _, err := os.Stat(filepath.Join(w.stateDir, "backup")); err == nil {
		t.Error("a backup exists although nothing was replaced")
	}
}

func TestApplyHoldsUnmanagedDifferingFile(t *testing.T) {
	w := newWorld(t)
	w.write(aliases, "mine\n")
	c := w.commit(map[model.SourcePath]string{"files/.config/shell/aliases.sh": "theirs\n"}, manifest.Entry{Target: aliases})
	r := w.apply(c)
	if a := actionOf(r, aliases); a.Kind != ActHold {
		t.Fatalf("%+v", a)
	}
	if w.read(aliases) != "mine\n" {
		t.Fatal("unmanaged file overwritten")
	}
}

func TestApplyHoldsDeletedTarget(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.config/shell/aliases.sh": "v1\n"}, manifest.Entry{Target: aliases})
	w.apply(c)
	os.Remove(w.path(aliases))
	r := w.apply(c)
	if a := actionOf(r, aliases); a.Kind != ActHold {
		t.Fatalf("%+v", a)
	}
	if _, err := os.Stat(w.path(aliases)); err == nil {
		t.Fatal("deleted target recreated")
	}
}

func TestApplyHoldsHandEditedRender(t *testing.T) {
	w := newWorld(t)
	tm := manifest.Entry{Target: ".gitconfig", Source: "files/.gitconfig.tmpl", Template: true}
	c1 := w.commit(map[model.SourcePath]string{"files/.gitconfig.tmpl": "[user]\nname = {{ machine.name }}\n"}, tm)
	w.apply(c1)
	if got := w.read(".gitconfig"); got != "[user]\nname = host-a\n" {
		t.Fatalf("render: %q", got)
	}
	w.write(".gitconfig", "[user]\nname = edited\n")
	c2 := w.commit(map[model.SourcePath]string{"files/.gitconfig.tmpl": "[user]\nname = {{ machine.name }}\n[core]\n"}, tm)
	r := w.apply(c2)
	if a := actionOf(r, ".gitconfig"); a.Kind != ActHold {
		t.Fatalf("%+v", a)
	}
	if w.read(".gitconfig") != "[user]\nname = edited\n" {
		t.Fatal("hand-edited render overwritten")
	}
}

func TestApplyModeChange(t *testing.T) {
	w := newWorld(t)
	c1 := w.commit(map[model.SourcePath]string{"files/.x": "x\n"}, manifest.Entry{Target: ".x"})
	w.apply(c1)
	c2 := w.commit(map[model.SourcePath]string{"files/.x": "x\n"}, manifest.Entry{Target: ".x", Mode: 0o600})
	r := w.apply(c2)
	if a := actionOf(r, ".x"); a.Kind != ActWrite || a.Reason != "mode" {
		t.Fatalf("%+v", a)
	}
	info, _ := os.Stat(w.path(".x"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
}

func TestOrphanRemovedOnlyWhenUnmodified(t *testing.T) {
	w := newWorld(t)
	files := map[model.SourcePath]string{"files/.a": "a\n", "files/.b": "b\n", "files/.c": "c\n"}
	c1 := w.commit(files, manifest.Entry{Target: ".a"}, manifest.Entry{Target: ".b"}, manifest.Entry{Target: ".c"})
	w.apply(c1)
	w.write(".b", "edited\n")
	os.Remove(w.path(".c"))
	c2 := w.commit(files) // every entry left the plan
	r := w.apply(c2)

	if a := actionOf(r, ".a"); a.Kind != ActDelete {
		t.Errorf(".a: %+v", a)
	}
	if _, err := os.Stat(w.path(".a")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("unmodified orphan not removed")
	}
	if a := actionOf(r, ".b"); a.Kind != ActHold {
		t.Errorf(".b: %+v", a)
	}
	if w.read(".b") != "edited\n" {
		t.Error("modified orphan removed or changed")
	}
	if a := actionOf(r, ".c"); a.Kind != ActSkip {
		t.Errorf(".c: %+v", a)
	}
	st := w.state()
	if _, ok := st.Targets[".a"]; ok {
		t.Error(".a still in state")
	}
	if _, ok := st.Targets[".b"]; !ok {
		t.Error(".b dropped from state while held")
	}
	if _, ok := st.Targets[".c"]; ok {
		t.Error(".c still in state")
	}
	// The removed bytes went to the backup directory.
	m, _ := filepath.Glob(filepath.Join(w.stateDir, "backup", "*", ".a"))
	if len(m) != 1 {
		t.Errorf("backup of .a: %v", m)
	}
}

func TestBackupOnReplaceAndPrune(t *testing.T) {
	w := newWorld(t)
	c1 := w.commit(map[model.SourcePath]string{"files/.a": "a1\n"}, manifest.Entry{Target: ".a"})
	w.apply(c1)
	c2 := w.commit(map[model.SourcePath]string{"files/.a": "a2\n"}, manifest.Entry{Target: ".a"})
	w.apply(c2)
	m, _ := filepath.Glob(filepath.Join(w.stateDir, "backup", "*", ".a"))
	if len(m) != 1 {
		t.Fatalf("backups: %v", m)
	}
	if b, _ := os.ReadFile(m[0]); string(b) != "a1\n" {
		t.Errorf("backup holds %q", b)
	}
	info, _ := os.Stat(m[0])
	if info.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v", info.Mode().Perm())
	}
	w.tick(BackupRetention + time.Hour)
	c3 := w.commit(map[model.SourcePath]string{"files/.a": "a3\n"}, manifest.Entry{Target: ".a"})
	w.apply(c3)
	m, _ = filepath.Glob(filepath.Join(w.stateDir, "backup", "*", ".a"))
	if len(m) != 1 {
		t.Errorf("old backup not pruned: %v", m)
	}
}

func TestAdoptIdenticalWithoutRewrite(t *testing.T) {
	w := newWorld(t)
	w.write(".same", "same\n")
	w.write(".diff", "local\n")
	same := w.id(".same")
	time.Sleep(20 * time.Millisecond)
	c := w.commit(map[model.SourcePath]string{"files/.same": "same\n", "files/.diff": "repo\n", "files/.new": "new\n"},
		manifest.Entry{Target: ".same"}, manifest.Entry{Target: ".diff"}, manifest.Entry{Target: ".new"})

	dry, err := w.eng.Adopt(context.Background(), c, AdoptOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(w.path(".new")); err == nil {
		t.Fatal("dry run wrote a file")
	}
	if a := actionOf(dry, ".same"); a.Kind != ActAdopt {
		t.Errorf("dry .same: %+v", a)
	}

	r, err := w.eng.Adopt(context.Background(), c, AdoptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a := actionOf(r, ".same"); a.Kind != ActAdopt {
		t.Errorf(".same: %+v", a)
	}
	if got := w.id(".same"); got != same {
		t.Errorf("adopted file rewritten: %+v -> %+v", same, got)
	}
	if a := actionOf(r, ".diff"); a.Kind != ActHold {
		t.Errorf(".diff: %+v", a)
	}
	if w.read(".diff") != "local\n" {
		t.Error("differing file overwritten by adopt")
	}
	if a := actionOf(r, ".new"); a.Kind != ActWrite || w.read(".new") != "new\n" {
		t.Errorf(".new: %+v", a)
	}
	st := w.state()
	if st.Targets[".same"].Written != hashOf([]byte("same\n")) {
		t.Error("adopted file not recorded")
	}
	if _, ok := st.Targets[".diff"]; ok {
		t.Error("held file recorded as managed")
	}
	if st.FirstApplyDone {
		t.Error("adopt marked the first apply done; first-apply tasks run on the first apply after it")
	}
}

type crashFS struct {
	osFS
	crash bool
}

func (c *crashFS) BeforeRename(tmp, dst string) error {
	if c.crash {
		return errors.New("simulated crash")
	}
	return nil
}

func TestAtomicWriteSurvivesCrashBeforeRename(t *testing.T) {
	w := newWorld(t)
	c1 := w.commit(map[model.SourcePath]string{"files/.a": "old\n"}, manifest.Entry{Target: ".a"})
	w.apply(c1)
	cfs := &crashFS{crash: true}
	w.eng.fs = cfs
	c2 := w.commit(map[model.SourcePath]string{"files/.a": "new\n"}, manifest.Entry{Target: ".a"})
	if _, err := w.eng.Apply(context.Background(), c2, ApplyOptions{}); err == nil {
		t.Fatal("want the simulated crash")
	}
	if got := w.read(".a"); got != "old\n" {
		t.Fatalf("target changed by a crashed write: %q", got)
	}
	temps, _ := filepath.Glob(filepath.Join(w.home, "..a"+tmpMarker+"*"))
	if len(temps) != 1 {
		t.Fatalf("crash should leave one temp file, found %v", temps)
	}
	if st := w.state(); st.Applied != c1 {
		t.Errorf("state advanced past a crashed apply: %s", st.Applied)
	}
	// Recovery: the next apply finishes and removes the stale temp file.
	cfs.crash = false
	r := w.apply(c2)
	if a := actionOf(r, ".a"); a.Kind != ActWrite {
		t.Fatalf("recovery: %+v", a)
	}
	if w.read(".a") != "new\n" {
		t.Error("recovery did not write")
	}
	temps, _ = filepath.Glob(filepath.Join(w.home, "..a"+tmpMarker+"*"))
	if len(temps) != 0 {
		t.Errorf("stale temp left: %v", temps)
	}
}

func TestApplyRefusesUnsafeTargets(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/x": "x\n"}, manifest.Entry{Target: "../escape", Source: "files/x"})
	if _, err := w.eng.Apply(context.Background(), c, ApplyOptions{}); err == nil {
		t.Fatal("a target outside $HOME was accepted")
	}
}

func TestApplyDoesNotReplaceSymlink(t *testing.T) {
	w := newWorld(t)
	other := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(other, []byte("keep\n"), 0o644)
	os.Symlink(other, w.path(".a"))
	c := w.commit(map[model.SourcePath]string{"files/.a": "repo\n"}, manifest.Entry{Target: ".a"})
	r := w.apply(c)
	if a := actionOf(r, ".a"); a.Kind != ActHold {
		t.Fatalf("%+v", a)
	}
	if info, _ := os.Lstat(w.path(".a")); info.Mode()&fs.ModeSymlink == 0 {
		t.Error("symlink replaced")
	}
}

func TestPlanIsDryRun(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "a\n"}, manifest.Entry{Target: ".a"})
	acts, err := w.eng.Plan(context.Background(), c)
	if err != nil || len(acts) != 1 || acts[0].Kind != ActWrite {
		t.Fatalf("%+v %v", acts, err)
	}
	if _, err := os.Stat(w.path(".a")); err == nil {
		t.Error("Plan wrote a file")
	}
	if _, err := os.Stat(filepath.Join(w.stateDir, StateFile)); err == nil {
		t.Error("Plan saved state")
	}
}

func TestResolveHoldTakeSource(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "repo\n"}, manifest.Entry{Target: ".a"})
	w.apply(c)
	w.write(".a", "local\n")
	r := w.apply(c)
	id := r.Holds[0].ID
	res, err := w.eng.ResolveHold(context.Background(), id, ResolveOptions{Take: "source"})
	if err != nil {
		t.Fatal(err)
	}
	if w.read(".a") != "repo\n" || len(res.Actions) != 1 {
		t.Errorf("take source: %q %+v", w.read(".a"), res)
	}
	if hs, _ := w.eng.Holds(context.Background()); len(hs) != 0 {
		t.Errorf("hold left: %+v", hs)
	}
}

func TestResolveHoldTakeTarget(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "repo\n"}, manifest.Entry{Target: ".a"})
	w.apply(c)
	w.write(".a", "local\n")
	r := w.apply(c)
	res, err := w.eng.ResolveHold(context.Background(), r.Holds[0].ID, ResolveOptions{Take: "target"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Capture == nil || len(res.Capture.Changes) != 1 || string(res.Capture.Changes[0].Blob) != "local\n" {
		t.Fatalf("take target: %+v", res)
	}
	if w.read(".a") != "local\n" {
		t.Error("take target changed the target")
	}
	// A merged file is written, then captured.
	w.apply(c)
	hs, _ := w.eng.Holds(context.Background())
	merged := filepath.Join(t.TempDir(), "merged")
	os.WriteFile(merged, []byte("merged\n"), 0o644)
	res, err = w.eng.ResolveHold(context.Background(), hs[0].ID, ResolveOptions{Take: merged})
	if err != nil {
		t.Fatal(err)
	}
	if w.read(".a") != "merged\n" || res.Capture == nil || string(res.Capture.Changes[0].Blob) != "merged\n" {
		t.Errorf("take file: %+v", res)
	}
}
