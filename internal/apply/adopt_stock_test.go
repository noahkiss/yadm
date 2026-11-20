package apply

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

func mustSymlink(t *testing.T, old, new string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(new), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(old, new); err != nil {
		t.Fatal(err)
	}
}

// TestAdoptMaterializesStockAlternates: adopt replaces a file symlink whose
// content equals the render with a regular file, fixes a read-only render's
// mode, replaces a directory symlink above a target with a real directory,
// holds a link whose content differs, and leaves every link target alone.
func TestAdoptMaterializesStockAlternates(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{
		"files/.linked":                  "linked\n",
		"files/.differs":                 "source\n",
		"files/.readonly":                "render\n",
		"files/.config/tool/scripts/run": "run\n",
	},
		manifest.Entry{Target: ".linked"},
		manifest.Entry{Target: ".differs"},
		manifest.Entry{Target: ".readonly"},
		manifest.Entry{Target: ".config/tool/scripts/run"},
	)
	w.write(".linked##class.home", "linked\n")
	mustSymlink(t, ".linked##class.home", w.path(".linked"))
	w.write(".differs##class.home", "other\n")
	mustSymlink(t, ".differs##class.home", w.path(".differs"))
	w.write(".readonly", "render\n")
	if err := os.Chmod(w.path(".readonly"), 0o444); err != nil {
		t.Fatal(err)
	}
	w.write(".config/tool/scripts##class.home/run", "run\n")
	w.write(".config/tool/scripts##class.home/helper", "helper\n")
	mustSymlink(t, "scripts##class.home", w.path(".config/tool/scripts"))

	dry, err := w.eng.Adopt(ctx, c, AdoptOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if li, _ := os.Lstat(w.path(".config/tool/scripts")); li.Mode()&os.ModeSymlink == 0 || len(dry.Actions) == 0 {
		t.Fatal("dry run changed a link")
	}

	res, err := w.eng.Adopt(ctx, c, AdoptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	regular := func(tg model.Target) os.FileInfo {
		t.Helper()
		li, err := os.Lstat(w.path(tg))
		if err != nil || !li.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file: %v %v", tg, li, err)
		}
		return li
	}
	regular(".linked")
	if w.read(".linked") != "linked\n" || w.read(".linked##class.home") != "linked\n" {
		t.Error("materialized content or link target changed")
	}
	if li := regular(".readonly"); li.Mode().Perm() != 0o644 {
		t.Errorf("read-only render mode %v", li.Mode().Perm())
	}
	if li, _ := os.Lstat(w.path(".config/tool/scripts")); li == nil || !li.IsDir() || li.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("directory link not materialized: %v", li)
	}
	regular(".config/tool/scripts/run")
	if w.read(".config/tool/scripts/helper") != "helper\n" || w.read(".config/tool/scripts##class.home/run") != "run\n" {
		t.Error("directory copy or original lost a file")
	}
	var held []model.Target
	for _, h := range res.Holds {
		held = append(held, h.Target)
	}
	if len(held) != 1 || held[0] != ".differs" {
		t.Fatalf("holds %v", held)
	}
	if li, _ := os.Lstat(w.path(".differs")); li.Mode()&os.ModeSymlink == 0 {
		t.Error("a differing link was replaced")
	}

	// A later apply writes the real directory, never the old variant.
	c2 := w.commit(map[model.SourcePath]string{
		"files/.linked": "linked\n", "files/.differs": "source\n", "files/.readonly": "render\n",
		"files/.config/tool/scripts/run": "run v2\n",
	}, w.plans[c].Entries...)
	if _, err := w.eng.Apply(ctx, c2, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if w.read(".config/tool/scripts/run") != "run v2\n" || w.read(".config/tool/scripts##class.home/run") != "run\n" {
		t.Error("apply wrote through to the old variant directory")
	}
}

// TestAdoptRunsNoTasks: adopt writes a missing target but runs no path
// task and no first-apply task; the first apply after it runs only the
// first-apply task.
func TestAdoptRunsNoTasks(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	exec := &countExec{runs: map[string]int{}}
	allow := tasks.FileAllowList(t.TempDir())
	w.eng.Tasks = &tasks.Runner{Exec: exec, Allow: allow}
	c := w.commit(map[model.SourcePath]string{"files/.pkglist": "a\n"}, manifest.Entry{Target: ".pkglist"})
	w.plans[c].Tasks = map[string]manifest.TaskDef{
		"bundle":    {On: []string{".pkglist"}, Command: []string{"pkg-tool"}},
		"bootstrap": {FirstApply: true, Command: []string{"bootstrap-tool"}},
	}
	if _, err := w.eng.Adopt(ctx, c, AdoptOptions{AllowTasks: true}); err != nil {
		t.Fatal(err)
	}
	if w.read(".pkglist") != "a\n" || len(exec.runs) != 0 || w.state().FirstApplyDone {
		t.Fatalf("adopt ran tasks %v or marked first apply done", exec.runs)
	}
	if _, err := w.eng.Apply(ctx, c, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if exec.runs["bootstrap"] != 1 || exec.runs["bundle"] != 0 || !w.state().FirstApplyDone {
		t.Fatalf("first apply after adopt: %v", exec.runs)
	}
}

// TestSettleHolds: a hold whose target is back at what was last written
// settles on a complete scan; a drifting target keeps its hold, and so do
// conflicts and weakened-protection holds.
func TestSettleHolds(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "a\n", "files/.b": "b\n"}, manifest.Entry{Target: ".a"}, manifest.Entry{Target: ".b"})
	if _, err := w.eng.Apply(ctx, c, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	st := w.state()
	now := w.clock
	st.Holds = append(st.Holds,
		fileHold(st, now, ".a", model.ScopeShared, model.HoldCheckFailed, now, "failed checks: scan"),
		fileHold(st, now, ".b", model.ScopeShared, model.HoldCheckFailed, now, "failed checks: scan"),
		fileHold(st, now, ".a", model.ScopeShared, model.HoldConflict, now, "conflict"),
		fileHold(st, now, ".a", model.ScopeShared, model.HoldSealGuard, now, "the manifest weakened this file's protection (x)"),
	)
	if err := w.eng.State.Save(st); err != nil {
		t.Fatal(err)
	}
	w.tick(1e9)
	w.write(".b", "b edited\n")
	drift, err := w.eng.Scan(ctx, ScanOptions{FullHash: true})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.eng.SettleHolds(ctx, drift); err != nil || n != 1 {
		t.Fatalf("settled %d: %v", n, err)
	}
	left := map[string]bool{}
	for _, h := range w.state().Holds {
		left[string(h.Target)+":"+string(h.Reason)] = true
	}
	if left[".a:check_failed"] || !left[".b:check_failed"] || !left[".a:conflict"] || !left[".a:seal_guard"] {
		t.Fatalf("holds left: %v", left)
	}
}
