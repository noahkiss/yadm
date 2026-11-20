package sync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// readCounter counts the blob reads apply makes through its store.
type readCounter struct {
	store.Store
	reads int
}

func (c *readCounter) ReadBlob(ctx context.Context, id string) ([]byte, error) {
	c.reads++
	return c.Store.ReadBlob(ctx, id)
}

func (c *readCounter) ReadPath(ctx context.Context, rev model.CommitID, p model.SourcePath) ([]byte, error) {
	c.reads++
	return c.Store.ReadPath(ctx, rev, p)
}

// gitShim puts a `git` on PATH that logs one line per process and runs the
// real git. It returns a function that reports the number of spawns so far.
func gitShim(t *testing.T) func() int {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := fmt.Sprintf("#!/bin/sh\necho x >> '%s'\nexec '%s' \"$@\"\n", log, real)
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() int {
		b, err := os.ReadFile(log)
		if err != nil {
			return 0
		}
		return strings.Count(string(b), "\n")
	}
}

// bulk adds n managed files to the fixture source: plain files, files
// sealed for the personal enclave (host-a is a member) and templates, in
// the proportions of a real dotfiles repository.
func bulk(n int) func(f *fixture.Fixture) {
	return func(f *fixture.Fixture) {
		write := func(rel string, b []byte) {
			p := filepath.Join(f.Root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				panic(err)
			}
			if err := os.WriteFile(p, b, 0o644); err != nil {
				panic(err)
			}
		}
		sealed, tmpl := n*2/5, n/20
		for i := 0; i < n-sealed-tmpl; i++ {
			write(fmt.Sprintf("files/.config/bulk/p%04d.txt", i), []byte(fmt.Sprintf("plain file %d\n", i)))
		}
		for i := 0; i < sealed; i++ {
			at := model.SourcePath(fmt.Sprintf("sealed/personal/.config/sbulk/s%04d.txt", i))
			blob, err := f.Rings["personal"].SealFile(at, []byte(fmt.Sprintf("sealed file %d\n", i)))
			if err != nil {
				panic(err)
			}
			write(string(at), blob)
		}
		for i := 0; i < tmpl; i++ {
			write(fmt.Sprintf("files/.config/tbulk/t%04d.conf", i), []byte(fmt.Sprintf("host = {{ machine.name }} %d\n", i)))
		}
		mp := filepath.Join(f.Root, "manifest.toml")
		mb, err := os.ReadFile(mp)
		if err != nil {
			panic(err)
		}
		// Entries go before the first table that is not [[file]]-like, so
		// append them as array tables at the end: TOML allows that.
		mb = append(mb, []byte(`
[[file]]
target = ".config/bulk/**"

[[file]]
target = ".config/sbulk/**"
enclave = "personal"
when = "type:personal"

[[file]]
target = ".config/tbulk/**"
template = true
`)...)
		if err := os.WriteFile(mp, mb, 0o644); err != nil {
			panic(err)
		}
	}
}

// spawnCounts runs the hot paths on a world with n bulk files on host-a and
// returns the git spawns and wall time of each.
type spawnRun struct {
	name   string
	spawns int
	reads  int // blob and path reads by apply
	wall   time.Duration
}

func measureSpawns(t *testing.T, n int) []spawnRun {
	t.Helper()
	count := gitShim(t)
	a := fixture.HostA
	w := newWorld(t, bulk(n), a)
	A := w.machines[a]
	A.sync() // first apply writes every target
	rc := &readCounter{Store: A.eng.Store}
	A.eng.Store = rc
	ctx := context.Background()
	var out []spawnRun
	measure := func(name string, f func()) {
		before, reads, start := count(), rc.reads, time.Now()
		f()
		out = append(out, spawnRun{name, count() - before, rc.reads - reads, time.Since(start)})
	}
	measure("sync, no change", func() { A.sync() })
	measure("sync, one edit", func() {
		A.write(aliases, fmt.Sprintf("alias ll=\"ls -la\"\n# edit %d\n", n))
		w.clock.offset += 3 * time.Hour
		r := A.sync()
		if len(r.Committed) != 1 || !r.Pushed {
			t.Fatalf("n=%d: one edit not committed and pushed: %+v", n, r)
		}
	})
	measure("commit --push (hook post-edit)", func() {
		A.write(aliases, fmt.Sprintf("alias ll=\"ls -la\"\n# hook edit %d\n", n))
		r, err := A.s.Commit(ctx, CommitOptions{Paths: []model.Target{aliases}, Trigger: TriggerHook, Unattended: true, Push: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Committed) != 1 || !r.Pushed {
			t.Fatalf("n=%d: hook commit not committed and pushed: %+v", n, r)
		}
	})
	return out
}

// TestSpawnsDoNotScaleWithFiles proves that a sync and a hook commit start
// the same number of git processes, and read the same number of source
// blobs, whatever the number of managed files.
func TestSpawnsDoNotScaleWithFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two large worlds")
	}
	small := measureSpawns(t, 20)
	large := measureSpawns(t, 400)
	for i := range small {
		t.Logf("%-32s n=20: %3d spawns %4d reads %7s   n=400: %3d spawns %4d reads %7s", small[i].name,
			small[i].spawns, small[i].reads, small[i].wall.Round(time.Millisecond), large[i].spawns, large[i].reads, large[i].wall.Round(time.Millisecond))
		if large[i].spawns != small[i].spawns {
			t.Errorf("%s: %d git spawns with 20 files, %d with 400", small[i].name, small[i].spawns, large[i].spawns)
		}
		if large[i].reads != small[i].reads {
			t.Errorf("%s: %d source reads with 20 files, %d with 400", small[i].name, small[i].reads, large[i].reads)
		}
	}
}

// TestSpawnsCorpusSize reports spawns and wall time on a 1,500-file world.
// It runs only with YADM_PERF=1.
func TestSpawnsCorpusSize(t *testing.T) {
	if os.Getenv("YADM_PERF") == "" {
		t.Skip("set YADM_PERF=1")
	}
	for _, r := range measureSpawns(t, 1500) {
		t.Logf("%-32s n=1500: %3d spawns %4d reads %7s", r.name, r.spawns, r.reads, r.wall.Round(time.Millisecond))
	}
}
