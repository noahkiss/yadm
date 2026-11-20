package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// spawnRead is the one-spawn read the batch reader replaced.
func spawnRead(t testing.TB, r *Repo, name string) ([]byte, error) {
	t.Helper()
	return r.git(context.Background(), "cat-file", "blob", name)
}

// blobSet returns named test blobs: empty, binary, large and many small ones.
func blobSet() map[string][]byte {
	rng := rand.New(rand.NewSource(1))
	big := make([]byte, 5<<20)
	rng.Read(big)
	bin := []byte{0, '\n', 0xff, '\r', '\n', 0, 0, 'x', '\n'}
	set := map[string][]byte{
		"files/empty":  {},
		"files/binary": bin,
		"files/large":  big,
		"files/nonl":   []byte("no newline"),
		"files/nl":     []byte("\n\n\n"),
		"files/a b":    []byte("space in path\n"),
	}
	for i := 0; i < 200; i++ {
		b := make([]byte, rng.Intn(4096))
		rng.Read(b)
		set[fmt.Sprintf("files/small/%03d", i)] = b
	}
	return set
}

func TestBatchReadMatchesSpawn(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	defer a.Close()
	set := blobSet()
	var changes []Change
	ids := map[string]string{}
	for p, b := range set {
		changes = append(changes, Change{Path: model.SourcePath(p), Blob: b, Mode: 0o100644})
		id, err := a.HashBlob(ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		ids[p] = id
	}
	head := commitMain(t, a, "blobs", changes...)

	before := spawns.Load()
	for p, want := range set {
		got, err := a.ReadBlob(ctx, ids[p])
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("ReadBlob %s: %d bytes, %v; want %d bytes", p, len(got), err, len(want))
		}
		got, err = a.ReadPath(ctx, head, model.SourcePath(p))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("ReadPath %s: %d bytes, %v; want %d bytes", p, len(got), err, len(want))
		}
	}
	if n := spawns.Load() - before; n != 1 {
		t.Fatalf("%d reads spawned %d processes, want 1", 2*len(set), n)
	}
	for p := range set {
		old, err := spawnRead(t, a, ids[p])
		if err != nil || !bytes.Equal(old, set[p]) {
			t.Fatalf("spawn read %s differs: %v", p, err)
		}
	}

	// Errors keep their old meaning.
	if _, err := a.ReadPath(ctx, head, "files/absent"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadPath missing: %v", err)
	}
	if _, err := a.ReadPath(ctx, "refs/heads/absent", "files/empty"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadPath missing rev: %v", err)
	}
	if _, err := a.ReadPath(ctx, head, "files"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadPath of a tree: %v, want a non-ErrNotExist error", err)
	}
	missing := "0123456789012345678901234567890123456789"
	_, oldErr := spawnRead(t, a, missing)
	if _, err := a.ReadBlob(ctx, missing); err == nil || err.Error() != oldErr.Error() {
		t.Fatalf("ReadBlob missing: %v, want %v", err, oldErr)
	}
	tree := rawGit(t, a.Dir(), "rev-parse", string(head)+"^{tree}")
	_, oldErr = spawnRead(t, a, tree)
	if _, err := a.ReadBlob(ctx, tree); err == nil || err.Error() != oldErr.Error() {
		t.Fatalf("ReadBlob of a tree: %v, want %v", err, oldErr)
	}
	// A path the protocol cannot carry still reads through the spawn path.
	if _, err := a.ReadPath(ctx, head, "files/new\nline"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadPath with a newline: %v", err)
	}
}

func TestBatchConcurrentReads(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	defer a.Close()
	want := map[string][]byte{}
	for i := 0; i < 50; i++ {
		b := bytes.Repeat([]byte{byte(i)}, i*997)
		id, err := a.HashBlob(ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		want[id] = b
	}
	var wg sync.WaitGroup
	errc := make(chan error, 16)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 3; k++ {
				for id, b := range want {
					got, err := a.ReadBlob(ctx, id)
					if err != nil || !bytes.Equal(got, b) {
						errc <- fmt.Errorf("%s: %d bytes, %v", id, len(got), err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func TestBatchConcurrentCancelAndReset(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	defer a.Close()
	const size = 100000
	id, err := a.HashBlob(ctx, bytes.Repeat([]byte("z"), size))
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var bg sync.WaitGroup
	errc := make(chan error, 32)
	// Readers whose ctx expires mid-flight.
	for g := 0; g < 4; g++ {
		bg.Add(1)
		go func() {
			defer bg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				c, cancel := context.WithTimeout(ctx, time.Duration(i%50)*time.Microsecond)
				b, err := a.ReadBlob(c, id)
				cancel()
				if err == nil && len(b) != size {
					errc <- fmt.Errorf("cancelled reader got %d bytes", len(b))
					return
				}
			}
		}()
	}
	// Close and reset in a loop.
	bg.Add(1)
	go func() {
		defer bg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				a.Close()
			} else {
				a.cat.reset()
			}
			time.Sleep(time.Millisecond)
		}
	}()
	// Plain readers must always succeed.
	var rg sync.WaitGroup
	for g := 0; g < 4; g++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for i := 0; i < 100; i++ {
				b, err := a.ReadBlob(ctx, id)
				if err != nil || len(b) != size {
					errc <- fmt.Errorf("plain reader: %d bytes, %v", len(b), err)
					return
				}
			}
		}()
	}
	rg.Wait()
	close(stop)
	bg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

// stuckBin is a stand-in for git that accepts input and never answers.
func stuckBin(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "stuck")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBatchCancellation(t *testing.T) {
	_, a, _ := seeded(t)
	defer a.Close()
	id, err := a.HashBlob(context.Background(), []byte("x\n"))
	if err != nil {
		t.Fatal(err)
	}

	done, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ReadBlob(done, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: %v", err)
	}

	a.cat.mu.Lock()
	a.cat.bin = stuckBin(t)
	a.cat.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = a.ReadBlob(ctx, id)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stuck read: %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stuck read took %v", d)
	}
	if a.cat.pid() != 0 {
		t.Fatal("cancelled read left its process running")
	}
	a.cat.mu.Lock()
	a.cat.bin = "git"
	a.cat.mu.Unlock()
	if b, err := a.ReadBlob(context.Background(), id); err != nil || string(b) != "x\n" {
		t.Fatalf("read after cancel: %q, %v", b, err)
	}
}

func TestBatchRestartsAfterDeath(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	defer a.Close()
	id, err := a.HashBlob(ctx, []byte("alive\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadBlob(ctx, id); err != nil {
		t.Fatal(err)
	}
	pid := a.cat.pid()
	if pid == 0 {
		t.Fatal("no reader process after a read")
	}
	p, _ := os.FindProcess(pid)
	p.Kill()
	time.Sleep(50 * time.Millisecond)
	before := spawns.Load()
	if b, err := a.ReadBlob(ctx, id); err != nil || string(b) != "alive\n" {
		t.Fatalf("read after death: %q, %v", b, err)
	}
	if n := spawns.Load() - before; n != 1 {
		t.Fatalf("restart spawned %d processes, want 1", n)
	}
	if np := a.cat.pid(); np == 0 || np == pid {
		t.Fatalf("pid after restart = %d (was %d)", np, pid)
	}
}

func TestBatchSeesNewObjects(t *testing.T) {
	ctx := context.Background()
	_, a, b := seeded(t)
	defer a.Close()
	defer b.Close()
	base, _ := a.ResolveRef(ctx, RefMain)
	if _, err := a.ReadPath(ctx, base, "files/.base"); err != nil {
		t.Fatal(err)
	}
	pid := a.cat.pid()

	// A loose object written after the reader started.
	id, err := a.HashBlob(ctx, []byte("late\n"))
	if err != nil {
		t.Fatal(err)
	}
	before := spawns.Load()
	if got, err := a.ReadBlob(ctx, id); err != nil || string(got) != "late\n" {
		t.Fatalf("late loose blob: %q, %v", got, err)
	}
	if n := spawns.Load() - before; n != 0 {
		t.Fatalf("late loose blob fell back to %d spawns", n)
	}
	// A ref moved after the reader started resolves to its new commit.
	commitMain(t, a, "late", change("files/.base", "moved\n"))
	before = spawns.Load()
	if got, err := a.ReadPath(ctx, RefMain, "files/.base"); err != nil || string(got) != "moved\n" {
		t.Fatalf("ReadPath through a moved ref: %q, %v", got, err)
	}
	if n := spawns.Load() - before; n != 0 {
		t.Fatalf("moved ref fell back to %d spawns", n)
	}
	// A pack written after the reader started (repack moves loose objects).
	rawGit(t, a.Dir(), "repack", "-a", "-d", "-q")
	rawGit(t, a.Dir(), "prune-packed")
	before = spawns.Load()
	if got, err := a.ReadBlob(ctx, id); err != nil || string(got) != "late\n" {
		t.Fatalf("repacked blob: %q, %v", got, err)
	}
	if n := spawns.Load() - before; n != 0 {
		t.Fatalf("repacked blob fell back to %d spawns", n)
	}
	if a.cat.pid() != pid {
		t.Fatal("reader restarted; the test no longer covers a long-lived process")
	}
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}

	// A pack written by a raw fetch, without Fetch's reader reset.
	if _, err := b.ReadPath(ctx, base, "files/.base"); err != nil {
		t.Fatal(err)
	}
	rawGit(t, b.Dir(), "fetch", "-q", "origin")
	before = spawns.Load()
	if got, err := b.ReadPath(ctx, RemoteMain, "files/.base"); err != nil || string(got) != "moved\n" {
		t.Fatalf("after raw fetch: %q, %v", got, err)
	}
	if n := spawns.Load() - before; n != 0 {
		t.Fatalf("raw-fetched pack fell back to %d spawns", n)
	}
	// Fetch resets the reader.
	commitMain(t, a, "later", change("files/.base", "later\n"))
	if err := a.Push(ctx, []string{RefMain + ":" + RefMain}); err != nil {
		t.Fatal(err)
	}
	if err := b.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if b.cat.pid() != 0 {
		t.Fatal("Fetch left the old reader running")
	}
	if got, err := b.ReadPath(ctx, RemoteMain, "files/.base"); err != nil || string(got) != "later\n" {
		t.Fatalf("after Fetch: %q, %v", got, err)
	}
}

func TestBatchIdleAndClose(t *testing.T) {
	ctx := context.Background()
	_, a, _ := seeded(t)
	a.cat.mu.Lock()
	a.cat.idle = 50 * time.Millisecond
	a.cat.mu.Unlock()
	id, err := a.HashBlob(ctx, []byte("idle\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadBlob(ctx, id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for a.cat.pid() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle reader was not stopped")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if b, err := a.ReadBlob(ctx, id); err != nil || string(b) != "idle\n" {
		t.Fatalf("read after idle stop: %q, %v", b, err)
	}
	if a.cat.pid() == 0 {
		t.Fatal("no reader after a read")
	}
	a.Close()
	a.Close()
	if a.cat.pid() != 0 {
		t.Fatal("Close left the reader running")
	}
	if b, err := a.ReadBlob(ctx, id); err != nil || string(b) != "idle\n" {
		t.Fatalf("read after Close: %q, %v", b, err)
	}
	a.Close()
}

// BenchmarkReadBlob compares the batch reader with one spawn per read. It
// reports spawns per 1,000 reads.
func BenchmarkReadBlob(b *testing.B) {
	ctx := context.Background()
	dir := b.TempDir()
	if out, err := runCmd(dir, "init", "-q", "-b", "main"); err != nil {
		b.Fatalf("init: %v %s", err, out)
	}
	r, err := Open(dir, filepath.Join(dir, ".state"))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	var ids []string
	for i := 0; i < 100; i++ {
		id, err := r.HashBlob(ctx, bytes.Repeat([]byte{byte(i)}, 2048))
		if err != nil {
			b.Fatal(err)
		}
		ids = append(ids, id)
	}
	bench := func(b *testing.B, read func(string) ([]byte, error)) {
		r.cat.reset() // count the reader's own start in every run
		start := spawns.Load()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := read(ids[i%len(ids)]); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		b.ReportMetric(float64(spawns.Load()-start)*1000/float64(b.N), "spawns/1000reads")
	}
	b.Run("batch", func(b *testing.B) {
		bench(b, func(id string) ([]byte, error) { return r.ReadBlob(ctx, id) })
	})
	b.Run("spawn", func(b *testing.B) {
		bench(b, func(id string) ([]byte, error) { return r.git(ctx, "cat-file", "blob", id) })
	})
}

func runCmd(dir string, args ...string) ([]byte, error) {
	return Output(context.Background(), dir, args...)
}
