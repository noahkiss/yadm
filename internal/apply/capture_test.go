package apply

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

func driftOf(ds []Drift, t model.Target) Drift {
	for _, d := range ds {
		if d.Target == t {
			return d
		}
	}
	return Drift{}
}

func TestScanFindsDriftKinds(t *testing.T) {
	w := newWorld(t)
	files := map[model.SourcePath]string{"files/.m": "m\n", "files/.d": "d\n", "files/.p": "p\n", "files/.ok": "ok\n"}
	c := w.commit(files, manifest.Entry{Target: ".m"}, manifest.Entry{Target: ".d"}, manifest.Entry{Target: ".p"}, manifest.Entry{Target: ".ok"})
	w.plans[c].Roots = []manifest.Root{{Path: ".config/shell"}}
	w.allowRoots(c)
	w.apply(c)
	w.write(".m", "changed\n")
	os.Remove(w.path(".d"))
	os.Chmod(w.path(".p"), 0o646) // wider than 0644; a stricter mode, or group write, is not drift
	w.write(".config/shell/extra.sh", "new\n")

	ds, err := w.eng.Scan(context.Background(), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[model.Target]DriftKind{".m": DriftModified, ".d": DriftDeleted, ".p": DriftMode, ".config/shell/extra.sh": DriftNew}
	for tgt, k := range want {
		if d := driftOf(ds, tgt); d.Kind != k {
			t.Errorf("%s: got %q, want %q", tgt, d.Kind, k)
		}
	}
	if d := driftOf(ds, ".ok"); d.Kind != "" {
		t.Errorf(".ok drifted: %+v", d)
	}
	if len(ds) != len(want) {
		t.Errorf("drift: %+v", ds)
	}
	// Since is the first sighting and stays put on later scans.
	first := driftOf(ds, ".m").Since
	w.tick(time.Hour)
	ds, _ = w.eng.Scan(context.Background(), ScanOptions{})
	if !driftOf(ds, ".m").Since.Equal(first) || !driftOf(ds, ".config/shell/extra.sh").Since.Equal(first) {
		t.Error("drift clock reset")
	}
}

// countFS counts reads and can hang one path forever.
type countFS struct {
	osFS
	reads atomic.Int32
	hang  string
	block chan struct{}
}

func (c *countFS) Lstat(n string) (fs.FileInfo, error) {
	if c.hang != "" && n == c.hang {
		<-c.block
	}
	return os.Lstat(n)
}

func (c *countFS) ReadFile(n string) ([]byte, error) {
	c.reads.Add(1)
	return os.ReadFile(n)
}

func TestScanHashesOnlyOnStatChange(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "aaaa\n"}, manifest.Entry{Target: ".a"})
	w.apply(c)
	if _, err := w.eng.Scan(context.Background(), ScanOptions{}); err != nil { // first scan is a full pass
		t.Fatal(err)
	}
	cfs := &countFS{}
	w.eng.fs = cfs
	// Same size and mtime, different bytes: the stat pass cannot see it.
	info, _ := os.Stat(w.path(".a"))
	os.WriteFile(w.path(".a"), []byte("bbbb\n"), 0o644)
	os.Chtimes(w.path(".a"), info.ModTime(), info.ModTime())

	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	if len(ds) != 0 || cfs.reads.Load() != 0 {
		t.Fatalf("stat pass hashed: drift=%+v reads=%d", ds, cfs.reads.Load())
	}
	ds, _ = w.eng.Scan(context.Background(), ScanOptions{FullHash: true})
	if d := driftOf(ds, ".a"); d.Kind != DriftModified || cfs.reads.Load() != 1 {
		t.Fatalf("full pass: %+v reads=%d", ds, cfs.reads.Load())
	}
	// The daily full pass runs on its own after FullHashInterval.
	w.eng.fs = osFS{}
	os.WriteFile(w.path(".a"), []byte("aaaa\n"), 0o644)
	os.Chtimes(w.path(".a"), info.ModTime(), info.ModTime())
	w.eng.Scan(context.Background(), ScanOptions{FullHash: true})
	os.WriteFile(w.path(".a"), []byte("cccc\n"), 0o644)
	os.Chtimes(w.path(".a"), info.ModTime(), info.ModTime())
	w.tick(FullHashInterval)
	ds, _ = w.eng.Scan(context.Background(), ScanOptions{})
	if d := driftOf(ds, ".a"); d.Kind != DriftModified {
		t.Errorf("daily full pass missing: %+v", ds)
	}
}

func TestScanDoesNotHangOnSlowMount(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.slow": "s\n", "files/.fast": "f\n"},
		manifest.Entry{Target: ".slow"}, manifest.Entry{Target: ".fast"})
	w.apply(c)
	w.write(".fast", "changed\n")
	cfs := &countFS{hang: w.path(".slow"), block: make(chan struct{})}
	defer close(cfs.block)
	w.eng.fs = cfs
	w.eng.StatTimeout = 100 * time.Millisecond

	start := time.Now()
	ds, err := w.eng.Scan(context.Background(), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("scan took %v", el)
	}
	if d := driftOf(ds, ".slow"); d.Kind != DriftUnreadable {
		t.Errorf(".slow: %+v", d)
	}
	if d := driftOf(ds, ".fast"); d.Kind != DriftModified {
		t.Errorf(".fast: %+v", d)
	}

	// Apply on the same mount holds the slow target instead of hanging.
	start = time.Now()
	r, err := w.eng.Apply(context.Background(), c, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("apply took %v", el)
	}
	if a := actionOf(r, ".slow"); a.Kind != ActHold || !strings.Contains(a.Reason, "unreadable") {
		t.Errorf("apply .slow: %+v", a)
	}
}

func TestScanBudget(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "a\n", "files/.b": "b\n"}, manifest.Entry{Target: ".a"}, manifest.Entry{Target: ".b"})
	w.apply(c)
	cfs := &countFS{hang: w.path(".a"), block: make(chan struct{})}
	defer close(cfs.block)
	w.eng.fs = cfs
	w.eng.StatTimeout = time.Second
	w.eng.ScanBudget = 150 * time.Millisecond
	start := time.Now()
	ds, err := w.eng.Scan(context.Background(), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("budget ignored: %v", el)
	}
	if driftOf(ds, ".a").Kind != DriftUnreadable || driftOf(ds, ".b").Kind != DriftUnreadable {
		t.Errorf("%+v", ds)
	}
	if st := w.state(); !st.LastFullHash.IsZero() && st.LastFullHash.Equal(w.clock) {
		t.Error("an incomplete scan counted as the full pass")
	}
}

func TestCaptureVerbatim(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "v1\n"}, manifest.Entry{Target: ".a"})
	w.apply(c)
	w.write(".a", "v2\n")
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, err := w.eng.Capture(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 1 || cp.Changes[0].Path != "files/.a" || string(cp.Changes[0].Blob) != "v2\n" || cp.Scopes[".a"] != model.ScopeShared {
		t.Fatalf("%+v", cp)
	}
	// Committed and applied, the target is clean and not rewritten.
	before := w.id(".a")
	c2 := w.commit(map[model.SourcePath]string{"files/.a": "v2\n"}, manifest.Entry{Target: ".a"})
	r := w.apply(c2)
	if a := actionOf(r, ".a"); a.Kind != ActSkip || w.id(".a") != before {
		t.Errorf("after commit: %+v", a)
	}
	if ds, _ := w.eng.Scan(context.Background(), ScanOptions{FullHash: true}); len(ds) != 0 {
		t.Errorf("still drifted: %+v", ds)
	}
}

func TestCaptureDeleted(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "v1\n"}, manifest.Entry{Target: ".a"})
	w.apply(c)
	os.Remove(w.path(".a"))
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, _ := w.eng.Capture(context.Background(), ds)
	if len(cp.Changes) != 1 || !cp.Changes[0].Delete {
		t.Fatalf("%+v", cp)
	}
}

func TestCaptureTemplate(t *testing.T) {
	w := newWorld(t)
	tm := manifest.Entry{Target: ".gitconfig", Source: "files/.gitconfig.tmpl", Template: true}
	c := w.commit(map[model.SourcePath]string{"files/.gitconfig.tmpl": "[user]\nname = {{ machine.name }}\neditor = vi\n"}, tm)
	w.apply(c)

	// An edit on a literal line patches into the template.
	w.write(".gitconfig", "[user]\nname = host-a\neditor = nano\n")
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, err := w.eng.Capture(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Changes) != 1 || string(cp.Changes[0].Blob) != "[user]\nname = {{ machine.name }}\neditor = nano\n" {
		t.Fatalf("patched template: %+v", cp)
	}

	// An edit on a rendered line cannot patch: rendered_edit hold.
	w.write(".gitconfig", "[user]\nname = other\neditor = vi\n")
	ds, _ = w.eng.Scan(context.Background(), ScanOptions{})
	cp, _ = w.eng.Capture(context.Background(), ds)
	if len(cp.Changes) != 0 || len(cp.Holds) != 1 || cp.Holds[0].Reason != model.HoldRenderedEdit {
		t.Fatalf("rendered edit: %+v", cp)
	}
	// The hold carries a proposed patch an agent can finish in one step.
	if h := cp.Holds[0]; h.Source != "files/.gitconfig.tmpl" || h.PatchOf != model.PatchOfRender ||
		!strings.Contains(h.Patch, "-name = host-a\n+name = other\n") {
		t.Fatalf("proposed patch: %+v", h)
	}
	// Apply never re-renders over it.
	c2 := w.commit(map[model.SourcePath]string{"files/.gitconfig.tmpl": "[user]\nname = {{ machine.name }}\neditor = ed\n"}, tm)
	w.apply(c2)
	if w.read(".gitconfig") != "[user]\nname = other\neditor = vi\n" {
		t.Error("render overwrote a held hand edit")
	}
}

func TestCaptureSealedTemplateHoldHasNoPlaintext(t *testing.T) {
	w := newWorld(t, "personal")
	tm := manifest.Entry{Target: ".netrc", Source: "sealed/personal/.netrc.tmpl", Template: true, Enclave: "personal"}
	c := w.commit(map[model.SourcePath]string{"sealed/personal/.netrc.tmpl": "machine {{ machine.name }}\npassword canary-pw\n"}, tm)
	w.apply(c)
	w.write(".netrc", "machine canary-host\npassword canary-pw\n")
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, _ := w.eng.Capture(context.Background(), ds)
	if len(cp.Holds) != 1 || cp.Holds[0].Reason != model.HoldRenderedEdit {
		t.Fatalf("%+v", cp)
	}
	if h := cp.Holds[0]; h.Patch != "" || h.Source != tm.Source {
		t.Fatalf("enclave hold carries a patch: %+v", h)
	}
	b, err := os.ReadFile(w.stateDir + "/" + StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "canary") {
		t.Fatal("state file holds enclave plaintext")
	}
}

func TestCaptureSealGuard(t *testing.T) {
	w := newWorld(t, "personal")
	en := manifest.Entry{Target: ".env", Format: manifest.FormatText, Seal: map[string]model.EnclaveName{"TOKEN": "personal"}}
	tok, _ := fakeCrypto{members: map[model.EnclaveName]bool{"personal": true}}.SealValue("personal", "TOKEN", []byte("s3cret"))
	c := w.commit(map[model.SourcePath]string{"files/.env": "A=1\nTOKEN=" + tok + "\n"}, en)
	w.apply(c)
	if w.read(".env") != "A=1\nTOKEN=s3cret\n" {
		t.Fatalf("member target: %q", w.read(".env"))
	}
	w.write(".env", "A=2\n") // the sealed key is gone
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, _ := w.eng.Capture(context.Background(), ds)
	if len(cp.Changes) != 0 || len(cp.Holds) != 1 || cp.Holds[0].Reason != model.HoldSealGuard {
		t.Fatalf("%+v", cp)
	}
}

func TestCaptureNewFileInEnclaveRoot(t *testing.T) {
	w := newWorld(t, "personal")
	c := w.commit(map[model.SourcePath]string{"files/.a": "a\n"}, manifest.Entry{Target: ".a"})
	w.plans[c].Roots = []manifest.Root{{Path: ".config/notes", Enclave: "personal"}, {Path: ".config/shell"}}
	w.allowRoots(c)
	w.apply(c)
	w.write(".config/notes/n.md", "note\n")
	w.write(".config/shell/s.sh", "sh\n")
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	cp, err := w.eng.Capture(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	got := map[model.SourcePath]store.Change{}
	for _, ch := range cp.Changes {
		got[ch.Path] = ch
	}
	if ch, ok := got["sealed/personal/.config/notes/n.md"]; !ok || !crypt.IsSealedFile(ch.Blob) {
		t.Errorf("enclave root: %+v", cp.Changes)
	}
	if ch, ok := got["files/.config/shell/s.sh"]; !ok || string(ch.Blob) != "sh\n" {
		t.Errorf("plain root: %+v", cp.Changes)
	}
	if cp.Scopes[".config/notes/n.md"] != "personal" {
		t.Errorf("scope: %+v", cp.Scopes)
	}
}

func TestMergeSealed(t *testing.T) {
	w := newWorld(t, "personal")
	cr := w.crypto
	seal := func(s string) string {
		b, _ := cr.SealFile("personal", "", []byte(s))
		w.st.blobs[blobID(b)] = b
		return blobID(b)
	}
	c := w.commit(nil)
	snap, _ := w.load(context.Background(), c)
	path := model.SourcePath("sealed/personal/.config/notes/private.md")

	ch, h, err := w.eng.MergeSealed(context.Background(), snap, store.Conflict{Path: path, Base: seal("a\n"), Ours: seal("a\n"), Theirs: seal("b\n")})
	if err != nil || h != nil || ch == nil {
		t.Fatalf("clean merge: %v %+v %v", ch, h, err)
	}
	if pt, _ := cr.OpenFile("personal", "", ch.Blob); string(pt) != "b\n" {
		t.Errorf("merged %q", pt)
	}
	ch, h, err = w.eng.MergeSealed(context.Background(), snap, store.Conflict{Path: path, Base: seal("a\n"), Ours: seal("b\n"), Theirs: seal("c\n")})
	if err != nil || ch != nil || h == nil || h.Reason != model.HoldConflict || h.Theirs == "" {
		t.Fatalf("conflict: %v %+v %v", ch, h, err)
	}
	if strings.Contains(h.Detail, "b\n") {
		t.Error("hold detail carries plaintext")
	}
	if _, _, err := w.eng.MergeSealed(context.Background(), snap, store.Conflict{Path: "files/x"}); err == nil {
		t.Error("plain path accepted")
	}
	w.crypto.members = map[model.EnclaveName]bool{}
	snap, _ = w.load(context.Background(), c)
	if _, _, err := w.eng.MergeSealed(context.Background(), snap, store.Conflict{Path: path}); err == nil {
		t.Error("non-member merged a sealed file")
	}
}

func TestReseal(t *testing.T) {
	w := newWorld(t, "personal")
	c := w.commit(map[model.SourcePath]string{"sealed/personal/.n": "note\n", "files/.a": "a\n"}, manifest.Entry{Target: ".n", Enclave: "personal"})
	snap, _ := w.load(context.Background(), c)
	cp, err := w.eng.Reseal(context.Background(), snap, "personal")
	if err != nil || len(cp.Changes) != 0 {
		t.Fatalf("reseal under the same key changed bytes: %+v %v", cp, err)
	}
	if _, err := w.eng.Reseal(context.Background(), snap, "client"); err == nil {
		t.Error("non-member resealed")
	}
}

func TestRetagMovesIntoEnclave(t *testing.T) {
	w := newWorld(t, "personal")
	man := "schema = 1\n\n[[file]]\ntarget = \".a\"\n\n[[file]]\ntarget = \".b\"   # keep me\nwhen = \"type:work\"\n\n[tasks.x]\ncommand = [\"true\"]\n"
	c := w.commit(map[model.SourcePath]string{"files/.b": "secret b\n", "manifest.toml": man},
		manifest.Entry{Target: ".a"}, manifest.Entry{Target: ".b", When: "type:work"})
	_ = c
	cp, err := w.eng.Retag(context.Background(), ".b", RetagOptions{Types: []model.TypeName{"personal"}, Enclave: "personal"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[model.SourcePath]store.Change{}
	for _, ch := range cp.Changes {
		got[ch.Path] = ch
	}
	if !got["files/.b"].Delete {
		t.Error("old source not deleted")
	}
	nb := got["sealed/personal/.b"]
	if pt, err := w.crypto.OpenFile("personal", "", nb.Blob); err != nil || string(pt) != "secret b\n" {
		t.Errorf("new source: %q %v", pt, err)
	}
	m := string(got["manifest.toml"].Blob)
	if !strings.Contains(m, "target = \".b\"   # keep me\nenclave = \"personal\"\nwhen = \"type:personal\"\n") || !strings.Contains(m, "[[file]]\ntarget = \".a\"\n") || !strings.Contains(m, "[tasks.x]") {
		t.Errorf("manifest edit:\n%s", m)
	}
	if cp.Scopes[".b"] != "personal" {
		t.Errorf("scope %v", cp.Scopes)
	}
	// Only a member of every enclave involved may retag.
	if _, err := w.eng.Retag(context.Background(), ".b", RetagOptions{Types: []model.TypeName{"client"}, Enclave: "client"}); err == nil {
		t.Error("non-member retagged into client")
	}
}

func TestEditEntryInsertsAndRemoves(t *testing.T) {
	src := "[[file]]\ntarget = \"x\"\nenclave = \"personal\"\nmode = 384\n"
	out, err := editEntry([]byte(src), 0, map[string]string{"when": "type:work", "enclave": ""})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "[[file]]\ntarget = \"x\"\nwhen = \"type:work\"\nmode = 384\n" {
		t.Errorf("%q", out)
	}
	if _, err := editEntry([]byte(src), 3, nil); err == nil {
		t.Error("missing entry accepted")
	}
}

func TestCaptureNoopUpdatesState(t *testing.T) {
	w := newWorld(t)
	c := w.commit(map[model.SourcePath]string{"files/.a": "a\n"}, manifest.Entry{Target: ".a"})
	w.apply(c)
	// Touch without a content change: the full pass hashes and finds no drift.
	now := time.Now().Add(time.Minute)
	os.Chtimes(w.path(".a"), now, now)
	ds, _ := w.eng.Scan(context.Background(), ScanOptions{})
	if len(ds) != 0 {
		t.Fatalf("touch is not drift: %+v", ds)
	}
	if st := w.state(); !st.Targets[".a"].ModTime.Equal(now) {
		t.Error("stat cache not refreshed")
	}
}
