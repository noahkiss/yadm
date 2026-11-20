package apply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// fakeStore holds commits in memory. Only the methods apply calls are real.
type fakeStore struct {
	store.Store
	dir     string
	head    model.CommitID
	commits map[model.CommitID]map[model.SourcePath][]byte
	modes   map[model.CommitID]map[model.SourcePath]uint32
	blobs   map[string][]byte
}

func newFakeStore(dir string) *fakeStore {
	return &fakeStore{dir: dir, commits: map[model.CommitID]map[model.SourcePath][]byte{},
		modes: map[model.CommitID]map[model.SourcePath]uint32{}, blobs: map[string][]byte{}}
}

func blobID(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:20]) }

func (s *fakeStore) Dir() string                                  { return s.dir }
func (s *fakeStore) Head(context.Context) (model.CommitID, error) { return s.head, nil }
func (s *fakeStore) ListTree(_ context.Context, rev model.CommitID) ([]store.TreeEntry, error) {
	files, ok := s.commits[rev]
	if !ok {
		return nil, fmt.Errorf("no commit %s", rev)
	}
	var out []store.TreeEntry
	for p, b := range files {
		mode := uint32(gitModeFile)
		if m, ok := s.modes[rev][p]; ok {
			mode = m
		}
		out = append(out, store.TreeEntry{Path: p, Mode: mode, Blob: blobID(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
func (s *fakeStore) ReadBlob(_ context.Context, id string) ([]byte, error) {
	b, ok := s.blobs[id]
	if !ok {
		return nil, fmt.Errorf("no blob %s", id)
	}
	return b, nil
}
func (s *fakeStore) ReadPath(_ context.Context, rev model.CommitID, p model.SourcePath) ([]byte, error) {
	b, ok := s.commits[rev][p]
	if !ok {
		return nil, fmt.Errorf("%s: not in %s", p, rev)
	}
	return b, nil
}

// fakeCrypto seals by XOR behind the real container magic. Its ciphertext
// never contains the plaintext bytes, which is all secrecy tests need.
type fakeCrypto struct {
	members map[model.EnclaveName]bool
	epoch   byte // sealing epoch; opening accepts any
}

func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 0x5a
	}
	return out
}

func (c fakeCrypto) CanOpen(e model.EnclaveName) bool { return c.members[e] }
func (c fakeCrypto) SealFile(e model.EnclaveName, _ model.SourcePath, pt []byte) ([]byte, error) {
	if !c.members[e] {
		return nil, crypt.ErrNotMember
	}
	return append([]byte(crypt.FileMagic+string(e)+"\x00"+string(rune('0'+c.epoch))), xor(pt)...), nil
}
func (c fakeCrypto) OpenFile(e model.EnclaveName, _ model.SourcePath, ct []byte) ([]byte, error) {
	if !c.members[e] {
		return nil, crypt.ErrNotMember
	}
	pre := []byte(crypt.FileMagic + string(e) + "\x00")
	if !bytes.HasPrefix(ct, pre) || len(ct) <= len(pre) {
		return nil, crypt.ErrNotSealed
	}
	return xor(ct[len(pre)+1:]), nil
}
func (c fakeCrypto) SealValue(e model.EnclaveName, k string, pt []byte) (string, error) {
	if !c.members[e] {
		return "", crypt.ErrNotMember
	}
	return fmt.Sprintf("tok:%s:%d:%s", e, c.epoch, hex.EncodeToString(xor(pt))), nil
}
func (c fakeCrypto) OpenValue(e model.EnclaveName, k, tok string) ([]byte, error) {
	if !c.members[e] {
		return nil, crypt.ErrNotMember
	}
	if !strings.HasPrefix(tok, "tok:"+string(e)+":") {
		return nil, crypt.ErrAuthFailed
	}
	b, err := hex.DecodeString(tok[strings.LastIndexByte(tok, ':')+1:])
	return xor(b), err
}
func (c fakeCrypto) SealRegion(e model.EnclaveName, l string, b []byte) (string, error) {
	return c.SealValue(e, l, b)
}
func (c fakeCrypto) OpenRegion(e model.EnclaveName, l, tok string) ([]byte, error) {
	return c.OpenValue(e, l, tok)
}

// fakeRules handles "key=value" lines: sealed keys hold tokens in the source.
type fakeRules struct{}

func splitKV(l string) (string, string, bool) {
	i := strings.IndexByte(l, '=')
	if i < 0 {
		return "", "", false
	}
	return l[:i], l[i+1:], true
}

func lines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func join(ls []string) []byte {
	if len(ls) == 0 {
		return nil
	}
	return []byte(strings.Join(ls, "\n") + "\n")
}

func (fakeRules) ToTarget(src, _ []byte, spec rules.Spec, s rules.Sealer) ([]byte, error) {
	var out []string
	for _, l := range lines(src) {
		k, v, ok := splitKV(l)
		enc, sealed := spec.Seal[k]
		if !ok || !sealed {
			out = append(out, l)
			continue
		}
		if !s.CanOpen(enc) {
			continue
		}
		p, err := s.OpenValue(enc, k, v)
		if err != nil {
			return nil, err
		}
		out = append(out, k+"="+string(p))
	}
	return join(out), nil
}

func (fakeRules) ToSource(target, prev []byte, spec rules.Spec, s rules.Sealer) ([]byte, []rules.Violation, error) {
	var out []string
	present := map[string]bool{}
	for _, l := range lines(target) {
		k, v, ok := splitKV(l)
		enc, sealed := spec.Seal[k]
		if !ok || !sealed {
			out = append(out, l)
			continue
		}
		present[k] = true
		tok, err := s.SealValue(enc, k, []byte(v))
		if err != nil {
			return nil, nil, err
		}
		out = append(out, k+"="+tok)
	}
	var viol []rules.Violation
	for i, l := range lines(prev) {
		k, _, ok := splitKV(l)
		enc, sealed := spec.Seal[k]
		if !ok || !sealed || present[k] {
			continue
		}
		if s.CanOpen(enc) {
			viol = append(viol, rules.Violation{Path: k, Kind: rules.SealedKeyRemoved})
			continue
		}
		if i > len(out) {
			i = len(out)
		}
		out = append(out[:i], append([]string{l}, out[i:]...)...)
	}
	return join(out), viol, nil
}

func (fakeRules) Reseal(src []byte, spec rules.Spec, e model.EnclaveName, s rules.Sealer) ([]byte, error) {
	var out []string
	for _, l := range lines(src) {
		k, v, ok := splitKV(l)
		if enc, sealed := spec.Seal[k]; ok && sealed && enc == e {
			p, err := s.OpenValue(e, k, v)
			if err != nil {
				return nil, err
			}
			tok, err := s.SealValue(e, k, p)
			if err != nil {
				return nil, err
			}
			l = k + "=" + tok
		}
		out = append(out, l)
	}
	return join(out), nil
}

// fakeRender substitutes {{ machine.name }} only.
type fakeRender struct{}

func (fakeRender) Render(_ string, src []byte, ctx model.Context) ([]byte, error) {
	return bytes.ReplaceAll(src, []byte("{{ machine.name }}"), []byte(ctx.Machine.Name)), nil
}

// fakeText patches templates line by line and merges trivially.
type fakeText struct{}

func (fakeText) PatchTemplate(tmpl, last, target []byte) ([]byte, error) {
	tl, ll, gl := lines(tmpl), lines(last), lines(target)
	if len(ll) != len(gl) || len(tl) != len(ll) {
		return nil, errors.New("line count changed")
	}
	out := append([]string(nil), tl...)
	for i := range ll {
		if ll[i] == gl[i] {
			continue
		}
		if tl[i] != ll[i] {
			return nil, fmt.Errorf("line %d is templated", i+1)
		}
		out[i] = gl[i]
	}
	return join(out), nil
}

func (fakeText) Merge3(base, ours, theirs []byte) ([]byte, []textmerge.Region, error) {
	switch {
	case bytes.Equal(ours, theirs), bytes.Equal(theirs, base):
		return ours, nil, nil
	case bytes.Equal(ours, base):
		return theirs, nil, nil
	}
	return []byte("<<<<<<<\n"), []textmerge.Region{{Ours: ours, Theirs: theirs}}, nil
}

// world is one machine with a home, a state directory and a fake source.
type world struct {
	t        *testing.T
	home     string
	stateDir string
	st       *fakeStore
	plans    map[model.CommitID]*manifest.Manifest
	machine  model.Machine
	crypto   fakeCrypto
	clock    time.Time
	eng      *Engine
	n        int
	loads    map[model.EnclaveName]crypt.EnclaveLoad
}

func newWorld(t *testing.T, members ...model.EnclaveName) *world {
	t.Helper()
	w := &world{
		t:        t,
		home:     t.TempDir(),
		stateDir: t.TempDir(),
		plans:    map[model.CommitID]*manifest.Manifest{},
		machine:  model.Machine{ID: "m-test01", Name: "host-a", Types: []model.TypeName{"work"}, OS: "linux", Arch: "amd64"},
		crypto:   fakeCrypto{members: map[model.EnclaveName]bool{}},
		clock:    time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	for _, m := range members {
		w.crypto.members[m] = true
	}
	w.st = newFakeStore(t.TempDir())
	w.eng = New(Deps{
		Store:        w.st,
		Self:         w.machine.ID,
		State:        FileStateDB(w.stateDir),
		Home:         w.home,
		User:         "user",
		StateDir:     w.stateDir,
		Allow:        tasks.FileAllowList(w.stateDir),
		Now:          func() time.Time { return w.clock },
		LoadSnapshot: w.load,
		Rules:        fakeRules{},
		Text:         fakeText{},
		StatTimeout:  500 * time.Millisecond,
		ScanBudget:   2 * time.Second,
	})
	return w
}

func (w *world) tick(d time.Duration) { w.clock = w.clock.Add(d) }

// allowRoots allows every owned root of a commit on this machine, as the
// user does with `yadm root allow`.
func (w *world) allowRoots(rev model.CommitID) {
	w.t.Helper()
	for _, r := range w.plans[rev].Roots {
		if err := w.eng.AllowRoot(context.Background(), rev, r.Path); err != nil {
			w.t.Fatal(err)
		}
	}
}

// commit records a source commit. files maps source paths to bytes; entries
// is the manifest. A file's plaintext under sealed/<e>/ is sealed here.
func (w *world) commit(files map[model.SourcePath]string, entries ...manifest.Entry) model.CommitID {
	w.t.Helper()
	w.n++
	id := model.CommitID(fmt.Sprintf("%040d", w.n))
	tree := map[model.SourcePath][]byte{}
	sealer := fakeCrypto{members: map[model.EnclaveName]bool{"personal": true, "client": true}}
	for p, s := range files {
		b := []byte(s)
		if enc, _, ok := sealedEnclave(p); ok {
			var err error
			if b, err = sealer.SealFile(enc, p, b); err != nil {
				w.t.Fatal(err)
			}
		}
		tree[p] = b
		w.st.blobs[blobID(b)] = b
	}
	w.st.commits[id] = tree
	w.st.head = id
	w.plans[id] = &manifest.Manifest{Schema: 1, Entries: entries}
	return id
}

// setMode marks a source path executable in a commit.
func (w *world) setMode(id model.CommitID, p model.SourcePath, mode uint32) {
	if w.st.modes[id] == nil {
		w.st.modes[id] = map[model.SourcePath]uint32{}
	}
	w.st.modes[id][p] = mode
}

func (w *world) load(ctx context.Context, rev model.CommitID) (*Snapshot, error) {
	man, ok := w.plans[rev]
	if !ok {
		return nil, fmt.Errorf("no commit %q", rev)
	}
	ents, err := w.st.ListTree(ctx, rev)
	if err != nil {
		return nil, err
	}
	tree := map[model.SourcePath]store.TreeEntry{}
	for _, e := range ents {
		tree[e.Path] = e
	}
	plan := &manifest.Plan{Targets: map[model.Target]manifest.Resolved{}}
	for i, e := range man.Entries {
		src := e.Source
		if src == "" {
			src = defaultSource(e.Target, e.Enclave)
		}
		plan.Targets[e.Target] = manifest.Resolved{Target: e.Target, Source: src, Entry: e, Index: i}
	}
	plan.Roots = man.Roots
	plan.Tasks = man.Tasks
	fl := &fleet.File{Schema: 1, Types: map[model.TypeName]fleet.TypeDef{
		"work": {}, "personal": {Enclave: true}, "client": {Enclave: true},
	}}
	return &Snapshot{
		Commit:   rev,
		Fleet:    fl,
		Manifest: man,
		Plan:     plan,
		Context:  model.Context{Machine: w.machine, Home: w.home, User: "user"},
		Render:   fakeRender{},
		Crypto:   w.crypto,
		Enclaves: w.loads,
		Tree:     tree,
	}, nil
}

func (w *world) path(t model.Target) string {
	return filepath.Join(w.home, filepath.FromSlash(string(t)))
}

func (w *world) read(t model.Target) string {
	w.t.Helper()
	b, err := os.ReadFile(w.path(t))
	if err != nil {
		w.t.Fatal(err)
	}
	return string(b)
}

func (w *world) write(t model.Target, s string) {
	w.t.Helper()
	p := w.path(t)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) apply(rev model.CommitID) Result {
	w.t.Helper()
	r, err := w.eng.Apply(context.Background(), rev, ApplyOptions{})
	if err != nil {
		w.t.Fatalf("apply: %v", err)
	}
	return r
}

func (w *world) state() *State {
	w.t.Helper()
	st, err := w.eng.State.Load()
	if err != nil {
		w.t.Fatal(err)
	}
	return st
}

type fileID struct {
	ino   uint64
	mtime time.Time
}

func (w *world) id(t model.Target) fileID {
	w.t.Helper()
	info, err := os.Stat(w.path(t))
	if err != nil {
		w.t.Fatal(err)
	}
	return fileID{ino: uint64(info.Sys().(*syscall.Stat_t).Ino), mtime: info.ModTime()}
}

func actionOf(r Result, t model.Target) Action {
	for _, a := range r.Actions {
		if a.Target == t {
			return a
		}
	}
	return Action{}
}
