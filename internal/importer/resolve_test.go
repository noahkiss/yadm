package importer

// Test helpers that resolve a converted tree with the real manifest, cond
// and render packages, so tests check what each machine would receive.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/render"
)

// fakeSealer seals with AES-GCM under a random in-memory key per enclave.
// Its output never contains the plaintext.
type fakeSealer struct {
	keys  map[model.EnclaveName][]byte
	calls int
}

const fakeMagic = "fake-sealed\x00"

func newFakeSealer() *fakeSealer { return &fakeSealer{keys: map[model.EnclaveName][]byte{}} }

func (s *fakeSealer) aead(e model.EnclaveName) cipher.AEAD {
	k := s.keys[e]
	if k == nil {
		k = make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		s.keys[e] = k
	}
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return g
}

func (s *fakeSealer) SealFile(e model.EnclaveName, pt []byte) ([]byte, error) {
	s.calls++
	g := s.aead(e)
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	hdr := fakeMagic + string(e) + "\x00"
	return append(append([]byte(hdr), nonce...), g.Seal(nil, nonce, pt, []byte(hdr))...), nil
}

func (s *fakeSealer) open(e model.EnclaveName, b []byte) ([]byte, error) {
	hdr := fakeMagic + string(e) + "\x00"
	if !strings.HasPrefix(string(b), hdr) {
		return nil, errors.New("not sealed for this enclave")
	}
	g := s.aead(e)
	rest := b[len(hdr):]
	return g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], []byte(hdr))
}

// resolvedTarget is what one machine receives at one target.
type resolvedTarget struct {
	Entry   manifest.Entry
	Content []byte
	Mode    fs.FileMode
	Skipped bool // sealed, and this machine is not a member
}

func (r resolvedTarget) sum() string {
	h := sha256.Sum256(r.Content)
	return hex.EncodeToString(h[:])
}

// resolveFor parses the converted manifest strictly, resolves it for one
// machine against the converted source tree, opens sealed files the machine
// is a member of and renders templates. v is the condition vocabulary; nil
// means the converted fleet's. A collision or a render failure is a problem;
// a manifest or fleet that does not parse is an error.
func resolveFor(conv *converted, sealer *fakeSealer, ctx model.Context, v *cond.Vocabulary, member func(model.EnclaveName) bool) (map[model.Target]resolvedTarget, []string, error) {
	mf, err := manifest.Parse(conv.Manifest)
	if err != nil {
		return nil, nil, err
	}
	if v == nil {
		fl, err := fleet.Parse(conv.Fleet)
		if err != nil {
			return nil, nil, err
		}
		voc := fl.Vocabulary()
		v = &voc
	}
	tree := make([]model.SourcePath, 0, len(conv.Files))
	for p := range conv.Files {
		tree = append(tree, p)
	}
	plan, err := mf.Resolve(ctx, tree, *v)
	var ce *manifest.CollisionError
	if errors.As(err, &ce) {
		var problems []string
		for _, c := range ce.Collisions {
			var srcs []string
			for _, i := range c.Indexes {
				srcs = append(srcs, string(mf.Entries[i].Source)+" when "+mf.Entries[i].When)
			}
			problems = append(problems, fmt.Sprintf("collision at %s: %s", c.Target, strings.Join(srcs, "; ")))
		}
		return nil, problems, nil
	}
	if err != nil {
		return nil, nil, err
	}
	eng := render.New(*v)
	out := map[model.Target]resolvedTarget{}
	var problems []string
	for tg, r := range plan.Targets {
		f := conv.Files[r.Source]
		t := resolvedTarget{Entry: r.Entry}
		data := f.Data
		if r.Entry.Enclave != "" {
			if member == nil || !member(r.Entry.Enclave) {
				t.Skipped = true
				out[tg] = t
				continue
			}
			data, err = sealer.open(r.Entry.Enclave, data)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: open: %v", tg, err)
			}
		}
		if r.Entry.Template {
			data, err = eng.Render(string(tg), data, ctx)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: render: %v", tg, err))
				continue
			}
		}
		t.Content = data
		t.Mode = r.FileMode(f.Exec)
		out[tg] = t
	}
	sort.Strings(problems)
	return out, problems, nil
}

// fleetMachine finds a machine by name in the converted fleet.
func fleetMachine(t testing.TB, conv *converted, name string) model.Machine {
	t.Helper()
	f, err := fleet.Parse(conv.Fleet)
	if err != nil {
		t.Fatal(err)
	}
	for id, m := range f.Machines {
		if m.Name == name {
			m.ID = id
			return m
		}
	}
	t.Fatalf("machine %s not in fleet", name)
	return model.Machine{}
}
