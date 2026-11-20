package importer

// A minimal reference resolver and renderer, for tests only. The manifest,
// cond and render packages own the real ones; these cover just the subset the
// importer emits, so tests can check what each machine would receive.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
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

// --- conditions ---

type refCond struct {
	toks []string
	pos  int
	m    model.Machine
}

var reTok = regexp.MustCompile(`\s*([()!&|]|[^\s()!&|]+)`)

func evalWhen(src string, m model.Machine) (bool, error) {
	if strings.TrimSpace(src) == "" {
		return true, nil
	}
	var toks []string
	for _, x := range reTok.FindAllStringSubmatch(src, -1) {
		toks = append(toks, x[1])
	}
	c := &refCond{toks: toks, m: m}
	v, err := c.or()
	if err != nil {
		return false, err
	}
	if c.pos != len(c.toks) {
		return false, fmt.Errorf("condition %q: trailing %q", src, c.toks[c.pos])
	}
	return v, nil
}

func (c *refCond) peek() string {
	if c.pos < len(c.toks) {
		return c.toks[c.pos]
	}
	return ""
}

func (c *refCond) or() (bool, error) {
	v, err := c.and()
	for err == nil && c.peek() == "|" {
		c.pos++
		var w bool
		w, err = c.and()
		v = v || w
	}
	return v, err
}

func (c *refCond) and() (bool, error) {
	v, err := c.not()
	for err == nil && c.peek() == "&" {
		c.pos++
		var w bool
		w, err = c.not()
		v = v && w
	}
	return v, err
}

func (c *refCond) not() (bool, error) {
	switch t := c.peek(); t {
	case "!":
		c.pos++
		v, err := c.not()
		return !v, err
	case "(":
		c.pos++
		v, err := c.or()
		if c.peek() != ")" {
			return false, fmt.Errorf("missing )")
		}
		c.pos++
		return v, err
	case "", ")", "&", "|":
		return false, fmt.Errorf("unexpected %q", t)
	default:
		c.pos++
		return refAtom(t, c.m)
	}
}

func refAtom(t string, m model.Machine) (bool, error) {
	switch t {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	kind, val, ok := strings.Cut(t, ":")
	if !ok {
		return false, fmt.Errorf("bad atom %q", t)
	}
	switch kind {
	case "type":
		return m.HasType(model.TypeName(val)), nil
	case "os":
		return m.OS == val, nil
	case "arch":
		return m.Arch == val, nil
	case "machine":
		return m.Name == val, nil
	case "fact":
		k, v, hasV := strings.Cut(val, "=")
		got, present := m.Facts[k]
		if !hasV {
			return present, nil
		}
		return present && got == v, nil
	}
	return false, fmt.Errorf("bad atom %q", t)
}

// --- templates ---

var (
	reRefIf    = regexp.MustCompile(`^\{% if (.+) %\}$`)
	reRefElse  = regexp.MustCompile(`^\{% else %\}$`)
	reRefEndif = regexp.MustCompile(`^\{% endif %\}$`)
	reRefVar   = regexp.MustCompile(`\{\{ ([a-z_.A-Z0-9]+) \}\}`)
)

func refRender(src []byte, ctx model.Context) ([]byte, error) {
	var out strings.Builder
	type frame struct{ parentOn, cond, inElse bool }
	var st []frame
	on := func() bool {
		if len(st) == 0 {
			return true
		}
		f := st[len(st)-1]
		return f.parentOn && (f.cond != f.inElse)
	}
	text := string(src)
	lines := strings.SplitAfter(text, "\n")
	for i, line := range lines {
		body := strings.TrimSuffix(line, "\n")
		switch {
		case reRefIf.MatchString(body):
			v, err := evalWhen(reRefIf.FindStringSubmatch(body)[1], ctx.Machine)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", i+1, err)
			}
			st = append(st, frame{parentOn: on(), cond: v})
		case reRefElse.MatchString(body):
			st[len(st)-1].inElse = true
		case reRefEndif.MatchString(body):
			st = st[:len(st)-1]
		default:
			if !on() {
				continue
			}
			var err error
			r := reRefVar.ReplaceAllStringFunc(line, func(s string) string {
				name := reRefVar.FindStringSubmatch(s)[1]
				switch {
				case name == "home":
					return ctx.Home
				case name == "user":
					return ctx.User
				case name == "machine.os":
					return ctx.Machine.OS
				case name == "machine.arch":
					return ctx.Machine.Arch
				case name == "machine.name":
					return ctx.Machine.Name
				case strings.HasPrefix(name, "machine.facts."):
					v, ok := ctx.Machine.Facts[strings.TrimPrefix(name, "machine.facts.")]
					if !ok {
						err = fmt.Errorf("line %d: missing fact %s", i+1, name)
					}
					return v
				}
				err = fmt.Errorf("line %d: unknown reference %s", i+1, name)
				return ""
			})
			if err != nil {
				return nil, err
			}
			out.WriteString(r)
		}
	}
	if len(st) != 0 {
		return nil, errors.New("unterminated if")
	}
	return []byte(out.String()), nil
}

// --- resolution ---

// refTarget is what one machine receives at one target.
type refTarget struct {
	Entry   manifest.Entry
	Content []byte
	Mode    fs.FileMode
	Skipped bool // sealed, and this machine is not a member
}

func (r refTarget) sum() string {
	h := sha256.Sum256(r.Content)
	return hex.EncodeToString(h[:])
}

// refResolve evaluates the converted tree for one machine.
func refResolve(conv *converted, sealer *fakeSealer, ctx model.Context, member func(model.EnclaveName) bool) (map[model.Target]refTarget, []string, error) {
	var mf manifest.Manifest
	if err := toml.Unmarshal(conv.Manifest, &mf); err != nil {
		return nil, nil, err
	}
	out := map[model.Target]refTarget{}
	var problems []string
	for _, e := range mf.Entries {
		ok, err := evalWhen(e.When, ctx.Machine)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", e.Target, err)
		}
		if !ok {
			continue
		}
		if prev, dup := out[e.Target]; dup {
			problems = append(problems, fmt.Sprintf("collision at %s: %s and %s", e.Target, prev.Entry.Source, e.Source))
			continue
		}
		src := e.Source
		if src == "" {
			src = defaultSource(e)
		}
		f, ok := conv.Files[src]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: source %s missing", e.Target, src))
			continue
		}
		t := refTarget{Entry: e}
		data := f.Data
		if e.Enclave != "" {
			if !member(e.Enclave) {
				t.Skipped = true
				out[e.Target] = t
				continue
			}
			data, err = sealer.open(e.Enclave, data)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: open: %v", e.Target, err)
			}
		}
		if e.Template {
			data, err = refRender(data, ctx)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: render: %v", e.Target, err))
				continue
			}
		}
		t.Content = data
		switch {
		case e.Mode != 0:
			t.Mode = e.Mode
		case e.Enclave != "":
			t.Mode = 0o600
		case f.Exec:
			t.Mode = 0o755
		default:
			t.Mode = 0o644
		}
		out[e.Target] = t
	}
	return out, problems, nil
}

// fleetMachine finds a machine by name in the converted fleet.
func fleetMachine(t testing.TB, conv *converted, name string) model.Machine {
	t.Helper()
	var f fleet.File
	if err := toml.Unmarshal(conv.Fleet, &f); err != nil {
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
