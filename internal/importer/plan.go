package importer

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// variant is one way upstream could fill a target: a plain file, a file
// alternate, or a directory alternate with every file below it.
type variant struct {
	Key      string // legacy path of the plain file or the tagged component
	Base     string // target path (a directory for a directory alternate)
	Conds    conj
	Score    int
	Template bool
	Plain    bool
	Dir      bool
	Order    int // position of its first file in the legacy tree
	Files    []*legacyFile
	Alt      AltName
}

// group is every variant of one target.
type group struct {
	Base     string
	Variants []*variant
}

// pendingLink is a tracked symlink, resolved after every regular entry exists.
type pendingLink struct {
	From   string // legacy path
	Target string // target path of the link
	When   string
	Text   string
}

type planner struct {
	opts    Options
	repo    *legacyRepo
	filters map[string]bool

	files    map[model.SourcePath]outFile
	entries  []manifest.Entry
	mappings []Mapping
	problems []Problem

	links     []pendingLink
	types     map[string]bool // every type a condition names
	factKeys  map[string]bool // every fact a condition or template reads
	enclaves  map[model.EnclaveName]bool
	plainPart map[string]string // decoded plaintext cache by legacy path
}

func (p *planner) problem(path string, format string, args ...any) {
	p.problems = append(p.problems, Problem{Path: path, Reason: fmt.Sprintf(format, args...)})
}

func (p *planner) run() {
	p.types = map[string]bool{}
	p.factKeys = map[string]bool{}
	p.enclaves = map[model.EnclaveName]bool{}
	p.plainPart = map[string]string{}

	groups := p.collect()
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.emitGroup(groups[k])
	}
	p.resolveLinks()
	sort.SliceStable(p.entries, func(i, j int) bool { return p.entries[i].Target < p.entries[j].Target })
	sort.SliceStable(p.mappings, func(i, j int) bool { return p.mappings[i].From < p.mappings[j].From })
}

// collect sorts every legacy file into variants and variants into groups.
func (p *planner) collect() map[string]*group {
	groups := map[string]*group{}
	byKey := map[string]*variant{}
	fileBases := map[string]string{} // file target -> legacy path, for overlap checks
	dirBases := map[string]string{}
	for i := range p.repo.Files {
		f := &p.repo.Files[i]
		alt, isAlt, err := ParseAltName(f.Path)
		if err != nil {
			p.problem(f.Path, "%v", err)
			continue
		}
		key, base := f.Path, f.Path
		if isAlt {
			key = alt.Alt
			base = alt.Base
			if alt.Dir {
				base = alt.Alt[:strings.Index(alt.Alt, "##")]
			}
		}
		v := byKey[key]
		if v == nil {
			v = &variant{Key: key, Base: base, Order: i, Plain: !isAlt, Alt: alt}
			if isAlt {
				v.Dir = alt.Dir
				_, v.Template = alt.Template()
				v.Score = alt.Score()
				var as []atom
				for _, c := range alt.Conds {
					if a, ok := atomFor(c); ok {
						as = append(as, a)
						p.noteAtom(a)
					}
				}
				v.Conds = newConj(as...)
			} else {
				v.Score = -1
			}
			byKey[key] = v
			g := groups[base]
			if g == nil {
				g = &group{Base: base}
				groups[base] = g
			}
			g.Variants = append(g.Variants, v)
		}
		v.Files = append(v.Files, f)
		if v.Dir {
			dirBases[base] = f.Path
		} else {
			fileBases[base] = f.Path
		}
	}
	// A directory alternate replaces the whole directory; a plain file or a
	// file alternate inside or at the same path has no upstream meaning we can keep.
	for d, from := range dirBases {
		if other, ok := fileBases[d]; ok {
			p.problem(from, "directory alternate %s collides with the file %s", d, other)
		}
		for fb, other := range fileBases {
			if strings.HasPrefix(fb, d+"/") {
				p.problem(other, "file lies inside the directory alternate %s (from %s)", d, from)
			}
		}
		for d2, from2 := range dirBases {
			if strings.HasPrefix(d2, d+"/") {
				p.problem(from2, "directory alternate lies inside the directory alternate %s", d)
			}
		}
	}
	return groups
}

func (p *planner) noteAtom(a atom) {
	if a.Kind == "type" {
		p.types[a.Value] = true
	}
	if k, ok := strings.CutPrefix(a.Kind, "fact:"); ok {
		p.factKeys[k] = true
	}
}

// rank orders variants the way upstream picks among matching ones: any
// template beats any other file; then the higher score wins; on a tie the
// first file wins, but the last template wins.
func rank(vs []*variant) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if a.Template != b.Template {
			return a.Template
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Template {
			return a.Order > b.Order
		}
		return a.Order < b.Order
	})
}

// emitGroup gives each reachable variant a condition that holds exactly when
// upstream would pick it, and emits its entries.
func (p *planner) emitGroup(g *group) {
	rank(g.Variants)
	type picked struct {
		v    *variant
		when whenExpr
	}
	var reach []picked
	for i, v := range g.Variants {
		w := whenExpr{Pos: v.Conds}
		dead := false
		for _, h := range g.Variants[:i] {
			if h.Conds.excludes(v.Conds) {
				continue
			}
			d := h.Conds.minus(v.Conds)
			if len(d) == 0 {
				dead = true // h matches whenever v does and outranks it
				break
			}
			w.Nots = append(w.Nots, d)
		}
		if dead {
			continue
		}
		w.Nots = pruneNots(w.Nots)
		reach = append(reach, picked{v, w})
	}
	single := len(reach) == 1
	for _, r := range reach {
		when := r.when.String()
		for _, f := range r.v.Files {
			target := g.Base
			if r.v.Dir {
				target = g.Base + f.Path[len(r.v.Key):]
			}
			p.emitFile(f, r.v, target, when, single)
		}
	}
}

// pruneNots drops a negated conjunction that a shorter one already covers:
// !a implies !(a & b).
func pruneNots(ns []conj) []conj {
	sort.SliceStable(ns, func(i, j int) bool { return len(ns[i]) < len(ns[j]) })
	var out []conj
	for _, n := range ns {
		covered := false
		for _, o := range out {
			if len(o.minus(n)) == 0 {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, n)
		}
	}
	return out
}

// emitFile converts one legacy file into a source file and a manifest entry.
func (p *planner) emitFile(f *legacyFile, v *variant, target, when string, single bool) {
	if f.Symlink {
		if v.Template {
			p.problem(f.Path, "a symlink cannot be a template")
			return
		}
		p.links = append(p.links, pendingLink{From: f.Path, Target: target, When: when, Text: string(p.repo.blobs[f.Blob])})
		return
	}
	data, encrypted, ok := p.decode(f)
	if !ok {
		return
	}
	strip, ok := p.stripRule(f.Path, f.Filter, target)
	if !ok {
		return
	}
	e := manifest.Entry{Target: model.Target(target), When: when}
	applyStrip(&e, strip)
	stored := target
	if !single {
		stored = f.Path
	}
	if encrypted {
		enc, ok := p.enclaveFor(f, v)
		if !ok {
			return
		}
		e.Enclave = enc
	}
	if v.Template {
		proc, _ := v.Alt.Template()
		if proc != "" && proc != "default" {
			p.problem(f.Path, "template processor %q is not supported; only the built-in one converts", proc)
			return
		}
		res, probs := convertTemplate(f.Path, target, data, p.includeFor(e.Enclave))
		p.problems = append(p.problems, probs...)
		if len(probs) > 0 {
			return
		}
		for k := range res.Facts {
			p.factKeys[k] = true
		}
		for _, a := range res.Atoms {
			p.noteAtom(a)
		}
		data = res.Out
		e.Template = true
	}
	e.Mode = modeFor(target, f.Exec)
	if e.Enclave != "" {
		e.Source = model.SourcePath("sealed/" + string(e.Enclave) + "/" + stored)
		if p.opts.Sealer == nil {
			p.problem(f.Path, "encrypted file needs a sealer for enclave %s", e.Enclave)
			return
		}
		sealed, err := p.opts.Sealer.SealFile(e.Enclave, e.Source, data)
		if err != nil {
			p.problem(f.Path, "seal for enclave %s: %v", e.Enclave, err)
			return
		}
		data = sealed
		p.enclaves[e.Enclave] = true
	} else {
		e.Source = model.SourcePath("files/" + stored)
	}
	if _, dup := p.files[e.Source]; dup {
		p.problem(f.Path, "source %s is produced twice", e.Source)
		return
	}
	p.files[e.Source] = outFile{Data: data, Exec: f.Exec}
	p.entries = append(p.entries, e)
	p.mappings = append(p.mappings, Mapping{From: f.Path, Target: e.Target, Source: e.Source, When: e.When, Sealed: e.Enclave != ""})
}

// decode returns a regular file's plaintext. A transcrypt file is decrypted.
func (p *planner) decode(f *legacyFile) ([]byte, bool, bool) {
	blob := p.repo.blobs[f.Blob]
	marked := p.filters[f.Filter]
	cipher := isTranscrypt(blob)
	switch {
	case marked && !cipher:
		p.problem(f.Path, "marked for transcrypt but stored as plaintext in the legacy repository")
		return nil, false, false
	case !marked && cipher:
		p.problem(f.Path, "stored as transcrypt ciphertext but not marked with a transcrypt filter")
		return nil, false, false
	case !marked:
		return blob, false, true
	}
	pw := ""
	if p.opts.PasswordEnv != "" {
		pw = os.Getenv(p.opts.PasswordEnv)
	}
	if pw == "" {
		p.problem(f.Path, "encrypted file needs the transcrypt password (set --password-env)")
		return nil, false, false
	}
	pt, err := transcryptDecrypt(blob, pw)
	if err != nil {
		p.problem(f.Path, "%v", err)
		return nil, false, false
	}
	return pt, true, true
}

// includeFor returns the include lookup for a template that is stored
// sealed for enclave (empty for a plaintext template). An encrypted include
// is inlined only into a template sealed for the same enclave, so its
// plaintext never lands in files/.
func (p *planner) includeFor(enclave model.EnclaveName) includeFunc {
	return func(home string) ([]byte, bool, error) {
		f := p.repo.byPath[home]
		if f == nil || f.Symlink {
			return nil, false, nil
		}
		n := len(p.problems)
		data, encrypted, ok := p.decode(f)
		if !ok {
			p.problems = p.problems[:n]
			return nil, false, fmt.Errorf("cannot read the included file")
		}
		if encrypted {
			v := &variant{}
			if alt, isAlt, err := ParseAltName(f.Path); err == nil && isAlt {
				var as []atom
				for _, c := range alt.Conds {
					if a, ok := atomFor(c); ok {
						as = append(as, a)
					}
				}
				v.Conds = newConj(as...)
			}
			inc, ok := p.enclaveFor(f, v)
			p.problems = p.problems[:n]
			if !ok || inc != enclave {
				return nil, false, fmt.Errorf("the included file is encrypted and the template is not sealed for its enclave")
			}
		}
		return data, true, nil
	}
}

// enclaveFor picks the enclave of an encrypted file from its classes.
func (p *planner) enclaveFor(f *legacyFile, v *variant) (model.EnclaveName, bool) {
	found := map[model.EnclaveName]bool{}
	for _, a := range v.Conds {
		if a.Kind != "type" {
			continue
		}
		for class, enc := range p.opts.ClassEnclaves {
			if strings.EqualFold(class, a.Value) {
				found[enc] = true
			}
		}
	}
	switch len(found) {
	case 1:
		for e := range found {
			return e, true
		}
	case 0:
		if p.opts.DefaultEnclave != "" {
			return p.opts.DefaultEnclave, true
		}
		p.problem(f.Path, "encrypted file has no class mapped to an enclave and no default enclave is set")
		return "", false
	}
	p.problem(f.Path, "encrypted file maps to more than one enclave")
	return "", false
}

// modeFor returns an explicit mode where the manifest default (0644, or 0755
// for an executable source) would differ from what upstream writes. Only
// under .ssh and .gnupg does upstream's perms step remove group and other
// access. Encryption protects the repository, not the disk, so a sealed
// file keeps the mode of its source.
func modeFor(target string, exec bool) fs.FileMode {
	first, _, _ := strings.Cut(target, "/")
	if first != ".ssh" && first != ".gnupg" {
		return 0
	}
	if exec {
		return 0o700
	}
	return 0o600
}

// resolveLinks turns each tracked symlink into entries that reuse the source
// of whatever the link points at, under both conditions.
func (p *planner) resolveLinks() {
	pending := p.links
	for pass := 0; len(pending) > 0 && pass < 16; pass++ {
		waiting := map[string]bool{}
		for _, l := range pending {
			waiting[l.Target] = true
		}
		var next []pendingLink
		progress := false
		for _, l := range pending {
			dest, ok := linkDest(l.Target, l.Text)
			if !ok {
				p.problem(l.From, "symlink points outside $HOME (%s)", l.Text)
				progress = true
				continue
			}
			blocked := false
			for w := range waiting {
				if w != l.Target && (w == dest || strings.HasPrefix(w, dest+"/") || strings.HasPrefix(dest, w+"/")) {
					blocked = true
				}
			}
			if blocked {
				next = append(next, l)
				continue
			}
			progress = true
			var add []manifest.Entry
			for _, e := range p.entries {
				t := string(e.Target)
				var nt string
				switch {
				case t == dest:
					nt = l.Target
				case strings.HasPrefix(t, dest+"/"):
					nt = l.Target + t[len(dest):]
				default:
					continue
				}
				a := e
				a.Target = model.Target(nt)
				a.When = andWhen(l.When, e.When)
				add = append(add, a)
			}
			if len(add) == 0 {
				p.problem(l.From, "symlink target %s is not provided by any file", dest)
				continue
			}
			for _, a := range add {
				p.entries = append(p.entries, a)
				p.mappings = append(p.mappings, Mapping{From: l.From, Target: a.Target, Source: a.Source, When: a.When, Sealed: a.Enclave != ""})
			}
		}
		pending = next
		if !progress {
			break
		}
	}
	for _, l := range pending {
		p.problem(l.From, "symlink chain through %s does not resolve", l.Text)
	}
}

// linkDest resolves a link's text against the link's own directory below $HOME.
func linkDest(target, text string) (string, bool) {
	if strings.HasPrefix(text, "/") {
		return "", false
	}
	d := path.Clean(path.Join(path.Dir(target), text))
	if d == "." || d == ".." || strings.HasPrefix(d, "../") {
		return "", false
	}
	return d, true
}
