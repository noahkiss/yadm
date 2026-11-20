package sync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// MergePolicy says how a conflicted file resolves when a line merge fails or
// is not wanted. It is read per target through Policy.MergeFor.
type MergePolicy string

// Merge policies. The manifest is expected to set them per entry (contract
// request: manifest.Entry.Merge and Entry.Volatile); Policy.MergeFor and
// Policy.VolatileFor read them.
const (
	MergeText       MergePolicy = "text"       // default: key-level merge for json, jsonc and toml, else a line merge
	MergeStructural MergePolicy = "structural" // key-level merge in the target's format only; a failure holds
	MergeJSONKeys   MergePolicy = "json-keys"  // key-level merge as JSON (JSONC accepted); a failure holds
	MergeTOMLKeys   MergePolicy = "toml-keys"  // key-level merge as TOML; a failure holds
	MergeUnion      MergePolicy = "union"      // line-set files: keep lines either side added, drop lines either side removed, dedupe
	MergeAddOnly    MergePolicy = "add-only"   // lines are only ever added: union of additions; any modify or delete holds
	MergeTheirs     MergePolicy = "theirs"     // take the remote side (app-churn files)
	MergeOurs       MergePolicy = "ours"       // take this machine's side
	MergeGenerated  MergePolicy = "generated"  // a tool writes it: never auto-committed; conflicts take the remote side
	MergeRegenerate MergePolicy = "regenerate" // older name of MergeGenerated
)

// Rungs of the resolution ladder, recorded in the Yadm-Resolved trailer.
const (
	RungClean      = "clean"      // git merge-tree merged it
	RungStructural = "structural" // key-level merge of json, jsonc or toml
	RungText       = "text"       // in-process line merge
	RungUnion      = "union"
	RungAddOnly    = "add-only"
	RungTheirs     = "theirs"
	RungOurs       = "ours"
	RungGenerated  = "generated"
	RungHold       = "hold" // no rung resolved it; an agent or the user resolves the hold
)

// TrailerResolved records one resolution: "<rung> <source path>".
const TrailerResolved = "Yadm-Resolved"

// Structural merges a structured file key by key: edits to different keys
// never conflict. Volatile key paths are machine-local: the merge keeps this
// machine's (ours) value for them. ok is false when it cannot decide
// (unsupported format, a parse failure, or both sides changed one key
// differently).
type Structural interface {
	Merge3(format string, volatile []string, base, ours, theirs []byte) (merged []byte, ok bool, err error)
}

// noStructural is the default Structural: it decides nothing, so the ladder
// falls through to the per-file policy.
type noStructural struct{}

func (noStructural) Merge3(string, []string, []byte, []byte, []byte) ([]byte, bool, error) {
	return nil, false, nil
}

// Resolution is one file the ladder resolved, or held.
type Resolution struct {
	Path   model.SourcePath `json:"path"`
	Target model.Target     `json:"target"`
	Rung   string           `json:"rung"`
	Commit model.CommitID   `json:"commit,omitempty"` // the local commit being replayed
}

// conflict is one conflicted path from this machine's point of view.
type conflict struct {
	store.Conflict // Ours: this machine's side; Theirs: the remote side
	Mode           uint32
}

// resolver runs the ladder for one replay or commit.
type resolver struct {
	s    *Syncer
	snap *apply.Snapshot
	st   *apply.State
}

// target maps a source path to its target.
func (r *resolver) target(p model.SourcePath) model.Target {
	if r.snap != nil && r.snap.Plan != nil {
		for t, res := range r.snap.Plan.Targets {
			if res.Source == p {
				return t
			}
		}
	}
	if r.st != nil {
		for t, ts := range r.st.Targets {
			if ts.Source == p {
				return t
			}
		}
	}
	s := string(p)
	if rest, ok := strings.CutPrefix(s, "files/"); ok {
		return model.Target(rest)
	}
	if rest, ok := strings.CutPrefix(s, "sealed/"); ok {
		if i := strings.IndexByte(rest, '/'); i > 0 {
			return model.Target(rest[i+1:])
		}
	}
	return model.Target(s)
}

func (r *resolver) policy(t model.Target) MergePolicy {
	if r.s.Policy.MergeFor != nil {
		if p := r.s.Policy.MergeFor(t); p != "" {
			return p
		}
	}
	return MergeText
}

func (r *resolver) format(t model.Target) string {
	if r.snap != nil && r.snap.Plan != nil {
		if res, ok := r.snap.Plan.Targets[t]; ok && res.Entry.Format != "" {
			return string(res.Entry.Format)
		}
	}
	switch strings.ToLower(path.Ext(string(t))) {
	case ".json":
		return "json"
	case ".jsonc":
		return "jsonc"
	case ".toml":
		return "toml"
	}
	return ""
}

// sealedEnclave returns the enclave of a whole-file sealed source path.
func sealedEnclave(p model.SourcePath) (model.EnclaveName, bool) {
	rest, ok := strings.CutPrefix(string(p), "sealed/")
	if !ok {
		return "", false
	}
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return "", false
	}
	return model.EnclaveName(rest[:i]), true
}

func (r *resolver) canOpen(e model.EnclaveName) bool {
	return r.snap != nil && r.snap.Keys != nil && r.snap.Keys.CanOpen(e)
}

// resolve runs the ladder on one conflicted path: structural merge for
// structured formats, then the file's merge policy (text by default), then a
// hold. Sealed files are opened in memory, merged and resealed; with the
// default policy and no structural format they go through apply.MergeSealed.
// No plaintext reaches the returned change unless it is resealed.
func (r *resolver) resolve(ctx context.Context, c conflict) (*store.Change, *model.Hold, string, error) {
	t := r.target(c.Path)
	pol := r.policy(t)
	format := r.format(t)
	enc, sealed := sealedEnclave(c.Path)
	scope := model.ScopeShared
	if sealed {
		scope = model.Scope(enc)
	}
	hold := func(detail string) (*store.Change, *model.Hold, string, error) {
		h := conflictHold(r.st, r.s.now(), t, scope, c.Conflict, detail)
		return nil, &h, RungHold, nil
	}
	if sealed && !r.canOpen(enc) {
		return hold("sealed for " + string(enc) + "; this machine is not a member")
	}
	if sealed && pol == MergeText && format == "" && c.Ours != "" && c.Theirs != "" {
		ch, h, err := r.s.Apply.MergeSealed(ctx, r.snap, c.Conflict)
		if err != nil {
			return nil, nil, "", err
		}
		if h != nil {
			h.Ours, h.Theirs = c.Ours, c.Theirs
			x := conflictHold(r.st, r.s.now(), t, scope, c.Conflict, h.Detail)
			return nil, &x, RungHold, nil
		}
		return ch, nil, RungText, nil
	}

	read := func(id string) ([]byte, error) {
		if id == "" {
			return nil, nil
		}
		b, err := r.s.Store.ReadBlob(ctx, id)
		if err != nil || !sealed {
			return b, err
		}
		return r.snap.Crypto.OpenFile(enc, c.Path, b)
	}
	base, err := read(c.Base)
	if err != nil {
		return nil, nil, "", fmt.Errorf("resolve %s: base: %w", c.Path, err)
	}
	ours, err := read(c.Ours)
	if err != nil {
		return nil, nil, "", fmt.Errorf("resolve %s: ours: %w", c.Path, err)
	}
	theirs, err := read(c.Theirs)
	if err != nil {
		return nil, nil, "", fmt.Errorf("resolve %s: theirs: %w", c.Path, err)
	}
	out := func(b []byte, del bool, rung string) (*store.Change, *model.Hold, string, error) {
		if del {
			return &store.Change{Path: c.Path, Delete: true}, nil, rung, nil
		}
		if sealed {
			if b, err = r.snap.Crypto.SealFile(enc, c.Path, b); err != nil {
				return nil, nil, "", fmt.Errorf("resolve %s: seal: %w", c.Path, err)
			}
		}
		mode := c.Mode
		if mode == 0 || sealed {
			mode = 0o100644
		}
		return &store.Change{Path: c.Path, Blob: b, Mode: mode}, nil, rung, nil
	}

	switch pol {
	case MergeOurs:
		return out(ours, c.Ours == "", RungOurs)
	case MergeTheirs:
		return out(theirs, c.Theirs == "", RungTheirs)
	case MergeGenerated, MergeRegenerate:
		return out(theirs, c.Theirs == "", RungGenerated)
	}
	if c.Ours == "" || c.Theirs == "" {
		return hold("one side deleted the file and the other changed it")
	}
	if textmerge.IsBinary(base) || textmerge.IsBinary(ours) || textmerge.IsBinary(theirs) {
		return hold("binary file changed on both sides")
	}
	switch pol {
	case MergeJSONKeys:
		format = "json"
	case MergeTOMLKeys:
		format = "toml"
	}
	keyed := pol == MergeStructural || pol == MergeJSONKeys || pol == MergeTOMLKeys
	if format != "" && (pol == MergeText || keyed) {
		st := r.s.Structural
		if st == nil {
			st = noStructural{}
		}
		var volatile []string
		if r.s.Policy.VolatileFor != nil {
			volatile = r.s.Policy.VolatileFor(t)
		}
		merged, ok, err := st.Merge3(format, volatile, base, ours, theirs)
		if err == nil && ok {
			return out(merged, false, RungStructural)
		}
		if keyed {
			return hold("key-level " + format + " merge could not resolve the file")
		}
	} else if keyed {
		return hold("key-level merge needs a json, jsonc or toml file")
	}
	switch pol {
	case MergeUnion:
		return out(unionLines(base, ours, theirs), false, RungUnion)
	case MergeAddOnly:
		merged, ok := addOnly(base, ours, theirs)
		if !ok {
			return hold("add-only file: a line was changed or removed on one side")
		}
		return out(merged, false, RungAddOnly)
	case MergeText:
		merged, regions, err := textmerge.Merge3(base, ours, theirs)
		if errors.Is(err, textmerge.ErrBinary) {
			return hold("binary file changed on both sides")
		}
		if err != nil {
			return nil, nil, "", fmt.Errorf("resolve %s: %w", c.Path, err)
		}
		if len(regions) > 0 {
			return hold(fmt.Sprintf("%d conflicting region(s) after a line merge", len(regions)))
		}
		return out(merged, false, RungText)
	}
	return hold("unknown merge policy " + string(pol))
}

// conflictHold builds a conflict hold with the stage blobs. Ours is this
// machine's side, Theirs the remote side.
func conflictHold(st *apply.State, now time.Time, t model.Target, scope model.Scope, c store.Conflict, detail string) model.Hold {
	h := targetHold(st, now, t, scope, model.HoldConflict, now, detail,
		"yadm hold resolve <id> --take source", "yadm hold resolve <id> --take target")
	h.Base, h.Ours, h.Theirs = c.Base, c.Ours, c.Theirs
	for i, n := range h.Next {
		h.Next[i] = strings.ReplaceAll(n, "<id>", h.ID)
	}
	return h
}

// unionLines keeps every line either side has, minus lines either side
// removed from base. Order: ours, then lines only theirs added.
func unionLines(base, ours, theirs []byte) []byte {
	split := func(b []byte) []string {
		s := strings.TrimSuffix(string(b), "\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	set := func(ls []string) map[string]bool {
		m := map[string]bool{}
		for _, l := range ls {
			m[l] = true
		}
		return m
	}
	b, o, th := split(base), split(ours), split(theirs)
	inB, inO, inT := set(b), set(o), set(th)
	removed := func(l string) bool { return inB[l] && (!inO[l] || !inT[l]) }
	var out []string
	seen := map[string]bool{}
	for _, l := range append(o, th...) {
		if seen[l] || removed(l) {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	if len(out) == 0 {
		return []byte{}
	}
	var buf bytes.Buffer
	buf.WriteString(strings.Join(out, "\n"))
	buf.WriteByte('\n')
	return buf.Bytes()
}

// addOnly merges files whose lines are only ever added: both sides must keep
// every base line in order. The result is base, then lines ours added, then
// lines theirs added that ours lacks.
func addOnly(base, ours, theirs []byte) ([]byte, bool) {
	split := func(b []byte) []string {
		s := strings.TrimSuffix(string(b), "\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	b, o, th := split(base), split(ours), split(theirs)
	added := func(side []string) ([]string, bool) {
		i := 0
		var extra []string
		for _, l := range side {
			if i < len(b) && l == b[i] {
				i++
				continue
			}
			extra = append(extra, l)
		}
		return extra, i == len(b)
	}
	oa, ok1 := added(o)
	ta, ok2 := added(th)
	if !ok1 || !ok2 {
		return nil, false
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range append(append(append([]string(nil), b...), oa...), ta...) {
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	if len(out) == 0 {
		return []byte{}, true
	}
	return []byte(strings.Join(out, "\n") + "\n"), true
}
