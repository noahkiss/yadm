package fleet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/model"
)

// FileName is the fleet file's path at the source root.
const FileName = "fleet.toml"

// Schema is the fleet file format version.
const Schema = 1

// DefaultCollectorTimeout applies when a collector sets no timeout.
const DefaultCollectorTimeout = 30 * time.Second

// File is the parsed fleet file.
type File struct {
	Schema     int                               `toml:"schema" json:"schema"`
	Types      map[model.TypeName]TypeDef        `toml:"types" json:"types"`
	Machines   map[model.MachineID]model.Machine `toml:"machines" json:"machines"`
	Collectors map[string]CollectorDef           `toml:"collectors" json:"collectors,omitempty"`
	// PauseRequires is what a fleet pause record needs to count: "" (any
	// well-formed record from a machine in this file) or PauseMember (a
	// signature by a member of a key log the receiver pinned).
	PauseRequires string `toml:"pause_requires,omitempty" json:"pause_requires,omitempty"`
}

// PauseMember is the PauseRequires value that requires a pinned member's
// signature on a fleet pause.
const PauseMember = "member"

// TypeDef declares one user-defined machine type.
type TypeDef struct {
	Enclave   bool `toml:"enclave" json:"enclave"`       // files of this type are sealed for members only
	HidePaths bool `toml:"hide_paths" json:"hide_paths"` // reserved; off by default; see crypt.HiddenNames
	// RerootKeep is how many backups of the old history a machine of this
	// type keeps when it accepts a re-root (`yadm reroot`). 0 or absent
	// takes none.
	RerootKeep int `toml:"reroot_keep,omitempty" json:"reroot_keep,omitempty"`
}

// MaxRerootKeep bounds reroot_keep.
const MaxRerootKeep = 100

// RerootKeep is how many re-root backups machine m keeps: the largest
// reroot_keep of its types, 0 when none sets one or m is not in the file.
func (f *File) RerootKeep(m model.MachineID) int {
	if f == nil {
		return 0
	}
	n := 0
	for _, t := range f.Machines[m].Types {
		if k := f.Types[t].RerootKeep; k > n {
			n = k
		}
	}
	return n
}

// PublishMode says where a collector's output goes.
type PublishMode string

// Publish modes.
const (
	PublishLocal  PublishMode = "local"  // kept in local state only; templates may read it
	PublishPlain  PublishMode = "plain"  // also in the status ref, readable by every machine
	PublishSealed PublishMode = "sealed" // also in the status ref, sealed for one enclave
)

// Publish is a collector's publish setting. In TOML it is a string:
// "local", "plain" or "sealed:<enclave>". The default is "local".
type Publish struct {
	Mode    PublishMode
	Enclave model.EnclaveName
}

// UnmarshalText parses "local", "plain" or "sealed:<enclave>".
func (p *Publish) UnmarshalText(b []byte) error {
	s := string(b)
	switch {
	case s == "" || s == string(PublishLocal):
		*p = Publish{Mode: PublishLocal}
	case s == string(PublishPlain):
		*p = Publish{Mode: PublishPlain}
	case strings.HasPrefix(s, "sealed:") && len(s) > len("sealed:"):
		*p = Publish{Mode: PublishSealed, Enclave: model.EnclaveName(strings.TrimPrefix(s, "sealed:"))}
	default:
		return fmt.Errorf("publish %q: want local, plain or sealed:<enclave>", s)
	}
	return nil
}

// MarshalText writes the string form.
func (p Publish) MarshalText() ([]byte, error) {
	switch p.Mode {
	case PublishSealed:
		return []byte("sealed:" + string(p.Enclave)), nil
	case "":
		return []byte(PublishLocal), nil
	}
	return []byte(p.Mode), nil
}

// CollectorDef declares one observed-fact collector.
type CollectorDef struct {
	Command []string       `toml:"command" json:"command"`
	Timeout model.Duration `toml:"timeout" json:"timeout"` // default 30s
	When    string         `toml:"when" json:"when,omitempty"`
	Publish Publish        `toml:"publish" json:"publish"`
}

// namePattern bounds every identifier the fleet file declares: type and
// collector names, machine ids, names and nicknames. Type names also become
// path segments (sealed/<enclave>/), so no separators or dots-only names.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Parse parses and validates a fleet file: unique names and nicknames, known
// types on every machine, valid collector settings. Unknown keys are errors.
func Parse(b []byte) (*File, error) {
	var f File
	dec := toml.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	if f.Schema != Schema {
		return nil, fmt.Errorf("%s: schema %d: want %d", FileName, f.Schema, Schema)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	return &f, nil
}

func (f *File) validate() error {
	if f.Types == nil {
		f.Types = map[model.TypeName]TypeDef{}
	}
	if f.Machines == nil {
		f.Machines = map[model.MachineID]model.Machine{}
	}
	if f.Collectors == nil {
		f.Collectors = map[string]CollectorDef{}
	}
	var errs []error
	if f.PauseRequires != "" && f.PauseRequires != PauseMember {
		errs = append(errs, fmt.Errorf("pause_requires %q: want %q or nothing", f.PauseRequires, PauseMember))
	}
	for t, def := range f.Types {
		if !namePattern.MatchString(string(t)) {
			errs = append(errs, fmt.Errorf("type %q: invalid name", t))
		}
		if def.RerootKeep < 0 || def.RerootKeep > MaxRerootKeep {
			errs = append(errs, fmt.Errorf("type %q: reroot_keep %d: want 0 to %d", t, def.RerootKeep, MaxRerootKeep))
		}
	}
	// Ids, names and nicknames share one namespace, so Lookup is never ambiguous.
	owner := map[string]model.MachineID{}
	claim := func(id model.MachineID, what, key string) {
		if !namePattern.MatchString(key) {
			errs = append(errs, fmt.Errorf("machine %s: %s %q: invalid", id, what, key))
			return
		}
		if prev, ok := owner[key]; ok && prev != id {
			errs = append(errs, fmt.Errorf("machine %s: %s %q already names machine %s", id, what, key, prev))
			return
		} else if ok {
			errs = append(errs, fmt.Errorf("machine %s: %s %q repeats", id, what, key))
			return
		}
		owner[key] = id
	}
	ids := make([]model.MachineID, 0, len(f.Machines))
	for id := range f.Machines {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		claim(id, "id", string(id))
	}
	for _, id := range ids {
		m := f.Machines[id]
		m.ID = id
		f.Machines[id] = m
		if m.Name == "" {
			errs = append(errs, fmt.Errorf("machine %s: name is required", id))
		} else {
			claim(id, "name", m.Name)
		}
		for _, n := range m.Nicknames {
			claim(id, "nickname", n)
		}
		if len(m.Types) == 0 {
			errs = append(errs, fmt.Errorf("machine %s: at least one type is required", id))
		}
		seen := map[model.TypeName]bool{}
		for _, t := range m.Types {
			if _, ok := f.Types[t]; !ok {
				errs = append(errs, fmt.Errorf("machine %s: unknown type %q", id, t))
			}
			if seen[t] {
				errs = append(errs, fmt.Errorf("machine %s: type %q repeats", id, t))
			}
			seen[t] = true
		}
		for k := range m.Facts {
			if k == "" || strings.ContainsAny(k, "= \t\n") {
				errs = append(errs, fmt.Errorf("machine %s: fact key %q: invalid", id, k))
			}
		}
	}
	voc := f.Vocabulary()
	names := make([]string, 0, len(f.Collectors))
	for n := range f.Collectors {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := f.Collectors[n]
		if !namePattern.MatchString(n) {
			errs = append(errs, fmt.Errorf("collector %q: invalid name", n))
		}
		if len(c.Command) == 0 || c.Command[0] == "" {
			errs = append(errs, fmt.Errorf("collector %s: command is required", n))
		}
		if c.Timeout < 0 {
			errs = append(errs, fmt.Errorf("collector %s: negative timeout", n))
		}
		if c.Publish.Mode == "" {
			c.Publish.Mode = PublishLocal
			f.Collectors[n] = c
		}
		if c.Publish.Mode == PublishSealed {
			if td, ok := f.Types[model.TypeName(c.Publish.Enclave)]; !ok || !td.Enclave {
				errs = append(errs, fmt.Errorf("collector %s: publish sealed:%s names no enclave type", n, c.Publish.Enclave))
			}
		}
		if err := checkWhen(c.When, voc); err != nil {
			errs = append(errs, fmt.Errorf("collector %s: %w", n, err))
		}
	}
	return errors.Join(errs...)
}

// checkWhen validates a condition. While package cond is not implemented it
// accepts any condition, so a valid fleet file never fails on a stub.
func checkWhen(when string, v cond.Vocabulary) error {
	_, err := cond.Parse(when, v)
	if errors.Is(err, model.ErrNotImplemented) {
		return nil
	}
	return err
}

// ErrUnknownMachine is returned by Lookup when nothing matches.
var ErrUnknownMachine = errors.New("unknown machine")

// Lookup finds a machine by id, name or nickname. An ambiguous match is an error.
func (f *File) Lookup(key string) (model.Machine, error) {
	var found []model.Machine
	for id, m := range f.Machines {
		m.ID = id
		hit := string(id) == key || m.Name == key
		for _, n := range m.Nicknames {
			hit = hit || n == key
		}
		if hit {
			found = append(found, m)
		}
	}
	switch len(found) {
	case 0:
		return model.Machine{}, fmt.Errorf("%w: %q", ErrUnknownMachine, key)
	case 1:
		return found[0], nil
	}
	ids := make([]string, len(found))
	for i, m := range found {
		ids[i] = string(m.ID)
	}
	sort.Strings(ids)
	return model.Machine{}, fmt.Errorf("machine %q is ambiguous: %s", key, strings.Join(ids, ", "))
}

// Vocabulary returns the names conditions may mention, plus the enclave
// types, which manifest checks `enclave` and `seal` names against.
func (f *File) Vocabulary() cond.Vocabulary {
	v := cond.Vocabulary{Types: map[string]bool{}, FactKeys: map[string]bool{}, Collectors: map[string]bool{}, Enclaves: map[string]bool{}}
	for t, d := range f.Types {
		v.Types[string(t)] = true
		if d.Enclave {
			v.Enclaves[string(t)] = true
		}
	}
	for _, m := range f.Machines {
		for k := range m.Facts {
			v.FactKeys[k] = true
		}
	}
	for c := range f.Collectors {
		v.Collectors[c] = true
	}
	return v
}

// Enclaves lists the types declared as enclaves, sorted.
func (f *File) Enclaves() []model.EnclaveName {
	var out []model.EnclaveName
	for t, d := range f.Types {
		if d.Enclave {
			out = append(out, model.EnclaveName(t))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IdentityFile is the local, untracked identity file, relative to $XDG_CONFIG_HOME/yadm.
const IdentityFile = "machine.toml"

// Identity is this machine's local configuration. It names the machine; the
// private keys that prove it live in the state directory (see crypt).
type Identity struct {
	Machine model.MachineID `toml:"machine"`
	Remote  string          `toml:"remote,omitempty"`
	Notify  []string        `toml:"notify,omitempty"` // extexec argv for alerts; empty means log only
	Busy    []string        `toml:"busy,omitempty"`   // extexec argv; exit 0 with items means "a session is busy with these paths"
	// OnDemand names enclaves this machine reads on demand only: it never
	// applies, captures or backs up their plaintext, and opens them only to
	// print to stdout (docs/design.md 7.6).
	OnDemand []model.EnclaveName `toml:"on_demand,omitempty"`
}

// IsOnDemand reports whether this machine reads enclave e on demand only.
func (id Identity) IsOnDemand(e model.EnclaveName) bool {
	for _, x := range id.OnDemand {
		if x == e {
			return true
		}
	}
	return false
}

// LoadIdentity reads the identity file. Unknown keys are errors, and the
// machine id is required.
func LoadIdentity(path string) (Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	dec := toml.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&id); err != nil {
		return Identity{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := id.validate(); err != nil {
		return Identity{}, fmt.Errorf("%s: %w", path, err)
	}
	return id, nil
}

func (id Identity) validate() error {
	if !namePattern.MatchString(string(id.Machine)) {
		return fmt.Errorf("machine %q: invalid or missing id", id.Machine)
	}
	for _, e := range id.OnDemand {
		if !namePattern.MatchString(string(e)) {
			return fmt.Errorf("on_demand: invalid enclave name %q", e)
		}
	}
	for _, argv := range [][]string{id.Notify, id.Busy} {
		if len(argv) > 0 && argv[0] == "" {
			return errors.New("notify and busy need a command as their first element")
		}
	}
	return nil
}

// SaveIdentity writes the identity file with mode 0600, atomically.
func SaveIdentity(path string, id Identity) error {
	if err := id.validate(); err != nil {
		return err
	}
	b, err := toml.Marshal(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".machine-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// NewMachineID returns a fresh random machine id, "m-" and 12 hex digits.
func NewMachineID() (model.MachineID, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return model.MachineID("m-" + hex.EncodeToString(b)), nil
}

// matchWhen evaluates a collector's condition for this machine with package
// cond. An empty condition matches every machine.
func matchWhen(when string, v cond.Vocabulary, mctx model.Context) (bool, error) {
	e, err := cond.Parse(when, v)
	if err != nil {
		return false, err
	}
	return e.Eval(mctx), nil
}

// now is the clock Collect stamps facts with.
var now = time.Now

// Collect runs every collector whose `when` matches this machine and whose
// definition allowed(name, hash) accepts (see tasks.AllowList). A failed
// collector yields an ObservedFact with Error set; it never fails the sync.
// A collector that is not allowed is skipped and reported by name.
func Collect(ctx context.Context, f *File, mctx model.Context, r extexec.Runner, allowed func(name string, def CollectorDef) bool) (map[string]model.ObservedFact, []string, error) {
	return CollectWith(ctx, f, mctx, r, allowed, extexec.Request{Home: mctx.Home})
}

// CollectWith is Collect with a base request, so the caller can pass the
// source directory and commit the exec contract carries. Kind, Name, Machine
// and Home are always set from the collector and mctx.
//
// A nil allowed function allows nothing. A `when` that cannot be evaluated
// yields a fact with Error set and runs nothing. The error result is non-nil
// only when ctx ends; facts collected so far are returned with it.
// CollectorApplies reports whether the named collector's `when` matches the
// machine in mctx. An unknown name, or a `when` that cannot be evaluated, does
// not apply.
func (f *File) CollectorApplies(name string, mctx model.Context) bool {
	if f == nil {
		return false
	}
	def, ok := f.Collectors[name]
	if !ok {
		return false
	}
	ok, err := matchWhen(def.When, f.Vocabulary(), mctx)
	return err == nil && ok
}

func CollectWith(ctx context.Context, f *File, mctx model.Context, r extexec.Runner, allowed func(name string, def CollectorDef) bool, base extexec.Request) (map[string]model.ObservedFact, []string, error) {
	facts := map[string]model.ObservedFact{}
	var skipped []string
	if f == nil {
		return facts, nil, nil
	}
	voc := f.Vocabulary()
	names := make([]string, 0, len(f.Collectors))
	for n := range f.Collectors {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return facts, skipped, err
		}
		def := f.Collectors[name]
		ok, err := matchWhen(def.When, voc, mctx)
		if err != nil {
			facts[name] = model.ObservedFact{Collector: name, CollectedAt: now().UTC(), Error: "when: " + err.Error()}
			continue
		}
		if !ok {
			continue
		}
		if allowed == nil || !allowed(name, def) {
			skipped = append(skipped, name)
			continue
		}
		req := base
		req.Kind = extexec.KindCollector
		req.Name = name
		req.Machine = mctx.Machine
		req.Home = mctx.Home
		timeout := def.Timeout.D()
		if timeout <= 0 {
			timeout = DefaultCollectorTimeout
		}
		res, err := r.Run(ctx, extexec.Spec{Argv: def.Command, Timeout: timeout}, req)
		fact := model.ObservedFact{Collector: name, CollectedAt: now().UTC()}
		if err != nil {
			if ctx.Err() != nil {
				return facts, skipped, ctx.Err()
			}
			// Keep only the error: partial output of a failed run is not a fact.
			fact.Error = err.Error()
		} else {
			fact.Items = res.Items
			if res.Response != nil && len(res.Response.Data) > 0 && string(res.Response.Data) != "null" {
				fact.Data = append(json.RawMessage(nil), res.Response.Data...)
			}
		}
		facts[name] = fact
	}
	return facts, skipped, nil
}

// FactSealer seals observed facts for one enclave. crypt.Set implements it.
type FactSealer interface {
	CanOpen(e model.EnclaveName) bool
	SealValue(e model.EnclaveName, keyPath string, plaintext []byte) (string, error)
}

// FactOpener opens sealed observed facts. crypt.Set implements it.
type FactOpener interface {
	CanOpen(e model.EnclaveName) bool
	OpenValue(e model.EnclaveName, keyPath, token string) ([]byte, error)
}

// sealedFactsKey is the key path sealed observed facts are bound to.
const sealedFactsKey = "status.observed"

// Published splits this machine's facts by their collector's publish mode,
// for model.Status.Observed and model.Status.Sealed.
//
//   - local, and any fact whose collector the fleet file no longer declares,
//     goes nowhere.
//   - plain goes into plain.
//   - sealed:<enclave> goes into sealed[enclave], one sealed JSON object per
//     enclave. When s is nil, cannot open the enclave or fails to seal, the
//     fact is dropped and a problem is reported. It never falls back to plain.
func Published(f *File, facts map[string]model.ObservedFact, s FactSealer) (plain map[string]model.ObservedFact, sealed map[model.EnclaveName][]byte, problems []error) {
	byEnclave := map[model.EnclaveName]map[string]model.ObservedFact{}
	for name, fact := range facts {
		def, ok := f.Collectors[name]
		if !ok {
			continue
		}
		switch def.Publish.Mode {
		case PublishPlain:
			if plain == nil {
				plain = map[string]model.ObservedFact{}
			}
			plain[name] = fact
		case PublishSealed:
			e := def.Publish.Enclave
			if byEnclave[e] == nil {
				byEnclave[e] = map[string]model.ObservedFact{}
			}
			byEnclave[e][name] = fact
		}
	}
	enclaves := make([]model.EnclaveName, 0, len(byEnclave))
	for e := range byEnclave {
		enclaves = append(enclaves, e)
	}
	sort.Slice(enclaves, func(i, j int) bool { return enclaves[i] < enclaves[j] })
	for _, e := range enclaves {
		if s == nil || !s.CanOpen(e) {
			problems = append(problems, fmt.Errorf("observed facts for %s dropped: not a member", e))
			continue
		}
		b, err := json.Marshal(byEnclave[e])
		if err != nil {
			problems = append(problems, fmt.Errorf("observed facts for %s dropped: %w", e, err))
			continue
		}
		tok, err := s.SealValue(e, sealedFactsKey, b)
		if err != nil {
			problems = append(problems, fmt.Errorf("observed facts for %s dropped: seal failed", e))
			continue
		}
		if sealed == nil {
			sealed = map[model.EnclaveName][]byte{}
		}
		sealed[e] = []byte(tok)
	}
	return plain, sealed, problems
}

// OpenSealed opens one enclave's sealed observed facts from a status record.
// It returns nil and no error when the record holds none for e.
func OpenSealed(st model.Status, e model.EnclaveName, o FactOpener) (map[string]model.ObservedFact, error) {
	tok, ok := st.Sealed[e]
	if !ok {
		return nil, nil
	}
	if o == nil || !o.CanOpen(e) {
		return nil, fmt.Errorf("observed facts for %s: not a member", e)
	}
	b, err := o.OpenValue(e, sealedFactsKey, string(tok))
	if err != nil {
		return nil, fmt.Errorf("observed facts for %s: %w", e, err)
	}
	var out map[string]model.ObservedFact
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("observed facts for %s: %w", e, err)
	}
	return out, nil
}

// OpenAll opens the sealed observed facts of st that o can open, keyed by
// enclave. It skips every enclave o cannot open without an error, so a
// non-member gets nil. It keeps only facts whose collector f declares
// `sealed:<that enclave>`. A record whose facts fail to open yields a problem
// and no facts for that enclave.
//
// The fact token is bound to its enclave and epoch, not to the machine whose
// status ref carries it, so a writer can copy one machine's token into
// another machine's ref.
func OpenAll(f *File, st model.Status, o FactOpener) (map[model.EnclaveName]map[string]model.ObservedFact, []error) {
	if f == nil || o == nil || len(st.Sealed) == 0 {
		return nil, nil
	}
	enclaves := make([]model.EnclaveName, 0, len(st.Sealed))
	for e := range st.Sealed {
		if o.CanOpen(e) {
			enclaves = append(enclaves, e)
		}
	}
	sort.Slice(enclaves, func(i, j int) bool { return enclaves[i] < enclaves[j] })
	var out map[model.EnclaveName]map[string]model.ObservedFact
	var problems []error
	for _, e := range enclaves {
		facts, err := OpenSealed(st, e, o)
		if err != nil {
			problems = append(problems, fmt.Errorf("machine %s: %w", st.Machine, err))
			continue
		}
		kept := map[string]model.ObservedFact{}
		for name, fact := range facts {
			def, ok := f.Collectors[name]
			if !ok || def.Publish.Mode != PublishSealed || def.Publish.Enclave != e {
				continue
			}
			fact.Collector = name
			kept[name] = fact
		}
		if len(kept) == 0 {
			continue
		}
		if out == nil {
			out = map[model.EnclaveName]map[string]model.ObservedFact{}
		}
		out[e] = kept
	}
	return out, problems
}

// Visible returns the observed facts of st a reader sees: the plain facts,
// with every collector declared `sealed:<e>` for an enclave the reader can
// open taken only from opened (the result of OpenAll). A plain value for
// such a collector is dropped, because any writer can put one in a status
// ref. For a reader that can open no enclave, the result equals st.Observed.
func Visible(f *File, st model.Status, o FactOpener, opened map[model.EnclaveName]map[string]model.ObservedFact) map[string]model.ObservedFact {
	var out map[string]model.ObservedFact
	put := func(name string, fact model.ObservedFact) {
		if out == nil {
			out = map[string]model.ObservedFact{}
		}
		out[name] = fact
	}
	for name, fact := range st.Observed {
		if f != nil && o != nil {
			if def, ok := f.Collectors[name]; ok && def.Publish.Mode == PublishSealed && o.CanOpen(def.Publish.Enclave) {
				continue
			}
		}
		put(name, fact)
	}
	for _, facts := range opened {
		for name, fact := range facts {
			put(name, fact)
		}
	}
	return out
}

// WithVisible returns copies of statuses whose Observed holds what a reader
// with o sees (Visible), for queries that evaluate or compare observed facts.
// The copies are for reading only: never publish them.
func WithVisible(f *File, statuses map[model.MachineID]model.Status, o FactOpener) (map[model.MachineID]model.Status, []error) {
	if statuses == nil {
		return nil, nil
	}
	out := make(map[model.MachineID]model.Status, len(statuses))
	var problems []error
	ids := make([]model.MachineID, 0, len(statuses))
	for id := range statuses {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		st := statuses[id]
		opened, errs := OpenAll(f, st, o)
		problems = append(problems, errs...)
		st.Observed = Visible(f, st, o, opened)
		out[id] = st
	}
	return out, problems
}

// StatusRef returns the ref that holds a machine's status record.
// Each machine fast-forwards only its own status ref.
func StatusRef(id model.MachineID) string { return "refs/yadm/status/" + string(id) }

// StatusRefs reads and writes status records. Package store implements it.
type StatusRefs interface {
	ReadAll(ctx context.Context) (map[model.MachineID]model.Status, error)
	Publish(ctx context.Context, s model.Status) error
}

// StaleAfter is how old a machine's last sync may be before `fleet list`
// flags it.
const StaleAfter = 24 * time.Hour

// PublishEvery is the longest a machine goes without publishing its status.
const PublishEvery = time.Hour

// PublishDue reports whether a sync should publish a new status record:
// after a sync that changed something, when nothing was published yet, or
// when the last record is PublishEvery old.
func PublishDue(last *model.Status, changed bool, at time.Time) bool {
	return changed || last == nil || !at.Before(last.LastSync.Add(PublishEvery))
}

// Summary is one machine's row in `yadm fleet list`.
type Summary struct {
	Machine model.Machine `json:"machine"`
	Status  *model.Status `json:"status,omitempty"`
	Stale   bool          `json:"stale"` // no status, or last sync older than StaleAfter
	// SealedObserved holds the sealed observed facts this machine opened from
	// Status, per enclave (OpenAll). It is empty on a non-member.
	SealedObserved map[model.EnclaveName]map[string]model.ObservedFact `json:"sealed_observed,omitempty"`
	// SealedErrors lists the enclaves of this machine's membership whose
	// sealed facts in Status failed to open. It never holds plaintext.
	SealedErrors []string `json:"sealed_errors,omitempty"`
}

// List joins the fleet file with the status records, sorted by machine id.
// A status ref for a machine the fleet file does not declare still appears,
// with only its id, so a removed or forged machine stays visible.
func List(f *File, statuses map[model.MachineID]model.Status, at time.Time) []Summary {
	ids := map[model.MachineID]bool{}
	if f != nil {
		for id := range f.Machines {
			ids[id] = true
		}
	}
	for id := range statuses {
		ids[id] = true
	}
	out := make([]Summary, 0, len(ids))
	for id := range ids {
		s := Summary{Machine: model.Machine{ID: id}}
		if f != nil {
			if m, ok := f.Machines[id]; ok {
				m.ID = id
				s.Machine = m
			}
		}
		if st, ok := statuses[id]; ok {
			st := st
			s.Status = &st
			s.Stale = at.Sub(st.LastSync) > StaleAfter
		} else {
			s.Stale = true
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Machine.ID < out[j].Machine.ID })
	return out
}

// ObservedDiff compares one collector's items across machines.
type ObservedDiff struct {
	Collector string                       `json:"collector"`
	Union     []string                     `json:"union"`
	Missing   map[model.MachineID][]string `json:"missing"` // items in the union this machine lacks
	Unknown   []model.MachineID            `json:"unknown"` // machines with no published value
}

// DiffObserved compares a published collector across machines. It reads only
// Status.Observed; pass WithVisible's copies to include the sealed facts a
// member opens. A machine whose value is absent or carries an
// error is Unknown. Every machine with a value has a Missing entry, empty when
// it lacks nothing.
func DiffObserved(statuses map[model.MachineID]model.Status, collector string) (ObservedDiff, error) {
	if collector == "" {
		return ObservedDiff{}, errors.New("collector name is required")
	}
	d := ObservedDiff{Collector: collector, Union: []string{}, Missing: map[model.MachineID][]string{}, Unknown: []model.MachineID{}}
	have := map[model.MachineID]map[string]bool{}
	union := map[string]bool{}
	for id, st := range statuses {
		fact, ok := st.Observed[collector]
		if !ok || fact.Error != "" {
			d.Unknown = append(d.Unknown, id)
			continue
		}
		set := map[string]bool{}
		for _, it := range fact.Items {
			set[it] = true
			union[it] = true
		}
		have[id] = set
	}
	for it := range union {
		d.Union = append(d.Union, it)
	}
	sort.Strings(d.Union)
	for id, set := range have {
		miss := []string{}
		for _, it := range d.Union {
			if !set[it] {
				miss = append(miss, it)
			}
		}
		d.Missing[id] = miss
	}
	sort.Slice(d.Unknown, func(i, j int) bool { return d.Unknown[i] < d.Unknown[j] })
	return d, nil
}
