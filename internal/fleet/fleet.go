package fleet

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/model"
)

// FileName is the fleet file's path at the source root.
const FileName = "fleet.toml"

// Schema is the fleet file format version.
const Schema = 1

// File is the parsed fleet file.
type File struct {
	Schema     int                               `toml:"schema" json:"schema"`
	Types      map[model.TypeName]TypeDef        `toml:"types" json:"types"`
	Machines   map[model.MachineID]model.Machine `toml:"machines" json:"machines"`
	Collectors map[string]CollectorDef           `toml:"collectors" json:"collectors,omitempty"`
}

// TypeDef declares one user-defined machine type.
type TypeDef struct {
	Enclave   bool `toml:"enclave" json:"enclave"`       // files of this type are sealed for members only
	HidePaths bool `toml:"hide_paths" json:"hide_paths"` // reserved; off by default; see crypt.HiddenNames
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

// Parse parses and validates a fleet file: unique names and nicknames, known
// types on every machine, valid collector settings.
func Parse(b []byte) (*File, error) { return nil, model.ErrNotImplemented }

// Lookup finds a machine by id, name or nickname. An ambiguous match is an error.
func (f *File) Lookup(key string) (model.Machine, error) {
	return model.Machine{}, model.ErrNotImplemented
}

// Vocabulary returns the names conditions may mention.
func (f *File) Vocabulary() cond.Vocabulary {
	v := cond.Vocabulary{Types: map[string]bool{}, FactKeys: map[string]bool{}, Collectors: map[string]bool{}}
	for t := range f.Types {
		v.Types[string(t)] = true
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
	Remote  string          `toml:"remote"`
	Notify  []string        `toml:"notify"` // extexec argv for alerts; empty means log only
	Busy    []string        `toml:"busy"`   // extexec argv; exit 0 with items means "a session is busy with these paths"
}

// LoadIdentity reads the identity file.
func LoadIdentity(path string) (Identity, error) { return Identity{}, model.ErrNotImplemented }

// Collect runs every collector whose `when` matches this machine and whose
// definition allowed(name, hash) accepts (see tasks.AllowList). A failed
// collector yields an ObservedFact with Error set; it never fails the sync.
// A collector that is not allowed is skipped and reported by name.
func Collect(ctx context.Context, f *File, mctx model.Context, r extexec.Runner, allowed func(name string, def CollectorDef) bool) (map[string]model.ObservedFact, []string, error) {
	return nil, nil, model.ErrNotImplemented
}

// StatusRef returns the ref that holds a machine's status record.
// Each machine fast-forwards only its own status ref.
func StatusRef(id model.MachineID) string { return "refs/yadm/status/" + string(id) }

// StatusRefs reads and writes status records. Package store implements it.
type StatusRefs interface {
	ReadAll(ctx context.Context) (map[model.MachineID]model.Status, error)
	Publish(ctx context.Context, s model.Status) error
}

// ObservedDiff compares one collector's items across machines.
type ObservedDiff struct {
	Collector string                       `json:"collector"`
	Union     []string                     `json:"union"`
	Missing   map[model.MachineID][]string `json:"missing"` // items in the union this machine lacks
	Unknown   []model.MachineID            `json:"unknown"` // machines with no published value
}

// DiffObserved compares a published collector across machines.
func DiffObserved(statuses map[model.MachineID]model.Status, collector string) (ObservedDiff, error) {
	return ObservedDiff{}, model.ErrNotImplemented
}
