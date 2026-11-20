package rules

import (
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Spec is the intra-file part of a manifest entry.
type Spec struct {
	Format  manifest.Format
	Keep    []string
	Drop    []string
	Seal    map[string]model.EnclaveName
	Regions bool
}

// SpecOf extracts the intra-file rules from a manifest entry.
func SpecOf(e manifest.Entry) Spec {
	return Spec{Format: e.Format, Keep: e.Keep, Drop: e.Drop, Seal: e.Seal, Regions: e.Regions}
}

// Empty reports whether the spec has no intra-file rules.
func (s Spec) Empty() bool {
	return len(s.Keep) == 0 && len(s.Drop) == 0 && len(s.Seal) == 0 && !s.Regions
}

// Sealer seals and opens parts of files. crypt.Set implements it.
type Sealer interface {
	CanOpen(e model.EnclaveName) bool
	SealValue(e model.EnclaveName, keyPath string, plaintext []byte) (string, error)
	OpenValue(e model.EnclaveName, keyPath, token string) ([]byte, error)
	SealRegion(e model.EnclaveName, label string, body []byte) (string, error)
	OpenRegion(e model.EnclaveName, label, token string) ([]byte, error)
}

// ViolationKind classifies a seal-guard refusal.
type ViolationKind string

// Violation kinds. Each one makes apply hold the file with model.HoldSealGuard.
const (
	SealedKeyRemoved  ViolationKind = "sealed_key_removed"  // target lost a sealed key or its parent
	SealedValueLeaked ViolationKind = "sealed_value_leaked" // a sealed plaintext appears outside its seal path
	RegionMarkerLost  ViolationKind = "region_marker_lost"  // a region's markers are gone or unbalanced
	ParseFailed       ViolationKind = "parse_failed"        // the target no longer parses in its format
)

// Violation is one reason capture refused.
type Violation struct {
	Path   string        `json:"path"` // key path or region label
	Kind   ViolationKind `json:"kind"`
	Detail string        `json:"detail,omitempty"`
}

// ToTarget produces the bytes to write to the target. live is the current
// target content, or nil when the target does not exist.
func ToTarget(source, live []byte, spec Spec, s Sealer) ([]byte, error) {
	return nil, model.ErrNotImplemented
}

// ToSource produces the bytes to store in the source from a live target.
// prevSource is the current source content; it supplies tokens this machine
// cannot open. A non-empty Violation list means "hold, do not commit".
func ToSource(target, prevSource []byte, spec Spec, s Sealer) ([]byte, []Violation, error) {
	return nil, nil, model.ErrNotImplemented
}
