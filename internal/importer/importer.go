package importer

import (
	"context"

	"github.com/noahkiss/yadm/internal/model"
)

// Options configures one import.
type Options struct {
	Legacy         string                       // path to a clone of the legacy repository
	Machines       string                       // path to the machines TSV; empty means one machine per class
	Branch         string                       // new branch name; default "main" in a fresh output
	Output         string                       // directory for the converted repository
	PasswordEnv    string                       // env var holding the transcrypt password
	ClassEnclaves  map[string]model.EnclaveName // legacy class -> enclave for its encrypted files
	DefaultEnclave model.EnclaveName            // enclave for encrypted files with no class
	DryRun         bool
}

// Mapping records one converted path.
type Mapping struct {
	From   string           `json:"from"`
	Target model.Target     `json:"target"`
	Source model.SourcePath `json:"source"`
	When   string           `json:"when,omitempty"`
	Sealed bool             `json:"sealed"`
}

// Problem is one path the importer could not convert.
type Problem struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

// Report is the outcome of an import. A non-empty Problems list means no commit was made.
type Report struct {
	Commit   model.CommitID `json:"commit,omitempty"`
	Mappings []Mapping      `json:"mappings"`
	Machines int            `json:"machines"`
	Problems []Problem      `json:"problems,omitempty"`
}

// Import converts the legacy repository.
func Import(ctx context.Context, opts Options) (Report, error) {
	return Report{}, model.ErrNotImplemented
}

// AltCond is one condition of an alternate file name.
type AltCond struct {
	Key   string // canonical long form: default, class, os, arch, hostname, user, distro, template
	Value string
}

// AltName is a parsed alternate file name.
type AltName struct {
	Base  string
	Conds []AltCond
}

// ParseAltName parses "dir/name##cond,cond". ok is false for a plain path.
func ParseAltName(path string) (AltName, bool, error) {
	return AltName{}, false, model.ErrNotImplemented
}
