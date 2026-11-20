package importer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/noahkiss/yadm/internal/model"
)

// Sealer seals one whole file for an enclave. The importer calls it once per
// encrypted legacy file, with the decrypted plaintext and the file's sealed
// source path (`sealed/<enclave>/<target>`), which the container binds, and
// stores only what it returns. A crypt.Keyring per enclave provides it; tests
// fake it.
type Sealer interface {
	SealFile(enclave model.EnclaveName, path model.SourcePath, plaintext []byte) ([]byte, error)
}

// Options configures one import.
type Options struct {
	Legacy         string                       // path to a clone of the legacy repository; read only
	Machines       string                       // path to the machines TSV; empty means one machine per class
	Branch         string                       // new branch name; default "main"
	Output         string                       // directory for the converted repository; must be absent or empty
	PasswordEnv    string                       // env var holding the transcrypt password
	ClassEnclaves  map[string]model.EnclaveName // legacy class -> enclave for its encrypted files
	DefaultEnclave model.EnclaveName            // enclave for encrypted files with no mapped class
	// CryptFilters names extra gitattributes filters that mark transcrypt
	// files. The importer always knows "crypt" and every filter in the legacy
	// repository's own local config (read, never run) whose smudge, clean or
	// textconv command runs transcrypt. A clone lacks that config, so a
	// custom filter name is declared here (`--crypt-filter`).
	CryptFilters []string
	// Filters maps the other gitattributes filters (strip filters) to
	// intra-file rules. A path marked with an unmapped filter fails the import.
	Filters map[string]Filter
	Sealer  Sealer // seals encrypted files; required when any exist
	DryRun  bool
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

func (p Problem) String() string {
	if p.Line > 0 {
		return fmt.Sprintf("%s:%d: %s", p.Path, p.Line, p.Reason)
	}
	return p.Path + ": " + p.Reason
}

// Report is the outcome of an import. A non-empty Problems list means no commit was made.
type Report struct {
	Commit   model.CommitID `json:"commit,omitempty"`
	Mappings []Mapping      `json:"mappings"`
	Machines int            `json:"machines"`
	Problems []Problem      `json:"problems,omitempty"`
}

// ErrProblems is returned when the import found paths it cannot convert.
// The Report lists them; nothing was written.
var ErrProblems = errors.New("import found paths it cannot convert; nothing was committed")

// Import converts the legacy repository. On any problem it writes nothing,
// returns the problems in the Report and ErrProblems.
func Import(ctx context.Context, opts Options) (Report, error) {
	if opts.Legacy == "" {
		return Report{}, errors.New("import: no legacy repository given")
	}
	if !opts.DryRun {
		if opts.Output == "" {
			return Report{}, errors.New("import: no output directory given")
		}
		if err := checkOutputDir(opts.Output); err != nil {
			return Report{}, err
		}
	}
	conv, err := convert(ctx, opts)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Mappings: conv.Mappings, Machines: conv.Machines, Problems: conv.Problems}
	if len(rep.Problems) > 0 {
		return rep, ErrProblems
	}
	if opts.DryRun {
		return rep, nil
	}
	commit, err := writeOutput(ctx, opts, conv)
	if err != nil {
		return rep, err
	}
	rep.Commit = commit
	return rep, nil
}

func checkOutputDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("import: output %s: %w", dir, err)
	}
	if len(ents) > 0 {
		return fmt.Errorf("import: output %s is not empty", dir)
	}
	return nil
}

// outFile is one file of the converted source tree.
type outFile struct {
	Data []byte // plaintext for files/, sealed bytes for sealed/
	Exec bool
}

// converted is the whole result of a conversion, before anything is written.
type converted struct {
	LegacyHead string
	Files      map[model.SourcePath]outFile
	Manifest   []byte
	Fleet      []byte
	Mappings   []Mapping
	Machines   int
	Problems   []Problem
}

// convert reads the legacy head and builds the new tree in memory. Problems
// do not stop it, so one run lists every path that needs attention.
func convert(ctx context.Context, opts Options) (*converted, error) {
	legacyDir, err := filepath.Abs(opts.Legacy)
	if err != nil {
		return nil, err
	}
	repo, err := readLegacy(ctx, legacyDir)
	if err != nil {
		return nil, err
	}
	filters := cryptFilters(ctx, legacyDir)
	for _, f := range opts.CryptFilters {
		filters[f] = true
	}
	for name, f := range opts.Filters {
		if f.Crypt {
			filters[name] = true
		}
	}
	p := &planner{opts: opts, repo: repo, filters: filters, files: map[model.SourcePath]outFile{}}
	var machines []machineRow
	if opts.Machines != "" {
		machines, err = readMachines(opts.Machines)
		if err != nil {
			return nil, err
		}
	}
	p.run()
	fl, err := buildFleet(machines, p, opts)
	if err != nil {
		where := opts.Machines
		if where == "" {
			where = "machines table"
		}
		p.problems = append(p.problems, Problem{Path: where, Reason: err.Error()})
	}
	conv := &converted{LegacyHead: repo.Head, Files: p.files, Mappings: p.mappings, Problems: p.problems}
	if fl != nil {
		conv.Machines = len(fl.Machines)
		conv.Fleet, err = encodeFleet(fl)
		if err != nil {
			conv.Problems = append(conv.Problems, Problem{Path: "fleet.toml", Reason: err.Error()})
		}
	}
	conv.Manifest, err = encodeManifest(p.entries)
	if err != nil {
		conv.Problems = append(conv.Problems, Problem{Path: "manifest.toml", Reason: err.Error()})
	} else if fl != nil && conv.Fleet != nil {
		conv.Problems = append(conv.Problems, checkExclusive(conv.Manifest, fl)...)
	}
	sort.SliceStable(conv.Problems, func(i, j int) bool {
		if conv.Problems[i].Path != conv.Problems[j].Path {
			return conv.Problems[i].Path < conv.Problems[j].Path
		}
		return conv.Problems[i].Line < conv.Problems[j].Line
	})
	return conv, nil
}
