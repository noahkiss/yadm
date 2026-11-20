package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/importer"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// importSealer is the importer.Sealer the cli owns. On the first file of an
// enclave it creates that enclave's key log (entry 1, signed by this
// machine, wrapped to it and the recovery identity) and seals with the new
// keyring. Plaintext stays in memory.
type importSealer struct {
	by       *crypt.Identity
	recovery crypt.Member
	rings    map[model.EnclaveName]*crypt.Keyring
	entries  map[model.EnclaveName]crypt.LogEntry
}

func newImportSealer(by *crypt.Identity, recovery crypt.Member) *importSealer {
	return &importSealer{by: by, recovery: recovery, rings: map[model.EnclaveName]*crypt.Keyring{}, entries: map[model.EnclaveName]crypt.LogEntry{}}
}

// SealFile implements importer.Sealer.
func (s *importSealer) SealFile(e model.EnclaveName, path model.SourcePath, plaintext []byte) ([]byte, error) {
	return s.SealFileAt(e, path, plaintext)
}

// SealFileAt seals plaintext for e, bound to its source path. On the first
// file of e it creates the enclave's key log.
func (s *importSealer) SealFileAt(e model.EnclaveName, path model.SourcePath, plaintext []byte) ([]byte, error) {
	ring, ok := s.rings[e]
	if !ok {
		entry, r, err := crypt.Create(e, s.by, s.recovery, crypt.MemPins())
		if err != nil {
			return nil, err
		}
		s.rings[e], s.entries[e], ring = r, entry, r
	}
	return ring.SealFile(path, plaintext)
}

// changes returns the key-log files of every enclave the import created.
func (s *importSealer) changes() ([]store.Change, map[model.EnclaveName]string, error) {
	var out []store.Change
	fps := map[model.EnclaveName]string{}
	for e, entry := range s.entries {
		b, err := crypt.MarshalLogEntry(entry)
		if err != nil {
			return nil, nil, err
		}
		fp, err := crypt.Fingerprint(entry)
		if err != nil {
			return nil, nil, err
		}
		fps[e] = fp
		out = append(out, store.Change{Path: crypt.LogPath(e, entry.Seq), Blob: b, Mode: 0o100644})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, fps, nil
}

type importData struct {
	importer.Report
	KeyLogs map[model.EnclaveName]string `json:"key_logs,omitempty"` // enclave -> fingerprint of entry 1
}

func (a *app) cmdImport(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	f := cmd.Flags()
	opts := importer.Options{Legacy: args[0]}
	opts.Machines, _ = f.GetString("machines")
	opts.Branch, _ = f.GetString("branch")
	opts.Output, _ = f.GetString("output")
	opts.PasswordEnv, _ = f.GetString("password-env")
	opts.DryRun, _ = f.GetBool("dry-run")
	de, _ := f.GetString("default-enclave")
	opts.DefaultEnclave = model.EnclaveName(de)
	if ce, _ := f.GetStringToString("class-enclave"); len(ce) > 0 {
		opts.ClassEnclaves = map[string]model.EnclaveName{}
		for k, v := range ce {
			opts.ClassEnclaves[k] = model.EnclaveName(v)
		}
	}
	opts.CryptFilters, _ = f.GetStringArray("crypt-filter")
	if ff, _ := f.GetString("filters"); ff != "" {
		filters, err := importer.ReadFilters(ff)
		if err != nil {
			return result{}, usagef("--filters: %v", err)
		}
		opts.Filters = filters
	}
	if opts.Output == "" && !opts.DryRun {
		return result{}, usagef("--output <dir> is required (or --dry-run)")
	}
	if opts.Branch == "" {
		opts.Branch = "main"
	}
	opts.Machine, _ = f.GetString("machine")
	var sealer *importSealer
	var state string
	if opts.PasswordEnv != "" || opts.Machine != "" {
		p, err := DefaultPaths()
		if err != nil {
			return result{}, err
		}
		state = p.State
		id, err := crypt.LoadIdentity(p.State)
		if err != nil {
			return result{next: []string{"yadm init <remote> --machine <name>"}},
				fmt.Errorf("--machine and sealing encrypted files need this machine's identity: %w", err)
		}
		if opts.Machine != "" {
			opts.Self = id.Machine
		}
		if opts.PasswordEnv != "" {
			out, _ := filepath.Abs(opts.Output)
			rec, _, err := recoveryMember(cmd, out, p.State, p.Source)
			if err != nil {
				return result{}, err
			}
			sealer = newImportSealer(id, rec)
			opts.Sealer = sealer
		}
	}
	rep, err := importer.Import(ctx, opts)
	d := importData{Report: rep}
	if d.Mappings == nil {
		d.Mappings = []importer.Mapping{}
	}
	if d.Problems == nil {
		d.Problems = []importer.Problem{}
	}
	if err != nil {
		res := result{data: d}
		if errors.Is(err, importer.ErrProblems) {
			res.details = rep.Problems
		}
		return res, err
	}
	var next []string
	if sealer != nil && len(sealer.entries) > 0 && !opts.DryRun {
		changes, fps, err := sealer.changes()
		if err != nil {
			return result{data: d}, err
		}
		id, err := addKeyLogs(ctx, opts.Output, opts.Branch, rep.Commit, changes, sealer.by.Machine)
		if err != nil {
			return result{data: d}, err
		}
		d.Commit, d.KeyLogs = id, fps
		// The key logs are committed: pin them for this machine, which
		// signed them, so it needs no `enclave join --expect`. An existing
		// different pin is a trust anchor for another log and is kept.
		pins := crypt.FilePins(state)
		for e, entry := range sealer.entries {
			pin, err := crypt.PinOf(entry)
			if err != nil {
				return result{data: d}, err
			}
			old, err := pins.Get(e)
			if err != nil {
				return result{data: d}, err
			}
			if old != nil && *old != pin {
				next = append(next, fmt.Sprintf("this machine already pins another %s key log; after switching to the new repository: yadm enclave join %s --expect %s", e, e, fps[e]))
				continue
			}
			if err := pins.Set(e, pin); err != nil {
				return result{data: d}, err
			}
		}
		sort.Strings(next)
	}
	next = append(next, "review "+opts.Output+", then push it to a new remote", "on each machine: yadm init <remote> --machine <name>")
	text := fmt.Sprintf("commit %s: %d mappings, %d machines", short(d.Commit), len(d.Mappings), d.Machines)
	return result{data: d, next: next, text: text}, nil
}

// addKeyLogs commits the key logs the import created on top of the import
// commit and moves the branch (and a non-bare worktree) to it.
func addKeyLogs(ctx context.Context, dir, branch string, parent model.CommitID, changes []store.Change, by model.MachineID) (model.CommitID, error) {
	tmp, err := os.MkdirTemp("", "yadm-import-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	repo, err := store.Open(dir, tmp)
	if err != nil {
		return "", err
	}
	defer repo.Close()
	var paths []string
	for _, c := range changes {
		paths = append(paths, string(c.Path))
	}
	msg := store.Message{
		Subject:  "import: add enclave key logs",
		Body:     strings.Join(paths, "\n"),
		Trailers: []store.Trailer{{Key: store.TrailerMachine, Value: string(by)}},
	}
	id, err := repo.CommitPaths(ctx, parent, changes, msg)
	if err != nil {
		return "", err
	}
	if err := repo.UpdateRef(ctx, "refs/heads/"+branch, id, parent); err != nil {
		return "", err
	}
	if out, err := store.Output(ctx, dir, "rev-parse", "--is-bare-repository"); err == nil && strings.TrimSpace(string(out)) == "false" {
		if head, err := store.Output(ctx, dir, "symbolic-ref", "-q", "HEAD"); err == nil && strings.TrimSpace(string(head)) == "refs/heads/"+branch {
			if _, err := store.Output(ctx, dir, "read-tree", "-u", "-m", string(parent), string(id)); err != nil {
				return id, fmt.Errorf("committed %s but the worktree did not move: %w", id, err)
			}
		}
	}
	return id, nil
}
