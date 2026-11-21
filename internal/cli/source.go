package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/sync"
)

// cmdSourceMv renames a source within its scope: the manifest's source
// lines and the blob, resealed under the new path for an enclave, in one
// protected commit.
func (a *app) cmdSourceMv(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	dry, _ := cmd.Flags().GetBool("dry-run")
	noPush, _ := cmd.Flags().GetBool("no-push")
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	from, to := model.SourcePath(strings.TrimPrefix(args[0], "./")), model.SourcePath(strings.TrimPrefix(args[1], "./"))
	var mv apply.SourceMove
	if err := m.locked(ctx, func() error {
		var err error
		mv, err = m.eng.MoveSource(ctx, from, to)
		return err
	}); err != nil {
		if errors.Is(err, apply.ErrRefused) {
			return result{}, usagef("%v", err)
		}
		return lockedResult(err), err
	}
	data := map[string]any{"from": mv.From, "to": mv.To, "targets": mv.Targets, "scope": mv.Scope, "commit": "", "pushed": false}
	if dry {
		return result{data: data}, nil
	}
	rep, pushErr, err := m.commitThrough(ctx, a.version, sync.CommitOptions{
		Message: fmt.Sprintf("move %s to %s", from, to), Capture: &apply.Capture{},
		Changes: mv.Changes, ChangesScope: mv.Scope, Atomic: true, Push: !noPush,
	})
	return a.landedResult(ctx, m, data, rep, pushErr, err, manifest.FileName)
}

// cmdUntrack removes one manifest entry and its source in one protected
// commit and stops managing the target here; the file stays on disk.
func (a *app) cmdUntrack(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	source, _ := cmd.Flags().GetString("source")
	dry, _ := cmd.Flags().GetBool("dry-run")
	noPush, _ := cmd.Flags().GetBool("no-push")
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	t, err := target(m.home, args[0])
	if err != nil {
		return result{}, err
	}
	opts := apply.UntrackOptions{Source: model.SourcePath(source)}
	if source == "" && m.snap != nil && m.snap.Manifest != nil && (strings.HasPrefix(string(t), "files/") || strings.HasPrefix(string(t), "sealed/")) {
		// A source path: untrack the entry that reads it, unless an entry
		// names this path as its target.
		named := false
		for _, en := range m.snap.Manifest.Entries {
			named = named || en.Target == t
		}
		if !named {
			opts.Source, t = model.SourcePath(t), ""
		}
	}
	var u apply.Untracked
	if err := m.locked(ctx, func() error {
		var err error
		u, err = m.eng.Untrack(ctx, t, opts)
		return err
	}); err != nil {
		if errors.Is(err, apply.ErrRefused) || errors.Is(err, apply.ErrVariants) {
			return result{}, usagef("%v", err)
		}
		return lockedResult(err), err
	}
	data := map[string]any{"target": u.Target, "source": u.Source, "scope": u.Scope, "source_kept": u.SourceKept, "commit": "", "pushed": false}
	if dry {
		return result{data: data}, nil
	}
	opts2 := sync.CommitOptions{
		Message: "untrack " + string(u.Target), Capture: &apply.Capture{},
		Changes: u.Changes, ChangesScope: u.Scope, Atomic: true, Push: !noPush,
	}
	if u.Here {
		opts2.Forget = []model.Target{u.Target}
	}
	rep, pushErr, err := m.commitThrough(ctx, a.version, opts2)
	return a.landedResult(ctx, m, data, rep, pushErr, err, manifest.FileName)
}

// landedResult finishes a command that commits source changes: it records
// the commit that holds p, whether it was pushed, and the push error.
func (a *app) landedResult(ctx context.Context, m *machineEnv, data map[string]any, rep sync.Report, pushErr, err error, p model.SourcePath) (result, error) {
	if pushErr != nil {
		data["push_error"] = pushErr.Error()
	}
	if err != nil {
		return result{data: data}, err
	}
	id, err := m.landed(ctx, rep, p)
	data["commit"] = id
	data["pushed"] = rep.Pushed
	if err != nil {
		return result{data: data}, err
	}
	var next []string
	if !rep.Pushed {
		next = []string{"yadm sync"}
	}
	return result{data: data, next: next, text: "committed " + short(id)}, nil
}
