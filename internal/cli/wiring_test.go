package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/importer"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/render"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/schedule"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
	"github.com/noahkiss/yadm/internal/tasks"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// TestContractsCompose wires every package through its exported contracts
// the way the commands will, so a signature change that breaks a seam fails
// here. Each stub must answer with model.ErrNotImplemented, not panic.
func TestContractsCompose(t *testing.T) {
	ctx := context.Background()
	ni := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, model.ErrNotImplemented) {
			t.Errorf("%s: want ErrNotImplemented, got %v", name, err)
		}
	}

	var (
		repo     *store.Repo
		st       store.Store      = repo
		keys                      = &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{}}
		sealer   rules.Sealer     = keys
		runner                    = extexec.NewRunner()
		fl                        = &fleet.File{}
		voc                       = fl.Vocabulary()
		eng      render.Engine    = render.New(voc)
		statusDB fleet.StatusRefs = store.StatusRefs(st, "m-test")
		gate     tasks.Gate       = tasks.NewGate(nil, runner, nil)
	)
	_ = sealer
	_ = statusDB

	// cond, manifest and render are implemented: they must reject bad input
	// with their own errors, not ErrNotImplemented.
	_, err := cond.Parse("type:x", voc)
	var ce *cond.Error
	if !errors.As(err, &ce) {
		t.Errorf("cond.Parse: want *cond.Error for an unknown type, got %v", err)
	}
	if _, err = fleet.Parse(nil); err == nil {
		t.Error("fleet.Parse: an empty fleet file must be rejected")
	}
	_, err = manifest.Parse(nil)
	if err == nil || errors.Is(err, model.ErrNotImplemented) {
		t.Errorf("manifest.Parse: want a schema error for an empty manifest, got %v", err)
	}
	_, err = eng.Render("t", []byte("{{ nope }}"), model.Context{})
	var re *render.Error
	if !errors.As(err, &re) {
		t.Errorf("render: want *render.Error for an unknown variable, got %v", err)
	}
	_, err = rules.ToTarget(nil, nil, rules.Spec{}, keys)
	ni("rules.ToTarget", err)
	if _, err = crypt.LoadIdentity(t.TempDir()); err == nil || errors.Is(err, model.ErrNotImplemented) {
		t.Errorf("crypt.LoadIdentity on an empty state dir: want a missing-file error, got %v", err)
	}
	if _, err = runner.Run(ctx, extexec.Spec{}, extexec.Request{}); !errors.Is(err, extexec.ErrNoCommand) {
		t.Errorf("extexec.Run: want ErrNoCommand, got %v", err)
	}
	if _, err = importer.Import(ctx, importer.Options{}); err == nil || errors.Is(err, model.ErrNotImplemented) {
		t.Errorf("importer.Import with no legacy repository: want a usage error, got %v", err)
	}
	if _, err = schedule.ForOS("linux"); err != nil {
		t.Errorf("schedule.ForOS: %v", err)
	}

	stateDir := t.TempDir()
	allow := tasks.FileAllowList(stateDir)
	if allow.Allowed(extexec.KindTask, "x", "h") {
		t.Error("allow list must deny until implemented")
	}
	tr := &tasks.Runner{Exec: runner, Allow: allow}
	ae := apply.New(apply.Deps{Store: st, Self: "m-test", Pins: crypt.FilePins(stateDir), State: apply.FileStateDB(stateDir), StateDir: stateDir, Tasks: tr})
	// apply.Load needs a real repository; integration tests cover it.
	if _, err = ae.Scan(ctx, apply.ScanOptions{}); err != nil {
		t.Errorf("apply.Scan on an empty state: %v", err)
	}
	if _, _, err = ae.MergeSealed(ctx, &apply.Snapshot{Keys: keys}, store.Conflict{}); err == nil {
		t.Error("apply.MergeSealed must refuse a conflict outside sealed/")
	}
	if _, _, err = crypt.LoadSet(nil, crypt.FilePins(stateDir), nil); err != nil {
		t.Errorf("crypt.LoadSet with no logs: %v", err)
	}
	_, _, err = textmerge.Merge3(nil, nil, nil)
	ni("textmerge.Merge3", err)
	if h, err := tasks.DefinitionHash(manifest.TaskDef{}); err != nil || len(h) != 64 {
		t.Errorf("tasks.DefinitionHash = %q, %v", h, err)
	}

	s := &sync.Syncer{Deps: sync.Deps{Store: st, Apply: ae, Fleet: fl, Status: statusDB, Keys: keys, Exec: runner, Gate: gate,
		Lock: sync.FileLock(stateDir), Leases: sync.FileLeases(stateDir)}}
	_, err = s.Run(ctx, sync.Options{})
	ni("sync.Run", err)

	pass, holds, _ := gate.Check(ctx, []tasks.Staged{{Target: ".x", Scope: model.ScopeShared}}, extexec.Request{})
	if len(pass) != 0 || len(holds) != 1 || holds[0].Reason != model.HoldCheckFailed {
		t.Errorf("gate must fail closed: pass=%v holds=%v", pass, holds)
	}
}
