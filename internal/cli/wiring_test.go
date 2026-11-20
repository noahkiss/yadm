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

	_, err := cond.Parse("type:x", voc)
	ni("cond.Parse", err)
	_, err = fleet.Parse(nil)
	ni("fleet.Parse", err)
	_, err = manifest.Parse(nil)
	ni("manifest.Parse", err)
	_, err = eng.Render("t", nil, model.Context{})
	ni("render", err)
	if _, err = rules.ToTarget(nil, nil, rules.Spec{}, keys); err != nil {
		t.Errorf("rules.ToTarget: %v", err)
	}
	_, err = crypt.LoadIdentity(t.TempDir())
	ni("crypt.LoadIdentity", err)
	_, err = runner.Run(ctx, extexec.Spec{}, extexec.Request{})
	ni("extexec.Run", err)
	_, err = importer.Import(ctx, importer.Options{})
	ni("importer.Import", err)
	_, err = schedule.ForOS("linux")
	ni("schedule.ForOS", err)

	stateDir := t.TempDir()
	allow := tasks.FileAllowList(stateDir)
	if allow.Allowed(extexec.KindTask, "x", "h") {
		t.Error("allow list must deny until implemented")
	}
	tr := &tasks.Runner{Exec: runner, Allow: allow}
	ae := apply.New(apply.Deps{Store: st, Self: "m-test", Pins: crypt.FilePins(stateDir), State: apply.FileStateDB(stateDir), StateDir: stateDir, Tasks: tr})
	_, err = ae.Load(ctx, "HEAD")
	ni("apply.Load", err)
	_, err = ae.Scan(ctx, apply.ScanOptions{})
	ni("apply.Scan", err)
	_, _, err = ae.MergeSealed(ctx, &apply.Snapshot{Keys: keys}, store.Conflict{})
	ni("apply.MergeSealed", err)
	_, _, err = crypt.LoadSet(nil, crypt.FilePins(stateDir), nil)
	ni("crypt.LoadSet", err)
	if _, _, err = textmerge.Merge3(nil, nil, nil); err != nil {
		t.Errorf("textmerge.Merge3: %v", err)
	}
	_, err = tasks.DefinitionHash(manifest.TaskDef{})
	ni("tasks.DefinitionHash", err)

	s := &sync.Syncer{Deps: sync.Deps{Store: st, Apply: ae, Fleet: fl, Status: statusDB, Keys: keys, Exec: runner, Gate: gate,
		Lock: sync.FileLock(stateDir), Leases: sync.FileLeases(stateDir)}}
	_, err = s.Run(ctx, sync.Options{})
	ni("sync.Run", err)

	pass, holds, _ := gate.Check(ctx, []tasks.Staged{{Target: ".x", Scope: model.ScopeShared}}, extexec.Request{})
	if len(pass) != 0 || len(holds) != 1 || holds[0].Reason != model.HoldCheckFailed {
		t.Errorf("gate must fail closed: pass=%v holds=%v", pass, holds)
	}
}
