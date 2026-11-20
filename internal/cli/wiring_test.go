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
	_, err = rules.ToTarget(nil, nil, rules.Spec{}, keys)
	ni("rules.ToTarget", err)
	_, err = crypt.LoadIdentity(t.TempDir())
	ni("crypt.LoadIdentity", err)
	_, err = runner.Run(ctx, extexec.Spec{}, extexec.Request{})
	ni("extexec.Run", err)
	_, err = importer.Import(ctx, importer.Options{})
	ni("importer.Import", err)
	_, err = schedule.ForOS("linux")
	ni("schedule.ForOS", err)

	ae := apply.New(apply.Deps{Store: st, Keys: keys, Render: eng, State: apply.FileStateDB(t.TempDir())})
	_, err = ae.Scan(ctx, apply.ScanOptions{})
	ni("apply.Scan", err)

	s := &sync.Syncer{Deps: sync.Deps{Store: st, Apply: ae, Fleet: fl, Keys: keys, Exec: runner, Gate: gate, Lock: sync.FileLock(t.TempDir())}}
	_, err = s.Run(ctx, sync.Options{})
	ni("sync.Run", err)

	pass, holds, _ := gate.Check(ctx, []tasks.Staged{{Target: ".x", Scope: model.ScopeShared}}, extexec.Request{})
	if len(pass) != 0 || len(holds) != 1 || holds[0].Reason != model.HoldCheckFailed {
		t.Errorf("gate must fail closed: pass=%v holds=%v", pass, holds)
	}
}
