package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

// Allow-list kinds for manifest changes that need a local allow, as task
// definitions do. Any machine can push manifest.toml, so a change that
// could make this machine stage plaintext takes effect only once the user
// allows it here.
const (
	// KindProtection allows a weaker protection of one target: an enclave
	// dropped or changed, a seal key dropped or moved to another enclave,
	// regions turned off. The name is the target; the hash covers the
	// target and its new protection.
	KindProtection extexec.Kind = "protection"
	// KindRoot allows an owned root that is new or changed its enclave. The
	// name is the root path; the hash covers the path and the enclave.
	KindRoot extexec.Kind = "root"
)

// protection is what keeps a target's plaintext out of the repository: the
// whole-file enclave, the sealed keys with their enclaves, and regions.
type protection struct {
	Enclave model.EnclaveName            `json:"enclave,omitempty"`
	Seal    map[string]model.EnclaveName `json:"seal,omitempty"`
	Regions bool                         `json:"regions,omitempty"`
}

func protOf(en manifest.Entry) protection {
	p := protection{Enclave: en.Enclave, Regions: en.Regions}
	if len(en.Seal) > 0 {
		p.Seal = make(map[string]model.EnclaveName, len(en.Seal))
		for k, v := range en.Seal {
			p.Seal[k] = v
		}
	}
	return p
}

// prot is the protection recorded for a target. A state written before the
// protection fields existed has only SealSet: its keys must stay sealed (to
// any enclave) and "regions" means regions.
func (ts TargetState) prot() protection {
	p := protection{Enclave: ts.Enclave, Regions: ts.Regions, Seal: ts.Seal}
	if p.Seal == nil && len(ts.SealSet) > 0 {
		p.Seal = map[string]model.EnclaveName{}
		for _, k := range ts.SealSet {
			if k == "regions" {
				p.Regions = true
				continue
			}
			p.Seal[k] = ""
		}
	}
	return p
}

// weakerBy lists how next protects less than old. An empty enclave in
// old.Seal (legacy state) accepts any enclave in next.
func weakerBy(old, next protection) []string {
	var why []string
	if old.Enclave != "" && next.Enclave != old.Enclave {
		if next.Enclave == "" {
			why = append(why, "the file is no longer sealed for "+string(old.Enclave))
		} else {
			why = append(why, fmt.Sprintf("the file moved from enclave %s to %s", old.Enclave, next.Enclave))
		}
	}
	keys := make([]string, 0, len(old.Seal))
	for k := range old.Seal {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e, ok := next.Seal[k]
		switch {
		case !ok:
			why = append(why, "seal "+k+" was dropped")
		case old.Seal[k] != "" && e != old.Seal[k]:
			why = append(why, fmt.Sprintf("seal %s moved from enclave %s to %s", k, old.Seal[k], e))
		}
	}
	if old.Regions && !next.Regions {
		why = append(why, "regions were turned off")
	}
	return why
}

// backupProt is the protection a backup of t follows: the recorded one
// merged with the plan's, so a backup never lands outside an enclave either
// one names.
func (e *Engine) backupProt(snap *Snapshot, st *State, t model.Target) protection {
	p := st.Targets[t].prot()
	if snap != nil && snap.Plan != nil {
		if r, ok := snap.Plan.Targets[t]; ok {
			p = union(p, protOf(r.Entry))
		}
	}
	return p
}

func protectionHash(t model.Target, p protection) string {
	b, _ := json.Marshal(struct {
		Target model.Target `json:"target"`
		protection
	}{t, p})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func rootHash(r manifest.Root) string {
	h := sha256.Sum256([]byte(string(r.Path) + "\x00" + string(r.Enclave)))
	return hex.EncodeToString(h[:])
}

// allowList is the local allow list: Deps.Allow, else the task runner's.
// Without one nothing is allowed.
func (e *Engine) allowList() tasks.AllowList {
	if e.Allow != nil {
		return e.Allow
	}
	if e.Tasks != nil {
		return e.Tasks.Allow
	}
	return nil
}

func (e *Engine) allowed(kind extexec.Kind, name, hash string) bool {
	a := e.allowList()
	return a != nil && a.Allowed(kind, name, hash)
}

// weakened reports, for a target this machine has written before, whether
// the resolved entry protects it less than the protection recorded in
// state and the user has not allowed that here. The detail names what was
// weakened.
func (e *Engine) weakened(ts TargetState, have bool, r manifest.Resolved) (string, bool) {
	if !have {
		return "", false
	}
	next := protOf(r.Entry)
	why := weakerBy(ts.prot(), next)
	if len(why) == 0 || e.allowed(KindProtection, string(r.Target), protectionHash(r.Target, next)) {
		return "", false
	}
	return "the manifest weakened this file's protection (" + strings.Join(why, "; ") + "); it is neither applied nor captured until allowed on this machine", true
}

// weakHold is the seal_guard hold for a weakened protection.
func weakHold(st *State, now time.Time, t model.Target, scope model.Scope, since time.Time, detail string) model.Hold {
	h := fileHold(st, now, t, scope, model.HoldSealGuard, since, detail)
	h.Next = append([]string{"yadm protection allow " + string(t)}, h.Next...)
	return h
}

// AllowProtection records on this machine that target t may take the
// protection its manifest entry has at rev, although it is weaker than the
// one recorded in state. The next apply writes and records it.
func (e *Engine) AllowProtection(ctx context.Context, rev model.CommitID, t model.Target) error {
	a := e.allowList()
	if a == nil {
		return errors.New("allow: no allow list")
	}
	snap, err := e.snapshot(ctx, rev)
	if err != nil {
		return err
	}
	r, ok := snap.Plan.Targets[t]
	if !ok {
		return fmt.Errorf("allow: %s is not in the plan at %s", t, rev)
	}
	return a.Allow(KindProtection, string(t), protectionHash(t, protOf(r.Entry)))
}

// AllowRoot records on this machine that the owned root at path, as the
// manifest at rev defines it, may take effect. Files already in it when the
// next apply accepts it are never captured automatically.
func (e *Engine) AllowRoot(ctx context.Context, rev model.CommitID, path model.Target) error {
	a := e.allowList()
	if a == nil {
		return errors.New("allow: no allow list")
	}
	snap, err := e.snapshot(ctx, rev)
	if err != nil {
		return err
	}
	for _, r := range snap.Plan.Roots {
		if r.Path == path {
			return a.Allow(KindRoot, string(path), rootHash(r))
		}
	}
	// Not in the plan: allow the removal of an accepted enclave root.
	st, err := e.loadState()
	if err != nil {
		return err
	}
	for _, r := range st.Roots {
		if r.Path == path {
			return a.Allow(KindRoot, string(path), rootRemovedHash(r))
		}
	}
	return fmt.Errorf("allow: no owned root %s at %s", path, rev)
}

// rootRemovedHash is the allow hash for dropping an accepted enclave root.
func rootRemovedHash(r manifest.Root) string {
	h := sha256.Sum256([]byte("removed\x00" + string(r.Path) + "\x00" + string(r.Enclave)))
	return hex.EncodeToString(h[:])
}

// acceptRoots updates st.Roots, the owned roots this machine scans and
// captures from, against the plan's roots. A root that is unchanged stays.
// A new root, or one whose enclave changed, takes effect only once allowed
// (KindRoot); until then the old version stays and a root_untrusted hold
// names it. A plain root that left the plan goes. An enclave root that left
// the plan (or whose `when` no longer applies) stays until its removal is
// allowed: otherwise a plain root around it would capture its new files in
// plaintext. Each newly accepted root is
// walked once: the unmanaged files already in it go into st.Baseline and
// are never captured automatically. It returns the root holds.
func (e *Engine) acceptRoots(ctx context.Context, snap *Snapshot, st *State, now time.Time) []model.Hold {
	old := map[model.Target]manifest.Root{}
	for _, r := range st.Roots {
		old[r.Path] = r
	}
	var roots []manifest.Root
	var holds []model.Hold
	for _, r := range snap.Plan.Roots {
		o, had := old[r.Path]
		if had && o.Enclave == r.Enclave {
			// The allow covers path and enclave; `when` and the ignore
			// globs only narrow what is captured, so they follow the plan.
			roots = append(roots, r)
			continue
		}
		if !e.allowed(KindRoot, string(r.Path), rootHash(r)) {
			if had {
				roots = append(roots, o)
			}
			detail := "new owned root; new files in it are not captured until it is allowed on this machine"
			if had {
				detail = fmt.Sprintf("owned root changed its enclave from %q to %q; the old setting stays until the change is allowed on this machine", o.Enclave, r.Enclave)
			}
			scope := model.ScopeShared
			if r.Enclave != "" {
				scope = model.Scope(r.Enclave)
			}
			h := model.KeepSince(st.Holds, model.Hold{Target: r.Path, Scope: scope, Reason: model.HoldRootUntrusted, Detail: detail}, now)
			h.Next = []string{"yadm root allow " + string(r.Path)}
			holds = append(holds, h)
			continue
		}
		if !e.baseline(ctx, st, r) {
			if had {
				roots = append(roots, o)
			}
			continue // walk did not finish; try again on the next apply
		}
		roots = append(roots, r)
	}
	inPlan := map[model.Target]bool{}
	for _, r := range snap.Plan.Roots {
		inPlan[r.Path] = true
	}
	for _, o := range st.Roots {
		if inPlan[o.Path] || o.Enclave == "" || e.allowed(KindRoot, string(o.Path), rootRemovedHash(o)) {
			continue
		}
		roots = append(roots, o)
		h := model.KeepSince(st.Holds, model.Hold{Target: o.Path, Scope: model.Scope(o.Enclave), Reason: model.HoldRootUntrusted,
			Detail: "enclave owned root left the manifest; it stays until its removal is allowed on this machine"}, now)
		h.Next = []string{"yadm root allow " + string(o.Path)}
		holds = append(holds, h)
	}
	st.Roots = roots
	// Root holds are recomputed on every full apply.
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Reason != model.HoldRootUntrusted {
			out = append(out, h)
		}
	}
	st.Holds = append(out, holds...)
	return holds
}

// baseline records the unmanaged regular files under root in st.Baseline.
// It reports false when the walk did not finish within the scan budget.
func (e *Engine) baseline(ctx context.Context, st *State, root manifest.Root) bool {
	news, done := e.walkRoot(ctx, st, root, e.ScanBudget)
	if !done {
		return false
	}
	if st.Baseline == nil {
		st.Baseline = map[model.Target]time.Time{}
	}
	now := e.Now()
	for _, d := range news {
		if _, ok := st.Baseline[d.Target]; !ok {
			st.Baseline[d.Target] = now
		}
	}
	return true
}

// forget drops a target from management. A target that had any recorded
// protection goes into the baseline: if it leaves the plan and the app
// writes it again inside a plain owned root, it must not be captured in
// plaintext.
func forget(st *State, t model.Target, now time.Time) {
	ts, ok := st.Targets[t]
	delete(st.Targets, t)
	if p := ts.prot(); ok && (p.Enclave != "" || len(p.Seal) > 0 || p.Regions) {
		st.Baseline[t] = now
	}
}

// inBaseline reports whether a file predates the root that holds it, or
// was dropped from management while it stayed on disk.
func inBaseline(st *State, t model.Target) bool {
	_, ok := st.Baseline[t]
	return ok
}
