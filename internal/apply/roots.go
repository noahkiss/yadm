package apply

import (
	"strings"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// RootIndex is the Resolved.Index of a target an owned root produces: no
// manifest entry names it.
const RootIndex = -1

// ExpandRoots adds to plan the files that owned roots share: a source file
// under files/<root>/ for a plain root, or sealed/<enclave>/<root>/ for an
// enclave root, becomes a target at <root>/... with the root's enclave.
// Capture writes a new file of an owned root there, so committing it shares
// it with every machine the root applies to. Only roots that apply here
// count, and only the deepest root that contains a file decides it. A file
// any manifest entry names (by target, source or glob, whether or not the
// entry applies here), a task output, or a file the root's ignore globs
// hide is left alone: the manifest decides those. With allowed set, only
// roots it accepts deliver: a root does nothing on a machine until allowed
// there. A nil allowed accepts every root (a preview for another machine).
func ExpandRoots(man *manifest.Manifest, plan *manifest.Plan, tree []model.SourcePath, allowed func(manifest.Root) bool) {
	if man == nil || plan == nil || len(plan.Roots) == 0 {
		return
	}
	for _, p := range tree {
		t, enc, ok := rootTarget(p)
		if !ok {
			continue
		}
		if _, ok := plan.Targets[t]; ok {
			continue
		}
		root := plan.Root(t)
		if root == nil || root.Path == t || root.Enclave != enc || root.Ignored(t) || man.Generated(t) || named(man, t, p) {
			continue
		}
		if allowed != nil && !allowed(*root) {
			continue
		}
		e := manifest.Entry{Target: t, Enclave: enc}
		plan.Targets[t] = manifest.Resolved{Target: t, Source: p, Entry: e, Index: RootIndex}
	}
}

// rootAccepted reports whether root r may deliver here: this machine
// accepted the same path and enclave, or allowed it (`yadm root allow`),
// which takes effect on the apply that loads this snapshot.
func (e *Engine) rootAccepted(st *State, r manifest.Root) bool {
	for _, o := range st.Roots {
		if o.Path == r.Path && o.Enclave == r.Enclave {
			return true
		}
	}
	return e.allowed(KindRoot, string(r.Path), rootHash(r))
}

// rootTarget maps a source path under files/ or sealed/<enclave>/ to its
// default target and enclave.
func rootTarget(p model.SourcePath) (model.Target, model.EnclaveName, bool) {
	s := string(p)
	if rest, ok := strings.CutPrefix(s, "files/"); ok && rest != "" {
		return model.Target(rest), "", true
	}
	if rest, ok := strings.CutPrefix(s, "sealed/"); ok {
		enc, t, ok := strings.Cut(rest, "/")
		if ok && enc != "" && t != "" {
			return model.Target(t), model.EnclaveName(enc), true
		}
	}
	return "", "", false
}

// named reports whether any manifest entry names target t or source p.
func named(man *manifest.Manifest, t model.Target, p model.SourcePath) bool {
	for _, e := range man.Entries {
		switch {
		case e.Target == t, e.Source == p:
			return true
		case manifest.IsGlob(string(e.Target)):
			if manifest.Match(string(e.Target), string(t)) {
				return true
			}
			if e.Source != "" && strings.HasPrefix(string(p), strings.TrimSuffix(string(e.Source), "/")+"/") {
				return true
			}
		}
	}
	return false
}
