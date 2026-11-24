package apply

import (
	"context"
	"errors"
	"fmt"
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
	_, ok := namedBy(man, t, p)
	return ok
}

// namedBy returns the index of the first manifest entry that names target t
// or source p.
func namedBy(man *manifest.Manifest, t model.Target, p model.SourcePath) (int, bool) {
	for i, e := range man.Entries {
		switch {
		case e.Target == t, e.Source == p:
			return i, true
		case manifest.IsGlob(string(e.Target)):
			if manifest.Match(string(e.Target), string(t)) {
				return i, true
			}
			if e.Source != "" && strings.HasPrefix(string(p), strings.TrimSuffix(string(e.Source), "/")+"/") {
				return i, true
			}
		}
	}
	return 0, false
}

// ErrRootRefused reports a file inside an owned root that may not be
// captured as asked on this machine: no root may capture it (captureRoot),
// or an entry for it would take an enclave root's file out of its enclave.
var ErrRootRefused = errors.New("an owned root refuses it")

// captureRoot returns the accepted owned root that captures t, a new file no
// entry manages, or ok false when no accepted root contains t. Only the
// deepest accepted root decides, and it never hands t to a shallower one.
// It refuses (ErrRootRefused) when that root's ignore globs match t, when a
// deeper manifest root carries an enclave the accepted root lacks (not
// accepted here, or not applying here: its plaintext must not land in
// files/ or another enclave; a root whose own enclave changed keeps its
// accepted setting until allowed), or when a manifest entry names t, so the root
// would write a source that entry reads. man is the manifest of the applied
// snapshot; plan, when set, tells an applying root from one whose `when` is
// false here.
func captureRoot(st *State, man *manifest.Manifest, plan *manifest.Plan, t model.Target) (manifest.Root, bool, error) {
	root, ok := rootOf(&manifest.Plan{Roots: st.Roots}, t)
	if !ok {
		return root, false, nil
	}
	var why []string
	if g, ok := ignoreGlob(root, t); ok {
		why = append(why, fmt.Sprintf("owned root %s ignores it (ignore glob %q)", root.Path, g))
	}
	if man != nil {
		var other *manifest.Root
		for i, r := range man.Roots {
			if !strings.HasPrefix(string(t), string(r.Path)+"/") || len(r.Path) <= len(root.Path) || r.Enclave == "" || r.Enclave == root.Enclave {
				continue
			}
			if other == nil || len(r.Path) > len(other.Path) {
				other = &man.Roots[i]
			}
		}
		if other != nil {
			applies := false
			if plan != nil {
				for _, r := range plan.Roots {
					if r.Path == other.Path && r.Enclave == other.Enclave {
						applies = true
					}
				}
			}
			if applies {
				why = append(why, fmt.Sprintf("it is under enclave root %s (enclave %s), which this machine has not accepted; run yadm root allow %s, then commit it again", other.Path, other.Enclave, model.ShellQuote(string(other.Path))))
			} else {
				why = append(why, fmt.Sprintf("it is under enclave root %s (enclave %s), which does not apply on this machine; commit it on a machine the root applies to", other.Path, other.Enclave))
			}
		}
		src := model.SourcePath("files/" + string(t))
		if root.Enclave != "" {
			src = model.SourcePath("sealed/" + string(root.Enclave) + "/" + string(t))
		}
		if i, ok := namedBy(man, t, src); ok {
			why = append(why, fmt.Sprintf("manifest entry #%d %q names it but does not produce it here", i, man.Entries[i].Target))
		}
	}
	if len(why) == 0 {
		return root, true, nil
	}
	return root, true, fmt.Errorf("%s: %w: %s", t, ErrRootRefused, strings.Join(why, "; "))
}

// ignoreGlob returns the first ignore glob of r that matches t.
func ignoreGlob(r manifest.Root, t model.Target) (string, bool) {
	for _, g := range r.Ignore {
		if (manifest.Root{Path: r.Path, Ignore: []string{g}}).Ignored(t) {
			return g, true
		}
	}
	return "", false
}

// CheckNew reports, with ErrRootRefused, why no owned root may capture t
// here: t is an unmanaged regular file inside an accepted owned root that
// no applying glob entry covers, and captureRoot refuses it. It returns nil
// for every other path; a commit that names t then goes ahead as usual.
func (e *Engine) CheckNew(ctx context.Context, t model.Target) error {
	st, err := e.loadState()
	if err != nil {
		return err
	}
	if _, managed := st.Targets[t]; managed {
		return nil
	}
	abs, err := e.abs(t)
	if err != nil {
		return nil
	}
	if info, err := e.fs.Lstat(abs); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	var man *manifest.Manifest
	var plan *manifest.Plan
	if st.Applied != "" {
		if snap, err := e.snapshot(ctx, st.Applied); err == nil {
			man, plan = snap.Manifest, snap.Plan
		}
	}
	if _, ok, gerr := plan.GlobNew(t); ok || gerr != nil {
		return nil
	}
	_, _, err = captureRoot(st, man, plan, t)
	return err
}
