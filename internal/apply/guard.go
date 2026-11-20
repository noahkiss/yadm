package apply

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

// Guard is the sync.RemoteGuard of this package. It refuses a fetched source
// whose manifest weakens protection against the source this machine runs
// now, until each weakening is allowed here with the same allow-list kinds
// apply uses: KindProtection for a target (`yadm protection allow`), KindRoot
// for an owned root (`yadm root allow`).
//
// Weakening means:
//   - a target both sources plan loses its enclave, a seal key or regions,
//     or moves them to another enclave (weakerBy);
//   - a new owned root, or one whose enclave changed, covers a path the
//     current source protects (a protected target, or a path inside an
//     enclave root), so new files there would be captured with less
//     protection.
//
// A new plain root over unprotected paths is not refused here: apply keeps
// it inactive (root_untrusted) until it is allowed.
type Guard struct {
	List tasks.AllowList // the local allow list; nil allows nothing weaker
}

func (g *Guard) allowed(kind extexec.Kind, name, hash string) bool {
	return g != nil && g.List != nil && g.List.Allowed(kind, name, hash)
}

// Allow implements sync.RemoteGuard.
func (g *Guard) Allow(_ context.Context, from, to *Snapshot) (bool, string, error) {
	why := g.Weakened(from, to)
	if len(why) == 0 {
		return true, "", nil
	}
	return false, strings.Join(why, "; "), nil
}

// Weakened lists each weakening of to against from that is not allowed
// here, with the command that allows it.
func (g *Guard) Weakened(from, to *Snapshot) []string {
	if from == nil || to == nil || from.Plan == nil || to.Plan == nil {
		return nil
	}
	var why []string
	targets := make([]model.Target, 0, len(to.Plan.Targets))
	for t := range to.Plan.Targets {
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	for _, t := range targets {
		old, ok := from.Plan.Targets[t]
		if !ok {
			continue
		}
		next := protOf(to.Plan.Targets[t].Entry)
		w := weakerBy(protOf(old.Entry), next)
		if len(w) == 0 || g.allowed(KindProtection, string(t), protectionHash(t, next)) {
			continue
		}
		why = append(why, fmt.Sprintf("%s: %s (yadm protection allow %s)", t, strings.Join(w, ", "), t))
	}
	oldRoots := map[model.Target]manifest.Root{}
	for _, r := range from.Plan.Roots {
		oldRoots[r.Path] = r
	}
	for _, r := range to.Plan.Roots {
		o, had := oldRoots[r.Path]
		if had && o.Enclave == r.Enclave {
			continue
		}
		cover := g.coversProtected(from, r)
		if cover == "" || g.allowed(KindRoot, string(r.Path), rootHash(r)) {
			continue
		}
		why = append(why, fmt.Sprintf("owned root %s (enclave %q) covers %s (yadm root allow %s)", r.Path, r.Enclave, cover, r.Path))
	}
	return why
}

// coversProtected names a path the current source protects that root r
// would hold with weaker protection, or "".
func (g *Guard) coversProtected(from *Snapshot, r manifest.Root) string {
	in := func(t model.Target) bool {
		return t == r.Path || strings.HasPrefix(string(t), string(r.Path)+"/")
	}
	var hits []string
	for t, res := range from.Plan.Targets {
		if !in(t) {
			continue
		}
		p := protOf(res.Entry)
		if (p.Enclave != "" && p.Enclave != r.Enclave) || len(p.Seal) > 0 || p.Regions {
			hits = append(hits, string(t))
		}
	}
	for _, o := range from.Plan.Roots {
		if o.Enclave == "" || o.Enclave == r.Enclave {
			continue
		}
		// The new root sits inside, or wraps, an enclave root.
		if in(o.Path) || strings.HasPrefix(string(r.Path), string(o.Path)+"/") || o.Path == r.Path {
			hits = append(hits, "enclave root "+string(o.Path))
		}
	}
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return hits[0]
}
