package apply

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Scan finds drift between targets and the state. It stats each managed
// target and hashes it only when its stat tuple (size, mtime, mode) changed,
// or on the full hash pass that runs at most once per FullHashInterval. Every
// stat and read has a timeout, and the whole scan has a budget: a path that
// does not answer in time is reported as DriftUnreadable and the scan goes on.
// Owned roots are walked for new files within the remaining budget.
func (e *Engine) Scan(ctx context.Context, opts ScanOptions) ([]Drift, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	now := e.Now()
	deadline := time.Now().Add(e.ScanBudget)
	full := opts.FullHash || st.LastFullHash.IsZero() || now.Sub(st.LastFullHash) >= FullHashInterval
	complete := true

	targets := make([]model.Target, 0, len(st.Targets))
	for t := range st.Targets {
		if inFilter(opts.Paths, t) {
			targets = append(targets, t)
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })

	var out []Drift
	for _, t := range targets {
		ts := st.Targets[t]
		d, ok, err := e.scanOne(ctx, t, ts, full, deadline)
		if err != nil {
			return nil, err
		}
		if d.Kind == DriftUnreadable {
			complete = false
		}
		if !ok {
			// No drift. Refresh the stat cache and clear the drift clock.
			if d.Kind == "" {
				ts.ChangedAt = time.Time{}
				if d.info != nil {
					// A stricter mode that is not drift becomes the cached
					// one; ts.want keeps what the entry asked for.
					w := ts.want()
					ts.Size, ts.ModTime, ts.Mode = d.info.Size(), d.info.ModTime(), uint32(d.info.Mode().Perm())
					ts.Want = uint32(w)
				}
				st.Targets[t] = ts
			}
			continue
		}
		if d.Kind != DriftUnreadable {
			if ts.ChangedAt.IsZero() {
				ts.ChangedAt = now
				st.Targets[t] = ts
			}
			d.Since = ts.ChangedAt
		}
		out = append(out, d.Drift)
	}

	if len(opts.Paths) > 0 {
		out = append(out, e.scanNamedNew(ctx, st, opts.Paths, now)...)
	}
	if len(opts.Paths) == 0 {
		news, ok := e.scanRoots(ctx, st, deadline)
		if !ok {
			complete = false
		}
		seen := map[model.Target]bool{}
		for _, d := range news {
			seen[d.Target] = true
			if _, ok := st.Seen[d.Target]; !ok {
				st.Seen[d.Target] = now
			}
			d.Since = st.Seen[d.Target]
			out = append(out, d)
		}
		if ok {
			for t := range st.Seen {
				if !seen[t] {
					delete(st.Seen, t)
				}
			}
		}
	}

	if len(st.Outputs) > 0 {
		kept := out[:0]
		for _, d := range out {
			if !generated(st, d.Target) {
				kept = append(kept, d)
			}
		}
		out = kept
	}

	if full && complete && len(opts.Paths) == 0 {
		st.LastFullHash = now
	}
	if err := e.State.Save(st); err != nil {
		return nil, err
	}
	return out, nil
}

type scanned struct {
	Drift
	info fs.FileInfo
}

// scanOne checks one target. ok reports drift (DriftUnreadable included).
// A zero Kind with ok false means "clean, refresh the stat cache"; a
// non-zero Kind with ok false never happens.
func (e *Engine) scanOne(ctx context.Context, t model.Target, ts TargetState, full bool, deadline time.Time) (scanned, bool, error) {
	d := scanned{Drift: Drift{Target: t, Scope: ts.Scope}}
	abs, err := e.abs(t)
	if err != nil {
		return d, false, err
	}
	left := time.Until(deadline)
	if left <= 0 {
		d.Kind, d.Detail = DriftUnreadable, "scan budget exhausted"
		return d, true, nil
	}
	timeout := min(e.StatTimeout, left)
	info, err := bounded(ctx, timeout, func() (fs.FileInfo, error) { return e.fs.Lstat(abs) })
	switch {
	case errors.Is(err, fs.ErrNotExist):
		d.Kind = DriftDeleted
		return d, true, nil
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return d, false, err
	case err != nil:
		d.Kind, d.Detail = DriftUnreadable, err.Error()
		return d, true, nil
	}
	d.info = info
	if !info.Mode().IsRegular() {
		d.Kind, d.Detail = DriftModified, "no longer a regular file"
		return d, true, nil
	}
	mode := uint32(info.Mode().Perm())
	statSame := info.Size() == ts.Size && info.ModTime().Equal(ts.ModTime) && mode == ts.Mode
	if statSame && !full {
		return d, false, nil
	}
	left = time.Until(deadline)
	if left <= 0 {
		d.Kind, d.Detail = DriftUnreadable, "scan budget exhausted"
		return d, true, nil
	}
	if err := InsideHome(e.Home, abs); err != nil {
		// Never read through a link that leaves $HOME; capture holds it.
		d.Kind, d.Detail = DriftModified, err.Error()
		return d, true, nil
	}
	b, err := bounded(ctx, min(e.StatTimeout, left), func() ([]byte, error) { return e.fs.ReadFile(abs) })
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return d, false, err
		}
		d.Kind, d.Detail = DriftUnreadable, err.Error()
		return d, true, nil
	}
	h := hashOf(b)
	switch {
	case h != ts.Written:
		d.Kind, d.Hash = DriftModified, h
		return d, true, nil
	case mode != ts.Mode && !ModeAccepted(fs.FileMode(mode), ts.want()):
		d.Kind, d.Hash = DriftMode, h
		return d, true, nil
	}
	return d, false, nil
}

// scanNamedNew reports each named path that is an unmanaged regular file
// as DriftNew with Named set when an applying glob entry of the applied
// snapshot matches it (its source is not in the tree yet), or when it is
// inside an accepted owned root, baseline files included. A walk of the
// roots does not run when paths are named, and no directory is walked for
// globs: only a named file is new under a glob.
func (e *Engine) scanNamedNew(ctx context.Context, st *State, paths []model.Target, now time.Time) []Drift {
	var out []Drift
	var plan *manifest.Plan
	loaded := false
	for _, t := range paths {
		if _, managed := st.Targets[t]; managed {
			continue
		}
		if !loaded {
			loaded = true
			if st.Applied != "" {
				if snap, err := e.snapshot(ctx, st.Applied); err == nil {
					plan = snap.Plan
				}
			}
		}
		scope := model.ScopeShared
		if r, ok, err := plan.GlobNew(t); err != nil {
			continue
		} else if ok {
			scope = r.Entry.Scope()
		} else if root, ok := rootOf(&manifest.Plan{Roots: st.Roots}, t); ok {
			if root.Enclave != "" {
				scope = model.Scope(root.Enclave)
			}
		} else {
			continue
		}
		abs, err := e.abs(t)
		if err != nil {
			continue
		}
		info, err := e.fs.Lstat(abs)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		since, ok := st.Seen[t]
		if !ok {
			since = now
		}
		out = append(out, Drift{Target: t, Kind: DriftNew, Scope: scope, Since: since, Baseline: inBaseline(st, t), Named: true})
	}
	return out
}

// scanRoots walks each owned root for regular files the state does not
// manage. It reports ok false if the budget ran out before every walk ended.
func (e *Engine) scanRoots(ctx context.Context, st *State, deadline time.Time) ([]Drift, bool) {
	// A file under nested roots belongs to the deepest one.
	best := map[model.Target]Drift{}
	depth := map[model.Target]int{}
	ok := true
	for _, root := range st.Roots {
		left := time.Until(deadline)
		if left <= 0 {
			ok = false
			break
		}
		news, done := e.walkRoot(ctx, st, root, left, false)
		for _, d := range news {
			if n, seen := depth[d.Target]; !seen || len(root.Path) > n {
				best[d.Target], depth[d.Target] = d, len(root.Path)
			}
		}
		if !done {
			ok = false
		}
	}
	out := make([]Drift, 0, len(best))
	for _, d := range best {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, ok
}

// walkRoot walks one root in a goroutine and returns what it found when the
// walk ends or the time runs out, whichever comes first.
func (e *Engine) walkRoot(ctx context.Context, st *State, root manifest.Root, limit time.Duration, all bool) ([]Drift, bool) {
	abs, err := e.abs(root.Path)
	if err != nil {
		return nil, true
	}
	scope := model.ScopeShared
	if root.Enclave != "" {
		scope = model.Scope(root.Enclave)
	}
	// Managed files are never new. Baseline files (they predate their root)
	// are reported with Baseline set, so callers can show them; capture
	// skips them unless named. Both maps are copied: the walk may outlive
	// this call.
	managed := make(map[model.Target]bool, len(st.Targets))
	for t := range st.Targets {
		managed[t] = true
	}
	baseline := make(map[model.Target]bool, len(st.Baseline))
	for t := range st.Baseline {
		baseline[t] = true
	}
	// Ignored files (hold ignore, or the root's ignore globs) are never new.
	ignored := make(map[model.Target]bool, len(st.Ignored))
	for t := range st.Ignored {
		ignored[t] = true
	}
	// A baseline walk resolves a root that is itself a symlink to a
	// directory: the files behind it are on disk when the root is accepted,
	// and a later adopt copies them into a real directory there.
	start := abs
	if all {
		if li, err := e.fs.Lstat(abs); err == nil && li.Mode()&fs.ModeSymlink != 0 {
			start = abs + string(filepath.Separator)
		}
	}
	var (
		mu    sync.Mutex
		found []Drift
		stop  = make(chan struct{})
		done  = make(chan struct{})
	)
	go func() {
		defer close(done)
		_ = filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
			select {
			case <-stop:
				return filepath.SkipAll
			default:
			}
			if err != nil {
				return nil
			}
			if !d.Type().IsRegular() || isTempName(d.Name()) {
				return nil
			}
			rel, err := filepath.Rel(e.Home, p)
			if err != nil || strings.HasPrefix(rel, "..") {
				return nil
			}
			t := model.Target(filepath.ToSlash(rel))
			if managed[t] || !all && (ignored[t] || root.Ignored(t)) {
				return nil
			}
			mu.Lock()
			found = append(found, Drift{Target: t, Kind: DriftNew, Scope: scope, Baseline: baseline[t]})
			mu.Unlock()
			return nil
		})
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	finished := true
	select {
	case <-done:
	case <-timer.C:
		finished = false
	case <-ctx.Done():
		finished = false
	}
	close(stop)
	mu.Lock()
	defer mu.Unlock()
	return append([]Drift(nil), found...), finished
}

// generated reports whether t matches a task output glob of the last
// applied manifest.
func generated(st *State, t model.Target) bool {
	for _, g := range st.Outputs {
		if manifest.Match(g, string(t)) {
			return true
		}
	}
	return false
}

// Generated lists the files on disk that match a task `outputs` glob of the
// last applied manifest, sorted. A literal output is checked with one stat;
// a glob walks the directory of its fixed prefix within the scan budget.
// Status shows the list; scan and capture never report or take these files.
func (e *Engine) Generated(ctx context.Context) ([]model.Target, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(e.ScanBudget)
	found := map[model.Target]bool{}
	for _, g := range st.Outputs {
		if !manifest.IsGlob(g) {
			abs, err := e.abs(model.Target(g))
			if err != nil {
				continue
			}
			if info, err := e.fs.Lstat(abs); err == nil && info.Mode().IsRegular() {
				found[model.Target(g)] = true
			}
			continue
		}
		segs := strings.Split(g, "/")
		i := 0
		for i < len(segs) && !manifest.IsGlob(segs[i]) {
			i++
		}
		dir := e.Home
		if i > 0 {
			abs, err := e.abs(model.Target(strings.Join(segs[:i], "/")))
			if err != nil {
				continue
			}
			dir = abs
		}
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil || time.Now().After(deadline) {
				if err == nil {
					return filepath.SkipAll
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(e.Home, p)
			if err != nil || strings.HasPrefix(rel, "..") {
				return nil
			}
			if t := model.Target(filepath.ToSlash(rel)); manifest.Match(g, string(t)) {
				found[t] = true
			}
			return nil
		})
	}
	out := make([]model.Target, 0, len(found))
	for t := range found {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
