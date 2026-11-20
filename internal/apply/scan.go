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
					ts.Size, ts.ModTime = d.info.Size(), d.info.ModTime()
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
	case mode != ts.Mode:
		d.Kind, d.Hash = DriftMode, h
		return d, true, nil
	}
	return d, false, nil
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
		news, done := e.walkRoot(ctx, st, root, left)
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
func (e *Engine) walkRoot(ctx context.Context, st *State, root manifest.Root, limit time.Duration) ([]Drift, bool) {
	abs, err := e.abs(root.Path)
	if err != nil {
		return nil, true
	}
	scope := model.ScopeShared
	if root.Enclave != "" {
		scope = model.Scope(root.Enclave)
	}
	// Managed files and the baseline (files that predate their root) are
	// never new. Both maps are copied: the walk may outlive this call.
	managed := make(map[model.Target]bool, len(st.Targets)+len(st.Baseline))
	for t := range st.Targets {
		managed[t] = true
	}
	for t := range st.Baseline {
		managed[t] = true
	}
	var (
		mu    sync.Mutex
		found []Drift
		stop  = make(chan struct{})
		done  = make(chan struct{})
	)
	go func() {
		defer close(done)
		_ = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
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
			if managed[t] {
				return nil
			}
			mu.Lock()
			found = append(found, Drift{Target: t, Kind: DriftNew, Scope: scope})
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
