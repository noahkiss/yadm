package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Adopt takes over targets another dotfiles tool left, and some tools
// deliver a target as a symlink to a variant file or directory. Nothing in
// $HOME may stay a symlink (design section 1), so adopt materializes:
//
//   - a target that is a symlink to a regular file whose bytes equal the
//     render is replaced by a regular file with those bytes;
//   - a directory symlink above a target, pointing into $HOME, is replaced
//     by a real directory holding a copy of what it pointed to. Without
//     this, later writes would land in the other tool's variant directory.
//
// The link's target is never changed or removed.

// materializeLink plans a symlinked target for adopt: a link to a regular
// file with the rendered bytes becomes a write of those bytes (the rename
// replaces the link, not what it points to). Anything else is held.
func (e *Engine) materializeLink(ctx context.Context, snap *Snapshot, r manifest.Resolved, s step, ts TargetState, hold func(string) (step, error)) (step, error) {
	info, err := os.Stat(s.abs)
	if err != nil || !info.Mode().IsRegular() {
		return hold("target is a symlink that does not point to a regular file; not replaced")
	}
	b, err := os.ReadFile(s.abs)
	if err != nil {
		return hold("target is a symlink that cannot be read: " + err.Error())
	}
	d, err := e.produce(ctx, snap, r, b, ts.SourceBlob)
	if err != nil {
		return hold("target is a symlink; the source does not render: " + err.Error())
	}
	if !bytes.Equal(b, d.bytes) {
		return hold("target is a symlink whose content differs from the source; not replaced")
	}
	s.d = d
	s.live.bytes = b
	s.Kind, s.Reason = ActWrite, "materialize symlink"
	return s, nil
}

// dirLinks lists, for the plan's targets, each directory symlink above a
// target that points to a directory inside $HOME, outermost first. Links
// that point outside $HOME, or to something that is not a directory, are
// left alone.
func (e *Engine) dirLinks(snap *Snapshot) []model.Target {
	if snap == nil || snap.Plan == nil {
		return nil
	}
	home, err := filepath.EvalSymlinks(e.Home)
	if err != nil {
		return nil
	}
	seen := map[model.Target]bool{}
	var out []model.Target
	for t := range snap.Plan.Targets {
		parts := strings.Split(string(t), "/")
		for i := 1; i < len(parts); i++ {
			p := model.Target(strings.Join(parts[:i], "/"))
			if seen[p] {
				continue
			}
			seen[p] = true
			abs := filepath.Join(e.Home, filepath.FromSlash(string(p)))
			info, err := os.Lstat(abs)
			if err != nil || info.Mode()&fs.ModeSymlink == 0 {
				continue
			}
			to, err := filepath.EvalSymlinks(abs)
			if err != nil {
				continue
			}
			ti, err := os.Stat(to)
			if err != nil || !ti.IsDir() || !within(home, to) {
				continue
			}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := strings.Count(string(out[i]), "/"), strings.Count(string(out[j]), "/"); a != b {
			return a < b
		}
		return out[i] < out[j]
	})
	return out
}

func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../")
}

// materializeDirLinks replaces each directory link dirLinks finds with a
// real directory holding a copy of its content, outermost first. A link
// below one already materialized is found again inside the copy. It
// returns the links it replaced (or would replace, with dry), and the
// regular files it copied in.
func (e *Engine) materializeDirLinks(snap *Snapshot, dry bool) ([]model.Target, []model.Target, error) {
	var done, files []model.Target
	for range 8 { // nested links: each round exposes the next level
		links := e.dirLinks(snap)
		if len(links) == 0 {
			break
		}
		if dry {
			return append(done, links...), files, nil
		}
		for _, p := range links {
			copied, err := e.materializeDir(p)
			files = append(files, copied...)
			if err != nil {
				return done, files, fmt.Errorf("materialize %s: %w", p, err)
			}
			done = append(done, p)
		}
	}
	return done, files, nil
}

// baselineCopies records in the baseline each copied file that no plan
// target names and the state does not manage. Those files were on disk
// behind the link; an owned root over them must not capture them as new.
func (e *Engine) baselineCopies(snap *Snapshot, copied []model.Target) error {
	if len(copied) == 0 {
		return nil
	}
	st, err := e.loadState()
	if err != nil {
		return err
	}
	if st.Baseline == nil {
		st.Baseline = map[model.Target]time.Time{}
	}
	now := e.Now()
	for _, t := range copied {
		if _, planned := snap.Plan.Targets[t]; planned {
			continue
		}
		if _, managed := st.Targets[t]; managed {
			continue
		}
		if _, ok := st.Baseline[t]; !ok {
			st.Baseline[t] = now
		}
	}
	return e.State.Save(st)
}

// materializeDir copies what the link at p points to into a temporary
// sibling, then swaps it in for the link. The original directory stays. It
// returns the regular files it copied, as targets.
func (e *Engine) materializeDir(p model.Target) ([]model.Target, error) {
	abs := filepath.Join(e.Home, filepath.FromSlash(string(p)))
	from, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(from)
	if err != nil {
		return nil, err
	}
	tmp := abs + ".yadm-materialize"
	if err := os.RemoveAll(tmp); err != nil {
		return nil, err
	}
	var rels []string
	if err := copyTree(from, tmp, info.Mode().Perm(), "", &rels); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	li, err := os.Lstat(abs)
	if err != nil || li.Mode()&fs.ModeSymlink == 0 {
		_ = os.RemoveAll(tmp)
		return nil, errors.New("no longer a symlink")
	}
	if err := os.Remove(abs); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, abs); err != nil {
		return nil, err
	}
	out := make([]model.Target, len(rels))
	for i, r := range rels {
		out[i] = model.Target(string(p) + "/" + r)
	}
	return out, nil
}

// copyTree copies a directory: regular files with their modes, symlinks as
// symlinks with the same text, directories recursively. It appends the
// slash path of each regular file it copied, relative to the top, to files.
func copyTree(from, to string, mode fs.FileMode, rel string, files *[]string) error {
	if err := os.Mkdir(to, mode|0o700); err != nil {
		return err
	}
	ents, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, de := range ents {
		src, dst := filepath.Join(from, de.Name()), filepath.Join(to, de.Name())
		info, err := os.Lstat(src)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			l, err := os.Readlink(src)
			if err != nil {
				return err
			}
			if err := os.Symlink(l, dst); err != nil {
				return err
			}
		case info.IsDir():
			if err := copyTree(src, dst, info.Mode().Perm(), path.Join(rel, de.Name()), files); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, info.Mode().Perm()); err != nil {
				return err
			}
			*files = append(*files, path.Join(rel, de.Name()))
		}
	}
	return os.Chmod(to, mode)
}
