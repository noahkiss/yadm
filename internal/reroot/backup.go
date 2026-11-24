package reroot

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// DefaultKeep is the number of bundles `yadm backups prune` keeps when
// neither --keep nor fleet.toml says otherwise.
const DefaultKeep = 3

// BackupDir is the directory of re-root backups for a source clone at
// source: `backups` beside it, outside the clone and the state directory
// (`$XDG_DATA_HOME/yadm/backups`).
func BackupDir(source string) string {
	return filepath.Join(filepath.Dir(source), "backups")
}

var bundleRE = regexp.MustCompile(`^(\d{8}T\d{6}Z)-([0-9a-f]{12})\.bundle$`)

// BundleName is the file name of the backup taken at at of a history
// whose head was old: `<UTC time>-<old head, 12 hex>.bundle`. Names sort by
// time.
func BundleName(at time.Time, old model.CommitID) string {
	h := string(old)
	if len(h) > 12 {
		h = h[:12]
	}
	return at.UTC().Format("20060102T150405Z") + "-" + h + ".bundle"
}

// Bundle is one backup file.
type Bundle struct {
	Path    string    `json:"path"`
	Name    string    `json:"name"`
	Taken   time.Time `json:"taken"`
	OldHead string    `json:"old_head"` // 12 hex
	Size    int64     `json:"size"`
}

// List returns the bundles in dir, newest first. A missing dir is empty.
// Files that do not match BundleName are not listed and never pruned.
func List(dir string) ([]Bundle, error) {
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []Bundle{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Bundle{}
	for _, e := range ents {
		m := bundleRE.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		at, err := time.Parse("20060102T150405Z", m[1])
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		out = append(out, Bundle{Path: filepath.Join(dir, e.Name()), Name: e.Name(), Taken: at, OldHead: m[2], Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Prune deletes all but the keep newest bundles in dir and returns the
// deleted ones. keep below 1 is refused: prune never deletes every backup.
func Prune(dir string, keep int) ([]Bundle, error) {
	if keep < 1 {
		return nil, fmt.Errorf("prune: keep must be at least 1, not %d", keep)
	}
	all, err := List(dir)
	if err != nil {
		return nil, err
	}
	var gone []Bundle
	for i, b := range all {
		if i < keep {
			continue
		}
		if err := os.Remove(b.Path); err != nil {
			return gone, err
		}
		gone = append(gone, b)
	}
	return gone, nil
}

// EnsureDir creates dir with mode 0700, refusing one that group or other
// can read.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}
