package sync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// FileLeases returns the Leases stored under LeaseDir in stateDir, one JSON
// file per holder. List drops expired leases.
func FileLeases(stateDir string) Leases {
	return fileLeases{dir: filepath.Join(stateDir, LeaseDir), now: time.Now}
}

type fileLeases struct {
	dir string
	now func() time.Time
}

func (l fileLeases) file(holder string) string {
	h := sha256.Sum256([]byte(holder))
	return filepath.Join(l.dir, hex.EncodeToString(h[:16])+".json")
}

// List returns the leases that have not expired, sorted by holder.
func (l fileLeases) List() ([]Lease, error) {
	ents, err := os.ReadDir(l.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := l.now()
	var out []Lease
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(l.dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var x Lease
		if json.Unmarshal(b, &x) != nil {
			continue
		}
		if !now.Before(x.Expires) {
			os.Remove(p)
			continue
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Holder < out[j].Holder })
	return out, nil
}

// Take records a lease and replaces any lease of the same holder. A lease
// must expire.
func (l fileLeases) Take(x Lease) error {
	if strings.TrimSpace(x.Holder) == "" {
		return fmt.Errorf("lease: empty holder")
	}
	if x.Expires.IsZero() {
		return fmt.Errorf("lease: no expiry; leases must expire")
	}
	for _, p := range x.Paths {
		if err := manifest.ValidPattern(p); err != nil {
			return fmt.Errorf("lease: %w", err)
		}
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(x)
	if err != nil {
		return err
	}
	p := l.file(x.Holder)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Release removes the holder's lease. Releasing a missing lease is not an error.
func (l fileLeases) Release(holder string) error {
	err := os.Remove(l.file(holder))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// leased reports whether a lease that has not expired names t. A lease path
// is a glob, or a directory that covers everything below it.
func leased(leases []Lease, t model.Target, now time.Time) bool {
	for _, x := range leases {
		if !x.Expires.IsZero() && !now.Before(x.Expires) {
			continue
		}
		for _, g := range x.Paths {
			if manifest.Match(g, string(t)) || strings.HasPrefix(string(t), strings.TrimSuffix(g, "/")+"/") {
				return true
			}
		}
	}
	return false
}
