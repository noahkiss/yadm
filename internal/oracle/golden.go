package oracle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Golden is one profile's oracle record as read back from disk.
type Golden struct {
	Manifest
	// Dir is the profile's record directory; Dir/content holds the
	// normalized bytes of every target.
	Dir string
}

// LoadGoldens reads every <dir>/<profile>/manifest.json, sorted by profile
// name.
func LoadGoldens(dir string) ([]Golden, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Golden
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(filepath.Join(p, "manifest.json"))
		if err != nil {
			continue
		}
		var g Golden
		if err := json.Unmarshal(b, &g.Manifest); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		g.Dir = p
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Profile.Name < out[j].Profile.Name })
	return out, nil
}

// Content returns the normalized golden bytes of a target.
func (g Golden) Content(target string) ([]byte, error) {
	return os.ReadFile(filepath.Join(g.Dir, "content", filepath.FromSlash(target)))
}

// Mismatch reasons.
const (
	MissMissing  = "missing"       // the golden has the target, the home does not
	MissDangling = "dangling"      // the golden target is a dangling link; the home has a file
	MissContent  = "content"       // bytes differ
	MissMode     = "mode"          // bytes match, permission bits differ
	MissExtra    = "extra"         // the home has a file the golden lacks
	MissNotFile  = "not-a-file"    // the home path is a directory or symlink
	MissCipher   = "golden-cipher" // the golden holds ciphertext (a keyless profile)
)

// Mismatch is one target that differs from the golden.
type Mismatch struct {
	Path   string
	Reason string
	Detail string // modes or sizes; never content
}

// Comparison is the result of comparing a home with a golden.
type Comparison struct {
	Matched    int
	Mismatches []Mismatch
}

// Counts groups mismatches by reason.
func (c Comparison) Counts() map[string]int {
	m := map[string]int{}
	for _, x := range c.Mismatches {
		m[x.Reason]++
	}
	return m
}

// CompareHome compares the regular files under home with the golden's
// targets: content (normalized with replace) and permission bits. Paths in
// skip are not walked (state kept inside $HOME, for example). A golden
// dangling target matches when the home has no file there.
func CompareHome(g Golden, home string, replace [][2]string, skip func(rel string) bool) (Comparison, error) {
	var c Comparison
	seen := map[string]bool{}
	for _, t := range g.Targets {
		seen[t.Path] = true
		p := filepath.Join(home, filepath.FromSlash(t.Path))
		fi, err := os.Lstat(p)
		if t.Kind == KindDangling {
			if err != nil {
				c.Matched++
			} else {
				c.Mismatches = append(c.Mismatches, Mismatch{Path: t.Path, Reason: MissDangling})
			}
			continue
		}
		if err != nil {
			c.Mismatches = append(c.Mismatches, Mismatch{Path: t.Path, Reason: MissMissing})
			continue
		}
		if !fi.Mode().IsRegular() {
			c.Mismatches = append(c.Mismatches, Mismatch{Path: t.Path, Reason: MissNotFile, Detail: fi.Mode().Type().String()})
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return c, err
		}
		norm := Normalize(raw, replace)
		sum := sha256.Sum256(norm)
		mode := fmt.Sprintf("%04o", fi.Mode().Perm())
		switch {
		case hex.EncodeToString(sum[:]) != t.SHA256:
			r := MissContent
			if t.Ciphertext {
				r = MissCipher
			}
			c.Mismatches = append(c.Mismatches, Mismatch{Path: t.Path, Reason: r,
				Detail: fmt.Sprintf("size %d vs %d", len(norm), t.Size)})
		case mode != t.Mode:
			c.Mismatches = append(c.Mismatches, Mismatch{Path: t.Path, Reason: MissMode, Detail: mode + " vs " + t.Mode})
		default:
			c.Matched++
		}
	}
	err := filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(home, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if skip != nil && skip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !seen[rel] {
			c.Mismatches = append(c.Mismatches, Mismatch{Path: rel, Reason: MissExtra})
		}
		return nil
	})
	sort.Slice(c.Mismatches, func(i, j int) bool { return c.Mismatches[i].Path < c.Mismatches[j].Path })
	return c, err
}

// HashFile is the SHA-256 of normalized bytes, as golden entries record it.
func HashFile(b []byte, replace [][2]string) string {
	sum := sha256.Sum256(Normalize(b, replace))
	return hex.EncodeToString(sum[:])
}

// ExclusiveHashes returns the content hashes that occur among the targets of
// the profiles in only but in none of the profiles in others: content one
// group must hold and the other must never see. Ciphertext and empty files
// are left out.
func ExclusiveHashes(only, others []Golden) map[string]string {
	shared := map[string]bool{}
	for _, g := range others {
		for _, t := range g.Targets {
			shared[t.SHA256] = true
		}
	}
	empty := sha256.Sum256(nil)
	nl := sha256.Sum256([]byte("\n"))
	skip := map[string]bool{hex.EncodeToString(empty[:]): true, hex.EncodeToString(nl[:]): true}
	out := map[string]string{}
	for _, g := range only {
		for _, t := range g.Targets {
			if t.SHA256 == "" || t.Ciphertext || shared[t.SHA256] || skip[t.SHA256] {
				continue
			}
			out[t.SHA256] = t.Path
		}
	}
	return out
}

// Denormalize is the inverse of Normalize for seeding a home with golden
// bytes: each (token, value) pair is replaced in order.
func Denormalize(b []byte, pairs [][2]string) []byte {
	for _, kv := range pairs {
		b = bytes.ReplaceAll(b, []byte(kv[0]), []byte(kv[1]))
	}
	return b
}
