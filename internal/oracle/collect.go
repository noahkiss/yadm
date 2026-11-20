package oracle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// HomeToken replaces the sandbox home path in recorded content.
const HomeToken = "@@HOME@@"

// cipherMagic is how transcrypt ciphertext begins: base64 of "Salted__".
var cipherMagic = []byte("U2FsdGVk")

// Target kinds.
const (
	KindPlain    = "plain"    // a tracked file at its own path
	KindLink     = "link"     // reached through a yadm alternate symlink
	KindTemplate = "template" // a real file rendered from a template
	KindUnknown  = "unknown"  // a real file nothing tracked accounts for
	KindDangling = "dangling" // a symlink whose target does not exist
)

// Entry is one file a profile's home holds.
type Entry struct {
	// Path is relative to $HOME, slash-separated.
	Path string `json:"path"`
	Kind string `json:"kind"`
	// Source is the tracked path the content comes from.
	Source   string `json:"source,omitempty"`
	Template bool   `json:"template"`
	// Mode is the permission bits of the dereferenced file, octal.
	Mode string `json:"mode,omitempty"`
	Size int64  `json:"size"`
	// SHA256 is of the normalized content.
	SHA256 string `json:"sha256,omitempty"`
	// Normalized is true when the sandbox home was replaced by HomeToken.
	Normalized bool `json:"normalized"`
	Ciphertext bool `json:"ciphertext"`
	// Link is the first symlink on the way to the content: the path that
	// is a link, relative to $HOME, and its link text.
	LinkAt   string `json:"link_at,omitempty"`
	LinkText string `json:"link_text,omitempty"`
	// TrackedSymlink is true when git tracks Source as a symlink.
	TrackedSymlink bool `json:"tracked_symlink,omitempty"`

	content []byte
}

// Collected is everything found in a sandbox home.
type Collected struct {
	Targets []Entry
	// Unresolved are paths with a ## component, as they sit on disk.
	// Symlinks inside them are recorded, not followed.
	Unresolved []Entry
	// SelfLinks are symlinks named like their parent directory, the
	// self-referential links yadm 3.5.0 can leave inside a tagged directory.
	SelfLinks []string
	Warnings  []string
}

// Tracked describes the repo's index.
type Tracked struct {
	Files    map[string]bool
	Symlinks map[string]bool
}

// Collect walks home. templates maps a target path to its template source.
func Collect(home string, tr Tracked, templates map[string]string, replace [][2]string) (*Collected, error) {
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return nil, err
	}
	c := &Collected{}
	w := walker{home: home, realHome: realHome, tr: tr, templates: templates, replace: replace, c: c}
	if err := w.dir(home, "", "", "", map[string]bool{realHome: true}); err != nil {
		return nil, err
	}
	sort.Slice(c.Targets, func(i, j int) bool { return c.Targets[i].Path < c.Targets[j].Path })
	sort.Slice(c.Unresolved, func(i, j int) bool { return c.Unresolved[i].Path < c.Unresolved[j].Path })
	sort.Strings(c.SelfLinks)
	return c, nil
}

type walker struct {
	home, realHome string
	tr             Tracked
	templates      map[string]string
	replace        [][2]string
	c              *Collected
}

// dir walks physical directory phys, which $HOME shows at logical path rel.
// linkAt and linkText name the first symlink crossed to get here.
func (w *walker) dir(phys, rel, linkAt, linkText string, stack map[string]bool) error {
	ents, err := os.ReadDir(phys)
	if err != nil {
		return err
	}
	for _, de := range ents {
		name := de.Name()
		p := filepath.Join(phys, name)
		r := path.Join(rel, name)
		if strings.Contains(name, "##") && linkAt == "" {
			if err := w.unresolved(p, r); err != nil {
				return err
			}
			continue
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		la, lt := linkAt, linkText
		if fi.Mode()&os.ModeSymlink != 0 {
			text, _ := os.Readlink(p)
			if la == "" {
				la, lt = r, text
			}
			st, err := os.Stat(p)
			if err != nil {
				w.c.Targets = append(w.c.Targets, Entry{Path: r, Kind: KindDangling, LinkAt: la, LinkText: lt,
					TrackedSymlink: w.tr.Symlinks[r]})
				continue
			}
			if st.IsDir() {
				real, err := filepath.EvalSymlinks(p)
				if err != nil {
					return err
				}
				if stack[real] {
					w.c.Warnings = append(w.c.Warnings, fmt.Sprintf("symlink cycle at %s (link text %q), not followed", r, text))
					continue
				}
				stack[real] = true
				err = w.dir(real, r, la, lt, stack)
				delete(stack, real)
				if err != nil {
					return err
				}
				continue
			}
			if err := w.file(p, r, la, lt); err != nil {
				return err
			}
			continue
		}
		if fi.IsDir() {
			real := filepath.Join(phys, name)
			if err := w.dir(real, r, la, lt, stack); err != nil {
				return err
			}
			continue
		}
		if fi.Mode().IsRegular() {
			if err := w.file(p, r, la, lt); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *walker) file(p, r, linkAt, linkText string) error {
	e := Entry{Path: r, LinkAt: linkAt, LinkText: linkText}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	src, err := filepath.Rel(w.realHome, real)
	if err != nil || strings.HasPrefix(src, "..") {
		w.c.Warnings = append(w.c.Warnings, fmt.Sprintf("%s resolves outside home", r))
		src = ""
	}
	src = filepath.ToSlash(src)
	tsrc, isTemplate := w.templates[r]
	switch {
	case isTemplate && src == r:
		e.Kind, e.Template, e.Source = KindTemplate, true, tsrc
	case linkAt != "":
		e.Kind, e.Source = KindLink, src
	case w.tr.Files[r]:
		e.Kind, e.Source = KindPlain, r
	default:
		e.Kind = KindUnknown
	}
	if linkAt != "" && w.tr.Symlinks[linkAt] {
		e.TrackedSymlink = true
	}
	if err := w.fill(&e, p); err != nil {
		return err
	}
	w.c.Targets = append(w.c.Targets, e)
	return nil
}

func (w *walker) fill(e *Entry, p string) error {
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	norm := Normalize(raw, w.replace)
	e.Mode = fmt.Sprintf("%04o", st.Mode().Perm())
	e.Size = int64(len(norm))
	e.Normalized = !bytes.Equal(norm, raw)
	e.Ciphertext = bytes.HasPrefix(raw, cipherMagic)
	sum := sha256.Sum256(norm)
	e.SHA256 = hex.EncodeToString(sum[:])
	e.content = norm
	return nil
}

// unresolved records a ## path and everything under it without following
// symlinks.
func (w *walker) unresolved(p, r string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		text, _ := os.Readlink(p)
		w.c.Unresolved = append(w.c.Unresolved, Entry{Path: r, Kind: "symlink", LinkAt: r, LinkText: text,
			TrackedSymlink: w.tr.Symlinks[r]})
		if path.Base(path.Dir(r)) == path.Base(r) {
			w.c.SelfLinks = append(w.c.SelfLinks, r)
		}
	case fi.IsDir():
		ents, err := os.ReadDir(p)
		if err != nil {
			return err
		}
		for _, de := range ents {
			if err := w.unresolved(filepath.Join(p, de.Name()), path.Join(r, de.Name())); err != nil {
				return err
			}
		}
	case fi.Mode().IsRegular():
		kind := KindPlain
		if !w.tr.Files[r] {
			kind = KindUnknown
		}
		e := Entry{Path: r, Kind: kind, Source: r}
		if err := w.fill(&e, p); err != nil {
			return err
		}
		e.content = nil // unresolved content is not stored
		w.c.Unresolved = append(w.c.Unresolved, e)
	}
	return nil
}

// Normalize replaces each (from, to) pair in order. Callers pass the longest
// sandbox paths first.
func Normalize(b []byte, replace [][2]string) []byte {
	for _, kv := range replace {
		if kv[0] == "" {
			continue
		}
		b = bytes.ReplaceAll(b, []byte(kv[0]), []byte(kv[1]))
	}
	return b
}
