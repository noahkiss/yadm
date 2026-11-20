package manifest

import (
	"fmt"
	"path"
	"strings"
)

// IsGlob reports whether a target or pattern holds a glob character.
func IsGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

// Match reports whether a slash-separated name matches pattern. A `**`
// segment matches zero or more whole segments; every other segment uses
// path.Match, so `*` never crosses a slash. A malformed pattern matches
// nothing; ValidPattern reports why.
func Match(pattern, name string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegs(p, n []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			rest := p[1:]
			for len(rest) > 0 && rest[0] == "**" {
				rest = rest[1:]
			}
			if len(rest) == 0 {
				return true
			}
			for i := 0; i <= len(n); i++ {
				if matchSegs(rest, n[i:]) {
					return true
				}
			}
			return false
		}
		if len(n) == 0 {
			return false
		}
		ok, err := path.Match(p[0], n[0])
		if err != nil || !ok {
			return false
		}
		p, n = p[1:], n[1:]
	}
	return len(n) == 0
}

// ValidPattern checks a glob: a valid relative path whose segments are
// either `**` or a well-formed path.Match pattern.
func ValidPattern(pattern string) error {
	if err := validRel(pattern); err != nil {
		return err
	}
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "**" {
			continue
		}
		if strings.Contains(seg, "**") {
			return fmt.Errorf("%q: ** must be a whole segment", pattern)
		}
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("%q: %v", pattern, err)
		}
	}
	return nil
}

// staticPrefix returns the leading segments of a pattern that hold no glob
// character, joined, and the rest.
func staticPrefix(pattern string) (prefix, rest string) {
	segs := strings.Split(pattern, "/")
	i := 0
	for i < len(segs) && !IsGlob(segs[i]) {
		i++
	}
	return strings.Join(segs[:i], "/"), strings.Join(segs[i:], "/")
}

// validRel checks a slash-separated relative path: not empty, not absolute,
// no empty, "." or ".." segment, no backslash or control character.
func validRel(p string) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("%q: path must be relative", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return fmt.Errorf("%q: control character or backslash", p)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".", "..":
			return fmt.Errorf("%q: empty, \".\" or \"..\" segment", p)
		}
	}
	return nil
}
