package rules

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/noahkiss/yadm/internal/model"
)

// RegionEnclaves returns the enclaves whose sealed regions b marks, sorted
// and without duplicates. Markers that do not parse fail.
func RegionEnclaves(b []byte) ([]model.EnclaveName, error) {
	regs, vio := parseRegions(b)
	if len(vio) > 0 {
		return nil, fmt.Errorf("%s: %s", vio[0].Path, vio[0].Detail)
	}
	var out []model.EnclaveName
	for _, r := range regs {
		if !slices.Contains(out, r.enclave) {
			out = append(out, r.enclave)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Region marker words, after a line-comment prefix.
const (
	markerSeal   = "yadm:seal"
	markerEnd    = "yadm:end"
	regionPrefix = "yadm:sealed 1 " // crypt.RegionPrefix: a region token in the source
)

// commentTokens are the line-comment prefixes a marker may follow.
var commentTokens = []string{"#", "//", ";", "--", "%", "\"", "!"}

// region is one marked region of a text file.
type region struct {
	enclave  model.EnclaveName
	label    string
	prefix   string // bytes before the marker word on the start line
	eol      string // the start line's terminator
	bodyFrom int
	bodyTo   int
}

func (r region) id() string { return string(r.enclave) + ":" + r.label }

// regionPath names a region in a Violation.
func (r region) path() string { return "region " + r.id() }

// splitLines splits b into lines that keep their terminators.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

func trimEOL(line []byte) (content []byte, eol string) {
	switch {
	case bytes.HasSuffix(line, []byte("\r\n")):
		return line[:len(line)-2], "\r\n"
	case bytes.HasSuffix(line, []byte("\n")):
		return line[:len(line)-1], "\n"
	}
	return line, ""
}

// marker parses a line as a marker. It returns the comment prefix (with
// surrounding space), the marker word and its arguments.
func marker(content []byte) (prefix, word string, args []string, ok bool) {
	s := string(content)
	t := strings.TrimLeft(s, " \t")
	var tok string
	for _, c := range commentTokens {
		if strings.HasPrefix(t, c) {
			tok = c
			break
		}
	}
	if tok == "" {
		return "", "", nil, false
	}
	rest := strings.TrimLeft(t[len(tok):], " \t")
	prefix = s[:len(s)-len(rest)]
	for _, w := range []string{markerSeal, markerEnd} {
		if rest == w || strings.HasPrefix(rest, w+" ") || strings.HasPrefix(rest, w+"\t") {
			return prefix, w, strings.Fields(rest[len(w):]), true
		}
	}
	return "", "", nil, false
}

// parseRegions finds the marked regions of b. A malformed or unbalanced
// marker is reported as a Violation.
func parseRegions(b []byte) ([]region, []Violation) {
	var out []region
	var vio []Violation
	var open *region
	seen := map[string]bool{}
	off := 0
	for _, line := range splitLines(b) {
		content, eol := trimEOL(line)
		prefix, word, args, ok := marker(content)
		next := off + len(line)
		if ok {
			switch word {
			case markerSeal:
				if open != nil {
					vio = append(vio, Violation{Path: open.path(), Kind: RegionMarkerLost, Detail: "a region starts inside another region"})
					return nil, vio
				}
				if len(args) == 0 {
					vio = append(vio, Violation{Path: "region", Kind: RegionMarkerLost, Detail: "a seal marker names no enclave"})
					return nil, vio
				}
				r := region{enclave: model.EnclaveName(args[0]), label: strings.Join(args[1:], " "), prefix: prefix, eol: eol, bodyFrom: next}
				if seen[r.id()] {
					vio = append(vio, Violation{Path: r.path(), Kind: RegionMarkerLost, Detail: "two regions share an enclave and label"})
					return nil, vio
				}
				seen[r.id()] = true
				open = &r
			case markerEnd:
				if open == nil {
					vio = append(vio, Violation{Path: "region", Kind: RegionMarkerLost, Detail: "an end marker has no start"})
					return nil, vio
				}
				open.bodyTo = off
				out = append(out, *open)
				open = nil
			}
		}
		off = next
	}
	if open != nil {
		vio = append(vio, Violation{Path: open.path(), Kind: RegionMarkerLost, Detail: "a region has no end marker"})
		return nil, vio
	}
	return out, nil
}

// regionToken extracts the token from a source region body.
func regionToken(body []byte) (string, bool) {
	lines := splitLines(body)
	if len(lines) != 1 {
		return "", false
	}
	content, _ := trimEOL(lines[0])
	t := strings.TrimSpace(string(content))
	for _, c := range commentTokens {
		if strings.HasPrefix(t, c) {
			t = strings.TrimSpace(t[len(c):])
			break
		}
	}
	if !strings.HasPrefix(t, regionPrefix) {
		return "", false
	}
	return t, true
}

// regionsToTarget opens the regions of the source file at path.
func regionsToTarget(src []byte, path model.SourcePath, s Sealer) ([]byte, error) {
	regs, vio := parseRegions(src)
	if len(vio) > 0 {
		return nil, fmt.Errorf("source regions: %s: %s", vio[0].Path, vio[0].Detail)
	}
	out := src
	for i := len(regs) - 1; i >= 0; i-- {
		r := regs[i]
		body := src[r.bodyFrom:r.bodyTo]
		var plain []byte
		if len(body) > 0 {
			tok, ok := regionToken(body)
			if !ok {
				return nil, fmt.Errorf("source %s: body is not one sealed token line", r.path())
			}
			if s.CanOpen(r.enclave) {
				name, err := partName(path, r.label)
				if err != nil {
					return nil, err
				}
				plain, err = s.OpenRegion(r.enclave, name, tok)
				if err != nil {
					return nil, fmt.Errorf("open %s: %w", r.path(), err)
				}
			}
		}
		out = splice(out, r.bodyFrom, r.bodyTo, plain)
	}
	return out, nil
}

// regionsToSource seals the regions of a target. It returns the sealed text,
// the region plaintexts for the leak check, and any Violations.
func regionsToSource(target, prev []byte, path model.SourcePath, s Sealer) ([]byte, [][]byte, []Violation, error) {
	regs, vio := parseRegions(target)
	if len(vio) > 0 {
		return nil, nil, vio, nil
	}
	prevBody := map[string][]byte{}
	var prevRegs []region
	if prev != nil {
		var pv []Violation
		prevRegs, pv = parseRegions(prev)
		if len(pv) > 0 {
			return nil, nil, nil, fmt.Errorf("previous source regions: %s: %s", pv[0].Path, pv[0].Detail)
		}
		for _, r := range prevRegs {
			prevBody[r.id()] = prev[r.bodyFrom:r.bodyTo]
		}
	}
	have := map[string]bool{}
	for _, r := range regs {
		have[r.id()] = true
	}
	for _, r := range prevRegs {
		if !have[r.id()] {
			vio = append(vio, Violation{Path: r.path(), Kind: RegionMarkerLost, Detail: "the region's markers are gone or changed"})
		}
	}
	var plains [][]byte
	out := target
	for i := len(regs) - 1; i >= 0; i-- {
		r := regs[i]
		body := target[r.bodyFrom:r.bodyTo]
		var repl []byte
		if s.CanOpen(r.enclave) {
			name, err := partName(path, r.label)
			if err != nil {
				return nil, nil, nil, err
			}
			tok, err := s.SealRegion(r.enclave, name, body)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("seal %s: %w", r.path(), err)
			}
			eol := r.eol
			if eol == "" {
				eol = "\n"
			}
			repl = []byte(r.prefix + tok + eol)
			plains = append(plains, body)
		} else {
			pb, ok := prevBody[r.id()]
			switch {
			case !ok:
				vio = append(vio, Violation{Path: r.path(), Kind: RegionNotMember, Detail: "a non-member cannot seal a new region"})
			case len(body) == 0 || bytes.Equal(body, pb):
				repl = pb
			default:
				vio = append(vio, Violation{Path: r.path(), Kind: RegionNotMember, Detail: "a non-member wrote text inside a sealed region"})
			}
		}
		out = splice(out, r.bodyFrom, r.bodyTo, repl)
	}
	return out, plains, vio, nil
}
