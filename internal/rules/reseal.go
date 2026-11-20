package rules

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/noahkiss/yadm/internal/model"
)

// Reseal rewrites every sealed value and region of one enclave in a source
// file under the enclave's current epoch, after a remove or rotate. Tokens
// of other enclaves and every other byte stay as they are. Deterministic
// sealing makes a token already at the current epoch come back unchanged.
//
// The plaintext exists only in memory. A token that does not open is an
// error: Reseal never drops or replaces a sealed part it cannot read.
func Reseal(source []byte, spec Spec, enclave model.EnclaveName, s Sealer) ([]byte, error) {
	if !s.CanOpen(enclave) {
		return nil, fmt.Errorf("reseal %s: not a member", enclave)
	}
	out := source
	if spec.Regions {
		var err error
		if out, err = resealRegions(out, enclave, s); err != nil {
			return nil, err
		}
	}
	if !spec.structured() {
		return out, nil
	}
	c, err := compile(spec)
	if err != nil {
		return nil, err
	}
	for _, r := range c.seals {
		if r.enclave != enclave {
			continue
		}
		root, err := c.f.parse(out)
		if err != nil {
			return nil, fmt.Errorf("reseal: source does not parse: %w", err)
		}
		paths := matchPaths(root, []pattern{r.pat})
		for i := len(paths) - 1; i >= 0; i-- {
			p := paths[i]
			root, err := c.f.parse(out)
			if err != nil {
				return nil, err
			}
			n := find(root, p)
			if n == nil || n.kind != kString || !strings.HasPrefix(n.str, valuePrefix) {
				continue
			}
			pt, err := s.OpenValue(r.enclave, r.pat.src, n.str)
			if err != nil {
				return nil, fmt.Errorf("reseal %s: open: %w", joinPath(p), err)
			}
			tok, err := s.SealValue(r.enclave, r.pat.src, pt)
			if err != nil {
				return nil, fmt.Errorf("reseal %s: seal: %w", joinPath(p), err)
			}
			if tok == n.str {
				continue
			}
			if out, err = edit(c.f, out, func(root *node) ([]byte, error) {
				return c.f.setString(out, find(root, p), tok)
			}); err != nil {
				return nil, fmt.Errorf("reseal %s: %w", joinPath(p), err)
			}
		}
	}
	return out, nil
}

// resealRegions reseals the region tokens of one enclave in a source file.
func resealRegions(src []byte, enclave model.EnclaveName, s Sealer) ([]byte, error) {
	regs, vio := parseRegions(src)
	if len(vio) > 0 {
		return nil, fmt.Errorf("source regions: %s: %s", vio[0].Path, vio[0].Detail)
	}
	out := src
	for i := len(regs) - 1; i >= 0; i-- {
		r := regs[i]
		if r.enclave != enclave {
			continue
		}
		body := src[r.bodyFrom:r.bodyTo]
		if len(body) == 0 {
			continue
		}
		tok, ok := regionToken(body)
		if !ok {
			return nil, fmt.Errorf("source %s: body is not one sealed token line", r.path())
		}
		pt, err := s.OpenRegion(r.enclave, r.label, tok)
		if err != nil {
			return nil, fmt.Errorf("reseal %s: open: %w", r.path(), err)
		}
		fresh, err := s.SealRegion(r.enclave, r.label, pt)
		if err != nil {
			return nil, fmt.Errorf("reseal %s: seal: %w", r.path(), err)
		}
		if fresh == tok {
			continue
		}
		out = splice(out, r.bodyFrom, r.bodyTo, bytes.Replace(body, []byte(tok), []byte(fresh), 1))
	}
	return out, nil
}
