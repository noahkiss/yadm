package rules

import (
	"bytes"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// fuzzCanary is a fixed marker; fuzz inputs may not contain it by chance.
const fuzzCanary = "FUZZ-CANARY-7f3a9c1e5b2d4f60"

var fuzzSpecs = []Spec{
	{Format: manifest.FormatJSONC, Keep: []string{"a.*", "b"}, Drop: []string{"a.x"}, Seal: map[string]model.EnclaveName{"s.t": personal}},
	{Format: manifest.FormatJSON, Drop: []string{"d", "a.1"}, Seal: map[string]model.EnclaveName{"s.*": personal}},
	{Format: manifest.FormatTOML, Drop: []string{"d", "t.x"}, Seal: map[string]model.EnclaveName{"s.t": personal}},
	{Format: manifest.FormatTOML, Keep: []string{"t", "a"}, Seal: map[string]model.EnclaveName{"s.t": personal}},
	{Regions: true},
}

func addSeeds(f *testing.F) {
	seeds := []string{
		"{\n  \"a\": {\"x\": 1, \"y\": 2},\n  // c\n  \"b\": [1, 2],\n  \"d\": true,\n  \"s\": {\"t\": \"" + fuzzCanary + "\"}\n}\n",
		"{\"a\": [1, 2, 3], \"d\": null, \"s\": {\"t\": \"" + fuzzCanary + "\", \"u\": \"" + fuzzCanary + "2\"},}",
		"a = 1\nd = 2 # c\n[t]\nx = \"v\"\ny = [1,\n  2]\n[s]\nt = '" + fuzzCanary + "'\n",
		"[t]\r\nx = 1\r\n[s]\r\nt = \"" + fuzzCanary + "\"\r\n",
		"Host a\n# yadm:seal personal h\nHostName " + fuzzCanary + "\n# yadm:end\n",
		"// yadm:seal personal x\n" + fuzzCanary + "\n// yadm:end",
		"{}",
		"",
	}
	for _, s := range seeds {
		for i := range fuzzSpecs {
			f.Add(s, uint8(i))
		}
	}
}

// FuzzToSource checks, for any target: a member capture never stores the
// canary; a capture that succeeds re-renders to the target; capturing again
// from the new source is a no-op; and a non-member render of the source never
// holds the canary.
func FuzzToSource(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, target string, which uint8) {
		spec := fuzzSpecs[int(which)%len(fuzzSpecs)]
		if strings.Count(target, fuzzCanary) == 0 {
			return
		}
		// A canary inside a marker line is shared text, not plaintext.
		for _, line := range splitLines([]byte(target)) {
			if _, _, _, ok := marker(line); ok && bytes.Contains(line, []byte(fuzzCanary)) {
				return
			}
		}
		m := member(personal)
		src, vio, err := ToSource([]byte(target), nil, spec, m)
		for _, v := range vio {
			if strings.Contains(v.Path+v.Detail, fuzzCanary) {
				t.Fatalf("violation carries plaintext: %+v", v)
			}
		}
		if err != nil || len(vio) > 0 {
			if src != nil {
				t.Fatalf("bytes returned with a refusal")
			}
			return
		}
		if bytes.Contains(src, []byte(fuzzCanary)) {
			// Only allowed when the canary sits outside every seal path,
			// which the capture cannot know is secret.
			if sealedCanary(t, []byte(target), spec) {
				t.Fatalf("source holds sealed plaintext:\n%q\nfrom\n%q", src, target)
			}
			return
		}
		back, err := ToTarget(src, []byte(target), spec, m)
		if err != nil || !bytes.Equal(back, []byte(target)) {
			t.Fatalf("round trip: %v\n%q\n%q", err, back, target)
		}
		again, vio, err := ToSource([]byte(target), src, spec, m)
		if err != nil || len(vio) > 0 || !bytes.Equal(again, src) {
			t.Fatalf("second capture changed the source: %v %v", vio, err)
		}
		nm := member()
		out, err := ToTarget(src, nil, spec, nm)
		if err != nil {
			return
		}
		if bytes.Contains(out, []byte(fuzzCanary)) {
			t.Fatalf("non-member target holds the canary:\n%q", out)
		}
		back2, vio, err := ToSource(out, src, spec, nm)
		if err == nil && len(vio) == 0 && bytes.Contains(back2, []byte(fuzzCanary)) {
			t.Fatalf("non-member capture holds the canary")
		}
	})
}

// sealedCanary reports whether every canary in target sits at a seal path or
// in a region, i.e. the canary is enclave plaintext.
func sealedCanary(t *testing.T, target []byte, spec Spec) bool {
	t.Helper()
	rest := target
	if spec.Regions {
		regs, vio := parseRegions(target)
		if len(vio) > 0 {
			return false
		}
		for i := len(regs) - 1; i >= 0; i-- {
			rest = splice(rest, regs[i].bodyFrom, regs[i].bodyTo, nil)
		}
	}
	if spec.structured() {
		c, err := compile(spec)
		if err != nil {
			return false
		}
		for _, r := range c.seals {
			root, err := c.f.parse(rest)
			if err != nil {
				return false
			}
			for _, p := range matchPaths(root, []pattern{r.pat}) {
				if rest, err = edit(c.f, rest, func(root *node) ([]byte, error) { return c.f.del(rest, find(root, p), false) }); err != nil {
					return false
				}
			}
		}
	}
	return !bytes.Contains(rest, []byte(fuzzCanary))
}

// FuzzToTarget checks that a source built by a member renders back to the
// same target, and that a non-member's render-capture cycle is a no-op.
func FuzzToTarget(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, target string, which uint8) {
		spec := fuzzSpecs[int(which)%len(fuzzSpecs)]
		m := member(personal)
		src, vio, err := ToSource([]byte(target), nil, spec, m)
		if err != nil || len(vio) > 0 {
			return
		}
		// Member: source -> target -> source is the identity.
		tgt, err := ToTarget(src, nil, spec, m)
		if err != nil {
			t.Fatalf("member render of a captured source: %v", err)
		}
		again, vio, err := ToSource(tgt, src, spec, m)
		if err != nil || len(vio) > 0 || !bytes.Equal(again, src) {
			t.Fatalf("member cycle changed the source: %v %v\n%q\n%q", vio, err, again, src)
		}
		// Non-member: source -> target -> source is the identity.
		nm := member()
		ntgt, err := ToTarget(src, nil, spec, nm)
		if err != nil {
			t.Fatalf("non-member render: %v", err)
		}
		nsrc, vio, err := ToSource(ntgt, src, spec, nm)
		if err != nil || len(vio) > 0 || !bytes.Equal(nsrc, src) {
			t.Fatalf("non-member cycle changed the source: %v %v\n%q\n%q", vio, err, nsrc, src)
		}
	})
}
