package rules

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
)

// TestTOMLTablePathWithoutParent: keep or drop names one table under a
// parent (`hooks.PreEdit`) that the rules do not own, so a sibling table the
// app writes (`hooks.state`) stays local.
func TestTOMLTablePathWithoutParent(t *testing.T) {
	tables := `model = "model-a"

[hooks.PreEdit]
command = "check-one"
timeout = 5

[hooks.state]
last = "2030-01-01"
`
	arrays := `model = "model-a"

[[hooks.PreEdit]]
command = "check-one"

[[hooks.PreEdit]]
command = "check-two"

[hooks.state]
last = "2030-01-01"
`
	cases := []struct {
		name       string
		live       string
		keep, drop []string
		has, lacks []string // in the captured source
		upstream   [2]string
	}{
		{"keep table", tables, []string{"hooks.PreEdit"}, nil,
			[]string{"[hooks.PreEdit]", "check-one"}, []string{"state", "model"},
			[2]string{`command = "check-one"`, `command = "check-new"`}},
		{"drop table", tables, nil, []string{"hooks.state"},
			[]string{"[hooks.PreEdit]", "model"}, []string{"state", "2030"},
			[2]string{`command = "check-one"`, `command = "check-new"`}},
		{"keep array of tables", arrays, []string{"hooks.PreEdit"}, nil,
			[]string{"[[hooks.PreEdit]]", "check-two"}, []string{"state", "model"},
			[2]string{`command = "check-two"`, `command = "check-new"`}},
		{"drop beside array of tables", arrays, nil, []string{"hooks.state"},
			[]string{"[[hooks.PreEdit]]", "model"}, []string{"state", "2030"},
			[2]string{`command = "check-two"`, `command = "check-new"`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := Spec{Format: manifest.FormatTOML, Keep: c.keep, Drop: c.drop, Source: testSource}
			src, vio, err := ToSource([]byte(c.live), nil, spec, member())
			if err != nil || len(vio) > 0 {
				t.Fatalf("ToSource: %v %v", err, vio)
			}
			for _, w := range c.has {
				if !strings.Contains(string(src), w) {
					t.Errorf("source lacks %q:\n%s", w, src)
				}
			}
			for _, w := range c.lacks {
				if strings.Contains(string(src), w) {
					t.Errorf("source holds %q:\n%s", w, src)
				}
			}
			// The app moves its own table on; the source changes upstream.
			live := strings.Replace(c.live, "2030-01-01", "2030-02-02", 1)
			up := strings.Replace(string(src), c.upstream[0], c.upstream[1], 1)
			out, err := ToTarget([]byte(up), []byte(live), spec, member())
			if err != nil {
				t.Fatal(err)
			}
			o := string(out)
			if !strings.Contains(o, "[hooks.state]\nlast = \"2030-02-02\"") {
				t.Errorf("app table not kept:\n%s", o)
			}
			if !strings.Contains(o, "check-new") {
				t.Errorf("upstream change not applied:\n%s", o)
			}
			// Capturing the result gives the upstream source back.
			back, vio, err := ToSource(out, []byte(up), spec, member())
			if err != nil || len(vio) > 0 || string(back) != up {
				t.Errorf("recapture: %v %v\n%s\nwant\n%s", err, vio, back, up)
			}
		})
	}
}
