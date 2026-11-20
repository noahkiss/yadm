package rules

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
)

// TestVolatileNeverCaptured: a volatile key's local change is never
// captured, apply keeps the live value, and a live file without the key is
// seeded from the source.
func TestVolatileNeverCaptured(t *testing.T) {
	cases := []struct {
		format       manifest.Format
		src, changed string
		from, to     string
		other        [2]string
	}{
		{manifest.FormatJSONC, "{\n  // shared\n  \"theme\": \"dark\",\n  \"model\": \"model-a\"\n}\n", "", `"model-a"`, `"model-b"`, [2]string{`"theme": "dark"`, `"theme": "light"`}},
		{manifest.FormatTOML, "theme = \"dark\"\nmodel = \"model-a\"\n\n[ui]\nwidth = 80\n", "", `"model-a"`, `"model-b"`, [2]string{`theme = "dark"`, `theme = "light"`}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			spec := Spec{Format: tc.format, Volatile: []string{"model"}, Source: "files/x"}
			target := strings.Replace(tc.src, tc.from, tc.to, 1)
			got, vio, err := ToSource([]byte(target), []byte(tc.src), spec, member())
			if err != nil || len(vio) > 0 || string(got) != tc.src {
				t.Fatalf("volatile-only change captured: %v %v\n%s", err, vio, got)
			}
			// A shared edit next to it captures without the local value.
			both := strings.Replace(target, tc.other[0], tc.other[1], 1)
			got, vio, err = ToSource([]byte(both), []byte(tc.src), spec, member())
			if err != nil || len(vio) > 0 {
				t.Fatal(err, vio)
			}
			if !strings.Contains(string(got), tc.other[1]) || strings.Contains(string(got), tc.to) || !strings.Contains(string(got), tc.from) {
				t.Fatalf("source:\n%s", got)
			}
			// Apply keeps this machine's value.
			back, err := ToTarget(got, []byte(target), spec, member())
			if err != nil || string(back) != both {
				t.Fatalf("apply: %v\n%s\nwant\n%s", err, back, both)
			}
			// A live file without the key is seeded from the source.
			seed, err := ToTarget([]byte(tc.src), nil, spec, member())
			if err != nil || !strings.Contains(string(seed), tc.from) {
				t.Fatalf("seed: %v\n%s", err, seed)
			}
			// A first capture with no previous source leaves the key out.
			first, _, err := ToSource([]byte(target), nil, spec, member())
			if err != nil || strings.Contains(string(first), "model") {
				t.Fatalf("first capture: %v\n%s", err, first)
			}
		})
	}
}
