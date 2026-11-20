package rules

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
)

// TestKeepWithDropBelow: keep names a table and drop names keys inside it.
// The source holds the kept table without the dropped keys, the live
// dropped values survive apply, and a capture round-trips.
func TestKeepWithDropBelow(t *testing.T) {
	cases := []struct {
		name   string
		format manifest.Format
		target string
		edit   [2]string
		absent []string
	}{
		{"toml", manifest.FormatTOML, `model = "model-a"
app_state = 7

[tui]
theme = "dark"
nux_seen = true

[hooks]
enabled = true

[hooks.state]
last = "2030-01-01"

[projects."/work/project-a"]
trust_level = "trusted"
`, [2]string{`theme = "dark"`, `theme = "light"`}, []string{"nux_seen", "app_state", "projects", "[hooks.state]"}},
		{"json", manifest.FormatJSON, `{
  "model": "model-a",
  "app_state": 7,
  "tui": {
    "theme": "dark",
    "nux_seen": true
  },
  "hooks": {
    "enabled": true,
    "state": {"last": "2030-01-01"}
  }
}
`, [2]string{`"theme": "dark"`, `"theme": "light"`}, []string{"nux_seen", "app_state", `"state"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := Spec{Format: tc.format, Keep: []string{"model", "tui", "hooks"}, Drop: []string{"tui.nux_seen", "hooks.state"}, Source: "files/x"}
			src, vio, err := ToSource([]byte(tc.target), nil, spec, member())
			if err != nil || len(vio) > 0 {
				t.Fatalf("ToSource: %v %v", err, vio)
			}
			for _, a := range tc.absent {
				if strings.Contains(string(src), a) {
					t.Errorf("source holds %q:\n%s", a, src)
				}
			}
			for _, p := range []string{"model-a", "theme", "enabled"} {
				if !strings.Contains(string(src), p) {
					t.Errorf("source lacks %q:\n%s", p, src)
				}
			}
			back, err := ToTarget(src, []byte(tc.target), spec, member())
			if err != nil || string(back) != tc.target {
				t.Fatalf("round trip: %v\n%s", err, back)
			}
			// A kept edit captures; the dropped keys stay live-only.
			edited := strings.Replace(tc.target, tc.edit[0], tc.edit[1], 1)
			src2, vio, err := ToSource([]byte(edited), src, spec, member())
			if err != nil || len(vio) > 0 || !strings.Contains(string(src2), tc.edit[1]) {
				t.Fatalf("kept edit: %v %v\n%s", err, vio, src2)
			}
			// Another machine's live file with its own dropped values.
			other := strings.Replace(strings.Replace(tc.target, "2030-01-01", "2031-05-05", 1), "nux_seen = true", "nux_seen = false", 1)
			other = strings.Replace(other, `"nux_seen": true`, `"nux_seen": false`, 1)
			got, err := ToTarget(src2, []byte(other), spec, member())
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Replace(other, tc.edit[0], tc.edit[1], 1)
			if string(got) != want {
				t.Fatalf("apply on another machine:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
