package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Error text and violations of the rules engine end up in hold details
// (state.json, hook packets, stderr). They must not quote file content.
func TestSec2RulesErrorsCarryNoContent(t *testing.T) {
	const canary = "SEC2CANARYsecretvalue0123456789"
	s := member("personal")
	cases := []struct {
		name   string
		format manifest.Format
		prev   string
		broken []string
	}{
		{"json", manifest.FormatJSON, `{"a": 1, "sync": {"token": "x"}}`, []string{
			`{"a": 1, "sync": {"token": "` + canary + `"`,
			`{"a": 1, "sync": {"token": "` + canary + `" "b"}}`,
			`{"a": 1, "sync": {"token": ` + canary + `}}`,
			`{"a": 1, "sync": {"token": "` + canary + `\q"}}`,
			`{"a": 1, "` + canary + `": {"token": "x"}, "` + canary + `": 2,}`,
			`{"a": "` + canary + `"}`,
			`[{"token": "` + canary + `"}]`,
		}},
		{"toml", manifest.FormatTOML, "a = 1\n[sync]\ntoken = \"x\"\n", []string{
			"a = 1\n[sync]\ntoken = \"" + canary + "\n",
			"a = 1\n[sync]\ntoken = " + canary + "\n",
			"a = 1\n[sync\ntoken = \"" + canary + "\"\n",
			"a = 1\n[sync]\ntoken = \"" + canary + "\"\ntoken = \"" + canary + "\"\n",
			"a = \"" + canary + "\"\n",
			"sync = \"" + canary + "\"\n",
			"[" + canary + "]\nx = 1\n[[" + canary + "]]\ny = 2\n",
		}},
	}
	for _, c := range cases {
		spec := Spec{Format: c.format, Seal: map[string]model.EnclaveName{"sync.token": "personal"}, Drop: []string{"a"}, Source: model.SourcePath("files/x." + c.name)}
		for i, b := range c.broken {
			check := func(what string, text string) {
				if strings.Contains(text, canary) {
					t.Errorf("%s case %d %s quotes content: %s", c.name, i, what, text)
				}
			}
			out, viol, err := ToSource([]byte(b), []byte(c.prev), spec, s)
			if err != nil {
				check("ToSource error", err.Error())
			}
			check("ToSource violations", fmt.Sprintf("%+v", viol))
			if err == nil && len(viol) == 0 && strings.Contains(string(out), canary) && strings.Contains(b, `token`) && !strings.Contains(c.name, "x") {
				t.Logf("%s case %d: source output holds the value in plain (expected only when it sits outside sync.token): %q", c.name, i, out)
			}
			if _, err := ToTarget([]byte(b), []byte(b), spec, s); err != nil {
				check("ToTarget error", err.Error())
			}
			if _, _, err := Merge3(string(c.format), nil, []byte(c.prev), []byte(b), []byte(c.prev+" ")); err != nil {
				check("Merge3 error", err.Error())
			}
		}
	}
}
