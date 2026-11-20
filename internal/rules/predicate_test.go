package rules

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
)

const genRule = "hooks.*[?hooks.*.command~=gen-tool run]"

// A JSONC hooks file: generated elements (command "gen-tool run …") are
// machine-local; the user's own hooks are owned by the source.
const predLive = `{
  // hook settings
  "hooks": {
    "PreEdit": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "gen-tool run pre"}]},
      // the user's own check
      {"matcher": "Shell", "hooks": [{"type": "command", "command": "user-check"}]},
      {"matcher": "*", "hooks": [{"type": "command", "command": "gen-tool run audit"}]} // trailing
    ],
    "Stop": [
      {"hooks": [{"command": "gen-tool run stop"}]}
    ]
  },
  "other": 1
}
`

func predSpec(f manifest.Format, drop ...string) Spec {
	return Spec{Format: f, Drop: drop, Source: testSource}
}

func TestPredicateDropCapture(t *testing.T) {
	spec := predSpec(manifest.FormatJSONC, genRule)
	src, vio, err := ToSource([]byte(predLive), nil, spec, member())
	if err != nil || len(vio) > 0 {
		t.Fatalf("ToSource: %v %v", err, vio)
	}
	s := string(src)
	if strings.Contains(s, "gen-tool") {
		t.Errorf("source holds a generated element:\n%s", s)
	}
	for _, want := range []string{"user-check", "// the user's own check", "// hook settings", `"Stop": [`, `"other": 1`} {
		if !strings.Contains(s, want) {
			t.Errorf("source lacks %q:\n%s", want, s)
		}
	}
	// Apply onto the live file gives back the same bytes.
	back, err := ToTarget(src, []byte(predLive), spec, member())
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != predLive {
		t.Errorf("round trip:\n%s\nwant\n%s", back, predLive)
	}
	// A capture of an unchanged target is a no-op.
	again, _, err := ToSource([]byte(predLive), src, spec, member())
	if err != nil || string(again) != s {
		t.Errorf("recapture changed the source: %v\n%s", err, again)
	}
	// A fresh machine (no live file) gets the source as is.
	fresh, err := ToTarget(src, nil, spec, member())
	if err != nil || string(fresh) != s {
		t.Errorf("fresh apply: %v\n%s", err, fresh)
	}
}

// TestPredicateDropRegeneration: another machine changes the owned
// elements; apply keeps this machine's generated elements and its
// hand-added local one, in order.
func TestPredicateDropRegeneration(t *testing.T) {
	spec := predSpec(manifest.FormatJSONC, genRule)
	src, _, err := ToSource([]byte(predLive), nil, spec, member())
	if err != nil {
		t.Fatal(err)
	}
	// The user hand-adds a local element on this machine.
	live := strings.Replace(predLive, `"Stop": [
      {"hooks": [{"command": "gen-tool run stop"}]}`, `"Stop": [
      {"hooks": [{"command": "gen-tool run stop"}]},
      {"hooks": [{"command": "gen-tool run local-extra"}]}`, 1)
	// Upstream adds an owned element at the front of PreEdit and drops
	// nothing.
	newSrc := strings.Replace(string(src), `"PreEdit": [`, `"PreEdit": [
      {"matcher": "Read", "hooks": [{"type": "command", "command": "team-check"}]},`, 1)
	out, err := ToTarget([]byte(newSrc), []byte(live), spec, member())
	if err != nil {
		t.Fatal(err)
	}
	o := string(out)
	order := []string{"gen-tool run pre", "team-check", "user-check", "gen-tool run audit", "gen-tool run stop", "gen-tool run local-extra", `"other"`}
	last := -1
	for _, w := range order {
		i := strings.Index(o, w)
		if i < 0 {
			t.Fatalf("output lacks %q:\n%s", w, o)
		}
		if i < last {
			t.Errorf("%q out of order:\n%s", w, o)
		}
		last = i
	}
	// The result captures back to the new source: local elements never
	// reach it.
	cap2, vio, err := ToSource(out, []byte(newSrc), spec, member())
	if err != nil || len(vio) > 0 {
		t.Fatalf("recapture: %v %v", err, vio)
	}
	if string(cap2) != newSrc {
		t.Errorf("recapture:\n%s\nwant\n%s", cap2, newSrc)
	}

	// Upstream removes the user's owned element: the generated ones stay.
	fewer := strings.Replace(string(src), "      // the user's own check\n      {\"matcher\": \"Shell\", \"hooks\": [{\"type\": \"command\", \"command\": \"user-check\"}]}\n", "", 1)
	if fewer == string(src) {
		t.Fatalf("edit did not apply:\n%s", src)
	}
	out, err = ToTarget([]byte(fewer), []byte(predLive), spec, member())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "user-check") || !strings.Contains(string(out), "gen-tool run pre") || !strings.Contains(string(out), "gen-tool run audit") {
		t.Errorf("after upstream removal:\n%s", out)
	}
	if _, err := manifestParse(out); err != nil {
		t.Errorf("output does not parse: %v\n%s", err, out)
	}
}

func manifestParse(b []byte) (*node, error) { return jsonFormat{}.parse(b) }

func TestPredicateDropShapes(t *testing.T) {
	cases := []struct {
		name   string
		format manifest.Format
		drop   string
		live   string
		source string // expected capture
	}{
		{"json equals flat field", manifest.FormatJSON, "list[?name==gen]", `{"list": [{"name": "gen"}, {"name": "mine"}, {"name": "gen"}], "x": 1}
`, `{"list": [{"name": "mine"}], "x": 1}
`},
		{"alone", manifest.FormatJSON, "list[?name==gen]", `{
  "list": [
    {"name": "gen"}
  ]
}
`, `{
  "list": [
  ]
}
`},
		{"element itself", manifest.FormatJSON, "tags[?~=local-]", `{"tags": ["a", "local-1", "b"]}
`, `{"tags": ["a", "b"]}
`},
		{"non-string field", manifest.FormatJSON, "list[?gen==true]", `{"list": [{"gen": true, "v": 1}, {"gen": false, "v": 2}]}
`, `{"list": [{"gen": false, "v": 2}]}
`},
		{"toml inline array", manifest.FormatTOML, "servers[?~=.local]", `servers = ["a.example", "b.local", "c.example"]
`, `servers = ["a.example", "c.example"]
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := predSpec(c.format, c.drop)
			src, vio, err := ToSource([]byte(c.live), nil, spec, member())
			if err != nil || len(vio) > 0 {
				t.Fatalf("ToSource: %v %v", err, vio)
			}
			if string(src) != c.source {
				t.Errorf("source:\n%s\nwant\n%s", src, c.source)
			}
			back, err := ToTarget(src, []byte(c.live), spec, member())
			if err != nil || string(back) != c.live {
				t.Errorf("ToTarget: %v\n%s\nwant\n%s", err, back, c.live)
			}
		})
	}
}

// TestPredicateDropWithKeep: keep owns the parent; the predicate still
// keeps the generated elements local.
func TestPredicateDropWithKeep(t *testing.T) {
	spec := Spec{Format: manifest.FormatJSONC, Keep: []string{"hooks"}, Drop: []string{genRule}, Source: testSource}
	src, vio, err := ToSource([]byte(predLive), nil, spec, member())
	if err != nil || len(vio) > 0 {
		t.Fatalf("ToSource: %v %v", err, vio)
	}
	if strings.Contains(string(src), "gen-tool") || strings.Contains(string(src), `"other"`) || !strings.Contains(string(src), "user-check") {
		t.Errorf("source:\n%s", src)
	}
	back, err := ToTarget(src, []byte(predLive), spec, member())
	if err != nil || string(back) != predLive {
		t.Errorf("ToTarget: %v\n%s", err, back)
	}
}

// TestPredicateDropSourceLacksArray: an array the source does not have is
// not recreated; the source decides that the array exists.
func TestPredicateDropSourceLacksArray(t *testing.T) {
	spec := predSpec(manifest.FormatJSON, "list[?name==gen]")
	live := `{"list": [{"name": "gen"}], "x": 1}
`
	out, err := ToTarget([]byte(`{"x": 2}
`), []byte(live), spec, member())
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"x": 2}
` {
		t.Errorf("out = %s", out)
	}
}

func TestPredicateDropErrors(t *testing.T) {
	for _, d := range []string{"list[?name==gen", "list[?name]", "list[?name==]", "[?a==b]", "list[?a..b==c]"} {
		_, _, err := ToSource([]byte(`{"list": []}`), nil, predSpec(manifest.FormatJSON, d), member())
		if err == nil {
			t.Errorf("%q: no error", d)
		}
	}
}
