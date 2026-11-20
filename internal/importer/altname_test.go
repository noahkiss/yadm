package importer

import (
	"reflect"
	"testing"
)

func TestParseAltName(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want AltName
	}{
		{in: ".config/shell/aliases.sh"},
		{in: ".gitconfig##default", ok: true, want: AltName{Base: ".gitconfig", Alt: ".gitconfig##default", Conds: []AltCond{{Key: "default"}}}},
		{in: "a/b##c.work,o.Darwin", ok: true, want: AltName{Base: "a/b", Alt: "a/b##c.work,o.Darwin", Conds: []AltCond{{"class", "work"}, {"os", "Darwin"}}}},
		{in: "x##hostname.host-a.example.invalid,template", ok: true, want: AltName{Base: "x", Alt: "x##hostname.host-a.example.invalid,template", Conds: []AltCond{{"hostname", "host-a.example.invalid"}, {"template", ""}}}},
		{in: "x##t.default,e.sh", ok: true, want: AltName{Base: "x", Alt: "x##t.default,e.sh", Conds: []AltCond{{"template", "default"}, {"extension", "sh"}}}},
		{in: ".config/app##class.work/sub/f.toml", ok: true, want: AltName{Base: ".config/app/sub/f.toml", Alt: ".config/app##class.work", Dir: true, Conds: []AltCond{{"class", "work"}}}},
		{in: "y##u.someone,d.distro-one,f.family-one,a.arm64", ok: true, want: AltName{Base: "y", Alt: "y##u.someone,d.distro-one,f.family-one,a.arm64", Conds: []AltCond{{"user", "someone"}, {"distro", "distro-one"}, {"distro_family", "family-one"}, {"arch", "arm64"}}}},
	}
	for _, c := range cases {
		got, ok, err := ParseAltName(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if ok != c.ok || (ok && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("%s: got %+v %v, want %+v %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseAltNameRejects(t *testing.T) {
	for _, in := range []string{
		"x##",
		"x##bogus.1",
		"x##~class.work",
		"x##class",
		"x##default.v",
		"x##os.Darwin,os.Linux",
		"##class.work",
		"a##class.work/b##os.Linux",
		"a##template/b",
	} {
		if _, ok, err := ParseAltName(in); err == nil || !ok {
			t.Errorf("%s: want an error, got ok=%v err=%v", in, ok, err)
		}
	}
}

func TestScore(t *testing.T) {
	a, _, _ := ParseAltName("x##class.work,hostname.h,e.sh")
	if got := a.Score(); got != 2048 {
		t.Errorf("score %d, want 2048", got)
	}
	d, _, _ := ParseAltName("x##default")
	if got := d.Score(); got != 1000 {
		t.Errorf("default score %d", got)
	}
}
