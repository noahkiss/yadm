package cond

import (
	"errors"
	"testing"
)

func TestRetype(t *testing.T) {
	defs := []Definition{
		{Name: "desk", Src: "type:work & !os:linux", File: "manifest.toml"},
		{Name: "mac", Src: "os:darwin", File: "manifest.toml"},
	}
	named, err := Define(defs, vocab())
	if err != nil {
		t.Fatal(err)
	}
	v := vocab()
	v.Conditions = named
	for _, c := range []struct {
		src   string
		types []string
		want  string
	}{
		{"", []string{"work"}, "type:work"},
		{"", []string{"work", "client"}, "type:work | type:client"},
		{"type:personal", []string{"work"}, "type:work"},
		{"type:personal | type:client", []string{"work", "client"}, "type:work | type:client"},
		{"type:personal & os:darwin", []string{"work"}, "type:work & os:darwin"},
		{"(type:personal | type:client) & os:darwin", []string{"work", "client"}, "(type:work | type:client) & os:darwin"},
		{"os:darwin & type:personal & !machine:host-b", []string{"work", "client"}, "os:darwin & (type:work | type:client) & !machine:host-b"},
		{"fact:editor=editor-one", []string{"work"}, "type:work & fact:editor=editor-one"},
		{"os:darwin | os:linux", []string{"work", "client"}, "(type:work | type:client) & (os:darwin | os:linux)"},
		{"type:personal & cond:mac", []string{"work"}, "type:work & cond:mac"},
		{"observed:packages=tool-one & type:personal", []string{"work"}, "observed:packages=tool-one & type:work"},
	} {
		got, err := Retype(c.src, c.types, v)
		if err != nil || got != c.want {
			t.Errorf("Retype(%q, %v) = %q, %v; want %q", c.src, c.types, got, err, c.want)
			continue
		}
		if _, err := Parse(got, v); err != nil {
			t.Errorf("Retype(%q) = %q does not parse: %v", c.src, got, err)
		}
	}
	for _, src := range []string{
		"!type:work",
		"type:work | os:darwin",
		"type:work & type:personal",
		"cond:desk",
		"cond:desk & os:darwin",
		"(type:work & os:darwin) | type:client",
		"os:darwin & !(type:work | type:client)",
	} {
		if got, err := Retype(src, []string{"client"}, v); !errors.Is(err, ErrRetype) {
			t.Errorf("Retype(%q) = %q, %v; want ErrRetype", src, got, err)
		}
	}
	if _, err := Retype("type:nope", []string{"work"}, v); err == nil || errors.Is(err, ErrRetype) {
		t.Errorf("unknown type: %v", err)
	}
}
