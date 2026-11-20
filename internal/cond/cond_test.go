package cond

import (
	"errors"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

func vocab() Vocabulary {
	return Vocabulary{
		Types:      map[string]bool{"personal": true, "work": true, "client": true},
		FactKeys:   map[string]bool{"editor": true, "proxy": true, "shell": true, "hostname": true},
		Collectors: map[string]bool{"packages": true},
	}
}

func hostA() model.Context {
	return model.Context{
		Machine: model.Machine{
			ID: "m-a", Name: "host-a", Nicknames: []string{"laptop-a"},
			Types: []model.TypeName{"personal"}, OS: "darwin", Arch: "arm64",
			Facts: map[string]string{"editor": "editor-one", "shell": "zsh", "hostname": "Host-A.example-lan"},
		},
		Observed: map[string]model.ObservedFact{"packages": {Collector: "packages", Items: []string{"tool-one", "tool-two"}}},
	}
}

func hostC() model.Context {
	return model.Context{Machine: model.Machine{
		ID: "m-c", Name: "host-c", Types: []model.TypeName{"work", "client"}, OS: "linux", Arch: "amd64",
		Facts: map[string]string{"editor": "editor-one", "proxy": "proxy.example.invalid:3128"},
	}}
}

func TestEval(t *testing.T) {
	cases := []struct {
		src  string
		a, c bool
	}{
		{"", true, true},
		{"true", true, true},
		{"false", false, false},
		{"type:personal", true, false},
		{"type:work", false, true},
		{"os:darwin", true, false},
		{"arch:amd64", false, true},
		{"machine:host-a", true, false},
		{"machine:laptop-a", true, false},
		{"machine:m-a", false, false}, // ids are not names
		{"fact:shell", true, false},
		{"fact:proxy", false, true},
		{"fact:editor=editor-one", true, true},
		{"fact:shell=bash", false, false},
		{"fact:proxy=proxy.example.invalid:3128", false, true},
		{"fact:hostname=Host-A.example-lan", true, false},
		{"fact:hostname=host-a.example-lan", true, false}, // case-insensitive
		{"fact:hostname=HOST-A.EXAMPLE-LAN&type:personal", true, false},
		{"fact:hostname=host-a", false, false},
		{"fact:shell=ZSH", true, false},
		{"observed:packages=tool-one", true, false},
		{"observed:packages=TOOL-ONE", false, false}, // items compare exactly
		{"observed:packages=tool-three", false, false},
		{"!type:work", true, false},
		{"!!type:work", false, true},
		{"type:work & os:linux", false, true},
		{"type:work | os:darwin", true, true},
		{"type:personal | type:work & os:darwin", true, false}, // & binds tighter
		{"(type:personal | type:work) & os:darwin", true, false},
		{"(type:personal | type:client) & !os:darwin", false, true},
		{"  type:work&os:linux  ", false, true},
		{"!(os:darwin)", false, true},
	}
	for _, tc := range cases {
		e, err := Parse(tc.src, vocab())
		if err != nil {
			t.Errorf("%q: %v", tc.src, err)
			continue
		}
		if got := e.Eval(hostA()); got != tc.a {
			t.Errorf("%q on host-a = %v, want %v", tc.src, got, tc.a)
		}
		if got := e.Eval(hostC()); got != tc.c {
			t.Errorf("%q on host-c = %v, want %v", tc.src, got, tc.c)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		src, msg string
		off      int
	}{
		{"type:wrok", `unknown type "wrok"`, 5},
		{"os:darwin & fact:editr", `unknown fact "editr"`, 17},
		{"fact:editr=x", `unknown fact "editr"`, 5},
		{"observed:pkgs=tool", `unknown collector "pkgs"`, 9},
		{"observed:packages", `needs "=ITEM"`, 17},
		{"observed:packages=", `needs "=ITEM"`, 17},
		{"colour:red", `unknown term kind "colour"`, 0},
		{"darwin", `unknown term "darwin"`, 0},
		{"os:", "needs a value", 3},
		{"type:work=x", `unexpected "="`, 9},
		{"fact:=x", "needs a key", 5},
		{"fact:editor=", `needs a value`, 12},
		{"   ", "empty condition", 0},
		{"type:work &", "found the end", 11},
		{"& type:work", `found "&"`, 0},
		{"(type:work", `expected ")"`, 10},
		{"type:work)", `unexpected ")"`, 9},
		{"type:work os:darwin", `unexpected "os:darwin"`, 10},
		{"()", `found ")"`, 1},
		{strings.Repeat("(", 100) + "true" + strings.Repeat(")", 100), "nests too deeply", 65},
		{"os:dar\x01win", "control character", 6},
	}
	for _, tc := range cases {
		_, err := Parse(tc.src, vocab())
		var ce *Error
		if !errors.As(err, &ce) {
			t.Errorf("%q: want *Error, got %v", tc.src, err)
			continue
		}
		if !strings.Contains(ce.Msg, tc.msg) || ce.Offset != tc.off {
			t.Errorf("%q: got %q at %d, want %q at %d", tc.src, ce.Msg, ce.Offset, tc.msg, tc.off)
		}
	}
}

func TestEmptyVocabularyRejectsNames(t *testing.T) {
	for _, src := range []string{"type:work", "fact:editor", "observed:packages=x"} {
		if _, err := Parse(src, Vocabulary{}); err == nil {
			t.Errorf("%q parsed with an empty vocabulary", src)
		}
	}
	if _, err := Parse("os:linux & machine:host-a", Vocabulary{}); err != nil {
		t.Errorf("os and machine need no vocabulary: %v", err)
	}
}

func TestString(t *testing.T) {
	cases := map[string]string{
		"type:work":                         "type:work",
		"  !  os:darwin":                    "!os:darwin",
		"a:b":                               "",
		"type:work&os:linux|true":           "type:work & os:linux | true",
		"type:work&(os:linux|false)":        "type:work & (os:linux | false)",
		"!(type:work|os:linux)":             "!(type:work | os:linux)",
		"type:work|(os:linux|os:darwin)":    "type:work | (os:linux | os:darwin)",
		"fact:editor=editor-one":            "fact:editor=editor-one",
		"observed:packages=tool-one & true": "observed:packages=tool-one & true",
	}
	for src, want := range cases {
		e, err := Parse(src, vocab())
		if want == "" {
			if err == nil {
				t.Errorf("%q: want error", src)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", src, err)
			continue
		}
		if got := e.String(); got != want {
			t.Errorf("%q: String = %q, want %q", src, got, want)
		}
	}
}

// FuzzParse checks the parser never panics and that String round-trips.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"", "type:work", "!(os:darwin|arch:arm64)&fact:editor=x", "observed:packages=a", "((", "fact:=", "true|false&!true"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		e, err := Parse(src, vocab())
		if err != nil {
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("%q: error is not *Error: %v", src, err)
			}
			if ce.Offset < 0 || ce.Offset > len(src) {
				t.Fatalf("%q: offset %d out of range", src, ce.Offset)
			}
			return
		}
		s := e.String()
		e2, err := Parse(s, vocab())
		if err != nil {
			t.Fatalf("%q: String %q does not re-parse: %v", src, s, err)
		}
		if e2.String() != s {
			t.Fatalf("%q: String not stable: %q then %q", src, s, e2.String())
		}
		for _, c := range []model.Context{hostA(), hostC()} {
			if e.Eval(c) != e2.Eval(c) {
				t.Fatalf("%q: re-parsed %q evaluates differently", src, s)
			}
		}
	})
}
