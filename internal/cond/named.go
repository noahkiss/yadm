package cond

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/noahkiss/yadm/internal/model"
)

// Definition is one named condition: `NAME = "expr"` in a `[conditions]`
// table. File names the file that defined it, for error messages.
type Definition struct {
	Name string
	Src  string
	File string
}

// ValidName reports whether s may name a condition: dot-separated segments
// of letters, digits, `_` and `-`, such as `editor.gui`.
func ValidName(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// DefineError lists every problem Define found. Each message names the file
// and the condition.
type DefineError struct{ Msgs []string }

func (e *DefineError) Error() string { return strings.Join(e.Msgs, "; ") }

// Define parses every named condition against v. A definition may reference
// another with `cond:NAME`. Bad names, duplicate names, unknown names and
// cycles are errors that name the file and the condition. The result is
// what Vocabulary.Conditions holds.
func Define(defs []Definition, v Vocabulary) (map[string]Expr, error) {
	byName := map[string]Definition{}
	var errs []string
	for _, d := range defs {
		if !ValidName(d.Name) {
			errs = append(errs, fmt.Sprintf("%s: conditions.%s: bad condition name", d.File, d.Name))
			continue
		}
		if prev, ok := byName[d.Name]; ok {
			errs = append(errs, fmt.Sprintf("%s: conditions.%s: already defined in %s", d.File, d.Name, prev.File))
			continue
		}
		byName[d.Name] = d
	}
	if len(errs) > 0 {
		return nil, &DefineError{Msgs: errs}
	}
	out := map[string]Expr{}
	var stack []string
	var resolve func(name string) (Expr, error)
	resolve = func(name string) (Expr, error) {
		if x, ok := out[name]; ok {
			return x, nil
		}
		d, ok := byName[name]
		if !ok {
			from := byName[stack[len(stack)-1]]
			return nil, fmt.Errorf("%s: conditions.%s: unknown condition %q", from.File, from.Name, name)
		}
		if i := slices.Index(stack, name); i >= 0 {
			chain := append(append([]string{}, stack[i:]...), name)
			return nil, fmt.Errorf("%s: conditions.%s: cycle %s", d.File, d.Name, strings.Join(chain, " -> "))
		}
		stack = append(stack, name)
		defer func() { stack = stack[:len(stack)-1] }()
		p := &parser{src: d.Src, v: v, named: resolve}
		x, err := p.parse()
		if err != nil {
			var ce *Error
			if errors.As(err, &ce) && ce.Src == d.Src {
				return nil, fmt.Errorf("%s: conditions.%s: %w", d.File, d.Name, err)
			}
			return nil, err
		}
		out[name] = x
		return x, nil
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if _, err := resolve(n); err != nil && !slices.Contains(errs, err.Error()) {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return nil, &DefineError{Msgs: errs}
	}
	return out, nil
}

type namedTerm struct {
	name string
	x    Expr
}

func (t namedTerm) Eval(c model.Context) bool { return t.x.Eval(c) }
func (t namedTerm) String() string            { return "cond:" + t.name }

// Expand returns e as a string with every `cond:NAME` replaced by its
// definition, parenthesized where precedence needs it. Without named
// conditions it equals e.String().
func Expand(e Expr) string {
	switch t := e.(type) {
	case namedTerm:
		return Expand(t.x)
	case notExpr:
		return "!" + wrapExpanded(t.x, precUnary)
	case andExpr:
		return wrapExpanded(t.l, precAnd) + " & " + wrapExpanded(t.r, precUnary)
	case orExpr:
		return wrapExpanded(t.l, precOr) + " | " + wrapExpanded(t.r, precAnd)
	}
	return e.String()
}

func unname(e Expr) Expr {
	for {
		n, ok := e.(namedTerm)
		if !ok {
			return e
		}
		e = n.x
	}
}

func wrapExpanded(e Expr, min int) string {
	if prec(unname(e)) < min {
		return "(" + Expand(e) + ")"
	}
	return Expand(e)
}

// Names returns the named conditions e references, directly or through
// another named condition, sorted and without duplicates.
func Names(e Expr) []string {
	var out []string
	walk(e, func(x Expr) {
		if n, ok := x.(namedTerm); ok && !slices.Contains(out, n.name) {
			out = append(out, n.name)
		}
	})
	slices.Sort(out)
	return out
}

// Collectors returns the collectors e reads through `observed:` terms,
// named conditions included, sorted and without duplicates.
func Collectors(e Expr) []string {
	var out []string
	walk(e, func(x Expr) {
		if o, ok := x.(observedTerm); ok && !slices.Contains(out, o.collector) {
			out = append(out, o.collector)
		}
	})
	slices.Sort(out)
	return out
}

func walk(e Expr, f func(Expr)) {
	f(e)
	switch t := e.(type) {
	case namedTerm:
		walk(t.x, f)
	case notExpr:
		walk(t.x, f)
	case andExpr:
		walk(t.l, f)
		walk(t.r, f)
	case orExpr:
		walk(t.l, f)
		walk(t.r, f)
	}
}
