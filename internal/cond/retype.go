package cond

import (
	"errors"
	"fmt"
	"strings"
)

// ErrRetype reports a condition whose type terms Retype cannot replace
// without changing what its other terms mean.
var ErrRetype = errors.New("cannot replace the type terms")

// Retype returns src with its type terms replaced by `type:t1 | type:t2 …`
// for types, keeping every other term. It works only where the type terms
// form one clean factor of a top-level conjunction:
//
//   - src is empty: the result is the type disjunction alone;
//   - src holds no type term: the result is `(types) & src`;
//   - one conjunct is a positive type term or a disjunction of only type
//     terms: that conjunct becomes the new disjunction, the others stay.
//
// Anything else fails with ErrRetype and changes nothing: a type term under
// `!`, inside a disjunction with other terms, in two conjuncts, or behind a
// `cond:` name. The kept terms are written back in canonical form
// (Expr.String), so `cond:` names stay named.
func Retype(src string, types []string, v Vocabulary) (string, error) {
	if len(types) == 0 {
		return "", errors.New("retype: no types")
	}
	terms := make([]string, len(types))
	for i, t := range types {
		terms[i] = "type:" + t
	}
	disj := strings.Join(terms, " | ")
	if strings.TrimSpace(src) == "" {
		return disj, nil
	}
	x, err := Parse(src, v)
	if err != nil {
		return "", err
	}
	factor := disj
	if len(types) > 1 {
		factor = "(" + disj + ")"
	}
	var parts []string
	replaced := false
	for _, c := range conjuncts(x) {
		switch {
		case pureTypes(c):
			if replaced {
				return "", fmt.Errorf("%w in %q: more than one conjunct names types", ErrRetype, src)
			}
			replaced = true
			parts = append(parts, factor)
		case mentionsType(c):
			return "", fmt.Errorf("%w in %q: a type term sits under !, beside other terms in |, or inside a cond: name", ErrRetype, src)
		default:
			parts = append(parts, wrap(c, precAnd))
		}
	}
	if !replaced {
		parts = append([]string{factor}, parts...)
	}
	if len(parts) == 1 {
		return disj, nil
	}
	return strings.Join(parts, " & "), nil
}

// conjuncts flattens the top-level conjunction of e.
func conjuncts(e Expr) []Expr {
	if a, ok := e.(andExpr); ok {
		return append(conjuncts(a.l), conjuncts(a.r)...)
	}
	return []Expr{e}
}

// pureTypes reports whether e is a type term or a disjunction of type terms
// written out (no cond: name).
func pureTypes(e Expr) bool {
	switch t := e.(type) {
	case typeTerm:
		return true
	case orExpr:
		return pureTypes(t.l) && pureTypes(t.r)
	}
	return false
}

// mentionsType reports whether e reads a type term anywhere, named
// conditions included.
func mentionsType(e Expr) bool {
	found := false
	walk(e, func(x Expr) {
		if _, ok := x.(typeTerm); ok {
			found = true
		}
	})
	return found
}
