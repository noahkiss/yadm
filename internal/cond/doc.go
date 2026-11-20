// Package cond parses and evaluates the condition language that manifest
// rules (`when = "..."`), tasks, collectors and template `{% if %}` blocks share.
//
// Grammar (whitespace is insignificant):
//
//	expr   = or
//	or     = and { "|" and }
//	and    = unary { "&" unary }
//	unary  = "!" unary | "(" expr ")" | term
//	term   = "type:" NAME | "os:" NAME | "arch:" NAME | "machine:" NAME
//	       | "fact:" KEY [ "=" VALUE ] | "observed:" COLLECTOR "=" ITEM
//	       | "true" | "false"
//
// `machine:` matches a machine name or nickname. `fact:k` is true when the
// machine declares k; `fact:k=v` compares the declared value without regard
// to case, so `fact:hostname=Host-A.example` matches `host-a.example`. A
// VALUE is any run of characters other than blanks and `!&|()`, so it may
// hold `.`, `-` and `=`. `observed:c=i` is true when collector c reported
// item i on this machine; items compare exactly.
//
// Parsing is strict. Parse checks every type, fact key and collector name
// against a Vocabulary built from the fleet file, so a typo fails at load time
// instead of silently evaluating to false.
//
// Exported API:
//
//	type Vocabulary struct{ Types, FactKeys, Collectors, Enclaves map[string]bool }
//	type Expr interface{ Eval(model.Context) bool; String() string }
//	func Parse(src string, v Vocabulary) (Expr, error)
//	func Always() Expr
//	type Error struct{ Src string; Offset int; Msg string }
package cond
