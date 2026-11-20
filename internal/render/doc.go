// Package render is the tiny, strict template engine for entries with
// `template = true`. Rendering is a pure function of the template bytes and a
// model.Context.
//
// Syntax (the whole language):
//
//	{{ home }} {{ user }}
//	{{ machine.id }} {{ machine.name }} {{ machine.os }} {{ machine.arch }}
//	{{ machine.facts.KEY }}            declared fact; missing is an error
//	{{ observed.COLLECTOR }}           observed items joined by "\n"; missing is an error
//	{% if COND %} ... {% elif COND %} ... {% else %} ... {% endif %}
//	{# comment #}
//	{{ "{{" }}                         a literal delimiter: {{ }} {% %} {# #}
//	{{ "{" }}                          a literal brace, for one right before a tag
//
// The literal form is the only escape. Escape applies it to plain text, so
// "{{ x: string }}" becomes `{{ "{{" }} x: string }}` and "${#arr}" becomes
// `${{ "{#" }}arr}`. A closer outside a tag (}}, %}, #}) is plain text.
//
// COND is the package cond language. A {% %} or {# #} tag alone on its line
// (only blanks around it) removes the whole line, newline included. A tag
// may not span lines. Anything else between {{ }} or {% %} is an error with
// the file, line and column; there are no filters, loops or includes.
//
// The whole template is parsed before it is evaluated, so a malformed block
// or an unknown name fails even in a branch this machine does not take. A
// missing value (a fact this machine lacks, a collector with no result or a
// failed one) fails only when its branch is taken. The output always ends
// with exactly one newline: trailing newlines collapse to one.
//
// Exported API:
//
//	type Engine interface{ Render(name string, src []byte, ctx model.Context) ([]byte, error) }
//	func New(v cond.Vocabulary) Engine
//	func Validate(name string, src []byte, v cond.Vocabulary) error
//	func Escape(s string) string
//	type Error struct{ Name string; Line, Col int; Msg string }
package render
