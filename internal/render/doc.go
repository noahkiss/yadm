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
//	{{ "{{" }}                         a literal "{{"
//
// COND is the package cond language. A directive that ends a line consumes that
// line's newline. Anything else between {{ }} or {% %} is an error with the
// file, line and column; there are no filters, loops or includes.
//
// Exported API:
//
//	type Engine interface{ Render(name string, src []byte, ctx model.Context) ([]byte, error) }
//	func New(v cond.Vocabulary) Engine
//	type Error struct{ Name string; Line, Col int; Msg string }
package render
