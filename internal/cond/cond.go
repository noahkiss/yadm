package cond

import (
	"fmt"

	"github.com/noahkiss/yadm/internal/model"
)

// Vocabulary lists the names a condition may mention. Build it from the fleet file.
type Vocabulary struct {
	Types      map[string]bool
	FactKeys   map[string]bool
	Collectors map[string]bool
}

// Expr is a parsed condition.
type Expr interface {
	Eval(ctx model.Context) bool
	String() string
}

// Error reports a parse failure at a byte offset in the source string.
type Error struct {
	Src    string
	Offset int
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("condition %q at %d: %s", e.Src, e.Offset, e.Msg) }

// Parse parses src and checks every name against v. An empty src means Always.
func Parse(src string, v Vocabulary) (Expr, error) {
	if src == "" {
		return Always(), nil
	}
	return nil, model.ErrNotImplemented
}

type always struct{}

func (always) Eval(model.Context) bool { return true }
func (always) String() string          { return "true" }

// Always returns the condition that matches every machine.
func Always() Expr { return always{} }
