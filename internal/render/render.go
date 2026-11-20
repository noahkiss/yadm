package render

import (
	"fmt"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/model"
)

// Engine renders templates.
type Engine interface {
	Render(name string, src []byte, ctx model.Context) ([]byte, error)
}

// Error is a template error with its position.
type Error struct {
	Name string
	Line int
	Col  int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s:%d:%d: %s", e.Name, e.Line, e.Col, e.Msg) }

// New returns the engine. v checks condition names inside {% if %}.
func New(v cond.Vocabulary) Engine { return engine{v: v} }

type engine struct{ v cond.Vocabulary }

func (engine) Render(name string, src []byte, ctx model.Context) ([]byte, error) {
	return nil, model.ErrNotImplemented
}
