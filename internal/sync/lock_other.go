//go:build !unix

package sync

import (
	"os"

	"github.com/noahkiss/yadm/internal/model"
)

func tryLock(*os.File) (bool, error) { return false, model.ErrNotImplemented }

func unlock(*os.File) {}
