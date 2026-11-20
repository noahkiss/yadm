//go:build !unix

package crypt

import (
	"io/fs"
	"os"
)

// ownedByMe has no portable owner check outside unix; the mode and Lstat
// checks still apply.
func ownedByMe(fs.FileInfo) bool { return true }

// openNoFollow opens p for reading. Outside unix the Lstat check before it
// and the SameFile check after it refuse a symlink.
func openNoFollow(p string) (*os.File, error) { return os.Open(p) }
