//go:build unix

package crypt

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether the file belongs to this process's user.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// openNoFollow opens p for reading and fails if p is a symlink.
func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
