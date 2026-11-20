package model

import (
	"strings"
	"unicode"
)

// ShellQuote quotes s as one POSIX shell word, so a suggested command
// (a hold's Next, a hook packet's Command) that names a path stays one
// argument when an agent runs it in a shell. A word made only of safe
// characters is returned as is.
func ShellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool { return !shellSafe(r) }) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellSafe(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("_-./,:@%+=", r)
}

// HasControl reports whether s holds a control character (a newline, a
// carriage return, NUL, escape and the like). Such a name cannot be shown
// or passed on safely, so targets that hold one are refused or held.
func HasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}
