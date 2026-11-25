package tasks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/noahkiss/yadm/internal/manifest"
)

// PluginExecutables returns the $HOME-relative executables a plugin runs:
// its command's and, when different, its news query's, sorted.
func PluginExecutables(def manifest.PluginDef) []string {
	var out []string
	if len(def.Command) > 0 {
		out = append(out, def.Command[0])
	}
	if len(def.News) > 0 && !slices.Contains(out, def.News[0]) {
		out = append(out, def.News[0])
	}
	slices.Sort(out)
	return out
}

// ErrPluginExecutable means a plugin's executable is missing, not a
// regular file or not executable.
var ErrPluginExecutable = errors.New("plugin executable")

// PluginHash returns the trust hash of a plugin on this machine: a SHA-256
// over its definition and the bytes of each executable under home, read
// through symlinks. A plugin whose executable changed has a new hash, so a
// peer that pushes a new script cannot run it here before an allow.
func PluginHash(home string, def manifest.PluginDef) (string, error) {
	type exe struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	doc := struct {
		Definition  manifest.PluginDef `json:"definition"`
		Executables []exe              `json:"executables"`
	}{Definition: def}
	for _, rel := range PluginExecutables(def) {
		b, err := ReadPluginExecutable(home, rel)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(b)
		doc.Executables = append(doc.Executables, exe{Path: rel, SHA256: hex.EncodeToString(sum[:])})
	}
	return DefinitionHash(doc)
}

// ReadPluginExecutable reads home/rel through symlinks. It fails with
// ErrPluginExecutable unless the result is a regular file with an execute
// bit.
func ReadPluginExecutable(home, rel string) ([]byte, error) {
	p := filepath.Join(home, filepath.FromSlash(rel))
	fi, err := os.Stat(p)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w %s: %v", ErrPluginExecutable, rel, err)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%w %s: not a regular file", ErrPluginExecutable, rel)
	case fi.Mode().Perm()&0o111 == 0:
		return nil, fmt.Errorf("%w %s: not executable", ErrPluginExecutable, rel)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", ErrPluginExecutable, rel, err)
	}
	return b, nil
}
