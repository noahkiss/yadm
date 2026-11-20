package tasks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/noahkiss/yadm/internal/extexec"
)

// AllowList is the local record of task and collector definitions this
// machine agreed to run.
// Collectors (fleet.CollectorDef) use the same list with extexec.KindCollector.
type AllowList interface {
	Allowed(kind extexec.Kind, name, hash string) bool
	Allow(kind extexec.Kind, name, hash string) error
}

// AllowFile is the allow list's file in the state directory.
const AllowFile = "allowed.json"

// allowSchema is the version of AllowFile.
const allowSchema = 1

// allowDoc is AllowFile's content: kind -> name -> definition hash.
type allowDoc struct {
	Schema  int                                `json:"schema"`
	Allowed map[extexec.Kind]map[string]string `json:"allowed"`
}

// FileAllowList returns the AllowList stored in AllowFile in stateDir.
//
// It fails closed: a missing, unreadable or corrupt file allows nothing.
// Allow keeps one hash per kind and name, so allowing a changed definition
// replaces the old one.
func FileAllowList(stateDir string) AllowList { return &fileAllow{dir: stateDir} }

type fileAllow struct {
	dir string
	mu  sync.Mutex
}

func (a *fileAllow) path() string { return filepath.Join(a.dir, AllowFile) }

func (a *fileAllow) load() (allowDoc, error) {
	doc := allowDoc{Schema: allowSchema, Allowed: map[extexec.Kind]map[string]string{}}
	b, err := os.ReadFile(a.path())
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return doc, fmt.Errorf("%s: %w", AllowFile, err)
	}
	if doc.Schema != allowSchema {
		return doc, fmt.Errorf("%s: schema %d", AllowFile, doc.Schema)
	}
	if doc.Allowed == nil {
		doc.Allowed = map[extexec.Kind]map[string]string{}
	}
	return doc, nil
}

// Allowed reports whether exactly this definition was allowed.
func (a *fileAllow) Allowed(kind extexec.Kind, name, hash string) bool {
	if a.dir == "" || name == "" || hash == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	doc, err := a.load()
	if err != nil {
		return false
	}
	return doc.Allowed[kind][name] == hash
}

// Allow records the definition hash, writing the file atomically with mode 0600.
func (a *fileAllow) Allow(kind extexec.Kind, name, hash string) error {
	if a.dir == "" {
		return errors.New("allow list: no state directory")
	}
	if kind == "" || name == "" || hash == "" {
		return errors.New("allow list: kind, name and hash are required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	doc, err := a.load()
	if err != nil {
		// Do not overwrite a file we cannot read; the user must fix or remove it.
		return err
	}
	if doc.Allowed[kind] == nil {
		doc.Allowed[kind] = map[string]string{}
	}
	doc.Allowed[kind][name] = hash
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.dir, ".allowed-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.path())
}
