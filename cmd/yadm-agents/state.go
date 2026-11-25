package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// State is what gen leaves for its next run and for the tripwire, at
// <home>/.local/state/yadm-agents/state.json. Losing it is safe: gen then
// owns no trust entry, so it removes none, and the tripwire says it has
// nothing to compare.
type State struct {
	Schema  int                     `json:"schema"`
	Harness map[string]HarnessState `json:"harness"`
}

// HarnessState is one harness's record.
type HarnessState struct {
	Target  string   `json:"target"`            // the file the harness loads, relative to home
	Trusted []string `json:"trusted,omitempty"` // project paths whose trust entry gen wrote
}

// stateRel is the state file, relative to home. A task that runs gen
// lists it in outputs.
const stateRel = ".local/state/yadm-agents/state.json"

func statePath(home string) string { return filepath.Join(home, filepath.FromSlash(stateRel)) }

// readState reads the state file. A missing file is an error the caller
// may treat as empty with errors.Is(err, fs.ErrNotExist).
func readState(path string) (State, error) {
	st := State{Schema: 1, Harness: map[string]HarnessState{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return State{Schema: 1, Harness: map[string]HarnessState{}}, fmt.Errorf("%s: %w", path, err)
	}
	if st.Schema != 1 {
		return State{Schema: 1, Harness: map[string]HarnessState{}}, fmt.Errorf("%s: schema %d, want 1", path, st.Schema)
	}
	if st.Harness == nil {
		st.Harness = map[string]HarnessState{}
	}
	return st, nil
}

// loadState reads the state for gen. A missing file is empty; a corrupt
// one is empty too, which only makes gen own less.
func loadState(path string) State {
	st, err := readState(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return State{Schema: 1, Harness: map[string]HarnessState{}}
	}
	return st
}

func writeState(path string, st State) error {
	for h, s := range st.Harness {
		sort.Strings(s.Trusted)
		st.Harness[h] = s
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil && string(old) == string(b)+"\n" {
		return nil
	}
	return writeAtomic(path, append(b, '\n'))
}
