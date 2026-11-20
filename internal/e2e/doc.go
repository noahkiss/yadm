// Package e2e drives the built yadm binary through whole-fleet scenarios:
// several simulated machines, each with its own $HOME, state and identity,
// sharing one bare remote.
//
// Every scenario runs the binary as a child process with a stripped
// environment:
//
//   - HOME and the XDG directories point into a temp directory per machine;
//   - PATH holds a shim directory first, whose launchctl and systemctl only
//     log their arguments, then git's directory and the system directories,
//     so no unit reload, schedule or nudge reaches the real machine;
//   - git reads no global or system config.
//
// The synthetic scenario runs in every `go test`. The corpus scenario is a
// cutover rehearsal on a real upstream-yadm repository and runs only with
// YADM_CORPUS=1:
//
//	YADM_CORPUS=1                 enable
//	YADM_LEGACY_REPO=<git dir>    the legacy repository; it is cloned, never written
//	YADM_ORACLE_DIR=<dir>         oracle records; default $HOME/.local/share/yadm-oracle
//	YADM_CORPUS_OUT=<dir>         where reports go; default a temp dir
//	YADM_IMPORT_FILTERS=<toml>    passed to import --filters (strip-filter mapping)
//	YADM_E2E_BIN=<path>           a prebuilt binary instead of building ./cmd/yadm
//	YADM_SOAK_ROUNDS=<n>          soak rounds (default 50 for the corpus, 6 otherwise)
//	YADM_SOAK_SEED=<n>            soak seed (default: time based, always printed)
//	YADM_E2E_SOAK=1               run the synthetic soak too (slow)
//	YADM_E2E_REPRO=1              run the minimal reproductions of soak findings
//
// Reports name paths and counts only, never file contents.
package e2e
