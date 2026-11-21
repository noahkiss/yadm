// Package extexec is the one contract for running anything outside the tool:
// external subcommands (`yadm-<name>` on PATH), collectors, on-change tasks,
// the notify hook and the busy probe. There is no in-process plugin API.
//
// Contract, identical for every kind:
//
//   - The tool runs argv directly (no shell) with a timeout, in the user's
//     $HOME, with stdin set to one JSON Request.
//   - The environment adds the machine's id, name, types, os, arch and declared
//     facts, plus home, source and commit (see Env), so a plain shell script
//     can ignore stdin.
//   - On exit 0, stdout is read as one JSON Response when its first non-space
//     byte is '{'. Otherwise each non-empty stdout line is one item; items are
//     trimmed, sorted and de-duplicated (the normalized collector form).
//   - A non-zero exit, a timeout or invalid JSON is a failure. The tool records
//     it and never retries within the same run.
//   - Stderr is captured (bounded) for the result record and never parsed.
//
// A check (KindCheck) also gets Request.Staged, target -> a 0600 temp
// file with its plaintext, and Request.Entries, target -> the Entry it has
// once the commit lands. Entries is read from the planned manifest, so a
// manifest edit in the same commit counts; it holds manifest fields only.
// A target that no entry or owned root covers has no key.
//
// External subcommands: `yadm foo args...` runs `yadm-foo` from PATH when foo
// is not a built-in command, with Request.Kind = "subcommand" and Args set.
// Its Response is wrapped in the normal CLI envelope under --json.
//
// Exported API:
//
//	type Kind string                    // KindSubcommand, KindCollector, KindTask, KindCheck, KindNotify, KindBusy, KindNudge
//	func Env(req Request) []string
//	type Request struct{...}            // stdin payload
//	type Entry struct{ Target model.Target; Source model.SourcePath; When string; Enclave model.EnclaveName; Root bool } // a check's view of a staged target's entry
//	type Response struct{...}           // stdout payload
//	type Result struct{...}             // what the runner observed
//	type Runner interface{ Run(ctx, Spec, Request) (Result, error) }
//	type Spec struct{ Argv []string; Timeout time.Duration }
//	func NewRunner() Runner
//	type ExitError struct{ Name string; Code int; Stderr string } // errors.Is(err, ErrExit)
//	var ErrNoCommand, ErrExit, ErrTimeout, ErrBadResponse, ErrNotOK, ErrTooLarge
//	func FindSubcommand(name string) (path string, err error)
//	func Normalize(stdout []byte) []string
package extexec
