// Package store is the only code that runs git. It shells out to the git
// binary (no library) against the source clone, always with a private index
// file and with configuration overrides that keep secrecy intact.
//
// Every git invocation:
//
//   - sets GIT_INDEX_FILE to a fresh private index per commit operation, seeded
//     from the parent commit and holding only that operation's paths, so the
//     clone's own index is never touched and parallel operations never sweep
//     each other's changes;
//   - passes `-c diff.cachetextconv=false -c core.hooksPath=/dev/null`
//     (hooks of the clone never run under the tool) and sets no textconv or
//     merge driver: the tool decrypts in memory, never inside git;
//   - sets GIT_TERMINAL_PROMPT=0 and never prompts.
//
// Merges use `git merge-tree --write-tree` and return every conflicted path
// with its three stage blobs, so apply can open sealed files, merge plaintext
// and reseal. Pushes are atomic and never forced.
//
// Exported API:
//
//	type Store interface{ ... }        // see store.go; *Repo implements it
//	func Open(sourceDir, stateDir string) (*Repo, error)
//	func Clone(ctx, remote, sourceDir, stateDir string) (*Repo, error)
//	type Change struct{ Path model.SourcePath; Blob []byte; Mode uint32; Delete bool }
//	type Message struct{ Subject, Body string; Trailers []Trailer }
//	type MergeResult struct{ Tree string; Conflicts []Conflict }
//	type Conflict struct{ Path model.SourcePath; Base, Ours, Theirs string }
//	var ErrRejected, ErrStaleRef
//	Ref names: RefMain, RefReviewed(scope), RefHeld(machine), fleet.StatusRef(machine)
package store
