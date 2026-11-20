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
// and reseal. Pushes are atomic and never forced; held refs are never pushed.
//
// Open and Clone require git 2.40 or newer (MinGitVersion). A ref or HEAD
// that does not exist resolves to "", the value UpdateRef reads as "must not
// exist". SyncWorktree records the commit it last checked out in the state
// directory, so staged edits in the clone's index count as local edits even
// after main has moved.
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
//	var ErrRejected, ErrStaleRef, ErrDirty
//	func CheckGitVersion(ctx) error
//	func FormatMessage(Message) string; func ParseMessage(raw string) Message
//	Ref names: RefMain, RefReviewed(scope), RefHeld(machine), fleet.StatusRef(machine)
package store
