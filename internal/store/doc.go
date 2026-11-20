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
// after main has moved. CheckWorktree makes the same test without moving
// anything; callers run it before they move main, so main never moves past
// a dirty clone.
//
// Blob reads (ReadBlob, ReadPath) go through one long-lived
// `git cat-file --batch` process per Repo. It starts on first read, stops
// after an idle period or at Close, restarts when it dies, and restarts after
// Fetch. A missing or non-blob object falls back to a one-shot git call, so
// results and errors match a plain `git cat-file blob`.
//
// Exported API:
//
//	type Store interface{ ... }        // see store.go; *Repo implements it
//	func Open(sourceDir, stateDir string) (*Repo, error)
//	func Clone(ctx, remote, sourceDir, stateDir string) (*Repo, error)
//	func (r *Repo) Close() error       // stops the batch reader; a later read restarts it
//	type Change struct{ Path model.SourcePath; Blob []byte; Mode uint32; Delete bool }
//	type Message struct{ Subject, Body string; Trailers []Trailer }
//	type MergeResult struct{ Tree string; Conflicts []Conflict }
//	type Conflict struct{ Path model.SourcePath; Base, Ours, Theirs string }
//	var ErrRejected, ErrStaleRef, ErrDirty
//	func CheckGitVersion(ctx) error
//	func (r *Repo) HashBlob(ctx, b) (string, error)
//	func (r *Repo) ConfigKeys(ctx, re string, localOnly bool) ([]string, error)
//	func (r *Repo) Git(ctx, stdin, stdout, stderr, args...) (exit int, err error) // `yadm git`
//	func (r *Repo) RemoteHeads(ctx) (map[string]model.CommitID, error)            // ls-remote main and refs/yadm/*
//	func Passthrough(ctx, dir, stdin, stdout, stderr, args...) (int, error); func Output(ctx, dir, args...) ([]byte, error)
//	func GitExitCode(err) int
//	func FormatMessage(Message) string; func ParseMessage(raw string) Message
//	Ref names: RefMain, RefReviewed(scope), RefHeld(machine), fleet.StatusRef(machine)
package store
