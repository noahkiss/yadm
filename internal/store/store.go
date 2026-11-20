package store

import (
	"context"
	"errors"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// Ref names the tool uses besides the remote branch.
const (
	RefMain          = "refs/heads/main"
	RemoteMain       = "refs/remotes/origin/main"
	RefYadmPrefix    = "refs/yadm/"
	FetchRefspecYadm = "+refs/yadm/*:refs/remotes/origin/yadm/*"
)

// RefReviewed is the reviewed-up-to ref for one scope.
func RefReviewed(s model.Scope) string { return "refs/yadm/reviewed/" + string(s) }

// RefHeld is a machine's local-only ref holding commits replay could not land.
// It is never pushed.
func RefHeld(m model.MachineID) string { return "refs/yadm/held/" + string(m) }

// Errors callers branch on.
var (
	ErrRejected = errors.New("push rejected: remote moved")           // retry the sync loop
	ErrStaleRef = errors.New("ref changed since it was read")         // compare-and-swap lost
	ErrDirty    = errors.New("source clone worktree has local edits") // sync stops; never stashes
)

// Trailer is one git commit trailer.
type Trailer struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Standard trailer keys.
const (
	TrailerMachine = "Machine"     // machine id that made the commit
	TrailerAuto    = "Yadm-Auto"   // "1" on mechanical commits
	TrailerScope   = "Yadm-Scope"  // shared or an enclave name
	TrailerLegacy  = "Legacy-Head" // import: the legacy head commit
)

// Message is a commit message.
type Message struct {
	Subject  string
	Body     string
	Trailers []Trailer
}

// Change is one path in a commit built through the private index.
type Change struct {
	Path   model.SourcePath
	Blob   []byte // ignored when Delete
	Mode   uint32 // 0100644 or 0100755
	Delete bool
}

// TreeEntry is one blob in a tree listing.
type TreeEntry struct {
	Path model.SourcePath
	Mode uint32
	Blob string // object id
}

// Commit is a parsed commit.
type Commit struct {
	ID      model.CommitID
	Parents []model.CommitID
	Author  string
	When    time.Time
	Message Message
	Paths   []model.SourcePath // paths changed against the first parent
}

// Conflict is one conflicted path from merge-tree with its stage blobs.
// An empty id means the side has no such path (add/delete conflicts).
type Conflict struct {
	Path   model.SourcePath
	Base   string
	Ours   string
	Theirs string
}

// MergeResult is the outcome of an in-memory three-way merge.
type MergeResult struct {
	Tree      string // written tree id; valid only when Conflicts is empty
	Conflicts []Conflict
}

// Store is everything the rest of the tool needs from git.
type Store interface {
	Dir() string
	Head(ctx context.Context) (model.CommitID, error)
	ResolveRef(ctx context.Context, ref string) (model.CommitID, error)
	Fetch(ctx context.Context) error // origin main and refs/yadm/*
	ListTree(ctx context.Context, rev model.CommitID) ([]TreeEntry, error)
	ReadBlob(ctx context.Context, id string) ([]byte, error)
	ReadPath(ctx context.Context, rev model.CommitID, p model.SourcePath) ([]byte, error)
	// CommitPaths builds a commit on parent from changes using the private index.
	CommitPaths(ctx context.Context, parent model.CommitID, changes []Change, msg Message) (model.CommitID, error)
	// MergeTree merges theirs into ours over base without touching any worktree.
	MergeTree(ctx context.Context, base, ours, theirs model.CommitID) (MergeResult, error)
	// WriteTree writes a tree from ours plus resolved blobs (after an in-memory merge).
	WriteTree(ctx context.Context, ours model.CommitID, resolved []Change) (string, error)
	CommitTree(ctx context.Context, tree string, parents []model.CommitID, msg Message) (model.CommitID, error)
	// UpdateRef sets ref to newID only if it still equals oldID ("" = must not exist).
	UpdateRef(ctx context.Context, ref string, newID, oldID model.CommitID) error
	// Push pushes refspecs atomically. It never forces. A non-fast-forward is ErrRejected.
	Push(ctx context.Context, refspecs []string) error
	Log(ctx context.Context, rangeSpec string, paths []model.SourcePath) ([]Commit, error)
	IsAncestor(ctx context.Context, a, b model.CommitID) (bool, error)
	// SyncWorktree moves the clone's worktree and index to rev; ErrDirty if it has local edits.
	SyncWorktree(ctx context.Context, rev model.CommitID) error
	// CheckSecrecyConfig fails if any setting could write plaintext into the repo,
	// such as diff.*.cachetextconv or a refs/notes/textconv ref.
	CheckSecrecyConfig(ctx context.Context) error
}

// Repo is the git-binary implementation of Store.
type Repo struct {
	dir       string
	indexFile string
}

// Open opens an existing source clone.
func Open(sourceDir, stateDir string) (*Repo, error) { return nil, model.ErrNotImplemented }

// Clone clones remote into sourceDir and configures the yadm fetch refspec.
func Clone(ctx context.Context, remote, sourceDir, stateDir string) (*Repo, error) {
	return nil, model.ErrNotImplemented
}

// Dir returns the source clone directory.
func (r *Repo) Dir() string { return r.dir }

func (r *Repo) Head(context.Context) (model.CommitID, error) { return "", model.ErrNotImplemented }
func (r *Repo) ResolveRef(context.Context, string) (model.CommitID, error) {
	return "", model.ErrNotImplemented
}
func (r *Repo) Fetch(context.Context) error { return model.ErrNotImplemented }
func (r *Repo) ListTree(context.Context, model.CommitID) ([]TreeEntry, error) {
	return nil, model.ErrNotImplemented
}
func (r *Repo) ReadBlob(context.Context, string) ([]byte, error) { return nil, model.ErrNotImplemented }
func (r *Repo) ReadPath(context.Context, model.CommitID, model.SourcePath) ([]byte, error) {
	return nil, model.ErrNotImplemented
}
func (r *Repo) CommitPaths(context.Context, model.CommitID, []Change, Message) (model.CommitID, error) {
	return "", model.ErrNotImplemented
}
func (r *Repo) MergeTree(context.Context, model.CommitID, model.CommitID, model.CommitID) (MergeResult, error) {
	return MergeResult{}, model.ErrNotImplemented
}
func (r *Repo) WriteTree(context.Context, model.CommitID, []Change) (string, error) {
	return "", model.ErrNotImplemented
}
func (r *Repo) CommitTree(context.Context, string, []model.CommitID, Message) (model.CommitID, error) {
	return "", model.ErrNotImplemented
}
func (r *Repo) UpdateRef(context.Context, string, model.CommitID, model.CommitID) error {
	return model.ErrNotImplemented
}
func (r *Repo) Push(context.Context, []string) error { return model.ErrNotImplemented }
func (r *Repo) Log(context.Context, string, []model.SourcePath) ([]Commit, error) {
	return nil, model.ErrNotImplemented
}
func (r *Repo) IsAncestor(context.Context, model.CommitID, model.CommitID) (bool, error) {
	return false, model.ErrNotImplemented
}
func (r *Repo) SyncWorktree(context.Context, model.CommitID) error { return model.ErrNotImplemented }
func (r *Repo) CheckSecrecyConfig(context.Context) error           { return model.ErrNotImplemented }

var _ Store = (*Repo)(nil)
