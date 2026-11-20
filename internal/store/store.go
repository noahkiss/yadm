package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

const refHeldPrefix = "refs/yadm/held/"

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
//
// A ref or HEAD that does not exist resolves to "" with a nil error, the same
// "" that UpdateRef reads as "must not exist".
type Store interface {
	Dir() string
	Head(ctx context.Context) (model.CommitID, error)
	ResolveRef(ctx context.Context, ref string) (model.CommitID, error)
	Fetch(ctx context.Context) error // origin main and refs/yadm/*
	ListTree(ctx context.Context, rev model.CommitID) ([]TreeEntry, error)
	ReadBlob(ctx context.Context, id string) ([]byte, error)
	// ReadPath returns the blob at p in rev; a missing path wraps fs.ErrNotExist.
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
	// ListRefs returns every ref under prefix (for example "refs/yadm/status/")
	// with the commit it points at.
	ListRefs(ctx context.Context, prefix string) (map[string]model.CommitID, error)
}

// Repo is the git-binary implementation of Store.
type Repo struct {
	dir      string
	stateDir string
	indexDir string // private index files, one per operation
	zeroOID  string
}

// worktreeFile records the commit the source worktree was last moved to.
const worktreeFile = "worktree-head"

// Open opens an existing source clone. It checks the git version, creates the
// private index directory under stateDir and makes sure origin fetches refs/yadm/*.
func Open(sourceDir, stateDir string) (*Repo, error) {
	ctx := context.Background()
	if err := CheckGitVersion(ctx); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(sourceDir)
	if err != nil {
		return nil, err
	}
	top, err := run(ctx, call{dir: abs, args: []string{"rev-parse", "--show-toplevel"}})
	if err != nil {
		return nil, fmt.Errorf("open source clone %s: %w", sourceDir, err)
	}
	top = bytes.TrimSpace(top)
	if real, _ := filepath.EvalSymlinks(abs); string(top) != abs && string(top) != real {
		return nil, fmt.Errorf("open source clone: %s is not the top of a git worktree", sourceDir)
	}
	stateAbs, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, err
	}
	r := &Repo{dir: abs, stateDir: stateAbs, indexDir: filepath.Join(stateAbs, "index")}
	if err := os.MkdirAll(r.indexDir, 0o700); err != nil {
		return nil, err
	}
	fmtOut, err := r.git(ctx, "rev-parse", "--show-object-format")
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(string(fmtOut)) {
	case "sha256":
		r.zeroOID = strings.Repeat("0", 64)
	default:
		r.zeroOID = strings.Repeat("0", 40)
	}
	if err := r.ensureFetchRefspec(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Clone clones remote into sourceDir and configures the yadm fetch refspec.
// An empty remote yields a clone whose HEAD points at an unborn main.
func Clone(ctx context.Context, remote, sourceDir, stateDir string) (*Repo, error) {
	if err := CheckGitVersion(ctx); err != nil {
		return nil, err
	}
	if _, err := run(ctx, call{network: true, args: []string{
		"clone", "--quiet", "--origin", "origin", "--template=", "--no-recurse-submodules",
		"--", remote, sourceDir,
	}}); err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	r, err := Open(sourceDir, stateDir)
	if err != nil {
		return nil, err
	}
	head, err := r.git(ctx, "symbolic-ref", "-q", "HEAD")
	if err != nil || strings.TrimSpace(string(head)) != RefMain {
		if _, err := r.git(ctx, "symbolic-ref", "HEAD", RefMain); err != nil {
			return nil, err
		}
	}
	if err := r.Fetch(ctx); err != nil {
		return nil, err
	}
	h, err := r.Head(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.recordWorktree(h); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Repo) git(ctx context.Context, args ...string) ([]byte, error) {
	return run(ctx, call{dir: r.dir, args: args})
}

func (r *Repo) ensureFetchRefspec(ctx context.Context) error {
	out, err := r.git(ctx, "config", "--get-all", "remote.origin.fetch")
	if err != nil && exitCode(err) != 1 {
		return err
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(l) == FetchRefspecYadm {
			return nil
		}
	}
	if _, err := r.git(ctx, "remote", "get-url", "origin"); err != nil {
		return nil // no origin yet; nothing to configure
	}
	_, err = r.git(ctx, "config", "--add", "remote.origin.fetch", FetchRefspecYadm)
	return err
}

// Dir returns the source clone directory.
func (r *Repo) Dir() string { return r.dir }

// Head returns the commit HEAD points at, or "" when HEAD is unborn.
func (r *Repo) Head(ctx context.Context) (model.CommitID, error) {
	return r.ResolveRef(ctx, "HEAD")
}

// ResolveRef returns the commit a ref or revision names, or "" when it does not exist.
func (r *Repo) ResolveRef(ctx context.Context, ref string) (model.CommitID, error) {
	if ref == "" || strings.HasPrefix(ref, "-") {
		return "", fmt.Errorf("resolve ref: invalid name %q", ref)
	}
	out, err := r.git(ctx, "rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}")
	if err != nil {
		if exitCode(err) == 1 {
			return "", nil
		}
		return "", err
	}
	return model.CommitID(strings.TrimSpace(string(out))), nil
}

// Fetch fetches origin's branches and refs/yadm/* into refs/remotes/origin/.
func (r *Repo) Fetch(ctx context.Context) error {
	_, err := run(ctx, call{dir: r.dir, network: true, args: []string{
		"fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", "origin",
	}})
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	return nil
}

// ListTree lists every blob (and symlink) of rev recursively. Submodule
// entries are skipped.
func (r *Repo) ListTree(ctx context.Context, rev model.CommitID) ([]TreeEntry, error) {
	if err := checkRev(string(rev)); err != nil {
		return nil, err
	}
	out, err := r.git(ctx, "ls-tree", "-r", "-z", "--full-tree", string(rev))
	if err != nil {
		return nil, err
	}
	var entries []TreeEntry
	for _, rec := range strings.Split(string(out), "\x00") {
		if rec == "" {
			continue
		}
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok {
			return nil, fmt.Errorf("ls-tree: bad record %q", rec)
		}
		f := strings.Fields(meta)
		if len(f) != 3 {
			return nil, fmt.Errorf("ls-tree: bad record %q", rec)
		}
		if f[1] != "blob" {
			continue
		}
		mode, err := strconv.ParseUint(f[0], 8, 32)
		if err != nil {
			return nil, fmt.Errorf("ls-tree: bad mode %q", f[0])
		}
		entries = append(entries, TreeEntry{Path: model.SourcePath(path), Mode: uint32(mode), Blob: f[2]})
	}
	return entries, nil
}

// ReadBlob returns the bytes of one blob.
func (r *Repo) ReadBlob(ctx context.Context, id string) ([]byte, error) {
	if err := checkRev(id); err != nil {
		return nil, err
	}
	return r.git(ctx, "cat-file", "blob", id)
}

// ReadPath returns the blob at p in rev. A missing path wraps fs.ErrNotExist.
func (r *Repo) ReadPath(ctx context.Context, rev model.CommitID, p model.SourcePath) ([]byte, error) {
	if err := checkRev(string(rev)); err != nil {
		return nil, err
	}
	spec := string(rev) + ":" + string(p)
	out, err := r.git(ctx, "rev-parse", "--verify", "--quiet", "--end-of-options", spec)
	if err != nil {
		if exitCode(err) == 1 {
			return nil, fmt.Errorf("%s at %s: %w", p, rev, fs.ErrNotExist)
		}
		return nil, err
	}
	return r.ReadBlob(ctx, strings.TrimSpace(string(out)))
}

// privateIndex returns a fresh index path in the state directory and a
// cleanup func. The clone's own index is never used to stage.
func (r *Repo) privateIndex() (string, func(), error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, err
	}
	p := filepath.Join(r.indexDir, "index-"+hex.EncodeToString(b[:]))
	return p, func() { os.Remove(p); os.Remove(p + ".lock") }, nil
}

// buildTree writes a tree from base (a commit or "") plus changes, through a
// fresh private index.
func (r *Repo) buildTree(ctx context.Context, base model.CommitID, changes []Change) (string, error) {
	idx, cleanup, err := r.privateIndex()
	if err != nil {
		return "", err
	}
	defer cleanup()
	env := []string{"GIT_INDEX_FILE=" + idx}
	g := func(stdin []byte, args ...string) ([]byte, error) {
		return run(ctx, call{dir: r.dir, args: args, env: env, stdin: stdin})
	}
	if base != "" {
		if err := checkRev(string(base)); err != nil {
			return "", err
		}
		if _, err := g(nil, "read-tree", string(base)+"^{tree}"); err != nil {
			return "", err
		}
	} else if _, err := g(nil, "read-tree", "--empty"); err != nil {
		return "", err
	}
	var info bytes.Buffer
	for _, c := range changes {
		if err := checkPath(c.Path); err != nil {
			return "", err
		}
		if c.Delete {
			fmt.Fprintf(&info, "0 %s\t%s\x00", r.zeroOID, c.Path)
			continue
		}
		mode := c.Mode
		if mode == 0 {
			mode = 0o100644
		}
		if mode != 0o100644 && mode != 0o100755 && mode != 0o120000 {
			return "", fmt.Errorf("%s: unsupported mode %o", c.Path, mode)
		}
		id, err := r.hashBlob(ctx, c.Blob)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&info, "%o %s\t%s\x00", mode, id, c.Path)
	}
	if info.Len() > 0 {
		if _, err := g(info.Bytes(), "update-index", "-z", "--index-info"); err != nil {
			return "", err
		}
	}
	out, err := g(nil, "write-tree")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// hashBlob writes b as a blob. No attribute filter runs on it.
func (r *Repo) hashBlob(ctx context.Context, b []byte) (string, error) {
	if b == nil {
		b = []byte{}
	}
	out, err := run(ctx, call{dir: r.dir, stdin: b, args: []string{"hash-object", "-w", "--no-filters", "--stdin"}})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// CommitPaths builds a commit on parent ("" for a root commit) from changes
// using a fresh private index. It moves no ref.
func (r *Repo) CommitPaths(ctx context.Context, parent model.CommitID, changes []Change, msg Message) (model.CommitID, error) {
	tree, err := r.buildTree(ctx, parent, changes)
	if err != nil {
		return "", err
	}
	var parents []model.CommitID
	if parent != "" {
		parents = []model.CommitID{parent}
	}
	return r.CommitTree(ctx, tree, parents, msg)
}

// MergeTree merges theirs into ours over base with `git merge-tree
// --write-tree`. base "" lets git pick the merge base. On conflict, Tree is
// empty and Conflicts lists every conflicted path with its stage blobs.
func (r *Repo) MergeTree(ctx context.Context, base, ours, theirs model.CommitID) (MergeResult, error) {
	for _, c := range []model.CommitID{ours, theirs} {
		if err := checkRev(string(c)); err != nil {
			return MergeResult{}, err
		}
	}
	args := []string{"merge-tree", "--write-tree", "-z", "--no-messages", "--allow-unrelated-histories"}
	if base != "" {
		if err := checkRev(string(base)); err != nil {
			return MergeResult{}, err
		}
		args = append(args, "--merge-base="+string(base))
	}
	args = append(args, string(ours), string(theirs))
	out, err := r.git(ctx, args...)
	if err != nil && exitCode(err) != 1 {
		return MergeResult{}, err
	}
	clean := err == nil
	tree, conflicts, perr := parseMergeTree(out)
	if perr != nil {
		return MergeResult{}, perr
	}
	if clean {
		return MergeResult{Tree: tree}, nil
	}
	if len(conflicts) == 0 {
		return MergeResult{}, fmt.Errorf("merge-tree reported a conflict but listed no paths")
	}
	return MergeResult{Conflicts: conflicts}, nil
}

// parseMergeTree reads `merge-tree --write-tree -z` output: the tree id, then
// "<mode> <oid> <stage>\t<path>" records, all NUL-terminated.
func parseMergeTree(out []byte) (string, []Conflict, error) {
	recs := strings.Split(string(out), "\x00")
	if len(recs) == 0 || recs[0] == "" {
		return "", nil, fmt.Errorf("merge-tree: empty output")
	}
	tree := strings.TrimSpace(recs[0])
	byPath := map[string]*Conflict{}
	var order []string
	for _, rec := range recs[1:] {
		if rec == "" {
			break // end of the conflicted-file section
		}
		meta, path, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return "", nil, fmt.Errorf("merge-tree: bad record %q", rec)
		}
		c := byPath[path]
		if c == nil {
			c = &Conflict{Path: model.SourcePath(path)}
			byPath[path] = c
			order = append(order, path)
		}
		switch f[2] {
		case "1":
			c.Base = f[1]
		case "2":
			c.Ours = f[1]
		case "3":
			c.Theirs = f[1]
		default:
			return "", nil, fmt.Errorf("merge-tree: bad stage %q", f[2])
		}
	}
	var conflicts []Conflict
	for _, p := range order {
		conflicts = append(conflicts, *byPath[p])
	}
	return tree, conflicts, nil
}

// WriteTree writes a tree from ours plus resolved changes.
func (r *Repo) WriteTree(ctx context.Context, ours model.CommitID, resolved []Change) (string, error) {
	return r.buildTree(ctx, ours, resolved)
}

// CommitTree writes a commit object for tree with parents and msg. It never
// signs and moves no ref.
func (r *Repo) CommitTree(ctx context.Context, tree string, parents []model.CommitID, msg Message) (model.CommitID, error) {
	if err := checkRev(tree); err != nil {
		return "", err
	}
	if strings.TrimSpace(msg.Subject) == "" {
		return "", fmt.Errorf("commit: empty subject")
	}
	args := []string{"commit-tree", "--no-gpg-sign"}
	for _, p := range parents {
		if err := checkRev(string(p)); err != nil {
			return "", err
		}
		args = append(args, "-p", string(p))
	}
	args = append(args, tree)
	out, err := run(ctx, call{dir: r.dir, args: args, stdin: []byte(FormatMessage(msg)), env: r.identityEnv(ctx)})
	if err != nil {
		return "", err
	}
	return model.CommitID(strings.TrimSpace(string(out))), nil
}

// identityEnv supplies a neutral identity only when git has none, so a fresh
// machine can still commit. Machine identity lives in the Machine trailer.
func (r *Repo) identityEnv(ctx context.Context) []string {
	var env []string
	for _, v := range []string{"AUTHOR", "COMMITTER"} {
		if _, err := r.git(ctx, "var", "GIT_"+v+"_IDENT"); err != nil {
			env = append(env, "GIT_"+v+"_NAME=yadm", "GIT_"+v+"_EMAIL=yadm@localhost.invalid")
		}
	}
	return env
}

// FormatMessage renders msg as a git commit message: subject, body, then a
// trailer block.
func FormatMessage(m Message) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(strings.ReplaceAll(m.Subject, "\n", " ")))
	b.WriteString("\n")
	if body := strings.TrimSpace(m.Body); body != "" {
		b.WriteString("\n" + body + "\n")
	}
	if len(m.Trailers) > 0 {
		b.WriteString("\n")
		for _, t := range m.Trailers {
			fmt.Fprintf(&b, "%s: %s\n", t.Key, strings.ReplaceAll(t.Value, "\n", " "))
		}
	}
	return b.String()
}

// ParseMessage splits a raw commit message into subject, body and trailers.
// The trailer block is the last paragraph when every line is "Key: Value".
func ParseMessage(raw string) Message {
	raw = strings.TrimRight(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	subject, rest, _ := strings.Cut(raw, "\n")
	m := Message{Subject: strings.TrimSpace(subject)}
	rest = strings.Trim(rest, "\n")
	if rest == "" {
		return m
	}
	paras := strings.Split(rest, "\n\n")
	last := paras[len(paras)-1]
	if tr, ok := parseTrailers(last); ok {
		m.Trailers = tr
		paras = paras[:len(paras)-1]
	}
	m.Body = strings.TrimSpace(strings.Join(paras, "\n\n"))
	return m
}

func parseTrailers(para string) ([]Trailer, bool) {
	var out []Trailer
	for _, l := range strings.Split(para, "\n") {
		k, v, ok := strings.Cut(l, ": ")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return nil, false
		}
		out = append(out, Trailer{Key: k, Value: strings.TrimSpace(v)})
	}
	return out, len(out) > 0
}

// UpdateRef sets ref to newID only if it still equals oldID ("" = must not
// exist). newID "" deletes the ref. A lost compare-and-swap is ErrStaleRef.
func (r *Repo) UpdateRef(ctx context.Context, ref string, newID, oldID model.CommitID) error {
	if err := checkRefName(ref); err != nil {
		return err
	}
	old := string(oldID)
	if old == "" {
		old = r.zeroOID
	}
	var args []string
	if newID == "" {
		if oldID == "" {
			return fmt.Errorf("update-ref %s: delete needs the old value", ref)
		}
		args = []string{"update-ref", "--no-deref", "-d", ref, old}
	} else {
		if err := checkRev(string(newID)); err != nil {
			return err
		}
		args = []string{"update-ref", "--no-deref", "-m", "yadm", ref, string(newID), old}
	}
	_, err := r.git(ctx, args...)
	if err == nil {
		return nil
	}
	cur, rerr := r.ResolveRef(ctx, ref)
	if rerr == nil && cur != oldID {
		return fmt.Errorf("%s: %w (want %q, found %q)", ref, ErrStaleRef, oldID, cur)
	}
	return err
}

// Push pushes refspecs to origin with --atomic. It refuses forced refspecs
// and the local-only held refs. A non-fast-forward is ErrRejected.
func (r *Repo) Push(ctx context.Context, refspecs []string) error {
	if len(refspecs) == 0 {
		return nil
	}
	for _, s := range refspecs {
		src, _, _ := strings.Cut(s, ":")
		switch {
		case strings.HasPrefix(s, "+"):
			return fmt.Errorf("push %q: forced refspecs are not allowed", s)
		case strings.HasPrefix(s, "-"), src == "":
			return fmt.Errorf("push %q: invalid refspec", s)
		case strings.HasPrefix(src, refHeldPrefix), strings.Contains(s, ":"+refHeldPrefix):
			return fmt.Errorf("push %q: held refs are local only", s)
		}
	}
	args := append([]string{"push", "--atomic", "--porcelain", "--no-verify", "--no-recurse-submodules", "origin"}, refspecs...)
	out, err := run(ctx, call{dir: r.dir, network: true, args: args})
	if err == nil {
		return nil
	}
	var ge *gitError
	stderr := ""
	if errors.As(err, &ge) {
		stderr = ge.stderr
	}
	if pushRejected(string(out), stderr) {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return fmt.Errorf("push: %w", err)
}

// pushRejected reports whether porcelain output shows a ref the remote
// refused because it moved (non-fast-forward, fetch first, stale info).
func pushRejected(stdout, stderr string) bool {
	for _, l := range strings.Split(stdout, "\n") {
		if !strings.HasPrefix(l, "!") {
			continue
		}
		if strings.Contains(l, "non-fast-forward") || strings.Contains(l, "fetch first") ||
			strings.Contains(l, "stale info") || strings.Contains(l, "already exists") {
			return true
		}
	}
	return strings.Contains(stderr, "non-fast-forward") || strings.Contains(stderr, "fetch first")
}

// Log lists commits in rangeSpec ("" = HEAD), newest first, touching paths
// when given. Paths of each commit are all paths it changed against its first
// parent.
func (r *Repo) Log(ctx context.Context, rangeSpec string, paths []model.SourcePath) ([]Commit, error) {
	if rangeSpec == "" {
		rangeSpec = "HEAD"
	}
	if strings.HasPrefix(rangeSpec, "-") {
		return nil, fmt.Errorf("log: invalid range %q", rangeSpec)
	}
	args := []string{"log", "-z", "--no-color", "--name-only", "--no-renames", "--full-diff",
		"--diff-merges=first-parent", "--format=%x1e%H%x1f%P%x1f%an <%ae>%x1f%aI%x1f%B%x1f",
		"--end-of-options", rangeSpec, "--"}
	for _, p := range paths {
		if err := checkPath(p); err != nil {
			return nil, err
		}
		args = append(args, ":(literal)"+string(p))
	}
	out, err := r.git(ctx, args...)
	if err != nil {
		return nil, err
	}
	var commits []Commit
	for _, rec := range strings.Split(string(out), "\x1e") {
		if strings.Trim(rec, "\x00\n") == "" {
			continue
		}
		f := strings.SplitN(rec, "\x1f", 6)
		if len(f) != 6 {
			return nil, fmt.Errorf("log: bad record")
		}
		when, err := time.Parse(time.RFC3339, f[3])
		if err != nil {
			return nil, fmt.Errorf("log: bad date %q", f[3])
		}
		c := Commit{ID: model.CommitID(f[0]), Author: f[2], When: when, Message: ParseMessage(f[4])}
		for _, p := range strings.Fields(f[1]) {
			c.Parents = append(c.Parents, model.CommitID(p))
		}
		for _, n := range strings.Split(f[5], "\x00") {
			n = strings.Trim(n, "\n")
			if n != "" {
				c.Paths = append(c.Paths, model.SourcePath(n))
			}
		}
		commits = append(commits, c)
	}
	return commits, nil
}

// IsAncestor reports whether a is an ancestor of b (or equal to it).
func (r *Repo) IsAncestor(ctx context.Context, a, b model.CommitID) (bool, error) {
	if err := checkRev(string(a)); err != nil {
		return false, err
	}
	if err := checkRev(string(b)); err != nil {
		return false, err
	}
	_, err := r.git(ctx, "merge-base", "--is-ancestor", string(a), string(b))
	if err == nil {
		return true, nil
	}
	if exitCode(err) == 1 {
		return false, nil
	}
	return false, err
}

// SyncWorktree moves the clone's worktree and index from the commit it was
// last moved to (recorded in the state directory; HEAD when none) to rev. It
// moves no ref; callers compare-and-swap main first. Any unstaged edit,
// staged edit or untracked file in the way is ErrDirty, and nothing changes.
func (r *Repo) SyncWorktree(ctx context.Context, rev model.CommitID) error {
	if err := checkRev(string(rev)); err != nil {
		return err
	}
	old, err := r.worktreeHead(ctx)
	if err != nil {
		return err
	}
	// Refresh stat info so a touched but unchanged file is not dirty.
	r.git(ctx, "update-index", "-q", "--refresh")
	if _, err := r.git(ctx, "diff-files", "--quiet"); err != nil {
		if exitCode(err) == 1 {
			return fmt.Errorf("%w: unstaged edits", ErrDirty)
		}
		return err
	}
	oldTree := string(old)
	if old == "" {
		oldTree = r.emptyTree()
	} else {
		oldTree += "^{tree}"
	}
	if _, err := r.git(ctx, "diff-index", "--cached", "--quiet", oldTree, "--"); err != nil {
		if exitCode(err) == 1 {
			return fmt.Errorf("%w: staged edits", ErrDirty)
		}
		return err
	}
	if _, err := r.git(ctx, "read-tree", "-m", "-u", oldTree, string(rev)+"^{tree}"); err != nil {
		var ge *gitError
		if errors.As(err, &ge) && (strings.Contains(ge.stderr, "overwritten") ||
			strings.Contains(ge.stderr, "not uptodate") || strings.Contains(ge.stderr, "would be lost")) {
			return fmt.Errorf("%w: %s", ErrDirty, strings.TrimSpace(ge.stderr))
		}
		return err
	}
	return r.recordWorktree(rev)
}

func (r *Repo) emptyTree() string {
	if len(r.zeroOID) == 64 {
		return "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"
	}
	return "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
}

func (r *Repo) worktreeHead(ctx context.Context) (model.CommitID, error) {
	b, err := os.ReadFile(filepath.Join(r.stateDir, worktreeFile))
	if err == nil {
		id := strings.TrimSpace(string(b))
		if checkRev(id) == nil {
			return model.CommitID(id), nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return r.Head(ctx)
}

func (r *Repo) recordWorktree(id model.CommitID) error {
	p := filepath.Join(r.stateDir, worktreeFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(string(id)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// CheckSecrecyConfig fails if any setting could write plaintext into the
// repository: a true diff.*.cachetextconv in any config scope the clone sees,
// or a ref under refs/notes/textconv.
func (r *Repo) CheckSecrecyConfig(ctx context.Context) error {
	var problems []string
	out, err := r.git(ctx, "config", "--null", "--get-regexp", `^diff\.(.*\.)?cachetextconv$`)
	if err != nil && exitCode(err) != 1 {
		return err
	}
	for _, rec := range strings.Split(string(out), "\x00") {
		key, val, _ := strings.Cut(rec, "\n")
		if key == "" {
			continue
		}
		if isGitTrue(val) {
			problems = append(problems, "config "+key+" = "+val)
		}
	}
	refs, err := r.git(ctx, "for-each-ref", "--format=%(refname)", "refs/notes/textconv")
	if err != nil {
		return err
	}
	for _, ref := range strings.Fields(string(refs)) {
		problems = append(problems, "ref "+ref)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("secrecy: textconv cache can write plaintext into the repository: %s", strings.Join(problems, "; "))
	}
	return nil
}

func isGitTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "true", "yes", "on", "1": // a bare key means true
		return true
	}
	return false
}

func checkRev(s string) error {
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\n\x00") {
		return fmt.Errorf("invalid revision %q", s)
	}
	return nil
}

func checkRefName(s string) error {
	if !strings.HasPrefix(s, "refs/") && s != "HEAD" {
		return fmt.Errorf("invalid ref %q: want refs/...", s)
	}
	return checkRev(s)
}

func checkPath(p model.SourcePath) error {
	s := string(p)
	if s == "" || strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\x00\n") {
		return fmt.Errorf("invalid source path %q", s)
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.EqualFold(seg, ".git") {
			return fmt.Errorf("invalid source path %q", s)
		}
	}
	return nil
}

var _ Store = (*Repo)(nil)
