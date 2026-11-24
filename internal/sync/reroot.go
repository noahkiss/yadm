package sync

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/reroot"
	"github.com/noahkiss/yadm/internal/store"
)

// Tasks of the holds a rewritten remote raises. They have no target.
const (
	// HoldTaskRewrite: the remote main no longer descends from the accepted
	// one, and no verified re-root record announces the rewrite.
	HoldTaskRewrite = "history-rewrite"
	// HoldTaskReroot: a verified re-root record announces the rewrite, but
	// this machine cannot switch yet (unpushed local commits, a key-log
	// change in the rewrite, a failed backup).
	HoldTaskReroot = "reroot"
)

// Alert kinds of a rewritten remote.
const (
	AlertHistoryRewrite = "history_rewrite"
	AlertRerootAccepted = "reroot_accepted"
	AlertRerootHeld     = "reroot_held"
)

// RefCarry is the local-only ref that keeps this machine's commits as they
// were before `yadm reroot carry` replayed them onto a re-rooted history.
func RefCarry(id string) string { return "refs/yadm/carry/" + id }

// Errors of the initiator side.
var (
	// ErrRerootRefused refuses a re-root for trust or secrecy: the signer
	// is no pinned key-log member, the rewrite changes key-log files, or
	// the rewritten manifest weakens protection.
	ErrRerootRefused = errors.New("re-root refused")
	// ErrRerootState refuses a re-root this machine is not ready for:
	// local main differs from the remote, or a refusal hold is open.
	ErrRerootState = errors.New("not ready to re-root")
)

// rewriteResult is what a rewritten remote leads to in one run.
type rewriteResult struct {
	refusal  *refusal
	switched bool // local main now descends from the record's new head
	dirty    bool // the source clone has local edits; main did not move
	rec      reroot.Record
	local    model.CommitID // local main after the switch
	holds    []model.Hold   // conflict holds of a carry
}

// exists reports whether id names a commit in the local object store.
func (s *Syncer) exists(ctx context.Context, id model.CommitID) bool {
	got, err := s.Store.ResolveRef(ctx, string(id))
	return err == nil && got == id
}

func (s *Syncer) ancestor(ctx context.Context, a, b model.CommitID) bool {
	ok, err := s.Store.IsAncestor(ctx, a, b)
	return err == nil && ok
}

// keyEntries lists the key-log files of rev by path.
func (s *Syncer) keyEntries(ctx context.Context, rev model.CommitID) (map[model.SourcePath]string, error) {
	tree, err := s.treeMap(ctx, rev)
	if err != nil {
		return nil, err
	}
	out := map[model.SourcePath]string{}
	for p, e := range tree {
		if _, _, ok := keyLogPath(p); ok {
			out[p] = e.Blob
		}
	}
	return out, nil
}

// keyDiff lists how the key-log files of b differ from those of a. With
// exact, a file b adds counts too; without, b may append entries.
func (s *Syncer) keyDiff(ctx context.Context, a, b model.CommitID, exact bool) ([]string, error) {
	ka, err := s.keyEntries(ctx, a)
	if err != nil {
		return nil, err
	}
	kb, err := s.keyEntries(ctx, b)
	if err != nil {
		return nil, err
	}
	var out []string
	for p, blob := range ka {
		switch nb, ok := kb[p]; {
		case !ok:
			out = append(out, fmt.Sprintf("%s was deleted", p))
		case nb != blob:
			out = append(out, fmt.Sprintf("%s was rewritten", p))
		}
	}
	if exact {
		for p := range kb {
			if _, ok := ka[p]; !ok {
				out = append(out, fmt.Sprintf("%s was added", p))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// rewrite handles a fetched main that does not descend from the accepted
// one (base). Without a verified re-root record that leads there, it
// refuses the fetch (HoldTaskRewrite). With one, it checks the switch
// (unpushed commits, key logs, manifest guard), backs up the old history
// on a machine whose types set reroot_keep, moves local main to the new
// head (replaying local commits first with carry) and records the new
// head as accepted. The caller then runs the normal checks on new..remote
// and applies. onlyBy, when set, takes only a record that machine signed
// and raises no refusal: a machine a fleet pause holds switches only for
// the pause's initiator. The caller holds the sync lock.
func (s *Syncer) rewrite(ctx context.Context, base, local, remote model.CommitID, carry bool, onlyBy model.MachineID) (rewriteResult, error) {
	var out rewriteResult
	if base == "" || remote == "" || base == remote {
		return out, nil
	}
	if ok, err := s.Store.IsAncestor(ctx, base, remote); err != nil || ok {
		return out, err
	}
	recs, bad, err := reroot.Read(ctx, s.Store)
	if err != nil {
		return out, err
	}
	trustAt := local
	if trustAt == "" {
		trustAt = base
	}
	trust := s.Trust(ctx, trustAt)
	var ignored []string
	for _, x := range bad {
		ignored = append(ignored, x.ID+": "+x.Why)
	}
	var pick *reroot.Record
	oldKnown := false
	for i := range recs {
		r := recs[i]
		if onlyBy != "" && r.Initiator != onlyBy {
			continue
		}
		if !s.exists(ctx, r.NewHead) || !s.ancestor(ctx, r.NewHead, remote) {
			continue // not the history the remote shows
		}
		if s.ancestor(ctx, r.NewHead, base) {
			continue // already in the accepted history: a replay
		}
		if err := reroot.Verify(trust, r); err != nil {
			ignored = append(ignored, r.ID+": "+err.Error())
			continue
		}
		known := s.exists(ctx, r.OldHead)
		if known && !s.ancestor(ctx, base, r.OldHead) {
			ignored = append(ignored, fmt.Sprintf("%s: its old head %s does not descend from this machine's accepted %s", r.ID, short(r.OldHead), short(base)))
			continue
		}
		pick, oldKnown = &r, known
		break
	}
	if pick == nil {
		if onlyBy != "" {
			return out, nil
		}
		detail := fmt.Sprintf("the remote main was rewritten: %s does not descend from the accepted %s, and no verified re-root record announces it; nothing from the remote was applied and nothing is pushed", short(remote), short(base))
		if len(ignored) > 0 {
			detail += "; records not taken: " + strings.Join(ignored, "; ")
		}
		out.refusal = &refusal{task: HoldTaskRewrite, kind: AlertHistoryRewrite, detail: detail,
			next: []string{"yadm check", "yadm git log --oneline -5 origin/main"}}
		return out, nil
	}
	r := *pick
	out.rec = r
	who := string(r.Initiator)
	if s.Fleet != nil && s.Fleet.Machines[r.Initiator].Name != "" {
		who = s.Fleet.Machines[r.Initiator].Name
	}
	held := func(why string, next ...string) (rewriteResult, error) {
		if onlyBy != "" {
			return rewriteResult{}, nil // a held machine waits for its next unheld sync to report
		}
		out.refusal = &refusal{task: HoldTaskReroot, kind: AlertRerootHeld,
			detail: fmt.Sprintf("re-root %s by %s (%s to %s) is verified, but this machine has not switched: %s", r.ID, who, short(r.OldHead), short(r.NewHead), why),
			next:   next}
		return out, nil
	}

	switched := local != "" && s.ancestor(ctx, r.NewHead, local)
	// Local commits that are not in the old head: unpushed work.
	var unpushed []store.Commit
	from := base
	if oldKnown {
		from = r.OldHead
	}
	if !switched && local != "" && local != base {
		if unpushed, err = s.Store.Log(ctx, string(from)+".."+string(local), nil); err != nil {
			return out, err
		}
	}
	if len(unpushed) > 0 && !carry {
		return held(fmt.Sprintf("this machine has %d local commit(s) that are not in the old head (newest %s); they are kept, and nothing moves until they are carried over: `yadm reroot carry` replays them onto the new history (a conflict becomes a hold) and keeps the originals on %s", len(unpushed), short(unpushed[0].ID), RefCarry(r.ID)),
			"yadm git log --oneline "+short(from)+"..main", "yadm reroot carry")
	}

	// A rewrite never changes a key-log file.
	if oldKnown {
		v, err := s.keyDiff(ctx, r.OldHead, r.NewHead, true)
		if err != nil {
			return out, err
		}
		if len(v) > 0 {
			return held("the rewrite changes key-log files, which must stay byte for byte: "+strings.Join(v, "; "), "yadm check")
		}
	}
	v, err := s.keyDiff(ctx, base, r.NewHead, false)
	if err != nil {
		return out, err
	}
	if len(v) > 0 {
		return held("the new history does not keep the key-log entries this machine accepted: "+strings.Join(v, "; "), "yadm check")
	}
	to, err := s.load(ctx, r.NewHead)
	if err != nil {
		return out, fmt.Errorf("load %s: %w", r.NewHead, err)
	}
	if s.Guard != nil && trustAt != "" {
		ok, detail, err := s.guardFrom(ctx, trustAt, to)
		if err != nil {
			return out, err
		}
		if !ok {
			return held("the new history weakens protection and is not allowed here: "+detail, "yadm hold list")
		}
	}

	acc := reroot.Accepted{ID: r.ID, By: r.Initiator, OldHead: r.OldHead, NewHead: r.NewHead, At: s.now().UTC()}
	tip := local
	if !switched {
		if keep := s.rerootKeep(ctx, trustAt); keep > 0 && s.Backups != "" {
			p, err := s.backupHistory(ctx, base, keep)
			if err != nil {
				return held("the backup of the old history failed, so nothing moved: "+err.Error(), "yadm backups list")
			}
			acc.Backup = p
		}
		tip = r.NewHead
		if len(unpushed) > 0 {
			acc.Carried = RefCarry(r.ID)
			if cur, err := s.Store.ResolveRef(ctx, acc.Carried); err != nil {
				return out, err
			} else if cur != local {
				if err := s.Store.UpdateRef(ctx, acc.Carried, local, cur); err != nil {
					return out, err
				}
			}
			st, err := s.Apply.State.Load()
			if err != nil {
				return out, err
			}
			res := integrated{tip: r.NewHead}
			rs := &resolver{s: s, snap: to, st: st}
			for i := len(unpushed) - 1; i >= 0; i-- {
				if err := s.replayOne(ctx, rs, unpushed[i], &res); err != nil {
					return out, fmt.Errorf("carry %s: %w", unpushed[i].ID, err)
				}
			}
			tip, out.holds = res.tip, res.holds
		}
		if out.dirty, err = s.setMain(ctx, tip, local); err != nil || out.dirty {
			return out, err
		}
	}
	if err := s.rerootReviewed(ctx, remote); err != nil {
		return out, err
	}
	// The accepted remote moves last: a run that stops before this point
	// finds the same record next time and goes on from where it stopped.
	if err := s.setAccepted(r.NewHead); err != nil {
		return out, err
	}
	if l := reroot.Load(s.Apply.StateDir).Last(); l == nil || l.ID != r.ID {
		if err := reroot.RecordAccepted(s.Apply.StateDir, acc); err != nil {
			return out, err
		}
	}
	out.switched, out.local = true, tip
	return out, nil
}

// rerootKeep is how many backups this machine keeps, from the fleet file
// it ran before the switch.
func (s *Syncer) rerootKeep(ctx context.Context, rev model.CommitID) int {
	f := s.Fleet
	if snap, err := s.load(ctx, rev); err == nil && snap.Fleet != nil {
		f = snap.Fleet
	}
	return f.RerootKeep(s.self())
}

// bundler writes a backup bundle of the source clone; *store.Repo does.
type bundler interface {
	Bundle(ctx context.Context, path string) error
}

// backupHistory writes a bundle of every local ref (the old history,
// before main moves) into Deps.Backups and prunes it to keep bundles.
func (s *Syncer) backupHistory(ctx context.Context, old model.CommitID, keep int) (string, error) {
	b, ok := s.Store.(bundler)
	if !ok {
		return "", errors.New("this store cannot write a bundle")
	}
	if err := reroot.EnsureDir(s.Backups); err != nil {
		return "", err
	}
	// A run that stopped after its backup reuses it.
	have, err := reroot.List(s.Backups)
	if err != nil {
		return "", err
	}
	for _, x := range have {
		if strings.HasPrefix(string(old), x.OldHead) {
			return x.Path, nil
		}
	}
	p := filepath.Join(s.Backups, reroot.BundleName(s.now(), old))
	if err := b.Bundle(ctx, p); err != nil {
		return "", err
	}
	if _, err := reroot.Prune(s.Backups, keep); err != nil {
		return p, err
	}
	return p, nil
}

// rerootReviewed moves each local reviewed ref that points into the old
// history: to the fetched reviewed ref when that is in the new history
// (the initiator moved it there), else it is dropped, and every commit of
// the scope counts as unreviewed.
func (s *Syncer) rerootReviewed(ctx context.Context, remote model.CommitID) error {
	refs, err := s.Store.ListRefs(ctx, "refs/yadm/reviewed/")
	if err != nil {
		return err
	}
	for ref, id := range refs {
		if s.ancestor(ctx, id, remote) {
			continue
		}
		sc := model.Scope(strings.TrimPrefix(ref, "refs/yadm/reviewed/"))
		rv, err := s.Store.ResolveRef(ctx, remoteReviewed(sc))
		if err != nil {
			return err
		}
		if rv != "" && s.ancestor(ctx, rv, remote) {
			err = s.Store.UpdateRef(ctx, ref, rv, id)
		} else {
			err = s.Store.UpdateRef(ctx, ref, "", id)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// rewritePending reports whether the fetched main no longer descends from
// the accepted one: a rewrite this machine has not taken yet. Auto-commit
// waits while it is pending, so a waking machine does not commit onto the
// old history and then hold the re-root on its own new commit.
func (s *Syncer) rewritePending(ctx context.Context, f fetched) bool {
	if f.err != nil {
		return false
	}
	base, err := s.startBase(ctx, f.base)
	if err != nil || base == "" {
		return false
	}
	remote, err := s.Store.ResolveRef(ctx, store.RemoteMain)
	if err != nil || remote == "" || remote == base {
		return false
	}
	ok, err := s.Store.IsAncestor(ctx, base, remote)
	return err == nil && !ok
}

// RerootRequest is what `yadm reroot` asks of the initiator.
type RerootRequest struct {
	NewHead string // a commit or ref in the source clone holding the rewritten history
	Reason  string
	PauseID string // the fleet pause the switch runs inside
	Signer  *crypt.Identity
	// FoldUnreviewed accepts that commits not yet reviewed in the old
	// history are folded into the new root, which every scope's reviewed
	// ref then marks reviewed.
	FoldUnreviewed bool
}

// RerootResult is the outcome on the initiator.
type RerootResult struct {
	Record     reroot.Record       `json:"record"`
	Pushed     bool                `json:"pushed"`
	Unreviewed map[model.Scope]int `json:"unreviewed,omitempty"`
	Sync       *Report             `json:"sync,omitempty"`
}

// rewriter is the forced, leased push of a re-root; *store.Repo does.
type rewriter interface {
	PushRewrite(ctx context.Context, rewrites []store.Rewrite, plain []string) error
}

// Reroot replaces the remote's history with req.NewHead (design §10.2).
// It fetches, checks under the sync lock that local main is the remote
// main and that the rewrite keeps every key-log file byte for byte and
// passes the manifest guard, signs a re-root record and pushes, in one
// atomic call under the network lock, main to the new head (leased on the
// old one), each reviewed ref to the new head, and the record. Then it
// accepts the re-root here through a normal sync, with a backup when
// fleet.toml asks for one. The caller holds neither lock and has made sure
// this machine runs a fleet pause.
func (s *Syncer) Reroot(ctx context.Context, req RerootRequest) (RerootResult, error) {
	var out RerootResult
	if err := s.check(); err != nil {
		return out, err
	}
	pusher, ok := s.Store.(rewriter)
	if !ok {
		return out, errors.New("reroot: this store cannot push a rewrite")
	}
	if req.Signer == nil {
		return out, fmt.Errorf("%w: this machine has no signing identity", ErrRerootRefused)
	}
	if err := s.FetchRefs(ctx); err != nil {
		return out, fmt.Errorf("reroot: fetch first: %w", err)
	}
	rec, rewrites, prev, next, err := s.prepareReroot(ctx, req, &out, false)
	if err != nil {
		return out, err
	}
	out.Record = rec
	release, err := s.netLock().TryAcquire()
	if err == nil {
		err = pusher.PushRewrite(ctx, rewrites, []string{reroot.Ref + ":" + reroot.Ref})
		release()
	}
	if err != nil {
		if r, lerr := s.Lock.Acquire(ctx); lerr == nil {
			_ = reroot.Unwrite(ctx, s.Store, prev, next)
			r()
		}
		if errors.Is(err, store.ErrRejected) {
			err = fmt.Errorf("%w: the remote moved since the fetch; run yadm sync, then yadm reroot again", err)
		}
		return out, err
	}
	out.Pushed = true
	// git updates the remote-tracking refs on push; make sure of it.
	_ = s.FetchRefs(ctx)
	rep, err := s.Run(ctx, Options{Push: true})
	out.Sync = &rep
	if err != nil {
		return out, fmt.Errorf("reroot: pushed, but the switch here failed (the next sync retries): %w", err)
	}
	s.nudge(ctx, rec.NewHead)
	return out, nil
}

// RerootCheck runs the checks of Reroot on the last fetched remote and
// changes nothing, so `yadm reroot` refuses before it starts a pause.
func (s *Syncer) RerootCheck(ctx context.Context, req RerootRequest) (RerootResult, error) {
	var out RerootResult
	if err := s.check(); err != nil {
		return out, err
	}
	if req.Signer == nil {
		return out, fmt.Errorf("%w: this machine has no signing identity", ErrRerootRefused)
	}
	_, _, _, _, err := s.prepareReroot(ctx, req, &out, true)
	return out, err
}

// prepareReroot runs the initiator's checks under the sync lock and writes
// the signed record on the local re-root ref.
func (s *Syncer) prepareReroot(ctx context.Context, req RerootRequest, out *RerootResult, dry bool) (rec reroot.Record, rewrites []store.Rewrite, prev, next model.CommitID, err error) {
	defer s.begin()()
	release, err := s.Lock.Acquire(ctx)
	if err != nil {
		return rec, nil, "", "", err
	}
	defer release()
	local, err := s.Store.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return rec, nil, "", "", err
	}
	remote, err := s.Store.ResolveRef(ctx, store.RemoteMain)
	if err != nil {
		return rec, nil, "", "", err
	}
	switch acc, ok := s.acceptedRecord(); {
	case remote == "":
		return rec, nil, "", "", fmt.Errorf("%w: the remote has no main to rewrite", ErrRerootState)
	case local != remote:
		return rec, nil, "", "", fmt.Errorf("%w: local main %s is not the remote main %s; run yadm sync first so no commit is lost", ErrRerootState, short(local), short(remote))
	case ok && acc != remote:
		return rec, nil, "", "", fmt.Errorf("%w: this machine has not accepted the remote main %s; run yadm sync first", ErrRerootState, short(remote))
	}
	st, err := s.Apply.State.Load()
	if err != nil {
		return rec, nil, "", "", err
	}
	for _, h := range st.Holds {
		if refusalHold(h) {
			return rec, nil, "", "", fmt.Errorf("%w: a %s hold is open: %s", ErrRerootState, h.Task, h.Detail)
		}
	}
	newID, err := s.Store.ResolveRef(ctx, req.NewHead)
	if err != nil || newID == "" {
		return rec, nil, "", "", fmt.Errorf("%w: --new-head %q names no commit in the source clone", ErrRerootState, req.NewHead)
	}
	switch {
	case newID == remote:
		return rec, nil, "", "", fmt.Errorf("%w: --new-head is the remote main already", ErrRerootState)
	case s.ancestor(ctx, remote, newID):
		return rec, nil, "", "", fmt.Errorf("%w: --new-head descends from the remote main; that is an ordinary push, not a rewrite: commit and sync instead", ErrRerootState)
	}
	if v, err := s.keyDiff(ctx, remote, newID, true); err != nil {
		return rec, nil, "", "", err
	} else if len(v) > 0 {
		return rec, nil, "", "", fmt.Errorf("%w: a rewrite must keep every key-log file byte for byte: %s", ErrRerootRefused, strings.Join(v, "; "))
	}
	to, err := s.load(ctx, newID)
	if err != nil {
		return rec, nil, "", "", fmt.Errorf("%w: the new head does not load: %v", ErrRerootState, err)
	}
	if s.Guard != nil {
		ok, detail, err := s.guardFrom(ctx, remote, to)
		if err != nil {
			return rec, nil, "", "", err
		}
		if !ok {
			return rec, nil, "", "", fmt.Errorf("%w: the new history weakens protection: %s", ErrRerootRefused, detail)
		}
	}
	trust := s.Trust(ctx, remote)
	member := false
	for _, m := range trust.Members[s.self()] {
		if m.SignKey == req.Signer.Member().SignKey {
			member = true
		}
	}
	if !trust.Fleet[s.self()] || !member {
		return rec, nil, "", "", fmt.Errorf("%w: a re-root must be signed by a member of a key log this machine pinned, and %s is not one; run it on a machine that is", ErrRerootRefused, s.self())
	}
	scopes, err := reviewScopes(ctx, s.Store)
	if err != nil {
		return rec, nil, "", "", err
	}
	out.Unreviewed = map[model.Scope]int{}
	var behind []string
	for _, sc := range scopes {
		lr, err := s.Store.ResolveRef(ctx, store.RefReviewed(sc))
		if err != nil {
			return rec, nil, "", "", err
		}
		n, err := skippedInScope(ctx, s.Store, sc, lr, remote)
		if err != nil {
			return rec, nil, "", "", err
		}
		if n > 0 {
			out.Unreviewed[sc] = n
			behind = append(behind, fmt.Sprintf("%s %d", sc, n))
		}
		rv, err := s.Store.ResolveRef(ctx, remoteReviewed(sc))
		if err != nil {
			return rec, nil, "", "", err
		}
		rewrites = append(rewrites, store.Rewrite{Ref: store.RefReviewed(sc), New: newID, Old: rv})
	}
	if len(behind) > 0 && !req.FoldUnreviewed {
		return rec, nil, "", "", fmt.Errorf("%w: unreviewed commits would be folded into the new root and marked reviewed (%s); review them first (yadm review list), or pass --fold-unreviewed", ErrRerootState, strings.Join(behind, ", "))
	}
	if len(out.Unreviewed) == 0 {
		out.Unreviewed = nil
	}
	if dry {
		return rec, nil, "", "", nil
	}
	id, err := reroot.NewID()
	if err != nil {
		return rec, nil, "", "", err
	}
	rec, err = reroot.Sign(reroot.Record{ID: id, Initiator: s.self(), Reason: req.Reason, Created: s.now(),
		OldHead: remote, NewHead: newID, PauseID: req.PauseID}, req.Signer)
	if err != nil {
		return rec, nil, "", "", err
	}
	if prev, next, err = reroot.Write(ctx, s.Store, rec); err != nil {
		return rec, nil, "", "", err
	}
	rewrites = append([]store.Rewrite{{Ref: store.RefMain, New: newID, Old: remote}}, rewrites...)
	return rec, rewrites, prev, next, nil
}

// RerootStatus is this machine's view of re-roots: the last one it
// accepted, and an open hold that keeps it from switching.
type RerootStatus struct {
	Last *reroot.Accepted `json:"last,omitempty"`
	Held *model.Hold      `json:"held,omitempty"`
}

// ReadRerootStatus reads the re-root state in stateDir and the holds.
func ReadRerootStatus(stateDir string, holds []model.Hold) RerootStatus {
	var out RerootStatus
	out.Last = reroot.Load(stateDir).Last()
	for i := range holds {
		if holds[i].Target == "" && (holds[i].Task == HoldTaskRewrite || holds[i].Task == HoldTaskReroot) {
			h := holds[i]
			out.Held = &h
			break
		}
	}
	return out
}
