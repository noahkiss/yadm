package sync

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// treeMap lists rev's blobs by path. An empty rev is an empty tree.
func (s *Syncer) treeMap(ctx context.Context, rev model.CommitID) (map[model.SourcePath]store.TreeEntry, error) {
	out := map[model.SourcePath]store.TreeEntry{}
	if rev == "" {
		return out, nil
	}
	ents, err := s.Store.ListTree(ctx, rev)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		out[e.Path] = e
	}
	return out, nil
}

// blobID writes b to the object store and returns its id. The bytes are
// source bytes (ciphertext for sealed files), never target plaintext of an
// enclave.
func (s *Syncer) blobID(ctx context.Context, b []byte) (string, error) {
	tree, err := s.Store.WriteTree(ctx, "", []store.Change{{Path: "blob", Blob: b, Mode: 0o100644}})
	if err != nil {
		return "", err
	}
	ents, err := s.Store.ListTree(ctx, model.CommitID(tree))
	if err != nil {
		return "", err
	}
	if len(ents) != 1 {
		return "", fmt.Errorf("blob id: unexpected tree")
	}
	return ents[0].Blob, nil
}

// integrated is the outcome of putting local main on top of origin main.
type integrated struct {
	tip         model.CommitID
	replayed    int
	holds       []model.Hold
	resolutions []Resolution
}

// integrate returns the commit local main should move to: remote when local
// is behind, local when it is ahead, and otherwise each local commit replayed
// onto remote in memory. History stays linear; no merge commit is made.
func (s *Syncer) integrate(ctx context.Context, r *resolver, local, remote model.CommitID) (integrated, error) {
	switch {
	case remote == "" || local == remote:
		return integrated{tip: local}, nil
	case local == "":
		return integrated{tip: remote}, nil
	}
	if ok, err := s.Store.IsAncestor(ctx, local, remote); err != nil {
		return integrated{}, err
	} else if ok {
		return integrated{tip: remote}, nil
	}
	if ok, err := s.Store.IsAncestor(ctx, remote, local); err != nil {
		return integrated{}, err
	} else if ok {
		return integrated{tip: local}, nil
	}
	commits, err := s.Store.Log(ctx, string(remote)+".."+string(local), nil)
	if err != nil {
		return integrated{}, err
	}
	out := integrated{tip: remote}
	for i := len(commits) - 1; i >= 0; i-- {
		if err := s.replayOne(ctx, r, commits[i], &out); err != nil {
			return integrated{}, fmt.Errorf("replay %s: %w", commits[i].ID, err)
		}
	}
	return out, nil
}

// replayOne replays one local commit onto out.tip. A clean merge keeps the
// message and trailers. Otherwise each conflicted path goes up the
// resolution ladder; the commit's other paths and every resolved path land,
// and unresolved paths become conflict holds with the commit kept on the
// local-only held ref.
func (s *Syncer) replayOne(ctx context.Context, r *resolver, c store.Commit, out *integrated) error {
	if len(c.Parents) != 1 {
		return fmt.Errorf("commit has %d parents; only linear history replays", len(c.Parents))
	}
	parent := c.Parents[0]
	mr, err := s.Store.MergeTree(ctx, parent, out.tip, c.ID)
	if err != nil {
		return err
	}
	if len(mr.Conflicts) == 0 {
		id, err := s.Store.CommitTree(ctx, mr.Tree, []model.CommitID{out.tip}, c.Message)
		if err != nil {
			return err
		}
		out.tip = id
		out.replayed++
		return nil
	}

	mine, err := s.treeMap(ctx, c.ID)
	if err != nil {
		return err
	}
	before, err := s.treeMap(ctx, parent)
	if err != nil {
		return err
	}
	var resolved, reverts []store.Change
	var trailers []store.Trailer
	held := 0
	for _, x := range mr.Conflicts {
		// merge-tree ran with ours = remote tip, theirs = this commit.
		cf := conflict{Conflict: store.Conflict{Path: x.Path, Base: x.Base, Ours: x.Theirs, Theirs: x.Ours}, Mode: mine[x.Path].Mode}
		ch, h, rung, err := r.resolve(ctx, cf)
		if err != nil {
			return err
		}
		res := Resolution{Path: x.Path, Target: r.target(x.Path), Rung: rung, Commit: c.ID}
		out.resolutions = append(out.resolutions, res)
		if h != nil {
			out.holds = append(out.holds, *h)
			held++
		} else {
			resolved = append(resolved, *ch)
			trailers = append(trailers, store.Trailer{Key: TrailerResolved, Value: rung + " " + string(x.Path)})
		}
		// Revert the path to the parent's version so the second merge is clean.
		if e, ok := before[x.Path]; ok {
			b, err := s.Store.ReadBlob(ctx, e.Blob)
			if err != nil {
				return err
			}
			reverts = append(reverts, store.Change{Path: x.Path, Blob: b, Mode: e.Mode})
		} else {
			reverts = append(reverts, store.Change{Path: x.Path, Delete: true})
		}
	}
	if held > 0 {
		if err := s.keepHeld(ctx, c); err != nil {
			return err
		}
	}
	if len(c.Paths) <= held && len(resolved) == 0 {
		return nil // nothing of this commit lands
	}
	if held > 0 && slices.Contains(c.Paths, model.SourcePath(manifest.FileName)) {
		// A manifest edit and the source changes it describes (a track, a
		// retag, a committed deletion) land together or not at all: a
		// partial landing could name a source that is not there.
		return nil
	}
	stripped, err := s.Store.CommitPaths(ctx, c.ID, reverts, store.Message{Subject: "replay"})
	if err != nil {
		return err
	}
	mr2, err := s.Store.MergeTree(ctx, parent, out.tip, stripped)
	if err != nil {
		return err
	}
	if len(mr2.Conflicts) > 0 {
		return fmt.Errorf("conflicts remain after reverting conflicted paths: %s", mr2.Conflicts[0].Path)
	}
	tree := mr2.Tree
	if len(resolved) > 0 {
		if tree, err = s.Store.WriteTree(ctx, model.CommitID(tree), resolved); err != nil {
			return err
		}
	}
	msg := c.Message
	msg.Trailers = append(append([]store.Trailer(nil), msg.Trailers...), trailers...)
	id, err := s.Store.CommitTree(ctx, tree, []model.CommitID{out.tip}, msg)
	if err != nil {
		return err
	}
	out.tip = id
	out.replayed++
	return nil
}

// keepHeld records c on this machine's held ref, so the blobs its conflict
// holds name stay reachable. The ref is local only; the store refuses to push it.
func (s *Syncer) keepHeld(ctx context.Context, c store.Commit) error {
	ref := store.RefHeld(s.self())
	prev, err := s.Store.ResolveRef(ctx, ref)
	if err != nil {
		return err
	}
	tree, err := s.Store.WriteTree(ctx, c.ID, nil)
	if err != nil {
		return err
	}
	parents := []model.CommitID{c.ID}
	if prev != "" {
		parents = append(parents, prev)
	}
	msg := store.Message{
		Subject:  "held(" + string(s.self()) + "): " + c.Message.Subject,
		Trailers: []store.Trailer{{Key: store.TrailerMachine, Value: string(s.self())}},
	}
	id, err := s.Store.CommitTree(ctx, tree, parents, msg)
	if err != nil {
		return err
	}
	return s.Store.UpdateRef(ctx, ref, id, prev)
}

// nonMemberAlerts reports fetched commits that touch sealed/<enclave>/ or
// keys/<enclave>/ and whose Machine trailer names no member of that
// enclave's verified key-log head at snap. The trailer is not authenticated;
// the alert is a prompt to review, not proof.
func (s *Syncer) nonMemberAlerts(ctx context.Context, snap *apply.Snapshot, local, remote model.CommitID, seen map[model.CommitID]bool) ([]model.Alert, error) {
	if remote == "" || remote == local || snap == nil {
		return nil, nil
	}
	rng := string(remote)
	if local != "" {
		rng = string(local) + ".." + string(remote)
	}
	commits, err := s.Store.Log(ctx, rng, nil)
	if err != nil {
		return nil, err
	}
	members := func(e model.EnclaveName) map[model.MachineID]bool {
		m := map[model.MachineID]bool{}
		if l, ok := snap.Enclaves[e]; ok {
			for _, x := range l.Head.Members {
				m[x.Machine] = true
			}
		}
		return m
	}
	var out []model.Alert
	for i := len(commits) - 1; i >= 0; i-- {
		c := commits[i]
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		machine := model.MachineID(trailer(c.Message, store.TrailerMachine))
		if machine == s.self() {
			continue
		}
		hit := map[model.EnclaveName]bool{}
		for _, p := range c.Paths {
			e, ok := sealedEnclave(p)
			if !ok {
				rest, isKey := strings.CutPrefix(string(p), "keys/")
				if !isKey {
					continue
				}
				i := strings.IndexByte(rest, '/')
				if i <= 0 {
					continue
				}
				e = model.EnclaveName(rest[:i])
			}
			if !members(e)[machine] {
				hit[e] = true
			}
		}
		for _, e := range sortedEnclaves(hit) {
			who := string(machine)
			if who == "" {
				who = "a commit with no Machine trailer"
			}
			out = append(out, model.Alert{
				Kind:    AlertNonMember,
				Commit:  c.ID,
				Machine: machine,
				Detail:  fmt.Sprintf("%s changed enclave %s and is not a member; review it", who, e),
				At:      s.now(),
			})
		}
	}
	return out, nil
}

func trailer(m store.Message, key string) string {
	for _, t := range m.Trailers {
		if strings.EqualFold(t.Key, key) {
			return t.Value
		}
	}
	return ""
}
