package sync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// RefReviewNotes is the notes ref: a chain of commits whose tree holds one
// file per annotated commit, `<commit id>.json`. It lives under refs/yadm/,
// so it is fetched with the other yadm refs, and sync pushes it.
const RefReviewNotes = "refs/yadm/notes/review"

// remoteReviewNotes is the fetched copy of RefReviewNotes.
const remoteReviewNotes = remoteYadmPrefix + "notes/review"

// NoteSchema is the version of a stored note.
const NoteSchema = 1

// ErrNoteNeedsSeal refuses a free-text note on a commit that touches an
// enclave when it cannot be sealed to exactly that enclave.
var ErrNoteNeedsSeal = errors.New("note: a free-text note on a commit that touches an enclave must be sealed to that enclave")

// storedNote is a note as the notes ref stores it. A sealed note holds no
// plaintext: Sealed is the enclave's file container, bound to the note's
// path, in base64.
type storedNote struct {
	Schema    int               `json:"schema"`
	Commit    model.CommitID    `json:"commit"`
	Machine   model.MachineID   `json:"machine"`
	Time      time.Time         `json:"time"`
	Why       string            `json:"why,omitempty"`
	PathsOnly bool              `json:"paths_only,omitempty"`
	Enclave   model.EnclaveName `json:"enclave,omitempty"`
	Sealed    string            `json:"sealed,omitempty"`
}

// Note is a note as a reader sees it. A sealed note shows its text only to a
// member of its enclave; anyone else gets Sealed true and an empty Why.
type Note struct {
	Commit    model.CommitID    `json:"commit"`
	Machine   model.MachineID   `json:"machine"`
	Time      time.Time         `json:"time"`
	Why       string            `json:"why,omitempty"`
	PathsOnly bool              `json:"paths_only,omitempty"`
	Sealed    bool              `json:"sealed,omitempty"`
	Enclave   model.EnclaveName `json:"enclave,omitempty"`
	Opened    bool              `json:"opened,omitempty"` // a sealed note this machine opened
}

// Text is the note's one-line form: its text, or "sealed note".
func (n Note) Text() string {
	if n.Sealed && !n.Opened {
		return "sealed note"
	}
	return n.Why
}

func notePath(c model.CommitID) model.SourcePath { return model.SourcePath(string(c) + ".json") }

// NoteOptions is one `yadm review note`.
type NoteOptions struct {
	Commit    model.CommitID // any revision; resolved to a commit id
	Why       string         // free text; ignored with PathsOnly
	PathsOnly bool           // the tool writes the text: the commit's paths, nothing else
	Seal      model.EnclaveName
	Machine   model.MachineID
	Now       time.Time
}

// noteEnclaves returns the enclaves whose content commit paths touch:
// sealed/<e>/ and keys/<e>/ paths, and plain sources whose entry seals
// values for e. regions is set when a path's entry has sealed regions,
// whose enclave the manifest does not name.
func noteEnclaves(paths []model.SourcePath, man *manifest.Manifest) (encs []model.EnclaveName, regions bool) {
	seen := map[model.EnclaveName]bool{}
	add := func(e model.EnclaveName) {
		if !seen[e] {
			seen[e] = true
			encs = append(encs, e)
		}
	}
	for _, p := range paths {
		s := string(p)
		for _, pre := range []string{"sealed/", "keys/"} {
			if rest, ok := strings.CutPrefix(s, pre); ok {
				if e, _, ok := strings.Cut(rest, "/"); ok && e != "" {
					add(model.EnclaveName(e))
				}
			}
		}
		if man == nil || !strings.HasPrefix(s, "files/") {
			continue
		}
		for _, en := range man.Entries {
			if len(en.Seal) == 0 && !en.Regions {
				continue
			}
			for _, r := range manifest.Expand(en, []model.SourcePath{p}) {
				if r.Source != p {
					continue
				}
				for _, e := range en.Seal {
					add(e)
				}
				if en.Regions {
					regions = true
				}
			}
		}
	}
	sort.Slice(encs, func(i, j int) bool { return encs[i] < encs[j] })
	return encs, regions
}

// WriteNote attaches a note to a commit on RefReviewNotes. It never pushes;
// the next sync does, or the caller with PushNotes.
//
// A note on a commit that touches no enclave is stored as written, unless
// opts.Seal asks for a seal. On a commit that touches an enclave, a
// free-text note is sealed to that enclave (opts.Seal may name it), and
// refused when the commit touches more than one enclave, when it has sealed
// regions and opts.Seal is empty, or when this machine is not a member. A
// PathsOnly note is never refused: its text is the commit's paths, which
// every machine already sees. The note is sealed before anything is
// written, so its plaintext never enters the object store.
func WriteNote(ctx context.Context, st store.Store, snap *apply.Snapshot, opts NoteOptions) (Note, error) {
	if st == nil || snap == nil {
		return Note{}, errors.New("note: no store")
	}
	id, err := st.ResolveRef(ctx, string(opts.Commit))
	if err != nil {
		return Note{}, err
	}
	if id == "" {
		return Note{}, fmt.Errorf("note: unknown commit %q", opts.Commit)
	}
	cs, err := st.Log(ctx, string(id)+"^!", nil)
	if err != nil {
		return Note{}, err
	}
	if len(cs) != 1 {
		return Note{}, fmt.Errorf("note: %s is not one commit", id)
	}
	paths := cs[0].Paths
	sn := storedNote{Schema: NoteSchema, Commit: id, Machine: opts.Machine, Time: opts.Now.UTC()}
	if opts.PathsOnly {
		names := make([]string, len(paths))
		for i, p := range paths {
			names[i] = string(p)
		}
		sn.PathsOnly = true
		sn.Why = "paths: " + strings.Join(names, ", ")
	} else {
		if strings.TrimSpace(opts.Why) == "" {
			return Note{}, errors.New("note: --why is empty")
		}
		encs, regions := noteEnclaves(paths, snap.Manifest)
		seal := opts.Seal
		switch {
		case len(encs) > 1:
			return Note{}, fmt.Errorf("%w: %s touches %d enclaves; use --paths-only", ErrNoteNeedsSeal, id, len(encs))
		case len(encs) == 1 && seal == "":
			seal = encs[0]
		case len(encs) == 1 && seal != encs[0]:
			return Note{}, fmt.Errorf("%w: %s touches %s, not %s", ErrNoteNeedsSeal, id, encs[0], seal)
		case regions && seal == "":
			return Note{}, fmt.Errorf("%w: %s changes a file with sealed regions; name the enclave with --seal or use --paths-only", ErrNoteNeedsSeal, id)
		}
		if seal == "" {
			sn.Why = opts.Why
		} else {
			if snap.Crypto == nil || !snap.CanOpen(seal) {
				return Note{}, fmt.Errorf("%w: %s", crypt.ErrNotMember, seal)
			}
			ct, err := snap.Crypto.SealFile(seal, noteSealPath(id), []byte(opts.Why))
			if err != nil {
				return Note{}, fmt.Errorf("note: seal: %w", err)
			}
			sn.Enclave = seal
			sn.Sealed = base64.StdEncoding.EncodeToString(ct)
		}
	}
	b, err := json.MarshalIndent(sn, "", "  ")
	if err != nil {
		return Note{}, err
	}
	head, err := st.ResolveRef(ctx, RefReviewNotes)
	if err != nil {
		return Note{}, err
	}
	msg := store.Message{Subject: "note " + string(id), Trailers: []store.Trailer{{Key: "Machine", Value: string(opts.Machine)}}}
	next, err := st.CommitPaths(ctx, head, []store.Change{{Path: notePath(id), Blob: append(b, '\n'), Mode: 0o100644}}, msg)
	if err != nil {
		return Note{}, err
	}
	if err := st.UpdateRef(ctx, RefReviewNotes, next, head); err != nil {
		return Note{}, err
	}
	return view(sn, snap.Crypto), nil
}

// noteSealPath is the path a sealed note is bound to, so a token moved to
// another commit's note fails to open.
func noteSealPath(c model.CommitID) model.SourcePath {
	return model.SourcePath("notes/review/" + string(c))
}

// view turns a stored note into what this machine may see.
func view(sn storedNote, cr apply.Crypto) Note {
	n := Note{Commit: sn.Commit, Machine: sn.Machine, Time: sn.Time, Why: sn.Why, PathsOnly: sn.PathsOnly, Enclave: sn.Enclave}
	if sn.Sealed == "" {
		return n
	}
	n.Sealed, n.Why = true, ""
	if cr == nil || !cr.CanOpen(sn.Enclave) {
		return n
	}
	ct, err := base64.StdEncoding.DecodeString(sn.Sealed)
	if err != nil {
		return n
	}
	pt, err := cr.OpenFile(sn.Enclave, noteSealPath(sn.Commit), ct)
	if err != nil {
		return n
	}
	n.Why, n.Opened = string(pt), true
	return n
}

// ReadNotes returns every note on the local and fetched notes refs, per
// commit; the newer note wins. keys opens sealed notes for members (every
// epoch it holds); nil opens none.
func ReadNotes(ctx context.Context, st store.Store, keys *crypt.Set) (map[model.CommitID]Note, error) {
	if keys != nil {
		keys = keys.History()
	}
	cr := apply.SetCrypto(keys)
	byCommit := map[model.CommitID]storedNote{}
	for _, ref := range []string{RefReviewNotes, remoteReviewNotes} {
		head, err := st.ResolveRef(ctx, ref)
		if err != nil {
			return nil, err
		}
		if head == "" {
			continue
		}
		ents, err := st.ListTree(ctx, head)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			b, err := st.ReadBlob(ctx, e.Blob)
			if err != nil {
				return nil, err
			}
			var sn storedNote
			if json.Unmarshal(b, &sn) != nil || sn.Schema != NoteSchema || notePath(sn.Commit) != e.Path {
				continue
			}
			if old, ok := byCommit[sn.Commit]; !ok || sn.Time.After(old.Time) {
				byCommit[sn.Commit] = sn
			}
		}
	}
	out := make(map[model.CommitID]Note, len(byCommit))
	for c, sn := range byCommit {
		out[c] = view(sn, cr)
	}
	return out, nil
}

// notesSpec brings the local notes ref and its fetched copy together and
// returns the refspec to push, if any. A ref the remote advanced is
// fast-forwarded. A diverged one is rebuilt on the remote head with the
// local notes the remote lacks (the newer note wins on one commit), so
// history stays linear and no note is lost.
func notesSpec(ctx context.Context, st store.Store) (string, error) {
	local, err := st.ResolveRef(ctx, RefReviewNotes)
	if err != nil {
		return "", err
	}
	remote, err := st.ResolveRef(ctx, remoteReviewNotes)
	if err != nil {
		return "", err
	}
	spec := RefReviewNotes + ":" + RefReviewNotes
	switch {
	case local == remote:
		return "", nil
	case local == "":
		return "", st.UpdateRef(ctx, RefReviewNotes, remote, "")
	case remote == "":
		return spec, nil
	}
	if ok, err := st.IsAncestor(ctx, local, remote); err != nil {
		return "", err
	} else if ok {
		return "", st.UpdateRef(ctx, RefReviewNotes, remote, local)
	}
	if ok, err := st.IsAncestor(ctx, remote, local); err != nil {
		return "", err
	} else if ok {
		return spec, nil
	}
	theirs, err := st.ListTree(ctx, remote)
	if err != nil {
		return "", err
	}
	have := map[model.SourcePath]store.TreeEntry{}
	for _, e := range theirs {
		have[e.Path] = e
	}
	ours, err := st.ListTree(ctx, local)
	if err != nil {
		return "", err
	}
	var changes []store.Change
	for _, e := range ours {
		if t, ok := have[e.Path]; ok && t.Blob == e.Blob {
			continue
		}
		b, err := st.ReadBlob(ctx, e.Blob)
		if err != nil {
			return "", err
		}
		if t, ok := have[e.Path]; ok {
			tb, err := st.ReadBlob(ctx, t.Blob)
			if err != nil {
				return "", err
			}
			var a, r storedNote
			if json.Unmarshal(b, &a) == nil && json.Unmarshal(tb, &r) == nil && !a.Time.After(r.Time) {
				continue
			}
		}
		changes = append(changes, store.Change{Path: e.Path, Blob: b, Mode: 0o100644})
	}
	next := remote
	if len(changes) > 0 {
		if next, err = st.CommitPaths(ctx, remote, changes, store.Message{Subject: fmt.Sprintf("merge %d notes", len(changes))}); err != nil {
			return "", err
		}
	}
	if err := st.UpdateRef(ctx, RefReviewNotes, next, local); err != nil {
		return "", err
	}
	if next == remote {
		return "", nil
	}
	return spec, nil
}

// PushNotes fetches, merges the local notes ref with the remote one and
// pushes it, retrying once on a rejected push. It never forces. It reports
// whether anything was pushed.
func PushNotes(ctx context.Context, st store.Store) (bool, error) {
	for attempt := 0; ; attempt++ {
		if err := st.Fetch(ctx); err != nil {
			return false, err
		}
		spec, err := notesSpec(ctx, st)
		if err != nil || spec == "" {
			return false, err
		}
		err = st.Push(ctx, []string{spec})
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, store.ErrRejected) || attempt > 0 {
			return false, err
		}
	}
}
