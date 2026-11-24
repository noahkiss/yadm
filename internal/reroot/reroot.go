package reroot

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/pause"
	"github.com/noahkiss/yadm/internal/store"
)

// Names and limits.
const (
	// Ref is the re-root ref. It lives under refs/yadm/, so every sync
	// fetches it.
	Ref = "refs/yadm/reroot"
	// RemoteRef is the fetched copy of Ref.
	RemoteRef = "refs/remotes/origin/yadm/reroot"
	// StateFile is this machine's re-root state in the state directory.
	StateFile = "reroot.json"
	// Kind is the statement kind a re-root record is signed as.
	Kind = "reroot"
	// Schema is the version of a stored record.
	Schema = 1

	// keepRecords is how many records Write keeps on the ref, newest
	// first. A machine offline for longer than that many re-roots
	// re-clones.
	keepRecords = 16
	// maxReason bounds the reason text.
	maxReason = 200
	// maxRecords and maxRecordBytes bound what Read takes from a ref any
	// writer controls; maxIgnored bounds what is reported.
	maxRecords     = 64
	maxRecordBytes = 4096
	maxIgnored     = 16
	// keepAccepted bounds the accepted re-roots StateFile remembers.
	keepAccepted = 16
)

// Errors.
var (
	// ErrMalformed means a record breaks a structural rule.
	ErrMalformed = errors.New("malformed re-root record")
	// ErrUnverified means no key log this machine pinned lists the signer
	// with a key the signature verifies under. A re-root replaces history,
	// so an unverified record never counts.
	ErrUnverified = errors.New("re-root record is not verified")
	// ErrUntrusted means the signer is not a machine in fleet.toml.
	ErrUntrusted = errors.New("signer is not trusted")
	// ErrForged means the signature fails under every pinned key of the
	// signer it names.
	ErrForged = errors.New("forged re-root record")
)

// Record announces one history rewrite: the remote main moved from OldHead
// to NewHead on purpose. Times are UTC, whole seconds.
type Record struct {
	Schema    int             `json:"schema"`
	ID        string          `json:"id"`
	Initiator model.MachineID `json:"initiator"`
	Reason    string          `json:"reason,omitempty"`
	Created   time.Time       `json:"created"`
	OldHead   model.CommitID  `json:"old_head"`
	NewHead   model.CommitID  `json:"new_head"`
	PauseID   string          `json:"pause_id,omitempty"`
	Signer    model.MachineID `json:"signer"`
	Sig       model.Base64    `json:"sig,omitempty"`
}

var (
	idPattern     = regexp.MustCompile(`^r-[0-9a-f]{12}$`)
	fileRE        = regexp.MustCompile(`^r-[0-9a-f]{12}\.json$`)
	commitPattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// NewID returns a fresh re-root id.
func NewID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "r-" + hex.EncodeToString(b[:]), nil
}

// SignedBytes is the canonical JSON the signature covers: the record with
// Sig empty.
func (r Record) SignedBytes() ([]byte, error) {
	r.Sig = nil
	return json.Marshal(r)
}

// Sign normalizes r, sets the signer to id's machine and signs it.
func Sign(r Record, id *crypt.Identity) (Record, error) {
	if id == nil {
		return Record{}, errors.New("reroot: no signing identity")
	}
	r.Schema = Schema
	r.Created = r.Created.UTC().Truncate(time.Second)
	r.Signer = id.Machine
	if err := r.shape(); err != nil {
		return Record{}, err
	}
	body, err := r.SignedBytes()
	if err != nil {
		return Record{}, err
	}
	if r.Sig, err = id.SignStatement(Kind, body); err != nil {
		return Record{}, err
	}
	return r, nil
}

// shape checks a record on its own.
func (r Record) shape() error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrMalformed, why) }
	switch {
	case r.Schema != Schema:
		return bad("unknown schema")
	case !idPattern.MatchString(r.ID):
		return bad("bad id")
	case r.Initiator == "" || model.HasControl(string(r.Initiator)) || model.HasControl(string(r.Signer)):
		return bad("no initiator")
	case r.Signer != r.Initiator:
		return bad("a re-root is signed by its initiator")
	case len(r.Reason) > maxReason || model.HasControl(r.Reason):
		return bad("reason too long or holds a control character")
	case r.Created.IsZero():
		return bad("no creation time")
	case !commitPattern.MatchString(string(r.OldHead)) || !commitPattern.MatchString(string(r.NewHead)):
		return bad("old_head and new_head must be full commit ids")
	case r.OldHead == r.NewHead:
		return bad("old_head equals new_head")
	case r.PauseID != "" && model.HasControl(r.PauseID):
		return bad("bad pause id")
	}
	return nil
}

// Verify checks a record against the trust of a fleet pause (fleet.toml
// machines and the members of the key logs this machine pinned), but
// requires what a pause does not: a re-root counts only when its signer is
// a pinned key-log member and the signature verifies under that member's
// key. It returns nil only for such a record.
func Verify(t pause.Trust, r Record) error {
	if err := r.shape(); err != nil {
		return err
	}
	if !t.Fleet[r.Signer] {
		return fmt.Errorf("%w: %s is not a machine in fleet.toml", ErrUntrusted, r.Signer)
	}
	keys := t.Members[r.Signer]
	if len(keys) == 0 {
		return fmt.Errorf("%w: no key log this machine pinned lists %s", ErrUnverified, r.Signer)
	}
	if len(r.Sig) == 0 {
		return fmt.Errorf("%w: the record carries no signature", ErrUnverified)
	}
	body, err := r.SignedBytes()
	if err != nil {
		return err
	}
	for _, m := range keys {
		if crypt.VerifyStatement(m, Kind, body, r.Sig) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: the signature fails under every pinned key of %s", ErrForged, r.Signer)
}

// Ignored is a record this machine did not accept, or a part of the ref it
// could not read.
type Ignored struct {
	ID     string          `json:"id"`
	Signer model.MachineID `json:"signer,omitempty"`
	Why    string          `json:"why"`
}

// Read returns the records on the fetched re-root ref and the local one,
// newest first, one per id. Any writer controls the fetched ref, so Read
// takes at most maxRecords top-level `<id>.json` files of at most
// maxRecordBytes each. A file that breaks a rule, or a ref that does not
// read, comes back as Ignored; it never fails the caller.
func Read(ctx context.Context, st store.Store) ([]Record, []Ignored, error) {
	seen := map[string]bool{}
	var recs []Record
	var bad []Ignored
	report := func(x Ignored) {
		if len(bad) < maxIgnored {
			bad = append(bad, x)
		}
	}
	for _, ref := range []string{RemoteRef, Ref} {
		head, err := st.ResolveRef(ctx, ref)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			report(Ignored{ID: "-", Why: "cannot read " + ref})
			continue
		}
		if head == "" {
			continue
		}
		ents, err := st.ListTree(ctx, head)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			report(Ignored{ID: "-", Why: "cannot read " + ref})
			continue
		}
		junk, taken := 0, 0
		for _, e := range ents {
			name := string(e.Path)
			if !fileRE.MatchString(name) || taken >= maxRecords {
				junk++
				continue
			}
			taken++
			id := strings.TrimSuffix(name, ".json")
			b, err := st.ReadBlob(ctx, e.Blob)
			if err != nil {
				if ctx.Err() != nil {
					return nil, nil, ctx.Err()
				}
				junk++
				continue
			}
			var r Record
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if len(b) > maxRecordBytes || dec.Decode(&r) != nil || r.ID != id {
				report(Ignored{ID: id, Why: "does not parse"})
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			recs = append(recs, r)
		}
		if junk > 0 {
			report(Ignored{ID: "-", Why: fmt.Sprintf("%d file(s) on %s are not re-root records, or are over the limit of %d", junk, ref, maxRecords)})
		}
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if !recs[i].Created.Equal(recs[j].Created) {
			return recs[i].Created.After(recs[j].Created)
		}
		return recs[i].ID > recs[j].ID
	})
	return recs, bad, nil
}

// Write commits rec onto the re-root ref as `<id>.json` and moves Ref to
// the new commit. It builds on the fetched ref (or on Ref when Ref is
// ahead of it) and keeps the keepRecords newest records. It never pushes:
// `yadm reroot` pushes Ref with the rewritten main in one atomic push.
// It returns the old value of Ref, for Unwrite.
func Write(ctx context.Context, st store.Store, rec Record) (prev, next model.CommitID, err error) {
	remote, err := st.ResolveRef(ctx, RemoteRef)
	if err != nil {
		return "", "", err
	}
	local, err := st.ResolveRef(ctx, Ref)
	if err != nil {
		return "", "", err
	}
	base := remote
	if local != "" && local != remote {
		if remote == "" {
			base = local
		} else if ok, err := st.IsAncestor(ctx, remote, local); err != nil {
			return "", "", err
		} else if ok {
			base = local
		}
	}
	var changes []store.Change
	if base != "" {
		ents, err := st.ListTree(ctx, base)
		if err != nil {
			return "", "", err
		}
		type dated struct {
			path model.SourcePath
			at   time.Time
		}
		var kept []dated
		for _, e := range ents {
			b, err := st.ReadBlob(ctx, e.Blob)
			var r Record
			if err != nil || !fileRE.MatchString(string(e.Path)) || json.Unmarshal(b, &r) != nil {
				changes = append(changes, store.Change{Path: e.Path, Delete: true})
				continue
			}
			kept = append(kept, dated{e.Path, r.Created})
		}
		sort.Slice(kept, func(i, j int) bool { return kept[i].at.After(kept[j].at) })
		for i, k := range kept {
			if i >= keepRecords-1 {
				changes = append(changes, store.Change{Path: k.path, Delete: true})
			}
		}
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", "", err
	}
	changes = append(changes, store.Change{Path: model.SourcePath(rec.ID + ".json"), Blob: append(b, '\n'), Mode: 0o100644})
	msg := store.Message{Subject: "reroot " + rec.ID, Trailers: []store.Trailer{{Key: store.TrailerMachine, Value: string(rec.Signer)}}}
	next, err = st.CommitPaths(ctx, base, changes, msg)
	if err != nil {
		return "", "", err
	}
	if err := st.UpdateRef(ctx, Ref, next, local); err != nil {
		return "", "", err
	}
	return local, next, nil
}

// Unwrite moves Ref back to prev after a push that did not go out, so a
// record the remote never took does not linger on this machine.
func Unwrite(ctx context.Context, st store.Store, prev, next model.CommitID) error {
	if prev == "" {
		return st.UpdateRef(ctx, Ref, "", next)
	}
	return st.UpdateRef(ctx, Ref, prev, next)
}

// Accepted is one re-root this machine switched to.
type Accepted struct {
	ID      string          `json:"id"`
	By      model.MachineID `json:"by"`
	OldHead model.CommitID  `json:"old_head"`
	NewHead model.CommitID  `json:"new_head"`
	// Created is the record's signed creation time: a record not newer
	// than the newest accepted one is a replay.
	Created time.Time `json:"created"`
	At      time.Time `json:"at"`
	// Backup is the bundle written before the switch, if any.
	Backup string `json:"backup,omitempty"`
	// Carried is the local ref that keeps this machine's commits as they
	// were before `yadm reroot carry` replayed them.
	Carried string `json:"carried,omitempty"`
}

// Local is StateFile.
type Local struct {
	Accepted []Accepted `json:"accepted,omitempty"` // newest last
}

// Last returns the newest accepted re-root, or nil.
func (l Local) Last() *Accepted {
	if len(l.Accepted) == 0 {
		return nil
	}
	return &l.Accepted[len(l.Accepted)-1]
}

// Load reads StateFile in stateDir; a missing or unreadable file is empty.
func Load(stateDir string) Local {
	var l Local
	if stateDir == "" {
		return l
	}
	if b, err := os.ReadFile(filepath.Join(stateDir, StateFile)); err == nil {
		_ = json.Unmarshal(b, &l)
	}
	return l
}

// RecordAccepted appends a to StateFile in stateDir.
func RecordAccepted(stateDir string, a Accepted) error {
	if stateDir == "" {
		return nil
	}
	l := Load(stateDir)
	l.Accepted = append(l.Accepted, a)
	if n := len(l.Accepted); n > keepAccepted {
		l.Accepted = l.Accepted[n-keepAccepted:]
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(stateDir, StateFile)
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}
