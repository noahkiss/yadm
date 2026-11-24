package pause

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
	"github.com/noahkiss/yadm/internal/store"
)

// Names and limits.
const (
	// Ref is the pause ref. It lives under refs/yadm/, so every sync
	// fetches it.
	Ref = "refs/yadm/pause"
	// RemoteRef is the fetched copy of Ref.
	RemoteRef = "refs/remotes/origin/yadm/pause"
	// StateFile is this machine's pause state in the state directory.
	StateFile = "pause.json"
	// Kind is the statement kind a pause or resume record is signed as.
	Kind = "pause"
	// Schema is the version of a stored record.
	Schema = 1

	// MaxSpan is the longest a pause holds: after its creation, and after
	// this machine first saw it.
	MaxSpan = 4 * time.Hour
	// DefaultFor is the length of a pause when `--for` is not given.
	DefaultFor = 30 * time.Minute

	// keepFor is how long Write keeps a record on the ref after it can no
	// longer hold anyone, and Evaluate keeps local state for it.
	keepFor = 24 * time.Hour
	// maxReason bounds the reason text.
	maxReason = 200
)

// Op is the kind of a record.
type Op string

// Record operations.
const (
	OpPause  Op = "pause"  // start or extend a pause; signed by its initiator
	OpResume Op = "resume" // lift a pause early; signed by any trusted signer
)

// Errors.
var (
	// ErrHeld refuses a write on a machine another machine's pause holds.
	ErrHeld = errors.New("the fleet is paused")
	// ErrUntrusted means a record's signer is not a member of a key log
	// this machine has pinned.
	ErrUntrusted = errors.New("signer is not a member of a key log this machine has pinned")
	// ErrMalformed means a record breaks a structural rule.
	ErrMalformed = errors.New("malformed pause record")
)

// Record is one pause or resume as the ref stores it. Times are UTC, whole
// seconds. A resume carries the pause's id, initiator, reason, created and
// deadline unchanged.
type Record struct {
	Schema    int             `json:"schema"`
	Op        Op              `json:"op"`
	ID        string          `json:"id"`
	Initiator model.MachineID `json:"initiator"`
	Reason    string          `json:"reason,omitempty"`
	Created   time.Time       `json:"created"`
	Deadline  time.Time       `json:"deadline"`
	Signer    model.MachineID `json:"signer"`
	Sig       model.Base64    `json:"sig,omitempty"`
}

var idPattern = regexp.MustCompile(`^p-[0-9a-f]{12}$`)

// NewID returns a fresh pause id.
func NewID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "p-" + hex.EncodeToString(b[:]), nil
}

// SignedBytes is the canonical JSON the signature covers: the record with
// Sig empty.
func (r Record) SignedBytes() ([]byte, error) {
	r.Sig = nil
	return json.Marshal(r)
}

// Sign normalizes r (UTC, whole seconds), sets the signer to id's machine
// and signs it.
func Sign(r Record, id *crypt.Identity) (Record, error) {
	if id == nil {
		return Record{}, errors.New("pause: no signing identity")
	}
	r.Schema = Schema
	r.Created = r.Created.UTC().Truncate(time.Second)
	r.Deadline = r.Deadline.UTC().Truncate(time.Second)
	r.Signer = id.Machine
	if err := r.shape(); err != nil {
		return Record{}, err
	}
	body, err := r.SignedBytes()
	if err != nil {
		return Record{}, err
	}
	sig, err := id.SignStatement(Kind, body)
	if err != nil {
		return Record{}, err
	}
	r.Sig = sig
	return r, nil
}

// shape checks a record on its own.
func (r Record) shape() error {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrMalformed, why) }
	switch {
	case r.Schema != Schema:
		return bad("unknown schema")
	case r.Op != OpPause && r.Op != OpResume:
		return bad("unknown op")
	case !idPattern.MatchString(r.ID):
		return bad("bad id")
	case r.Initiator == "" || r.Signer == "" || model.HasControl(string(r.Initiator)) || model.HasControl(string(r.Signer)):
		return bad("no initiator or signer")
	case len(r.Reason) > maxReason || model.HasControl(r.Reason):
		return bad("reason too long or holds a control character")
	case r.Created.IsZero() || r.Deadline.IsZero() || !r.Deadline.After(r.Created):
		return bad("deadline is not after created")
	case r.Op == OpPause && r.Signer != r.Initiator:
		return bad("a pause is signed by its initiator")
	}
	return nil
}

// Signers are the machines whose signatures this machine trusts, with the
// keys the pinned key logs give them.
type Signers map[model.MachineID][]crypt.Member

// TrustedSigners collects the members of every key log this machine has
// pinned and that verified. An enclave without a pin gives nothing: a writer
// can replace an unpinned log with one that lists a key it holds.
func TrustedSigners(loads map[model.EnclaveName]crypt.EnclaveLoad, pins crypt.PinStore) Signers {
	out := Signers{}
	if pins == nil {
		return out
	}
	for e, l := range loads {
		if l.Err != nil {
			continue
		}
		if p, err := pins.Get(e); err != nil || p == nil {
			continue
		}
		for _, m := range l.Head.Members {
			out[m.Machine] = append(out[m.Machine], m)
		}
	}
	return out
}

// Verify checks a record's shape, that its signer is trusted, and its
// signature.
func (s Signers) Verify(r Record) error {
	if err := r.shape(); err != nil {
		return err
	}
	keys := s[r.Signer]
	if len(keys) == 0 {
		return fmt.Errorf("%w: %s", ErrUntrusted, r.Signer)
	}
	body, err := r.SignedBytes()
	if err != nil {
		return err
	}
	var last error
	for _, m := range keys {
		if last = crypt.VerifyStatement(m, Kind, body, r.Sig); last == nil {
			return nil
		}
	}
	return last
}

// Active is a pause that holds now.
type Active struct {
	ID        string          `json:"id"`
	Initiator model.MachineID `json:"initiator"`
	Reason    string          `json:"reason,omitempty"`
	Created   time.Time       `json:"created"`
	// Until is when this machine resumes: the signed deadline, clamped to
	// MaxSpan after creation and after this machine first saw the pause.
	Until time.Time `json:"until"`
	// Requested is the signed deadline; Clamped says Until is earlier.
	Requested time.Time `json:"requested"`
	Clamped   bool      `json:"clamped,omitempty"`
}

// Ignored is a record this machine did not accept.
type Ignored struct {
	ID     string          `json:"id"`
	Signer model.MachineID `json:"signer,omitempty"`
	Why    string          `json:"why"`
}

// View is the pause state on this machine.
type View struct {
	Active  []Active  `json:"active,omitempty"`
	Ignored []Ignored `json:"ignored,omitempty"`
	Lifted  []string  `json:"lifted,omitempty"` // pauses a signed resume lifted, still within their window
}

// Holding returns the pause that holds self: an active pause another
// machine started. nil means self may sync, commit and apply.
func (v View) Holding(self model.MachineID) *Active {
	for i := range v.Active {
		if v.Active[i].Initiator != self {
			return &v.Active[i]
		}
	}
	return nil
}

// Find returns the active pause with this id.
func (v View) Find(id string) *Active {
	for i := range v.Active {
		if v.Active[i].ID == id {
			return &v.Active[i]
		}
	}
	return nil
}

// HeldError refuses a write on a machine a pause holds.
type HeldError struct {
	Active Active
	Self   model.MachineID
	Name   string // the initiator's fleet name, when known
}

func (e *HeldError) Error() string {
	who := string(e.Active.Initiator)
	if e.Name != "" && e.Name != who {
		who = e.Name + " (" + who + ")"
	}
	why := ""
	if e.Active.Reason != "" {
		why = fmt.Sprintf(" for %q", e.Active.Reason)
	}
	return fmt.Sprintf("%s: %s paused the fleet%s until %s; nothing commits or applies here until then; this machine resumes by itself at that time, or after `yadm resume`",
		ErrHeld, who, why, e.Active.Until.UTC().Format(time.RFC3339))
}

func (e *HeldError) Unwrap() error { return ErrHeld }

// entry is what this machine remembers about one pause.
type entry struct {
	Record    Record          `json:"record"` // the latest accepted record
	FirstSeen time.Time       `json:"first_seen"`
	Lifted    *time.Time      `json:"lifted,omitempty"`
	LiftedBy  model.MachineID `json:"lifted_by,omitempty"`
}

// local is StateFile.
type local struct {
	Pauses map[string]*entry `json:"pauses,omitempty"`
	// HeldUntil is the deadline the last Evaluate held this machine to.
	// The quick check runs a full sync once it has passed.
	HeldUntil time.Time `json:"held_until,omitempty"`
}

func loadLocal(stateDir string) local {
	var l local
	if stateDir == "" {
		return l
	}
	if b, err := os.ReadFile(filepath.Join(stateDir, StateFile)); err == nil {
		_ = json.Unmarshal(b, &l)
	}
	return l
}

func saveLocal(stateDir string, l local) error {
	if stateDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(stateDir, StateFile)
	f, err := os.CreateTemp(stateDir, StateFile+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, p)
	}
	if werr != nil {
		_ = os.Remove(tmp)
	}
	return werr
}

// HeldUntil returns the deadline the last saved Evaluate held this machine
// to, or the zero time.
func HeldUntil(stateDir string) time.Time { return loadLocal(stateDir).HeldUntil }

// until is when a pause stops holding this machine.
func until(r Record, firstSeen time.Time) (time.Time, bool) {
	u := r.Deadline
	for _, c := range []time.Time{r.Created.Add(MaxSpan), firstSeen.Add(MaxSpan)} {
		if c.Before(u) {
			u = c
		}
	}
	return u, u.Before(r.Deadline)
}

// claimedUntil is the latest a record could hold anyone, by its own times.
func claimedUntil(r Record) time.Time {
	u := r.Deadline
	if c := r.Created.Add(MaxSpan); c.Before(u) {
		u = c
	}
	return u
}

// Read returns the records on the fetched pause ref and the local one. A
// file that does not parse comes back as Ignored.
func Read(ctx context.Context, st store.Store) ([]Record, []Ignored, error) {
	var recs []Record
	var bad []Ignored
	for _, ref := range []string{RemoteRef, Ref} {
		head, err := st.ResolveRef(ctx, ref)
		if err != nil {
			return nil, nil, err
		}
		if head == "" {
			continue
		}
		ents, err := st.ListTree(ctx, head)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range ents {
			b, err := st.ReadBlob(ctx, e.Blob)
			if err != nil {
				return nil, nil, err
			}
			var r Record
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil || string(e.Path) != r.ID+".json" {
				bad = append(bad, Ignored{ID: strings.TrimSuffix(string(e.Path), ".json"), Why: "does not parse"})
				continue
			}
			recs = append(recs, r)
		}
	}
	return recs, bad, nil
}

// Evaluate reads the pause ref, merges every trusted record into this
// machine's state and returns the pauses that hold now. With save it writes
// the state back (the caller holds the sync lock); without, it changes
// nothing on disk (status and check).
func Evaluate(ctx context.Context, st store.Store, stateDir string, self model.MachineID, signers Signers, now time.Time, save bool) (View, error) {
	recs, bad, err := Read(ctx, st)
	if err != nil {
		return View{}, err
	}
	l := loadLocal(stateDir)
	if l.Pauses == nil {
		l.Pauses = map[string]*entry{}
	}
	var v View
	ignore := func(r Record, why string) {
		if !now.Before(claimedUntil(r)) {
			return // expired junk holds no one; nothing to report
		}
		for _, x := range v.Ignored {
			if x.ID == r.ID && x.Why == why {
				return
			}
		}
		v.Ignored = append(v.Ignored, Ignored{ID: r.ID, Signer: r.Signer, Why: why})
	}
	v.Ignored = append(v.Ignored, bad...)
	for _, r := range recs {
		if err := signers.Verify(r); err != nil {
			ignore(r, err.Error())
			continue
		}
		e := l.Pauses[r.ID]
		if e == nil {
			if r.Op == OpPause && !now.Before(claimedUntil(r)) {
				continue // expired before this machine saw it: a no-op
			}
			e = &entry{Record: r, FirstSeen: now}
			l.Pauses[r.ID] = e
		}
		switch r.Op {
		case OpResume:
			if e.Lifted == nil {
				t := now
				e.Lifted, e.LiftedBy = &t, r.Signer
			}
		case OpPause:
			cur := e.Record
			switch {
			case cur.Initiator != r.Initiator || !cur.Created.Equal(r.Created):
				ignore(r, "conflicts with the pause of the same id this machine accepted")
			case r.Deadline.After(cur.Deadline):
				// An extension. A resume record kept as the entry is
				// replaced, but the entry stays lifted.
				e.Record = r
			}
		}
	}
	l.HeldUntil = time.Time{}
	ids := make([]string, 0, len(l.Pauses))
	for id := range l.Pauses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := l.Pauses[id]
		u, clamped := until(e.Record, e.FirstSeen)
		if now.After(u.Add(keepFor)) && now.After(e.FirstSeen.Add(keepFor)) {
			delete(l.Pauses, id)
			continue
		}
		if !now.Before(u) {
			continue
		}
		if e.Lifted != nil {
			v.Lifted = append(v.Lifted, id)
			continue
		}
		if e.Record.Op != OpPause {
			continue
		}
		v.Active = append(v.Active, Active{
			ID: id, Initiator: e.Record.Initiator, Reason: e.Record.Reason, Created: e.Record.Created,
			Until: u, Requested: e.Record.Deadline, Clamped: clamped,
		})
		if e.Record.Initiator != self && u.After(l.HeldUntil) {
			l.HeldUntil = u
		}
	}
	sort.Slice(v.Active, func(i, j int) bool { return v.Active[i].Created.Before(v.Active[j].Created) })
	if save {
		if err := saveLocal(stateDir, l); err != nil {
			return v, err
		}
	}
	return v, nil
}

// Write commits recs onto the pause ref, each as `<id>.json`, and moves
// Ref to the new commit. It builds on the fetched ref (or on Ref when Ref
// is ahead of it), drops records that can hold no one for a day, and never
// pushes: the caller pushes Spec.
func Write(ctx context.Context, st store.Store, recs []Record, now time.Time) (model.CommitID, error) {
	remote, err := st.ResolveRef(ctx, RemoteRef)
	if err != nil {
		return "", err
	}
	local, err := st.ResolveRef(ctx, Ref)
	if err != nil {
		return "", err
	}
	base := remote
	if local != "" && local != remote {
		if remote == "" {
			base = local
		} else if ok, err := st.IsAncestor(ctx, remote, local); err != nil {
			return "", err
		} else if ok {
			base = local
		}
	}
	var changes []store.Change
	if base != "" {
		ents, err := st.ListTree(ctx, base)
		if err != nil {
			return "", err
		}
		for _, e := range ents {
			b, err := st.ReadBlob(ctx, e.Blob)
			if err != nil {
				return "", err
			}
			var r Record
			if json.Unmarshal(b, &r) != nil || now.After(claimedUntil(r).Add(keepFor)) {
				changes = append(changes, store.Change{Path: e.Path, Delete: true})
			}
		}
	}
	subject := []string{}
	for _, r := range recs {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", err
		}
		changes = append(changes, store.Change{Path: model.SourcePath(r.ID + ".json"), Blob: append(b, '\n'), Mode: 0o100644})
		subject = append(subject, string(r.Op)+" "+r.ID)
	}
	msg := store.Message{Subject: strings.Join(subject, ", ")}
	if len(recs) > 0 {
		msg.Trailers = []store.Trailer{{Key: store.TrailerMachine, Value: string(recs[0].Signer)}}
	}
	next, err := st.CommitPaths(ctx, base, changes, msg)
	if err != nil {
		return "", err
	}
	if err := st.UpdateRef(ctx, Ref, next, local); err != nil {
		return "", err
	}
	return next, nil
}

// Spec returns the refspec that pushes Ref, when Ref is ahead of the
// fetched copy; "" when there is nothing to push or the remote moved past
// it (a write is redone on the new remote head, never forced).
func Spec(ctx context.Context, st store.Store) (string, error) {
	local, err := st.ResolveRef(ctx, Ref)
	if err != nil || local == "" {
		return "", err
	}
	remote, err := st.ResolveRef(ctx, RemoteRef)
	if err != nil {
		return "", err
	}
	if local == remote {
		return "", nil
	}
	if remote != "" {
		if ok, err := st.IsAncestor(ctx, remote, local); err != nil || !ok {
			return "", err
		}
	}
	return Ref + ":" + Ref, nil
}
