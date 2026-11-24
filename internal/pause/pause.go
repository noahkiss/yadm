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
	// maxRecords and maxRecordBytes bound what Read takes from a ref any
	// writer controls; maxIgnored bounds what a View reports.
	maxRecords     = 64
	maxRecordBytes = 4096
	maxIgnored     = 16
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
	// ErrUntrusted means a record's signer is not a machine in fleet.toml,
	// or the record is unverified where fleet.toml requires a member's
	// signature.
	ErrUntrusted = errors.New("signer is not trusted")
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

var (
	idPattern = regexp.MustCompile(`^p-[0-9a-f]{12}$`)
	fileRE    = regexp.MustCompile(`^p-[0-9a-f]{12}\.json$`)
)

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
	// Verified says a member of a key log this machine pinned signed it.
	// An unverified pause counts unless fleet.toml requires a member.
	Verified bool `json:"verified"`
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
// machine started. While self runs a pause of its own, only a pause ordered
// before it holds self, so two machines that pause at the same time never
// hold each other: the later one is held. nil means self may sync, commit
// and apply.
func (v View) Holding(self model.MachineID) *Active {
	h := v.holding(self)
	if len(h) == 0 {
		return nil
	}
	return &v.Active[h[0]]
}

// holding returns the indexes of the active pauses that hold self.
func (v View) holding(self model.MachineID) []int {
	var own *Active
	for i := range v.Active {
		if v.Active[i].Initiator == self {
			own = &v.Active[i]
			break
		}
	}
	var out []int
	for i := range v.Active {
		a := v.Active[i]
		if a.Initiator == self || (own != nil && !a.before(*own)) {
			continue
		}
		out = append(out, i)
	}
	return out
}

// before orders pauses by creation, then id.
func (a Active) before(b Active) bool {
	if !a.Created.Equal(b.Created) {
		return a.Created.Before(b.Created)
	}
	return a.ID < b.ID
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
	Record    Record    `json:"record"` // the latest accepted record
	FirstSeen time.Time `json:"first_seen"`
	// Verified says a pinned key-log member signed the accepted record.
	Verified bool `json:"verified,omitempty"`
	// Cap is the end of the hold run this machine was in when it first saw
	// the pause: a pause seen while another holds extends no hold past
	// MaxSpan.
	Cap      *time.Time      `json:"cap,omitempty"`
	Lifted   *time.Time      `json:"lifted,omitempty"`
	LiftedBy model.MachineID `json:"lifted_by,omitempty"`
}

// local is StateFile.
type local struct {
	Pauses map[string]*entry `json:"pauses,omitempty"`
	// HeldUntil is the deadline the last Evaluate held this machine to.
	// The quick check runs a full sync once it has passed.
	HeldUntil time.Time `json:"held_until,omitempty"`
	// HoldStart is when the current hold run began: the first Evaluate
	// that found this machine held since the last one that did not.
	HoldStart time.Time `json:"hold_start,omitempty"`
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
	return writeAtomic(stateDir, StateFile, b)
}

// writeAtomic writes b to name in dir through a temporary file.
func writeAtomic(dir, name string, b []byte) error {
	p := filepath.Join(dir, name)
	f, err := os.CreateTemp(dir, name+".*.tmp")
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

// until is when a pause stops holding this machine: the signed deadline,
// at most MaxSpan after creation, and at most the signed span (capped at
// MaxSpan) after this machine first saw it, so an initiator's clock that
// runs ahead never makes a short pause hold longer here. cap, when set,
// ends it with the hold run it was first seen in.
func until(r Record, firstSeen time.Time, cap *time.Time) (time.Time, bool) {
	u := r.Deadline
	span := r.Deadline.Sub(r.Created)
	if span > MaxSpan {
		span = MaxSpan
	}
	cs := []time.Time{r.Created.Add(MaxSpan), firstSeen.Add(span)}
	if cap != nil {
		cs = append(cs, *cap)
	}
	for _, c := range cs {
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

// Read returns the records on the fetched pause ref and the local one. Any
// writer controls the fetched ref, so Read takes at most maxRecords
// top-level `<id>.json` files of at most maxRecordBytes each. A file that
// breaks a rule, or a ref that does not read, comes back as Ignored with an
// id of this machine's choosing; it never fails the caller.
func Read(ctx context.Context, st store.Store) ([]Record, []Ignored, error) {
	var recs []Record
	var bad []Ignored
	for _, ref := range []string{RemoteRef, Ref} {
		junk := 0
		head, err := st.ResolveRef(ctx, ref)
		if err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			bad = append(bad, Ignored{ID: "-", Why: "cannot read " + ref})
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
			bad = append(bad, Ignored{ID: "-", Why: "cannot read " + ref})
			continue
		}
		taken := 0
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
				bad = append(bad, Ignored{ID: id, Why: "does not parse"})
				continue
			}
			recs = append(recs, r)
		}
		if junk > 0 {
			bad = append(bad, Ignored{ID: "-", Why: fmt.Sprintf("%d file(s) on %s are not pause records, or are over the limit of %d", junk, ref, maxRecords)})
		}
	}
	return recs, bad, nil
}

// Evaluate reads the pause ref, merges every trusted record into this
// machine's state and returns the pauses that hold now. With save it writes
// the state back (the caller holds the sync lock); without, it changes
// nothing on disk (status and check).
func Evaluate(ctx context.Context, st store.Store, stateDir string, self model.MachineID, trust Trust, now time.Time, save bool) (View, error) {
	recs, bad, err := Read(ctx, st)
	if err != nil {
		return View{}, err
	}
	l := loadLocal(stateDir)
	if l.Pauses == nil {
		l.Pauses = map[string]*entry{}
	}
	var v View
	report := func(x Ignored) {
		for _, y := range v.Ignored {
			if y == x {
				return
			}
		}
		if len(v.Ignored) < maxIgnored {
			v.Ignored = append(v.Ignored, x)
		}
	}
	ignore := func(r Record, why string) {
		if !now.Before(claimedUntil(r)) {
			return // expired junk holds no one; nothing to report
		}
		x := Ignored{ID: r.ID, Why: why}
		if r.shape() == nil {
			x.Signer = r.Signer // a malformed record's fields are any writer's text
		} else {
			x.Why = "malformed pause record"
		}
		report(x)
	}
	for _, x := range bad {
		report(x)
	}
	for _, r := range recs {
		verified, err := trust.Verify(r)
		if err != nil {
			ignore(r, err.Error())
			continue
		}
		e := l.Pauses[r.ID]
		if e == nil {
			if r.Op == OpPause && !now.Before(claimedUntil(r)) {
				continue // expired before this machine saw it: a no-op
			}
			e = &entry{Record: r, FirstSeen: now, Verified: verified && r.Op == OpPause}
			if !l.HoldStart.IsZero() {
				// Seen during a hold run: it ends with that run, so chained
				// pauses hold at most MaxSpan before one unheld sync
				// replays main and its key logs.
				c := l.HoldStart.Add(MaxSpan)
				e.Cap = &c
			}
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
			case e.Verified && !verified:
				if r.Deadline.After(cur.Deadline) {
					ignore(r, "an unverified extension of a verified pause")
				}
			case r.Deadline.After(cur.Deadline):
				// An extension. A resume record kept as the entry is
				// replaced, but the entry stays lifted.
				e.Record, e.Verified = r, verified
			case verified && cur.Op == OpPause && r.Deadline.Equal(cur.Deadline):
				e.Verified = true
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
		u, clamped := until(e.Record, e.FirstSeen, e.Cap)
		// Forget a pause only once its record can hold no one by its own
		// times too: a record created in the future would otherwise come
		// back as new and hold again.
		if now.After(u.Add(keepFor)) && now.After(claimedUntil(e.Record).Add(keepFor)) && now.After(e.FirstSeen.Add(keepFor)) {
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
			Until: u, Requested: e.Record.Deadline, Clamped: clamped, Verified: e.Verified,
		})
	}
	sort.Slice(v.Active, func(i, j int) bool { return v.Active[i].before(v.Active[j]) })
	for _, i := range v.holding(self) {
		if u := v.Active[i].Until; u.After(l.HeldUntil) {
			l.HeldUntil = u
		}
	}
	switch {
	case l.HeldUntil.IsZero():
		l.HoldStart = time.Time{}
	case l.HoldStart.IsZero():
		l.HoldStart = now
	}
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
// pushes: the caller pushes Spec. When the fetched ref moved past Ref, the
// records written here that never went out are carried onto it. A pause
// record never replaces a resume of the same pause. A write that changes
// nothing makes no commit.
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
	diverged := false
	if local != "" && local != remote {
		if remote == "" {
			base = local
		} else if ok, err := st.IsAncestor(ctx, remote, local); err != nil {
			return "", err
		} else if ok {
			base = local
		} else if ok, err := st.IsAncestor(ctx, local, remote); err != nil {
			return "", err
		} else {
			diverged = !ok
		}
	}
	onBase, err := treeRecords(ctx, st, base)
	if err != nil {
		return "", err
	}
	if diverged {
		mine, err := treeRecords(ctx, st, local)
		if err != nil {
			return "", err
		}
		var carry []Record
		for id, r := range mine {
			if r.err != nil || !now.Before(claimedUntil(r.Record)) {
				continue
			}
			if b, ok := onBase[id]; ok && b.err == nil && !(r.Op == OpPause && b.Op == OpPause && r.Deadline.After(b.Deadline)) {
				continue // the remote holds it, a resume of it, or a later one
			}
			carry = append(carry, r.Record)
		}
		sort.Slice(carry, func(i, j int) bool { return carry[i].ID < carry[j].ID })
		recs = append(carry, recs...)
	}
	var changes []store.Change
	for path, r := range onBase {
		if r.err != nil || now.After(claimedUntil(r.Record).Add(keepFor)) {
			changes = append(changes, store.Change{Path: model.SourcePath(path), Delete: true})
		}
	}
	subject := []string{}
	for _, r := range recs {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", err
		}
		b = append(b, '\n')
		if cur, ok := onBase[r.ID+".json"]; ok && cur.err == nil {
			if cur.Op == OpResume && r.Op == OpPause {
				continue // a lifted pause stays lifted on the ref too
			}
			if bytes.Equal(cur.raw, b) {
				continue
			}
		}
		changes = append(changes, store.Change{Path: model.SourcePath(r.ID + ".json"), Blob: b, Mode: 0o100644})
		subject = append(subject, string(r.Op)+" "+r.ID)
	}
	if len(changes) == 0 {
		return local, nil
	}
	if len(subject) == 0 {
		subject = []string{"prune"}
	}
	msg := store.Message{Subject: strings.Join(subject, ", ")}
	if len(recs) > 0 {
		msg.Trailers = []store.Trailer{{Key: store.TrailerMachine, Value: string(recs[len(recs)-1].Signer)}}
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

// Restage carries the records written here that never went out onto the
// fetched ref, when that ref moved past Ref. Otherwise it changes nothing.
// The caller holds the sync lock and then pushes Spec.
func Restage(ctx context.Context, st store.Store, now time.Time) error {
	local, err := st.ResolveRef(ctx, Ref)
	if err != nil || local == "" {
		return err
	}
	remote, err := st.ResolveRef(ctx, RemoteRef)
	if err != nil || remote == "" || remote == local {
		return err
	}
	for _, p := range [][2]model.CommitID{{remote, local}, {local, remote}} {
		if ok, err := st.IsAncestor(ctx, p[0], p[1]); err != nil || ok {
			return err
		}
	}
	_, err = Write(ctx, st, nil, now)
	return err
}

// treeRecord is one file on a pause ref commit.
type treeRecord struct {
	Record
	raw []byte
	err error
}

// treeRecords reads the files of a pause ref commit by path; ids are the
// map keys without ".json". A file that does not parse carries err.
func treeRecords(ctx context.Context, st store.Store, rev model.CommitID) (map[string]treeRecord, error) {
	out := map[string]treeRecord{}
	if rev == "" {
		return out, nil
	}
	ents, err := st.ListTree(ctx, rev)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		b, err := st.ReadBlob(ctx, e.Blob)
		if err != nil {
			return nil, err
		}
		var r treeRecord
		r.raw = b
		if r.err = json.Unmarshal(b, &r.Record); r.err == nil && string(e.Path) != r.ID+".json" {
			r.err = ErrMalformed
		}
		out[string(e.Path)] = r
	}
	return out, nil
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
