package sync

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// RemoteGuard decides whether a fetched source may be applied on this
// machine. It sees the snapshot this machine runs now and the fetched one. A
// guard refuses, for example, a manifest change that weakens protection for
// a path (an entry losing its enclave, seal or regions, or a new owned root
// over a private directory) until the change is allowed locally.
type RemoteGuard interface {
	Allow(ctx context.Context, from, to *apply.Snapshot) (ok bool, detail string, err error)
}

// PathGuard is a RemoteGuard that names each weakening (apply.Guard). With
// one, a fetched source whose weakenings are all targets is taken: those
// targets alone are held back (apply.Engine.HoldBack), and every other
// change applies and pushes. A weakened owned root, or a guard that is not
// a PathGuard, refuses the whole source.
type PathGuard interface {
	RemoteGuard
	Weakenings(from, to *apply.Snapshot) []apply.Weakening
}

// Tasks of the holds a refused fetch raises. They have no target, except
// a held path's hold, which names its target and shares HoldTaskGuard.
const (
	HoldTaskKeyLog = "key-log"       // a fetched commit rewrote or deleted a key-log entry
	HoldTaskGuard  = apply.GuardTask // RemoteGuard refused the fetched source, or held one target of it
)

// Alert kinds.
const (
	AlertNonMember     = "non_member_enclave_commit"
	AlertKeyLogRewrite = "key_log_rewrite"
	AlertGuardRefused  = "remote_refused"
	// AlertPathHeld: a fetched source was taken with some targets held
	// back, because it weakens their protection.
	AlertPathHeld = "protection_held"
)

// keyLogPath reports a path under keys/: crypt.ParseLogPath's enclave and
// seq for a canonical entry name, or the enclave and seq 0 for any other
// file under keys/<enclave>/, which is a violation whatever it holds.
func keyLogPath(p model.SourcePath) (model.EnclaveName, uint64, bool) {
	if e, n, ok := crypt.ParseLogPath(p); ok {
		return e, n, true
	}
	rest, ok := strings.CutPrefix(string(p), "keys/")
	if !ok {
		return "", 0, false
	}
	e, _, ok := strings.Cut(rest, "/")
	if !ok || e == "" {
		return "", 0, false
	}
	return model.EnclaveName(e), 0, true
}

// appendOnly runs crypt.CheckLogAppendOnly on every enclave's parsed log at
// base against remote, so an entry whose bytes changed in a way the blob
// check cannot judge (a re-signed fork at an existing seq) is refused too.
func (s *Syncer) appendOnly(ctx context.Context, base, remote map[model.SourcePath]store.TreeEntry) ([]string, error) {
	logs := func(tree map[model.SourcePath]store.TreeEntry) (map[model.EnclaveName][]crypt.LogEntry, error) {
		var paths []model.SourcePath
		for p := range tree {
			if _, n, ok := keyLogPath(p); ok && n > 0 {
				paths = append(paths, p)
			}
		}
		sort.Slice(paths, func(i, j int) bool {
			ei, ni, _ := keyLogPath(paths[i])
			ej, nj, _ := keyLogPath(paths[j])
			if ei != ej {
				return ei < ej
			}
			return ni < nj
		})
		out := map[model.EnclaveName][]crypt.LogEntry{}
		for _, p := range paths {
			e, _, _ := keyLogPath(p)
			b, err := s.Store.ReadBlob(ctx, tree[p].Blob)
			if err != nil {
				return nil, err
			}
			le, err := crypt.ParseLogEntry(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			out[e] = append(out[e], le)
		}
		return out, nil
	}
	old, err := logs(base)
	if err != nil {
		return nil, nil // a base this machine accepted but cannot parse: the blob checks still run
	}
	next, err := logs(remote)
	if err != nil {
		return []string{"fetched key log does not parse: " + err.Error()}, nil
	}
	var out []string
	for e, l := range old {
		if err := crypt.CheckLogAppendOnly(l, next[e]); err != nil {
			out = append(out, err.Error())
		}
	}
	return out, nil
}

// keyLogViolations checks that remote only appends to key logs: every entry
// under keys/ at base is byte-identical at remote, and each fetched commit
// only adds the next sequence number of an enclave. Entries are immutable
// in history; a rewrite or deletion is refused before anything is applied.
func (s *Syncer) keyLogViolations(ctx context.Context, base, remote model.CommitID) ([]string, error) {
	if remote == "" || base == remote {
		return nil, nil
	}
	var out []string
	baseTree, err := s.treeMap(ctx, base)
	if err != nil {
		return nil, err
	}
	remoteTree, err := s.treeMap(ctx, remote)
	if err != nil {
		return nil, err
	}
	more, err := s.appendOnly(ctx, baseTree, remoteTree)
	if err != nil {
		return nil, err
	}
	out = append(out, more...)
	for p, e := range baseTree {
		if _, _, ok := keyLogPath(p); !ok {
			continue
		}
		r, ok := remoteTree[p]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s was deleted", p))
		case r.Blob != e.Blob:
			out = append(out, fmt.Sprintf("%s was rewritten", p))
		}
	}
	rng := string(remote)
	if base != "" {
		rng = string(base) + ".." + string(remote)
	}
	commits, err := s.Store.Log(ctx, rng, nil)
	if err != nil {
		return nil, err
	}
	for _, c := range commits {
		var keys []model.SourcePath
		for _, p := range c.Paths {
			if _, _, ok := keyLogPath(p); ok {
				keys = append(keys, p)
			}
		}
		if len(keys) == 0 {
			continue
		}
		var parent model.CommitID
		if len(c.Parents) > 0 {
			parent = c.Parents[0]
		}
		before, err := s.treeMap(ctx, parent)
		if err != nil {
			return nil, err
		}
		after, err := s.treeMap(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		last := map[model.EnclaveName]uint64{}
		for p := range before {
			if e, n, ok := keyLogPath(p); ok && n > last[e] {
				last[e] = n
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, p := range keys {
			e, n, _ := keyLogPath(p)
			_, had := before[p]
			_, has := after[p]
			switch {
			case had && !has:
				out = append(out, fmt.Sprintf("commit %s deleted %s", short(c.ID), p))
			case had:
				out = append(out, fmt.Sprintf("commit %s rewrote %s", short(c.ID), p))
			case n == 0 || n != last[e]+1:
				out = append(out, fmt.Sprintf("commit %s added %s, not the next entry of %s", short(c.ID), p, e))
			default:
				last[e] = n
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func short(id model.CommitID) string {
	if len(id) > 12 {
		return string(id[:12])
	}
	return string(id)
}

// refusal is why a fetched source is not taken.
type refusal struct {
	task   string
	kind   string
	detail string
	next   []string // the hold's suggested commands; default hold show and review list
}

// checkRemote runs the key-log rule and the RemoteGuard on a fetched source.
// It returns a refusal of the whole source, or, with a PathGuard, the
// target weakenings to hold back while the rest is taken.
func (s *Syncer) checkRemote(ctx context.Context, base, local, remote model.CommitID, to *apply.Snapshot) (*refusal, []apply.Weakening, error) {
	if remote == "" || remote == local {
		return nil, nil, nil
	}
	if base == "" {
		base = local
	}
	v, err := s.keyLogViolations(ctx, base, remote)
	if err != nil {
		return nil, nil, err
	}
	if len(v) > 0 {
		return &refusal{task: HoldTaskKeyLog, kind: AlertKeyLogRewrite,
			detail: "key-log entries are append-only; the fetched source was not applied: " + strings.Join(v, "; ")}, nil, nil
	}
	if s.Guard == nil || local == "" || to == nil || remote == base {
		return nil, nil, nil
	}
	refuse := func(detail string) *refusal {
		return &refusal{task: HoldTaskGuard, kind: AlertGuardRefused,
			detail: "the fetched source weakens protection and is not allowed here: " + detail}
	}
	if pg, ok := s.Guard.(PathGuard); ok {
		ws, err := s.weakenings(ctx, pg, base, local, to)
		if err != nil || len(ws) == 0 {
			return nil, nil, err
		}
		var why []string
		root := false
		for _, w := range ws {
			why = append(why, w.Detail)
			root = root || w.Root
		}
		if root {
			// An owned root covers paths apply cannot pin one by one: the
			// files under it would leave the plan and be removed.
			return refuse(strings.Join(why, "; ")), nil, nil
		}
		return nil, ws, nil
	}
	// The guard judges what the fetch changed: the accepted remote (base)
	// against the fetched one. A weakening this machine already runs (its
	// own pushed commit, or one it allowed) is not refused, so the guard
	// must also refuse against local main. Comparing with local alone
	// would refuse an unpushed local strengthening (a retag into an
	// enclave) as the remote "weakening" it.
	ok, detail, err := s.guardFrom(ctx, base, to)
	if err != nil && local != base {
		// The accepted source does not load (a bad commit was accepted
		// before the guard existed): judge from local.
		ok, detail, err = s.guardFrom(ctx, local, to)
	} else if err == nil && !ok && local != base {
		var okLocal bool
		okLocal, _, err = s.guardFrom(ctx, local, to)
		ok = okLocal
	}
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return refuse(detail), nil, nil
	}
	return nil, nil, nil
}

// weakenings lists what pg finds weakened from the accepted remote (base)
// to the fetched source that it also finds weakened from local main, as
// the whole-source judgement does: a weakening this machine already runs
// is not held. A base that does not load is judged from local alone.
func (s *Syncer) weakenings(ctx context.Context, pg PathGuard, base, local model.CommitID, to *apply.Snapshot) ([]apply.Weakening, error) {
	from, err := s.load(ctx, base)
	if err != nil {
		if local == base {
			return nil, err
		}
		if from, err = s.load(ctx, local); err != nil {
			return nil, err
		}
		return pg.Weakenings(from, to), nil
	}
	ws := pg.Weakenings(from, to)
	if len(ws) == 0 || local == base {
		return ws, nil
	}
	lf, err := s.load(ctx, local)
	if err != nil {
		return nil, err
	}
	type key struct {
		t    model.Target
		root bool
	}
	inLocal := map[key]bool{}
	for _, w := range pg.Weakenings(lf, to) {
		inLocal[key{w.Target, w.Root}] = true
	}
	out := ws[:0]
	for _, w := range ws {
		if inLocal[key{w.Target, w.Root}] {
			out = append(out, w)
		}
	}
	return out, nil
}

// holdBack records the held paths of a fetched source taken with ws held
// back, and returns one alert naming the targets held for the first time.
func (s *Syncer) holdBack(ctx context.Context, ws []apply.Weakening, remote model.CommitID) (*model.Alert, error) {
	if len(ws) == 0 {
		return nil, nil
	}
	fresh, err := s.Apply.HoldBack(ctx, ws, remote)
	if err != nil || len(fresh) == 0 {
		return nil, err
	}
	isFresh := map[model.Target]bool{}
	for _, t := range fresh {
		isFresh[t] = true
	}
	var why []string
	for _, w := range ws {
		if isFresh[w.Target] {
			why = append(why, w.Detail)
		}
	}
	a := model.Alert{Kind: AlertPathHeld, Commit: remote, At: s.now(),
		Detail: "the fetched source weakens protection that is not allowed here; it was taken without these files, which stay as they are on this machine: " + strings.Join(why, "; ")}
	return &a, nil
}

// guardFrom runs the RemoteGuard from the source at rev to the fetched one.
func (s *Syncer) guardFrom(ctx context.Context, rev model.CommitID, to *apply.Snapshot) (bool, string, error) {
	from, err := s.load(ctx, rev)
	if err != nil {
		return false, "", err
	}
	return s.Guard.Allow(ctx, from, to)
}

// setRefusal records or clears the holds of refused fetches. It reports
// whether the refusal is new, so it is alerted once.
func (s *Syncer) setRefusal(r *refusal) (bool, error) {
	st, err := s.Apply.State.Load()
	if err != nil {
		return false, err
	}
	fresh := r != nil
	n := len(st.Holds)
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if refusalHold(h) {
			if r != nil && h.Task == r.task {
				out = append(out, h)
				fresh = false
			}
			continue
		}
		out = append(out, h)
	}
	st.Holds = out
	if r != nil {
		h := model.KeepSince(st.Holds, model.Hold{Task: r.task, Scope: model.ScopeShared, Reason: model.HoldProtected, Detail: r.detail}, s.now())
		h.Next = append([]string{"yadm hold show " + h.ID}, r.next...)
		if len(r.next) == 0 {
			h.Next = append(h.Next, "yadm review list")
		}
		putHold(st, h)
	} else if len(st.Holds) == n {
		return false, nil
	}
	return fresh, s.Apply.State.Save(st)
}

// AcceptedFile records the fetched remote main this machine last accepted:
// the base the key-log rule and the RemoteGuard judge each fetch from. A
// fetch never moves it; only an accepted source does. A machine with no
// record seeds one before its first fetch with the origin/main its clone
// holds (the clone's own fetch is the trusted start), so a source refused
// on the first sync stays refused on every later one. The record of an
// empty remote is emptySource.
const AcceptedFile = "remote-accepted"

// emptySource is the record of a start with an empty remote.
const emptySource = "-"

// ReadAccepted reads the AcceptedFile record in stateDir: the accepted
// commit ("" for an empty remote) and whether a record exists.
func ReadAccepted(stateDir string) (model.CommitID, bool) {
	if stateDir == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(stateDir, AcceptedFile))
	if err != nil {
		return "", false
	}
	switch id := strings.TrimSpace(string(b)); id {
	case "":
		return "", false
	case emptySource:
		return "", true
	default:
		return model.CommitID(id), true
	}
}

// SeedAccepted records start ("" for an empty remote) as the accepted
// remote main in stateDir when no record exists. It never replaces one.
func SeedAccepted(stateDir string, start model.CommitID) error {
	if stateDir == "" {
		return nil
	}
	if _, ok := ReadAccepted(stateDir); ok {
		return nil
	}
	v := string(start)
	if v == "" {
		v = emptySource
	}
	p := filepath.Join(stateDir, AcceptedFile)
	tmp, err := os.CreateTemp(stateDir, AcceptedFile+".seed-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(v + "\n")
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	// A link fails when the record exists: a concurrent seed or accept won.
	if err := os.Link(tmp.Name(), p); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

func (s *Syncer) acceptedRecord() (model.CommitID, bool) {
	if s.Apply == nil {
		return "", false
	}
	return ReadAccepted(s.Apply.StateDir)
}

func (s *Syncer) accepted() model.CommitID {
	id, _ := s.acceptedRecord()
	return id
}

// startBase is the base a fetched source is judged from: the record, else
// preFetch (origin/main before the first fetch), which it records. A
// machine that refused a source before the record existed (an open
// key-log or manifest-guard hold) records local main instead: its
// origin/main may already hold the refused source, while local main moved
// only by its own commits and by sources it accepted.
func (s *Syncer) startBase(ctx context.Context, preFetch model.CommitID) (model.CommitID, error) {
	if id, ok := s.acceptedRecord(); ok {
		return id, nil
	}
	st, err := s.Apply.State.Load()
	if err != nil {
		return "", err
	}
	start, err := SeedStart(ctx, s.Store, s.Apply.StateDir, st.Holds, preFetch)
	if err != nil {
		return "", err
	}
	if id, ok := s.acceptedRecord(); ok {
		return id, nil
	}
	return start, nil
}

// SeedStart records the start of a machine with no AcceptedFile record
// before a fetch moves origin/main: preFetch (origin/main now), or local
// main when holds include an open key-log or manifest-guard hold. It
// returns the start it chose. Every fetch path calls it first.
func SeedStart(ctx context.Context, st store.Store, stateDir string, holds []model.Hold, preFetch model.CommitID) (model.CommitID, error) {
	if id, ok := ReadAccepted(stateDir); ok {
		return id, nil
	}
	start := preFetch
	for _, h := range holds {
		if refusalHold(h) {
			var err error
			if start, err = st.ResolveRef(ctx, store.RefMain); err != nil {
				return "", err
			}
			break
		}
	}
	if err := SeedAccepted(stateDir, start); err != nil {
		return "", fmt.Errorf("record the accepted remote: %w", err)
	}
	return start, nil
}

// refusalHold reports a hold of a refused fetch.
func refusalHold(h model.Hold) bool {
	if h.Target != "" || h.Reason != model.HoldProtected {
		return false
	}
	switch h.Task {
	case HoldTaskKeyLog, HoldTaskGuard, HoldTaskRewrite, HoldTaskReroot:
		return true
	}
	return false
}

func (s *Syncer) setAccepted(id model.CommitID) error {
	if s.Apply.StateDir == "" || id == "" {
		return nil
	}
	if cur, ok := s.acceptedRecord(); ok && cur == id {
		return nil
	}
	p := filepath.Join(s.Apply.StateDir, AcceptedFile)
	if err := os.WriteFile(p+".tmp", []byte(string(id)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}
