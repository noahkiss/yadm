package sync

import (
	"context"
	"fmt"
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

// Tasks of the holds a refused fetch raises. They have no target.
const (
	HoldTaskKeyLog = "key-log"        // a fetched commit rewrote or deleted a key-log entry
	HoldTaskGuard  = "manifest-guard" // RemoteGuard refused the fetched source
)

// Alert kinds.
const (
	AlertNonMember     = "non_member_enclave_commit"
	AlertKeyLogRewrite = "key_log_rewrite"
	AlertGuardRefused  = "remote_refused"
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
}

// checkRemote runs the key-log rule and the RemoteGuard on a fetched source.
func (s *Syncer) checkRemote(ctx context.Context, base, local, remote model.CommitID, to *apply.Snapshot) (*refusal, error) {
	if remote == "" || remote == local {
		return nil, nil
	}
	if base == "" {
		base = local
	}
	v, err := s.keyLogViolations(ctx, base, remote)
	if err != nil {
		return nil, err
	}
	if len(v) > 0 {
		return &refusal{task: HoldTaskKeyLog, kind: AlertKeyLogRewrite,
			detail: "key-log entries are append-only; the fetched source was not applied: " + strings.Join(v, "; ")}, nil
	}
	if s.Guard != nil && local != "" && to != nil {
		from, err := s.load(ctx, local)
		if err != nil {
			return nil, err
		}
		ok, detail, err := s.Guard.Allow(ctx, from, to)
		if err != nil {
			return nil, err
		}
		if !ok {
			return &refusal{task: HoldTaskGuard, kind: AlertGuardRefused,
				detail: "the fetched source weakens protection and is not allowed here: " + detail}, nil
		}
	}
	return nil, nil
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
		if h.Target == "" && h.Reason == model.HoldProtected && (h.Task == HoldTaskKeyLog || h.Task == HoldTaskGuard) {
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
		h.Next = []string{"yadm hold show " + h.ID, "yadm review list"}
		putHold(st, h)
	} else if len(st.Holds) == n {
		return false, nil
	}
	return fresh, s.Apply.State.Save(st)
}

// AcceptedFile records the last fetched remote main this machine accepted.
// The key-log rule compares each new fetch with it, so a refused fetch stays
// refused on the next run.
const AcceptedFile = "remote-accepted"

func (s *Syncer) accepted() model.CommitID {
	if s.Apply.StateDir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(s.Apply.StateDir, AcceptedFile))
	if err != nil {
		return ""
	}
	return model.CommitID(strings.TrimSpace(string(b)))
}

func (s *Syncer) setAccepted(id model.CommitID) error {
	if s.Apply.StateDir == "" || id == "" || id == s.accepted() {
		return nil
	}
	p := filepath.Join(s.Apply.StateDir, AcceptedFile)
	if err := os.WriteFile(p+".tmp", []byte(string(id)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}
