package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/pause"
	"github.com/noahkiss/yadm/internal/reroot"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
)

const rerootLong = `Reroot replaces the history of the shared repository with a rewritten one,
for example to purge old plaintext with git filter-repo, or to start over
from one squashed commit. Every machine switches to the new history on its
next sync; none needs a new clone.

A rewrite is accepted only when a signed re-root record announces it. A
machine that finds the remote main rewritten without one refuses it, and
"yadm check" reports it. The record must be signed by a member of a key log
the receiving machine pinned; an unverified record is refused.

The procedure:
  1. Decide which machines keep a backup of the old history: set
     reroot_keep in fleet.toml ([types.<name>] reroot_keep = 3), commit it
     and let every machine sync. Without it no machine backs up.
  2. Review what is waiting (yadm review list). The re-root marks the new
     head reviewed for every scope; it refuses while commits are unreviewed
     unless --fold-unreviewed is given.
  3. Pause the fleet: yadm pause --for 1h --reason "re-root". (reroot starts
     a 30m pause by itself when this machine runs none.)
  4. Sync this machine (yadm sync), so local main is the remote main.
  5. Prepare the rewritten history in the source clone (yadm where shows
     it). Leave keys/ untouched: a rewrite that changes any key-log file is
     refused. Either
       - squash: yadm git commit-tree -m "new root" "main^{tree}"
         prints the id of one commit with today's tree and no parent; or
       - purge: run git filter-repo on a copy of the clone, then fetch its
         main into the source clone as a branch.
  6. Run: yadm reroot --new-head <commit-or-ref> --reason "<why>"
     It checks the rewrite, signs the record, and pushes the new main (with
     a lease on the old one), the reviewed refs and the record in one
     atomic push. Then it switches this machine and waits for the others.
  7. Wait until every machine switched (yadm fleet list shows "rerooted").
     A machine that is offline switches when it next syncs.
  8. Resume: yadm resume.

On each machine the switch backs up the old history first when its types
set reroot_keep in fleet.toml ([types.<name>] reroot_keep = 3): a git bundle
in $XDG_DATA_HOME/yadm/backups, newest reroot_keep kept (yadm backups).
A machine with local commits that the old history lacks does not switch:
it holds them, and "yadm reroot carry" replays them onto the new history.
Files in $HOME change only where the new tree differs from the old one.`

// registerReroot adds reroot and backups.
func (a *app) registerReroot(root *cobra.Command) {
	rr := a.leaf(root, "reroot", "Replace the shared history with a rewritten one, announced by a signed record", a.cmdReroot)
	rr.Long = rerootLong
	rr.Args = cobra.NoArgs
	rr.Flags().String("new-head", "", "the commit or ref in the source clone that holds the rewritten history (required)")
	rr.Flags().String("reason", "", "why, shown to every machine (plain text: every machine can read it)")
	rr.Flags().Bool("fold-unreviewed", false, "re-root even though some commits are unreviewed; the new head is marked reviewed")
	rr.Flags().Duration("for", pause.DefaultFor, "length of the fleet pause reroot starts when this machine runs none")
	rr.Flags().Duration("wait", pauseDefaultWait, "how long to wait for other machines to switch")
	rr.Flags().Bool("no-wait", false, "return as soon as the re-root is pushed")
	cy := a.leaf(rr, "carry", "Switch to a re-rooted history, replaying this machine's unpushed commits onto it", a.cmdRerootCarry)
	cy.Long = `Carry switches this machine to a re-rooted history although it holds local
commits that the old history lacks. It keeps them as they were on
refs/yadm/carry/<re-root id>, replays them onto the new history as sync
replays any local commit (a conflict becomes a hold), switches, and pushes.
Without carry such a machine holds the re-root and changes nothing.`
	cy.Args = cobra.NoArgs

	bk := a.group(root, "backups", "Backups of old histories that re-roots replaced")
	bl := a.leaf(bk, "list", "List re-root backup bundles, newest first", a.cmdBackupsList)
	bl.Args = cobra.NoArgs
	bp := a.leaf(bk, "prune", "Delete all but the newest re-root backup bundles", a.cmdBackupsPrune)
	bp.Args = cobra.NoArgs
	bp.Flags().Int("keep", 0, "bundles to keep (default: reroot_keep of this machine's types, or 3)")
}

// rerootData is the data of `yadm reroot`.
type rerootData struct {
	ID         string              `json:"id"`
	OldHead    model.CommitID      `json:"old_head"`
	NewHead    model.CommitID      `json:"new_head"`
	Reason     string              `json:"reason,omitempty"`
	PauseID    string              `json:"pause_id"`
	PauseStart bool                `json:"pause_started,omitempty"`
	Pushed     bool                `json:"pushed"`
	Backup     string              `json:"backup,omitempty"`
	Unreviewed map[model.Scope]int `json:"unreviewed,omitempty"`
	Switched   []model.MachineID   `json:"switched"`
	Waiting    []model.MachineID   `json:"waiting"`
	Held       []peerIgnored       `json:"held,omitempty"`
}

// rerootConfirm reads peers' status records: who switched to re-root id,
// who holds it, and who has not answered.
func (m *machineEnv) rerootConfirm(ctx context.Context, id string) (sw, waiting []model.MachineID, held []peerIgnored) {
	sw, waiting = []model.MachineID{}, []model.MachineID{}
	all, _ := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	ids := make([]model.MachineID, 0)
	for p := range m.peers() {
		ids = append(ids, p)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, p := range ids {
		st, ok := all[p]
		switch {
		case ok && st.Reroot == id:
			sw = append(sw, p)
		case ok && st.RerootHeld != "":
			held = append(held, peerIgnored{Machine: p, Why: st.RerootHeld})
		default:
			waiting = append(waiting, p)
		}
	}
	return sw, waiting, held
}

func (a *app) cmdReroot(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	newHead, _ := cmd.Flags().GetString("new-head")
	reason, _ := cmd.Flags().GetString("reason")
	fold, _ := cmd.Flags().GetBool("fold-unreviewed")
	forD, _ := cmd.Flags().GetDuration("for")
	wait, _ := cmd.Flags().GetDuration("wait")
	noWait, _ := cmd.Flags().GetBool("no-wait")
	if newHead == "" {
		return result{next: []string{"yadm reroot --help"}}, usagef("--new-head is required: the commit that holds the rewritten history")
	}
	if strings.HasPrefix(newHead, "-") || model.HasControl(newHead) {
		return result{}, usagef("--new-head %q is not a commit or ref", newHead)
	}
	if len(reason) > 200 || model.HasControl(reason) {
		return result{}, usagef("--reason must be one line of at most 200 bytes")
	}
	if forD <= 0 {
		return result{}, usagef("--for must be positive")
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	if _, err := m.load(ctx); err != nil {
		return result{}, err
	}
	self := m.local.Machine
	if m.id == nil {
		return result{}, fmt.Errorf("%w: this machine has no signing identity", ErrRefused)
	}
	s := m.syncer(a.version)
	if err := s.FetchRefs(ctx); err != nil {
		return result{next: []string{"yadm sync"}}, fmt.Errorf("reroot needs the remote: %w", err)
	}
	v, trust, err := s.EvalPause(ctx)
	if err != nil {
		return lockedResult(err), err
	}
	if h := v.Holding(self); h != nil {
		return heldResult(*h), m.heldErr(*h)
	}
	req := sync.RerootRequest{NewHead: newHead, Reason: reason, Signer: m.id, FoldUnreviewed: fold}
	// Refuse before a pause starts.
	if pre, err := s.RerootCheck(ctx, req); err != nil {
		if errors.Is(err, sync.ErrLocked) {
			return lockedResult(err), err
		}
		return result{data: map[string]any{"unreviewed": pre.Unreviewed}, next: []string{"yadm reroot --help"}}, err
	}
	d := rerootData{}
	for i := range v.Active {
		if v.Active[i].Initiator == self {
			d.PauseID = v.Active[i].ID
		}
	}
	if d.PauseID == "" {
		// The switch runs inside a fleet pause this machine started.
		if !trust.Can(self, m.id.Member().SignKey) {
			return result{next: []string{"yadm fleet list"}}, errNoSigner(self, trust)
		}
		now := hooks.now().UTC().Truncate(time.Second)
		if forD > pause.MaxSpan {
			forD = pause.MaxSpan
		}
		id, err := pause.NewID()
		if err != nil {
			return result{}, err
		}
		why := "re-root"
		if reason != "" {
			why = "re-root: " + reason
		}
		if len(why) > 200 {
			why = why[:200]
		}
		rec, err := pause.Sign(pause.Record{Op: pause.OpPause, ID: id, Initiator: self, Reason: why, Created: now, Deadline: now.Add(forD)}, m.id)
		if err != nil {
			return result{}, err
		}
		pushed, err := s.PublishPause(ctx, []pause.Record{rec})
		if err != nil || !pushed {
			if err == nil {
				err = errors.New("the remote pause ref moved")
			}
			return lockedResult(err), fmt.Errorf("reroot: start the fleet pause: %w", err)
		}
		if _, _, err := s.EvalPause(ctx); err != nil {
			return lockedResult(err), err
		}
		s.NudgePeers(ctx)
		d.PauseID, d.PauseStart = id, true
	}

	req.PauseID = d.PauseID
	res, err := s.Reroot(ctx, req)
	d.ID, d.OldHead, d.NewHead, d.Reason, d.Pushed, d.Unreviewed = res.Record.ID, res.Record.OldHead, res.Record.NewHead, res.Record.Reason, res.Pushed, res.Unreviewed
	if err != nil {
		next := []string{"yadm reroot --help"}
		if d.PauseStart {
			next = append(next, "yadm resume")
		}
		if d.Pushed {
			next = []string{"yadm sync", "yadm status"}
		}
		if errors.Is(err, sync.ErrLocked) {
			return lockedResult(err), err
		}
		return result{data: d, next: next}, err
	}
	if l := reroot.Load(m.paths.State).Last(); l != nil && l.ID == d.ID {
		d.Backup = l.Backup
	}
	d.Switched, d.Waiting, d.Held = m.rerootConfirm(ctx, d.ID)
	if !noWait && wait > 0 {
		end := hooks.now().Add(wait)
		last := ""
		for len(d.Waiting) > 0 {
			if !a.json {
				line := fmt.Sprintf("waiting… %d/%d switched (%s not yet)", len(d.Switched), len(d.Switched)+len(d.Waiting)+len(d.Held), m.names(d.Waiting))
				if line != last {
					fmt.Fprintln(a.stderr, line)
					last = line
				}
			}
			if !hooks.now().Before(end) {
				break
			}
			if err := hooks.sleep(ctx, pausePoll); err != nil {
				break
			}
			_ = s.FetchRefs(ctx)
			d.Switched, d.Waiting, d.Held = m.rerootConfirm(ctx, d.ID)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "re-root %s pushed: main %s -> %s", d.ID, short(d.OldHead), short(d.NewHead))
	if d.Reason != "" {
		fmt.Fprintf(&b, " (%s)", d.Reason)
	}
	if d.PauseStart {
		fmt.Fprintf(&b, "\nstarted fleet pause %s", d.PauseID)
	}
	if d.Backup != "" {
		fmt.Fprintf(&b, "\nbackup of the old history: %s", d.Backup)
	} else {
		b.WriteString("\nno backup on this machine: reroot_keep is 0 for its types")
	}
	total := len(d.Switched) + len(d.Waiting) + len(d.Held)
	fmt.Fprintf(&b, "\n%d/%d other machines switched", len(d.Switched), total)
	if len(d.Waiting) > 0 {
		fmt.Fprintf(&b, "; %s not yet (each switches on its next sync)", m.names(d.Waiting))
	}
	for _, x := range d.Held {
		fmt.Fprintf(&b, "\n%s holds it (%s): see yadm check there", m.names([]model.MachineID{x.Machine}), x.Why)
	}
	b.WriteString("\nwhen every machine has switched: yadm resume")
	return result{data: d, text: b.String(), next: []string{"yadm fleet list", "yadm resume"}}, nil
}

func (a *app) cmdRerootCarry(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	if res, err := m.refuseHeld(ctx); err != nil {
		return res, err
	}
	before := reroot.Load(m.paths.State).Last()
	rep, err := m.syncer(a.version).Run(ctx, sync.Options{Push: true, Carry: true})
	if err != nil {
		return lockedResult(err), err
	}
	after := reroot.Load(m.paths.State).Last()
	if after == nil || (before != nil && before.ID == after.ID) {
		return result{data: rep, next: []string{"yadm check", "yadm status"}, text: "no re-root to carry onto: this machine has nothing held"}, attention(rep.Holds)
	}
	text := fmt.Sprintf("switched to re-root %s; the commits as they were are on %s", after.ID, after.Carried)
	if after.Carried == "" {
		text = fmt.Sprintf("switched to re-root %s; there was nothing to carry", after.ID)
	}
	return result{data: map[string]any{"reroot": after, "sync": rep}, text: text, next: []string{"yadm status"}}, attention(rep.Holds)
}

// backupKeep is how many bundles this machine keeps.
func (m *machineEnv) backupKeep() int {
	if m.snap != nil && m.snap.Fleet != nil {
		if k := m.snap.Fleet.RerootKeep(m.local.Machine); k > 0 {
			return k
		}
	}
	return reroot.DefaultKeep
}

func (a *app) cmdBackupsList(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	_, _ = m.load(ctx)
	dir := reroot.BackupDir(m.paths.Source)
	bs, err := reroot.List(dir)
	if err != nil {
		return result{}, err
	}
	var b strings.Builder
	if len(bs) == 0 {
		fmt.Fprintf(&b, "no re-root backups in %s", dir)
	}
	for _, x := range bs {
		fmt.Fprintf(&b, "%s  old head %s  %d MB  %s\n", x.Taken.UTC().Format(time.RFC3339), x.OldHead, x.Size>>20, x.Path)
	}
	return result{data: map[string]any{"dir": dir, "keep": m.backupKeep(), "bundles": bs}, text: strings.TrimRight(b.String(), "\n")}, nil
}

func (a *app) cmdBackupsPrune(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	keep, _ := cmd.Flags().GetInt("keep")
	if cmd.Flags().Changed("keep") && keep < 1 {
		return result{}, usagef("--keep must be at least 1; delete the last bundle by hand")
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	_, _ = m.load(ctx)
	if keep == 0 {
		keep = m.backupKeep()
	}
	dir := reroot.BackupDir(m.paths.Source)
	gone, err := reroot.Prune(dir, keep)
	if err != nil {
		return result{}, err
	}
	if gone == nil {
		gone = []reroot.Bundle{}
	}
	return result{data: map[string]any{"dir": dir, "keep": keep, "deleted": gone}, text: fmt.Sprintf("kept the newest %d bundle(s), deleted %d", keep, len(gone))}, nil
}

// rerootView is the re-root part of `yadm status` and `yadm check`.
func (m *machineEnv) rerootView() (sync.RerootStatus, error) {
	hs, err := m.eng.Holds(context.Background())
	if err != nil {
		return sync.RerootStatus{}, err
	}
	return sync.ReadRerootStatus(m.paths.State, hs), nil
}

// rerootCheck is the reroot item of `yadm check`.
func (m *machineEnv) rerootCheck() checkItem {
	v, err := m.rerootView()
	switch {
	case err != nil:
		return checkItem{Name: "reroot", OK: false, Detail: err.Error()}
	case v.Held != nil:
		return checkItem{Name: "reroot", OK: false, Detail: v.Held.Detail}
	case v.Last != nil:
		d := fmt.Sprintf("last re-root %s switched %s", v.Last.ID, v.Last.At.UTC().Format(time.RFC3339))
		if v.Last.Backup != "" {
			d += ", backup " + v.Last.Backup
		}
		return checkItem{Name: "reroot", OK: true, Detail: d}
	}
	return checkItem{Name: "reroot", OK: true, Detail: "the remote main descends from the accepted one"}
}
