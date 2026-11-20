package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/secrecytest"
)

// SoakSpec describes a multi-machine soak on an already set-up world.
type SoakSpec struct {
	Machines []*Machine
	// Members are the machines in the enclave; the others must never see
	// enclave plaintext.
	Members map[string]bool
	Enclave string
	// Shared are plain text targets every machine has.
	Shared []string
	// Union is a Brewfile-like list every machine appends to.
	Union string
	// JSON is a JSON target with a drop rule for its "volatile" key.
	JSON string
	// Sealed are whole-file enclave targets the members have.
	Sealed []string
	// Root is a shared owned root; new files go there.
	Root string
	// Types is the comma-separated type list a retag of a new root file
	// names, so it reaches every machine.
	Types  string
	Rounds int
	Seed   int64
	// Extra canaries planted before the soak (setup secrets).
	Canaries []secrecytest.Canary
}

type soakEdit struct {
	Round   int
	Machine string
	Target  string
	Token   string
	Kind    string // text, union, json, sealed, newfile
	Via     string // auto, commit, hook
}

// SoakReport is the outcome, in counts and paths.
type SoakReport struct {
	Seed           int64
	Rounds         int
	Edits          int
	ByVia          map[string]int
	Lost           []string // "round machine target via"
	Unexplained    []string // "machine reason target"
	Explained      map[string]int
	Resolved       int
	Diverged       []string // "round machine"
	CommandErrors  []string
	Leaks          []string
	VolatileLeaks  int
	NewFilesStuck  int            // new owned-root files never delivered to a peer
	NewFiles       map[string]int // new files by decision (commit, retag)
	StuckBy        map[string]int
	ConcurrentRuns int
	Duration       time.Duration
}

func (r SoakReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "seed=%d rounds=%d edits=%d via=%v concurrent=%d resolved=%d explained=%v lost=%d unexplained=%d diverged=%d cmd_errors=%d leaks=%d volatile_leaks=%d newfiles=%v stuck=%v dur=%s",
		r.Seed, r.Rounds, r.Edits, r.ByVia, r.ConcurrentRuns, r.Resolved, r.Explained, len(r.Lost), len(r.Unexplained), len(r.Diverged), len(r.CommandErrors), len(r.Leaks), r.VolatileLeaks, r.NewFiles, r.StuckBy, r.Duration.Round(time.Second))
	return b.String()
}

// Soak runs the rounds and returns the report. It fails the test on lost
// edits, unexplained holds, divergence, leaks and command errors.
func Soak(t *testing.T, w *World, s SoakSpec) SoakReport {
	t.Helper()
	start := time.Now()
	rng := rand.New(rand.NewSource(s.Seed))
	t.Logf("soak seed %d (rerun with YADM_SOAK_SEED=%d)", s.Seed, s.Seed)
	rep := SoakReport{Seed: s.Seed, Rounds: s.Rounds, ByVia: map[string]int{}, Explained: map[string]int{}, NewFiles: map[string]int{}, StuckBy: map[string]int{}}
	var edits []soakEdit
	canaries := append([]secrecytest.Canary{}, s.Canaries...)
	byName := map[string]*Machine{}
	for _, m := range s.Machines {
		byName[m.Name] = m
	}
	receives := func(m *Machine, target string) bool {
		for _, x := range s.Sealed {
			if x == target {
				return s.Members[m.Name]
			}
		}
		return true
	}
	cmdErr := func(round int, m *Machine, r Result) {
		if r.Code != 0 && r.Code != 3 {
			rep.CommandErrors = append(rep.CommandErrors, fmt.Sprintf("round %d %s: yadm %s: %s", round, m.Name, strings.Join(r.Args, " "), r.Err()))
		}
	}
	var syncDur time.Duration
	var syncN int
	var syncMax time.Duration
	syncOne := func(round int, m *Machine) {
		r := m.Run("sync", "--auto", "--full")
		syncN++
		syncDur += r.Dur
		if r.Dur > syncMax {
			syncMax = r.Dur
		}
		cmdErr(round, m, r)
	}
	pending := map[string][]soakEdit{} // machine -> edits awaiting a sync --auto

	for round := 1; round <= s.Rounds; round++ {
		order := rng.Perm(len(s.Machines))
		for _, i := range order {
			m := s.Machines[i]
			n := 1 + rng.Intn(3)
			for k := 0; k < n; k++ {
				e := soakEdit{Round: round, Machine: m.Name, Token: fmt.Sprintf("e2e-%d-%s-%d", round, m.Name, k)}
				kinds := []string{"text", "union", "json", "volatile"}
				if s.Members[m.Name] && len(s.Sealed) > 0 {
					kinds = append(kinds, "sealed", "sealed")
				}
				if s.Root != "" && rng.Intn(4) == 0 {
					kinds = append(kinds, "newfile")
				}
				e.Kind = kinds[rng.Intn(len(kinds))]
				vias := []string{"auto", "commit", "hook"}
				e.Via = vias[rng.Intn(len(vias))]
				switch e.Kind {
				case "text":
					e.Target = s.Shared[rng.Intn(len(s.Shared))]
					appendLine(m, e.Target, "# "+e.Token)
				case "union":
					e.Target = s.Union
					appendLine(m, e.Target, "brew \""+e.Token+"\"")
				case "json", "volatile":
					e.Target = s.JSON
					key := ""
					if e.Kind == "json" {
						key = e.Token
					}
					editJSON(t, m, e.Target, key, rng.Int63())
				case "sealed":
					c := secrecytest.NewCanary(t, s.Enclave+"-soak")
					canaries = append(canaries, c)
					e.Token = c.String()
					e.Target = s.Sealed[rng.Intn(len(s.Sealed))]
					appendLine(m, e.Target, e.Token)
				case "newfile":
					e.Target = s.Root + "/f-" + e.Token
					// A new file waits for a decision by design: share it
					// with a named commit, or track it with retag.
					e.Via = "commit"
					if s.Types != "" && rng.Intn(2) == 0 {
						e.Via = "retag"
					}
					m.WriteHome(e.Target, []byte(e.Token+"\n"), 0)
				}
				if e.Via == "auto" {
					ts := time.Now().Add(-10 * time.Minute)
					_ = os.Chtimes(filepath.Join(m.Home, filepath.FromSlash(e.Target)), ts, ts)
				}
				if e.Kind != "volatile" {
					rep.ByVia[e.Kind+"/"+e.Via]++
				}
				switch e.Via {
				case "commit":
					cmdErr(round, m, m.Run("commit", e.Target))
				case "retag":
					cmdErr(round, m, m.Run("retag", e.Target, s.Types))
				case "hook":
					payload, _ := json.Marshal(map[string]any{
						"session_id": fmt.Sprintf("soak-%d-%s", s.Seed, m.Name), "tool_name": "Edit", "cwd": m.Home,
						"hook_event_name": "PostToolUse",
						"tool_input":      map[string]string{"file_path": filepath.Join(m.Home, filepath.FromSlash(e.Target))},
					})
					r := m.RunIn(payload, "hook", "post-edit")
					if r.Code == 1 {
						rep.CommandErrors = append(rep.CommandErrors, fmt.Sprintf("round %d %s: hook post-edit %s: exit 1: %s", round, m.Name, e.Target, clip(r.Stderr, 200)))
					}
				default:
					pending[m.Name] = append(pending[m.Name], e)
				}
				if e.Kind != "volatile" {
					edits = append(edits, e)
				}
				if os.Getenv("YADM_SOAK_TRACE") != "" {
					t.Logf("  r%d %s %s %s via %s", round, m.Name, e.Kind, e.Target, e.Via)
				}
			}
		}
		// Sync in random order, sometimes two at once.
		order = rng.Perm(len(s.Machines))
		for i := 0; i < len(order); i++ {
			if i+1 < len(order) && rng.Intn(4) == 0 {
				a, b := s.Machines[order[i]], s.Machines[order[i+1]]
				var wg sync.WaitGroup
				var ra, rb Result
				wg.Add(2)
				go func() { defer wg.Done(); ra = a.Run("sync", "--auto", "--full") }()
				go func() { defer wg.Done(); rb = b.Run("sync", "--auto", "--full") }()
				wg.Wait()
				cmdErr(round, a, ra)
				cmdErr(round, b, rb)
				rep.ConcurrentRuns++
				i++
				continue
			}
			syncOne(round, s.Machines[order[i]])
		}
		// Settle: resolve conflicts with a union of both sides, then sync
		// every machine twice in a fixed order.
		for pass := 0; pass < 2; pass++ {
			for _, m := range s.Machines {
				// A conflict comes with a drifted hold on the same target;
				// resolving the conflict settles both.
				conflicted := map[string]bool{}
				for _, h := range m.Holds() {
					if h.Reason == "conflict" {
						conflicted[h.Target] = true
						rep.Explained["conflict"]++
						if resolveUnion(t, m, h, edits, s) {
							rep.Resolved++
						}
					}
				}
				for _, h := range m.Holds() {
					switch {
					case h.Reason == "drifted" && conflicted[h.Target]:
						rep.Unexplained = append(rep.Unexplained, fmt.Sprintf("round %d %s drifted-after-resolve %s (%s)", round, m.Name, h.Target, clip(h.Detail, 160)))
					case h.Reason == "conflict":
						rep.Unexplained = append(rep.Unexplained, fmt.Sprintf("round %d %s conflict-not-resolved %s", round, m.Name, h.Target))
					case h.Reason == "protected" && strings.HasPrefix(h.Target, s.Root+"/"):
						rep.Explained["protected-newfile"]++
					default:
						rep.Unexplained = append(rep.Unexplained, fmt.Sprintf("round %d %s %s %s (%s)", round, m.Name, h.Reason, h.Target, clip(h.Detail, 160)))
					}
				}
			}
			for _, m := range s.Machines {
				syncOne(round, m)
			}
		}
		pending = map[string][]soakEdit{}
		// Convergence.
		rm := w.RemoteMain()
		for _, m := range s.Machines {
			if m.Main() != rm {
				rep.Diverged = append(rep.Diverged, fmt.Sprintf("round %d %s", round, m.Name))
			}
		}
		// Lost edits: every receiving machine holds the token, unless a hold
		// names the target somewhere.
		held := map[string]bool{}
		for _, m := range s.Machines {
			for _, h := range m.Holds() {
				held[h.Target] = true
			}
		}
		lostNow := 0
		for _, e := range edits {
			if e.Kind == "newfile" {
				continue
			}
			for _, m := range s.Machines {
				if !receives(m, e.Target) {
					continue
				}
				b, _ := m.ReadHome(e.Target)
				if !bytes.Contains(b, []byte(e.Token)) && !held[e.Target] {
					lostNow++
					key := fmt.Sprintf("edit r%d %s %s via %s, missing on %s", e.Round, e.Machine, e.Target, e.Via, m.Name)
					if !contains(rep.Lost, key) {
						rep.Lost = append(rep.Lost, key)
					}
				}
			}
		}
		if round%10 == 0 || round == s.Rounds {
			rep.Leaks = append(rep.Leaks, leakScan(w, s, canaries)...)
			if b, err := w.GitErr(w.Remote, nil, "show", "main:files/"+s.JSON); err == nil && strings.Contains(b, "volatile") {
				rep.VolatileLeaks++
			}
		}
		if syncN > 0 {
			t.Logf("round %d: %d syncs, mean %s, max %s", round, syncN, (syncDur / time.Duration(syncN)).Round(time.Millisecond), syncMax.Round(time.Millisecond))
		}
		t.Logf("round %d: edits so far %d, lost now %d, diverged %d, unexplained %d, cmd errors %d", round, len(edits), lostNow, len(rep.Diverged), len(rep.Unexplained), len(rep.CommandErrors))
	}
	// New files: shared or retagged on their origin; delivered to a peer?
	for _, e := range edits {
		if e.Kind != "newfile" {
			continue
		}
		for _, m := range s.Machines {
			if m.Name == e.Machine {
				continue
			}
			if _, ok := m.ReadHome(e.Target); !ok {
				rep.NewFilesStuck++
				rep.StuckBy[e.Via]++
				break
			}
		}
		rep.NewFiles[e.Via]++
	}
	rep.Edits = len(edits)
	rep.Duration = time.Since(start)
	return rep
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func appendLine(m *Machine, target, line string) {
	b, _ := m.ReadHome(target)
	if len(b) > 0 && b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	b = append(b, []byte(line+"\n")...)
	m.WriteHome(target, b, 0)
}

// editJSON sets key (when not empty) and rewrites the app-owned "volatile"
// object, as an app would.
func editJSON(t *testing.T, m *Machine, target, key string, v int64) {
	b, _ := m.ReadHome(target)
	obj := map[string]any{}
	if len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, &obj); err != nil {
			t.Errorf("%s: %s is not JSON any more", m.Name, target)
			obj = map[string]any{}
		}
	}
	if key != "" {
		obj[key] = true
	}
	obj["volatile"] = map[string]any{"window": strconv.FormatInt(v, 36)}
	out, _ := json.MarshalIndent(obj, "", "  ")
	m.WriteHome(target, append(out, '\n'), 0)
}

// resolveUnion settles a conflict hold by writing the union of the target's
// lines (or JSON keys) and every token the soak wrote to that target, then
// `hold resolve --take <file>`.
func resolveUnion(t *testing.T, m *Machine, h Hold, edits []soakEdit, s SoakSpec) bool {
	cur, _ := m.ReadHome(h.Target)
	var out []byte
	if h.Target == s.JSON {
		obj := map[string]any{}
		_ = json.Unmarshal(cur, &obj)
		for _, e := range edits {
			if e.Target == h.Target && e.Kind == "json" {
				obj[e.Token] = true
			}
		}
		out, _ = json.MarshalIndent(obj, "", "  ")
		out = append(out, '\n')
	} else {
		have := string(cur)
		out = append(out, cur...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		for _, e := range edits {
			if e.Target != h.Target || strings.Contains(have, e.Token) {
				continue
			}
			line := "# " + e.Token
			switch e.Kind {
			case "union":
				line = "brew \"" + e.Token + "\""
			case "sealed":
				line = e.Token
			}
			out = append(out, []byte(line+"\n")...)
		}
	}
	f := filepath.Join(m.Root, "resolve-"+h.ID[:12])
	if err := os.WriteFile(f, out, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f)
	r := m.Run("hold", "resolve", h.ID, "--take", f)
	if r.Code != 0 && r.Code != 3 {
		t.Logf("%s: resolve %s %s: %s", m.Name, h.Reason, h.Target, r.Err())
		return false
	}
	return true
}

// leakScan checks every repository and every non-member's whole machine
// directory for enclave canaries.
func leakScan(w *World, s SoakSpec, canaries []secrecytest.Canary) []string {
	var out []string
	add := func(where string, fs []secrecytest.Finding, err error) {
		if err != nil {
			out = append(out, where+": scan error: "+clip(err.Error(), 200))
		}
		for _, f := range fs {
			out = append(out, where+": "+f.Where)
		}
	}
	fs, err := secrecytest.ScanRepo(w.Remote, canaries...)
	add("remote", fs, err)
	for _, m := range s.Machines {
		fs, err := secrecytest.ScanRepo(m.Source, canaries...)
		add(m.Name+" source repo", fs, err)
		if !s.Members[m.Name] {
			fs, err := secrecytest.ScanTree(m.Root, canaries...)
			add(m.Name+" tree", fs, err)
		}
	}
	sort.Strings(out)
	return out
}

func soakRounds(def int) int {
	if v, err := strconv.Atoi(os.Getenv("YADM_SOAK_ROUNDS")); err == nil && v > 0 {
		return v
	}
	return def
}

func soakSeed() int64 {
	if v, err := strconv.ParseInt(os.Getenv("YADM_SOAK_SEED"), 10, 64); err == nil {
		return v
	}
	return time.Now().UnixNano()
}
