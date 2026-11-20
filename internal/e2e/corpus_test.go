package e2e

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/oracle"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// corpus is the shared input of the cutover rehearsal.
type corpus struct {
	orig     string // the legacy repository; read only
	goldens  []oracle.Golden
	commit   string
	outDir   string
	enclave  string   // the legacy class that is encrypted, used as the enclave name
	filters  []string // crypt filter names from the legacy config
	password string   // in memory; reaches only the import child's environment
	report   *bytes.Buffer
	seeded   map[string]map[string]fileStamp // machine -> stamps right after seeding
	// noApply makes setup move the source with plain git instead of sync,
	// so nothing is applied before adopt.
	noApply bool
}

// syncOrPull fetches main: sync, or with noApply a fast-forward pull of the
// source clone that applies nothing.
func (c *corpus) syncOrPull(m *Machine) Result {
	if c.noApply {
		r := m.Run("git", "pull", "-q", "--ff-only", "origin", "main")
		return r
	}
	return m.Run("sync")
}

// syncOrPush publishes local commits: sync, or with noApply a plain push.
func (c *corpus) syncOrPush(m *Machine) Result {
	if c.noApply {
		return m.Run("git", "push", "-q", "origin", "main")
	}
	return m.Run("sync")
}

func loadCorpus(t *testing.T) *corpus {
	if os.Getenv("YADM_CORPUS") != "1" {
		t.Skip("set YADM_CORPUS=1 to rehearse the cutover on a real repository")
	}
	c := &corpus{orig: os.Getenv("YADM_LEGACY_REPO"), report: &bytes.Buffer{}, seeded: map[string]map[string]fileStamp{}}
	if c.orig == "" {
		t.Fatal("YADM_LEGACY_REPO is not set")
	}
	odir := os.Getenv("YADM_ORACLE_DIR")
	if odir == "" {
		home, _ := os.UserHomeDir()
		odir = filepath.Join(home, ".local", "share", "yadm-oracle")
	}
	var err error
	if c.goldens, err = oracle.LoadGoldens(odir); err != nil || len(c.goldens) == 0 {
		t.Fatalf("no oracle records in %s: %v", odir, err)
	}
	c.commit = c.goldens[0].SourceCommit
	for _, g := range c.goldens {
		if g.SourceCommit != c.commit {
			t.Fatal("oracle records name different source commits")
		}
	}
	c.outDir = os.Getenv("YADM_CORPUS_OUT")
	if c.outDir == "" {
		c.outDir = t.TempDir()
	}
	// The enclave class: in every decrypting profile, in no other one.
	count := map[string]int{}
	nDec := 0
	for _, g := range c.goldens {
		if g.Profile.Decrypt {
			nDec++
			for _, cl := range g.Profile.Classes {
				count[strings.ToLower(cl)]++
			}
		}
	}
	for cl, n := range count {
		if n != nDec {
			continue
		}
		shared := false
		for _, g := range c.goldens {
			for _, x := range g.Profile.Classes {
				if !g.Profile.Decrypt && strings.EqualFold(x, cl) {
					shared = true
				}
			}
		}
		if !shared {
			c.enclave = cl
		}
	}
	if c.enclave == "" {
		t.Fatal("cannot tell which class is encrypted from the profiles")
	}
	return c
}

func (c *corpus) logf(t *testing.T, format string, args ...any) {
	t.Helper()
	line := fmt.Sprintf(format, args...)
	t.Log(line)
	c.report.WriteString(line + "\n")
}

func (c *corpus) save(t *testing.T, name string) {
	p := filepath.Join(c.outDir, name)
	if err := os.WriteFile(p, c.report.Bytes(), 0o600); err != nil {
		t.Error(err)
		return
	}
	t.Logf("report: %s", p)
}

// readLegacySecrets reads the transcrypt password and the crypt filter names
// from the legacy repository's config, in process.
func (c *corpus) readLegacySecrets(t *testing.T, w *World) {
	cfg := filepath.Join(c.orig, "config")
	if _, err := os.Stat(cfg); err != nil {
		cfg = filepath.Join(c.orig, ".git", "config")
	}
	pw, err := w.GitErr("", nil, "config", "--file", cfg, "--get", "transcrypt.password")
	if err != nil || pw == "" {
		t.Fatal("cannot read the transcrypt password from the legacy repository config")
	}
	c.password = pw
	c.filters = nil
	out, _ := w.GitErr("", nil, "config", "--file", cfg, "--get-regexp", `^filter\..*\.smudge$`)
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, " ")
		if ok && strings.Contains(v, "transcrypt") {
			c.filters = append(c.filters, strings.TrimSuffix(strings.TrimPrefix(k, "filter."), ".smudge"))
		}
	}
}

// types is every legacy class, which the import turns into a type.
func (c *corpus) types() []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range c.goldens {
		for _, cl := range g.Profile.Classes {
			if cl = strings.ToLower(cl); !seen[cl] {
				seen[cl] = true
				out = append(out, cl)
			}
		}
	}
	sort.Strings(out)
	return out
}

// machinesTSV writes the machines table from the profiles.
func (c *corpus) machinesTSV(t *testing.T, dir string) string {
	var b strings.Builder
	b.WriteString("name\thostname\tclasses\tos\tuser\n")
	for _, g := range c.goldens {
		p := g.Profile
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Hostname, strings.Join(p.Classes, ","), p.OS, p.User)
	}
	f := filepath.Join(dir, "machines.tsv")
	if err := os.WriteFile(f, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// importWorld clones the legacy repository at the golden commit, imports
// it through the binary on an "importer" machine and pushes the result to
// the world's remote. It returns the admin machine (the enclave's first
// member) and the entry-1 fingerprint.
func (c *corpus) importWorld(t *testing.T, w *World, seed bool) (*profileMachine, string, bool) {
	clone := filepath.Join(w.Root, "legacy")
	w.Git("", "clone", "-q", "--no-hardlinks", "--no-checkout", c.orig, clone)
	w.Git(clone, "update-ref", "--no-deref", "HEAD", c.commit)
	// The importing machine is the first decrypting profile; import
	// --machine keeps its id in the fleet.
	var ag oracle.Golden
	for _, g := range c.goldens {
		if g.Profile.Decrypt {
			ag = g
			break
		}
	}
	admin := w.NewMachine("p-"+sanitize(ag.Profile.Name), oracle.UserToken)
	if seed {
		seedHome(t, admin, ag)
		c.seeded[admin.Name] = stamps(admin.Home)
	}
	if r := admin.Init(ag.Profile.Name); r.Code != 0 {
		t.Fatalf("importer init: %s", r.Err())
	}
	c.logf(t, "importer: profile %s", ag.Profile.Name)
	args := []string{"import", clone, "--output", filepath.Join(w.Root, "out"),
		"--machines", c.machinesTSV(t, w.Root), "--password-env", "YADM_E2E_PW",
		"--class-enclave", c.enclave + "=" + c.enclave, "--machine", ag.Profile.Name, "--new-recovery", filepath.Join(w.Root, "recovery")}
	for _, f := range c.filters {
		args = append(args, "--crypt-filter", f)
	}
	if f := os.Getenv("YADM_IMPORT_FILTERS"); f != "" {
		args = append(args, "--filters", f)
	}
	start := time.Now()
	r := admin.RunEnv([]string{"YADM_E2E_PW=" + c.password}, nil, args...)
	var d struct {
		Commit   string `json:"commit"`
		Mappings []struct {
			Sealed bool `json:"sealed"`
		} `json:"mappings"`
		Machines int `json:"machines"`
		Problems []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"problems"`
		KeyLogs map[string]string `json:"key_logs"`
	}
	_ = r.Decode(&d)
	sealed := 0
	for _, m := range d.Mappings {
		if m.Sealed {
			sealed++
		}
	}
	c.logf(t, "import: exit %d in %s: %d mappings (%d sealed), %d machines, %d problems, filters %v",
		r.Code, time.Since(start).Round(time.Second), len(d.Mappings), sealed, d.Machines, len(d.Problems), c.filters)
	reasons := map[string][]string{}
	for _, p := range d.Problems {
		reasons[p.Reason] = append(reasons[p.Reason], p.Path)
	}
	for reason, paths := range reasons {
		sort.Strings(paths)
		if len(paths) > 5 {
			paths = append(paths[:5], fmt.Sprintf("… %d more", len(paths)-5))
		}
		c.logf(t, "  problem x%d: %s: %s", len(reasons[reason]), clip(reason, 200), strings.Join(paths, ", "))
	}
	pm := &profileMachine{Machine: admin, g: ag, member: true}
	if r.Code != 0 {
		t.Errorf("import failed: %s", r.Err())
		return pm, "", false
	}
	fp := d.KeyLogs[c.enclave]
	out := filepath.Join(w.Root, "out")
	w.Git(out, "push", "-q", w.Remote, "main")
	if r := c.syncOrPull(admin); r.Code != 0 && r.Code != 3 && !strings.Contains(r.Err(), "not in fleet.toml") {
		c.logf(t, "importer sync after push: %s", r.Err())
	} else if r.Code != 0 && r.Code != 3 && strings.Contains(r.Err(), "not in fleet.toml") {
		c.logf(t, "importer sync after push: %s", r.Err())
		// The importing identity signed key-log entry 1 but the import put
		// no fleet entry for it. A writer adds one by hand.
		pushSourceEdit(t, w, "add the importing machine", func(dir string) {
			f, _ := os.OpenFile(filepath.Join(dir, "fleet.toml"), os.O_APPEND|os.O_WRONLY, 0)
			fmt.Fprintf(f, "\n[machines.%s]\nname = \"importer\"\ntypes = [%q]\nos = %q\narch = %q\n", admin.ID, c.enclave, runtime.GOOS, runtime.GOARCH)
			_ = f.Close()
		})
		if r := c.syncOrPull(admin); r.Code != 0 && r.Code != 3 {
			c.logf(t, "importer sync after the fleet entry: %s", r.Err())
		} else {
			c.logf(t, "importer: synced after a hand-added fleet entry")
		}
	}
	if r := admin.Run("enclave", "join", c.enclave, "--expect", fp); r.Code != 0 && r.Code != 3 {
		c.logf(t, "importer join: %s", r.Err())
	} else {
		c.logf(t, "importer join: %s", r.Err())
	}
	// An identity made against an empty remote: after the first fetch its
	// source clone shows staged edits, and every later sync holds
	// source_dirty. Report and reset that temp clone so the rehearsal goes on.
	if st, _ := w.GitErr(admin.Source, nil, "status", "--porcelain"); st != "" {
		c.logf(t, "importer source clone dirty after first fetch: %d entries; reset by the harness", len(strings.Split(st, "\n")))
		w.Git(admin.Source, "reset", "-q", "--hard", "main")
	}
	if r := c.syncOrPull(admin); r.Code != 0 {
		c.logf(t, "importer sync: %s", r.Err())
	}
	return pm, fp, true
}

// profileMachine is one simulated profile.
type profileMachine struct {
	*Machine
	g      oracle.Golden
	member bool
}

// joinProfiles inits a machine per profile. Decrypting profiles join the
// enclave with --expect; the others never do. With seed set, each $HOME is
// first filled with the golden content (what stock yadm rendered).
func (c *corpus) joinProfiles(t *testing.T, w *World, pa *profileMachine, seed bool) []*profileMachine {
	admin := pa.Machine
	var out []*profileMachine
	for _, g := range c.goldens {
		if g.Profile.Name == pa.g.Profile.Name {
			out = append(out, pa)
			continue
		}
		m := &profileMachine{Machine: w.NewMachine("p-"+sanitize(g.Profile.Name), oracle.UserToken), g: g, member: g.Profile.Decrypt}
		if seed {
			seedHome(t, m.Machine, g)
			c.seeded[m.Name] = stamps(m.Home)
		}
		if r := m.Init(g.Profile.Name); r.Code != 0 && r.Code != 3 {
			t.Errorf("%s: init: %s", g.Profile.Name, r.Err())
			continue
		}
		if m.member {
			r := admin.Run("enclave", "add", g.Profile.Name, "--enclave", c.enclave, "--recipient", m.Recipient, "--sign-key", m.SignKey)
			var d struct {
				Fingerprint string `json:"fingerprint"`
			}
			if r.Code != 0 || r.Decode(&d) != nil {
				t.Errorf("%s: enclave add: %s", g.Profile.Name, r.Err())
			} else {
				ra := c.syncOrPush(admin)
				if ra.Code == 3 {
					for _, h := range admin.Holds() {
						c.logf(t, "importer hold after enclave add %s: %s %s %s (%s)", g.Profile.Name, h.Reason, h.Target, h.Task, clip(h.Detail, 200))
					}
				}
				rm := c.syncOrPull(m.Machine)
				if r := m.Run("enclave", "join", c.enclave, "--expect", d.Fingerprint); r.Code != 0 && r.Code != 3 {
					t.Errorf("%s: join: %s (admin sync: %s; member sync: %s; admin main %.8s, member main %.8s, remote %.8s)",
						g.Profile.Name, r.Err(), ra.Err(), rm.Err(), admin.Main(), m.Main(), w.RemoteMain())
				}
			}
		}
		out = append(out, m)
	}
	return out
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

// seedHome writes every golden target into $HOME with its golden mode,
// tokens replaced by this machine's home and user.
func seedHome(t *testing.T, m *Machine, g oracle.Golden) {
	pairs := [][2]string{{oracle.HomeToken, m.Home}, {oracle.UserToken, m.User}}
	for _, e := range g.Targets {
		if e.Kind == oracle.KindDangling {
			continue
		}
		b, err := g.Content(e.Path)
		if err != nil {
			continue
		}
		var mode uint32 = 0o644
		fmt.Sscanf(e.Mode, "%o", &mode)
		p := filepath.Join(m.Home, filepath.FromSlash(e.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, oracle.Denormalize(b, pairs), os.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, os.FileMode(mode))
	}
}

func replaceFor(m *Machine) [][2]string {
	r := [][2]string{}
	if real, err := filepath.EvalSymlinks(m.Home); err == nil && real != m.Home {
		r = append(r, [2]string{real, oracle.HomeToken})
	}
	return append(r, [2]string{m.Home, oracle.HomeToken})
}

func (c *corpus) compareProfiles(t *testing.T, label string, ms []*profileMachine) map[string]oracle.Comparison {
	res := map[string]oracle.Comparison{}
	for _, m := range ms {
		cmp, err := oracle.CompareHome(m.g, m.Home, replaceFor(m.Machine), nil)
		if err != nil {
			t.Errorf("%s: compare: %v", m.g.Profile.Name, err)
			continue
		}
		res[m.g.Profile.Name] = cmp
		c.logf(t, "%s %s (%s, member=%v): golden %d, match %d, mismatch %d %v",
			label, m.g.Profile.Name, m.g.Profile.OS, m.member, len(m.g.Targets), cmp.Matched, len(cmp.Mismatches), cmp.Counts())
		for _, x := range cmp.Mismatches {
			fmt.Fprintf(c.report, "  %s\t%s\t%s\t%s\n", m.g.Profile.Name, x.Reason, x.Path, x.Detail)
		}
	}
	return res
}

// secrecy checks non-member machines for content that only members' goldens
// hold, and the repositories for that content as blobs.
func (c *corpus) secrecy(t *testing.T, w *World, ms []*profileMachine, canaries []secrecytest.Canary) {
	var members, others []oracle.Golden
	for _, m := range ms {
		if m.member {
			members = append(members, m.g)
		} else {
			others = append(others, m.g)
		}
	}
	exclusive := oracle.ExclusiveHashes(members, others)
	c.logf(t, "secrecy: %d member-only content hashes", len(exclusive))
	scan := func(m *profileMachine) []string {
		var paths []string
		_ = filepath.WalkDir(m.Root, func(p string, d os.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			if _, ok := exclusive[oracle.HashFile(b, replaceFor(m.Machine))]; ok {
				rel, _ := filepath.Rel(w.Root, p)
				paths = append(paths, rel)
			}
			return nil
		})
		return paths
	}
	for _, m := range ms {
		if m.member {
			continue
		}
		paths := scan(m)
		c.logf(t, "secrecy %s: %d member-only files found on disk %v", m.g.Profile.Name, len(paths), firstN(paths, 10))
		if len(paths) > 0 {
			t.Errorf("%s: %d member-only files on a non-member", m.g.Profile.Name, len(paths))
		}
		if len(canaries) > 0 {
			fs, _ := secrecytest.ScanTree(m.Root, canaries...)
			c.logf(t, "secrecy %s: canary findings %d", m.g.Profile.Name, len(fs))
			if len(fs) > 0 {
				t.Errorf("%s: canary on a non-member", m.g.Profile.Name)
			}
		}
	}
	// Positive control: the same scan on a member must find its files.
	for _, m := range ms {
		if m.member {
			n := len(scan(m))
			c.logf(t, "secrecy control %s (member): %d member-only files found on disk (expect hundreds)", m.g.Profile.Name, n)
			if n == 0 {
				t.Errorf("secrecy control: the scan finds nothing on a member, so it proves nothing")
			}
			break
		}
	}
	// Member-only plaintext as git blobs in the remote.
	var contents []string
	for _, m := range ms {
		if !m.member {
			continue
		}
		for _, e := range m.g.Targets {
			if _, ok := exclusive[e.SHA256]; ok && !e.Normalized && !e.Template {
				contents = append(contents, filepath.Join(m.g.Dir, "content", filepath.FromSlash(e.Path)))
			}
		}
		break
	}
	ids, err := w.GitErr(w.Remote, []byte(strings.Join(contents, "\n")+"\n"), "hash-object", "--stdin-paths")
	if err != nil {
		t.Errorf("hash-object: %v", err)
		return
	}
	found, err := w.GitErr(w.Remote, []byte(ids+"\n"), "cat-file", "--batch-check")
	if err != nil {
		t.Errorf("cat-file: %v", err)
	}
	present := 0
	sc := bufio.NewScanner(strings.NewReader(found))
	for sc.Scan() {
		if !strings.HasSuffix(sc.Text(), " missing") {
			present++
		}
	}
	// Positive control: shared plain files are present as blobs.
	var shared []string
	for _, e := range others[0].Targets {
		if e.Kind == oracle.KindPlain && !e.Normalized && !e.Template && !e.Ciphertext && e.Size > 0 {
			shared = append(shared, filepath.Join(others[0].Dir, "content", filepath.FromSlash(e.Path)))
		}
		if len(shared) == 50 {
			break
		}
	}
	if sids, err := w.GitErr(w.Remote, []byte(strings.Join(shared, "\n")+"\n"), "hash-object", "--stdin-paths"); err == nil {
		sfound, _ := w.GitErr(w.Remote, []byte(sids+"\n"), "cat-file", "--batch-check")
		n := strings.Count(sfound, " blob ")
		c.logf(t, "secrecy control remote: %d of %d shared plain blobs present (expect all)", n, len(shared))
		if n == 0 {
			t.Errorf("secrecy control: the blob check finds no shared blob, so it proves nothing")
		}
	}
	// The legacy history stays reachable (import parent), and it held these
	// files as transcrypt ciphertext, so a plaintext blob means a leak.
	c.logf(t, "secrecy remote: %d of %d member-only plaintext blobs present", present, len(contents))
	if present > 0 {
		t.Errorf("%d member-only plaintext blobs in the remote", present)
	}
	if len(canaries) > 0 {
		fs, _ := secrecytest.ScanRepo(w.Remote, canaries...)
		c.logf(t, "secrecy remote: canary findings %d", len(fs))
		if len(fs) > 0 {
			t.Error("canary in the remote")
		}
	}
}

func firstN(xs []string, n int) []string {
	sort.Strings(xs)
	if len(xs) > n {
		return append(xs[:n:n], fmt.Sprintf("… %d more", len(xs)-n))
	}
	return xs
}

type fileStamp struct {
	ino   uint64
	mtime time.Time
}

func stamps(home string) map[string]fileStamp {
	out := map[string]fileStamp{}
	_ = filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return nil
		}
		st, _ := fi.Sys().(*syscall.Stat_t)
		var ino uint64
		if st != nil {
			ino = uint64(st.Ino)
		}
		rel, _ := filepath.Rel(home, p)
		out[filepath.ToSlash(rel)] = fileStamp{ino: ino, mtime: fi.ModTime()}
		return nil
	})
	return out
}

// TestCorpusCutover is the cutover rehearsal.
func TestCorpusCutover(t *testing.T) {
	c := loadCorpus(t)
	defer c.save(t, "cutover-rehearsal.txt")
	t.Run("apply", func(t *testing.T) { c.rehearseApply(t) })
	t.Run("adopt", func(t *testing.T) { c.rehearseAdopt(t) })
}

func (c *corpus) rehearseApply(t *testing.T) {
	w := NewWorld(t)
	c.readLegacySecrets(t, w)
	admin, _, ok := c.importWorld(t, w, false)
	if !ok {
		return
	}
	ms := c.joinProfiles(t, w, admin, false)
	for _, m := range ms {
		m.Run("sync")
		r := m.Run("apply")
		holds := map[string]int{}
		var hs []Hold
		_ = r.Decode(&struct {
			Holds *[]Hold `json:"holds"`
		}{&hs})
		for _, h := range hs {
			holds[h.Reason]++
		}
		c.logf(t, "apply %s: %s, holds %v", m.g.Profile.Name, r.Err(), holds)
	}
	c.compareProfiles(t, "apply", ms)
	c.secrecy(t, w, ms, nil)
	c.logf(t, "unit shim calls: %d", len(w.UnitCalls()))

	// Canary through the tool: a member appends a canary to a sealed target.
	var member *profileMachine
	for _, m := range ms {
		if m.member {
			member = m
			break
		}
	}
	tg := sealedTarget(t, w, member)
	if member == nil || tg == "" {
		c.logf(t, "canary: no member or no sealed plain target; skipped")
	} else {
		cn := secrecytest.NewCanary(t, c.enclave)
		appendLine(member.Machine, tg, cn.String())
		r := member.Run("commit", tg)
		c.logf(t, "canary: commit %s on %s: %s", tg, member.g.Profile.Name, r.Err())
		for _, m := range ms {
			m.Run("sync")
		}
		c.secrecy(t, w, ms, []secrecytest.Canary{cn})
		for _, m := range ms {
			fs, _ := secrecytest.ScanRepo(m.Source, cn)
			if len(fs) > 0 {
				t.Errorf("%s: canary in its source repository", m.g.Profile.Name)
			}
		}
		delivered := 0
		for _, m := range ms {
			if b, ok := m.ReadHome(tg); ok && bytes.Contains(b, cn.Bytes()) && m.member {
				delivered++
			}
		}
		c.logf(t, "canary: delivered to %d members", delivered)
	}
	c.soak(t, w, ms)
}

// sealedTarget picks a non-template enclave target from the imported
// manifest that every member's golden holds.
func sealedTarget(t *testing.T, w *World, m *profileMachine) string {
	if m == nil {
		return ""
	}
	raw, err := w.GitErr(w.Remote, nil, "show", "main:manifest.toml")
	if err != nil {
		return ""
	}
	var mf struct {
		File []struct {
			Target   string `toml:"target"`
			Enclave  string `toml:"enclave"`
			Template bool   `toml:"template"`
			Format   string `toml:"format"`
		} `toml:"file"`
	}
	if err := toml.Unmarshal([]byte(raw), &mf); err != nil {
		t.Logf("manifest: %v", err)
		return ""
	}
	have := map[string]bool{}
	for _, e := range m.g.Targets {
		have[e.Path] = true
	}
	var cands []string
	for _, f := range mf.File {
		if f.Enclave != "" && !f.Template && f.Format == "" && have[f.Target] && strings.HasSuffix(f.Target, ".md") {
			cands = append(cands, f.Target)
		}
	}
	sort.Strings(cands)
	if len(cands) == 0 {
		return ""
	}
	return cands[0]
}

func (c *corpus) rehearseAdopt(t *testing.T) {
	c.noApply = true
	defer func() { c.noApply = false }()
	w := NewWorld(t)
	c.readLegacySecrets(t, w)
	admin, _, ok := c.importWorld(t, w, true)
	if !ok {
		return
	}
	ms := c.joinProfiles(t, w, admin, true)
	for _, m := range ms {
		if r := c.syncOrPull(m.Machine); r.Code != 0 { // fetch the key-log adds without applying
			c.logf(t, "%s: pull: %s", m.g.Profile.Name, r.Err())
		}
	}
	for _, m := range ms {
		before := stamps(m.Home)
		dr := m.Run("adopt", "--dry-run", "--no-schedule")
		afterDry := stamps(m.Home)
		changedDry := diffStamps(before, afterDry)
		r := m.Run("adopt", "--no-schedule")
		after := stamps(m.Home)
		changed := diffStamps(before, after)
		sinceSeed := diffStamps(c.seeded[m.Name], after)
		c.logf(t, "adopt %s: files rewritten since seeding (init and join included): %d %v", m.g.Profile.Name, len(sinceSeed), firstN(sinceSeed, 10))
		var d struct {
			Actions []struct {
				Target string `json:"target"`
				Kind   string `json:"kind"`
			} `json:"actions"`
			Holds []Hold `json:"holds"`
		}
		_ = r.Decode(&d)
		kinds := map[string]int{}
		for _, a := range d.Actions {
			kinds[a.Kind]++
		}
		holds := map[string]int{}
		for _, h := range d.Holds {
			holds[h.Reason]++
		}
		c.logf(t, "adopt %s: dry-run %s, files touched by dry-run %d; adopt %s, actions %v, holds %v, files rewritten %d %v",
			m.g.Profile.Name, dr.Err(), len(changedDry), r.Err(), kinds, holds, len(changed), firstN(changed, 10))
		if kinds["adopt"] == 0 {
			t.Errorf("%s: adopt recorded no target as adopted: %v", m.g.Profile.Name, kinds)
		}
		if len(changedDry) > 0 {
			t.Errorf("%s: adopt --dry-run touched %d files", m.g.Profile.Name, len(changedDry))
		}
	}
	c.compareProfiles(t, "adopt", ms)
}

func diffStamps(a, b map[string]fileStamp) []string {
	var out []string
	for p, s := range a {
		if s2, ok := b[p]; !ok || s2 != s {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// soak adds an overlay to the imported repository (a Brewfile-like list, a
// JSON file with a volatile key, a shared owned root) and runs the
// multi-machine soak on two members and one non-member.
func (c *corpus) soak(t *testing.T, w *World, ms []*profileMachine) {
	var mems, others []*profileMachine
	for _, m := range ms {
		if m.member {
			mems = append(mems, m)
		} else {
			others = append(others, m)
		}
	}
	if len(mems) < 2 || len(others) < 1 {
		c.logf(t, "soak: needs two members and one non-member; skipped")
		return
	}
	pick := []*profileMachine{mems[0], mems[1], others[0]}
	// A shared plain text target every picked golden holds identically.
	shared := sharedTargets(pick, 2)
	sealed := sealedTarget(t, w, mems[0])
	pushSourceEdit(t, w, "soak overlay", func(dir string) {
		writeFiles(t, dir, map[string]string{
			"files/.config/yadm-e2e/Brewfile":      "brew \"git\"\n",
			"files/.config/yadm-e2e/settings.json": "{\n  \"theme\": \"dark\"\n}\n",
		})
		f, _ := os.OpenFile(filepath.Join(dir, "manifest.toml"), os.O_APPEND|os.O_WRONLY, 0)
		_, _ = f.WriteString("\n[[file]]\ntarget = \".config/yadm-e2e/Brewfile\"\nmerge = \"union\"\n\n[[file]]\ntarget = \".config/yadm-e2e/settings.json\"\nformat = \"json\"\nvolatile = [\"volatile\"]\n\n[[root]]\npath = \".config/yadm-e2e/drop\"\n")
		_ = f.Close()
	})
	var machines []*Machine
	members := map[string]bool{}
	for _, m := range pick {
		m.Run("sync")
		m.Run("root", "allow", ".config/yadm-e2e/drop")
		m.Run("sync")
		machines = append(machines, m.Machine)
		members[m.Name] = m.member
	}
	spec := SoakSpec{Machines: machines, Members: members, Enclave: c.enclave, Shared: shared,
		Union: ".config/yadm-e2e/Brewfile", JSON: ".config/yadm-e2e/settings.json", Root: ".config/yadm-e2e/drop",
		Rounds: soakRounds(50), Seed: soakSeed(), Types: strings.Join(c.types(), ",")}
	if sealed != "" {
		spec.Sealed = []string{sealed}
	}
	c.logf(t, "soak: machines %s, %s, %s; shared %v; sealed %v", pick[0].g.Profile.Name, pick[1].g.Profile.Name, pick[2].g.Profile.Name, shared, spec.Sealed)
	rep := Soak(t, w, spec)
	c.logf(t, "soak: %s", rep)
	for _, group := range [][]string{rep.Lost, rep.Unexplained, rep.Diverged, rep.CommandErrors, rep.Leaks} {
		for _, x := range firstN(group, 20) {
			c.logf(t, "  %s", x)
		}
	}
	reportSoak(t, rep)
}

func sharedTargets(ms []*profileMachine, n int) []string {
	sums := map[string]map[string]string{}
	for _, m := range ms {
		sums[m.Name] = map[string]string{}
		for _, e := range m.g.Targets {
			if e.Kind == oracle.KindPlain && !e.Template && !e.Normalized && e.Size > 0 && e.Size < 4000 && e.Mode == "0644" {
				sums[m.Name][e.Path] = e.SHA256
			}
		}
	}
	var out []string
	for p, s := range sums[ms[0].Name] {
		ok := strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".txt") || strings.HasSuffix(p, ".sh")
		for _, m := range ms[1:] {
			if sums[m.Name][p] != s {
				ok = false
			}
		}
		if ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}
