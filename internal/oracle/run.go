package oracle

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

// FormatVersion is the manifest format version.
const FormatVersion = 1

// Options configures a run.
type Options struct {
	Repo    string // source git directory
	Out     string // output directory; one subdirectory per profile
	Work    string // sandbox parent; default Out/.work
	Yadm    string // yadm executable
	Git     string // git executable
	Keep    bool   // keep sandboxes after the run
	Profile Profile
}

// Manifest is the golden record for one profile.
type Manifest struct {
	Format       int               `json:"format"`
	Profile      Profile           `json:"profile"`
	SourceCommit string            `json:"source_commit"`
	Tools        map[string]string `json:"tools"`
	Placeholders map[string]string `json:"placeholders"`
	Counts       map[string]int    `json:"counts"`
	Targets      []Entry           `json:"targets"`
	Unresolved   []Entry           `json:"unresolved"`
	SelfLinks    []string          `json:"self_links"`
	// Encrypted lists tracked paths whose filter runs transcrypt.
	Encrypted []string `json:"encrypted"`
	// CaseCollisions lists tracked paths that differ only in letter case.
	CaseCollisions [][]string `json:"case_collisions"`
	Warnings       []string   `json:"warnings"`
}

var (
	reCreating = regexp.MustCompile(`^Creating (.+) from template (.+)$`)
	reFailed   = regexp.MustCompile(`^Error: failed to process template '(.+)'$`)
)

// Run produces the golden record for one profile.
func Run(o Options) (*Manifest, error) {
	p := o.Profile
	if o.Work == "" {
		o.Work = filepath.Join(o.Out, ".work")
	}
	syscall.Umask(0o022)
	if err := os.MkdirAll(o.Work, 0o700); err != nil {
		return nil, err
	}
	sb, err := NewSandbox(filepath.Join(o.Work, p.Name), o.Yadm, o.Git, p)
	if err != nil {
		return nil, err
	}
	if !o.Keep {
		defer os.RemoveAll(sb.Root)
	}
	if err := sb.Clone(o.Repo); err != nil {
		return nil, err
	}
	if err := sb.Configure(p); err != nil {
		return nil, err
	}
	if p.Decrypt {
		if err := sb.InstallKey(o.Repo); err != nil {
			return nil, err
		}
	}
	if err := sb.Checkout(); err != nil {
		return nil, err
	}
	alt, err := sb.Alt()
	if err != nil {
		return nil, err
	}
	if err := sb.Perms(); err != nil {
		return nil, err
	}

	m := &Manifest{
		Format:       FormatVersion,
		Profile:      p,
		Tools:        map[string]string{},
		Placeholders: map[string]string{HomeToken: "the home directory"},
		Counts:       map[string]int{},
	}
	if p.User == UserToken {
		m.Placeholders[UserToken] = "the login name (USER, LOGNAME and local.user)"
	}
	if r, err := sb.GitCmd("rev-parse", "HEAD"); err == nil {
		m.SourceCommit = strings.TrimSpace(r.Stdout)
	}
	m.Tools["yadm"] = lineWith(sb.YadmCmd("version"))
	m.Tools["git"] = firstLine(sb.GitCmd("version"))
	m.Tools["awk"] = awkInUse()

	tr, err := tracked(sb)
	if err != nil {
		return nil, err
	}
	m.CaseCollisions = caseCollisions(tr.Files)

	replace := [][2]string{{sb.Root, "@@SANDBOX@@"}}
	if real, err := filepath.EvalSymlinks(sb.Home); err == nil && real != sb.Home {
		replace = append([][2]string{{real, HomeToken}}, replace...)
	}
	replace = append([][2]string{{sb.Home, HomeToken}}, replace...)

	templates := map[string]string{}
	rel := func(abs string) string {
		r, err := filepath.Rel(sb.Home, abs)
		if err != nil {
			return abs
		}
		return filepath.ToSlash(r)
	}
	for _, line := range strings.Split(alt.Stdout+"\n"+alt.Stderr, "\n") {
		line = strings.TrimSpace(line)
		if mm := reCreating.FindStringSubmatch(line); mm != nil {
			templates[rel(mm[1])] = rel(mm[2])
		} else if mm := reFailed.FindStringSubmatch(line); mm != nil {
			m.Warnings = append(m.Warnings, "template failed: "+rel(mm[1]))
		}
	}
	for _, line := range strings.Split(alt.Stderr, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			m.Warnings = append(m.Warnings, "alt stderr: "+string(Normalize([]byte(line), replace)))
		}
	}
	for _, line := range strings.Split(alt.Stdout, "\n") {
		if strings.HasPrefix(line, "Skipping alt") {
			m.Warnings = append(m.Warnings, "alt: "+string(Normalize([]byte(line), replace)))
		}
	}

	c, err := Collect(sb.Home, tr, templates, replace)
	if err != nil {
		return nil, err
	}
	m.Targets, m.Unresolved, m.SelfLinks = c.Targets, c.Unresolved, c.SelfLinks
	m.Warnings = append(m.Warnings, c.Warnings...)

	enc, err := encryptedPaths(sb, o.Repo, tr)
	if err != nil {
		return nil, err
	}
	m.Encrypted = enc
	if err := checkEncryption(m, sb.Home, p.Decrypt); err != nil {
		return nil, err
	}
	for _, e := range m.Targets {
		m.Counts["targets"]++
		m.Counts["kind_"+e.Kind]++
		if e.Normalized {
			m.Counts["normalized"]++
		}
		if e.Ciphertext {
			m.Counts["ciphertext_targets"]++
		}
	}
	m.Counts["unresolved"] = len(m.Unresolved)
	m.Counts["tracked"] = len(tr.Files)
	m.Counts["encrypted_tracked"] = len(m.Encrypted)
	m.Counts["self_links"] = len(m.SelfLinks)

	// Nothing from the sandbox path may survive in recorded content.
	for _, e := range m.Targets {
		if strings.Contains(string(e.content), sb.Root) || strings.Contains(string(e.content), "@@SANDBOX@@") {
			m.Warnings = append(m.Warnings, "sandbox path survives in "+e.Path)
		}
	}
	if err := write(o.Out, m, c.Targets, alt, replace); err != nil {
		return nil, err
	}
	return m, nil
}

// lineWith picks the "yadm version" line from yadm's version output.
func lineWith(r Result, err error) string {
	if err != nil {
		return "unknown"
	}
	for _, l := range strings.Split(r.Stdout, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "yadm version") {
			return l
		}
	}
	return firstLine(r, nil)
}

func firstLine(r Result, err error) string {
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(strings.SplitN(strings.TrimSpace(r.Stdout), "\n", 2)[0])
}

// awkInUse names the awk yadm 3.5.0 picks: gawk when present, else awk.
func awkInUse() string {
	for _, n := range []string{"gawk", "awk"} {
		if p, err := exec.LookPath(n); err == nil {
			out, _ := exec.Command(p, "--version").Output()
			v := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
			return n + " " + v
		}
	}
	return "none"
}

func tracked(sb *Sandbox) (Tracked, error) {
	r, err := sb.GitCmd("ls-files", "-s", "-z")
	if err != nil {
		return Tracked{}, err
	}
	t := Tracked{Files: map[string]bool{}, Symlinks: map[string]bool{}}
	for _, rec := range strings.Split(r.Stdout, "\x00") {
		meta, name, ok := strings.Cut(rec, "\t")
		if !ok {
			continue
		}
		t.Files[name] = true
		if strings.HasPrefix(meta, "120000 ") {
			t.Symlinks[name] = true
		}
	}
	return t, nil
}

func caseCollisions(files map[string]bool) [][]string {
	by := map[string][]string{}
	for f := range files {
		by[strings.ToLower(f)] = append(by[strings.ToLower(f)], f)
	}
	var out [][]string
	for _, v := range by {
		if len(v) > 1 {
			sort.Strings(v)
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// encryptedPaths lists tracked paths whose filter attribute names a filter
// that the source repo runs through transcrypt.
func encryptedPaths(sb *Sandbox, src string, tr Tracked) ([]string, error) {
	vals, _, err := srcConfig(sb.Git, src)
	if err != nil {
		return nil, err
	}
	crypt := map[string]bool{}
	for k, v := range vals {
		if strings.HasPrefix(k, "filter.") && strings.HasSuffix(k, ".smudge") && strings.Contains(v[0], "transcrypt") {
			crypt[strings.TrimSuffix(strings.TrimPrefix(k, "filter."), ".smudge")] = true
		}
	}
	if len(crypt) == 0 {
		return nil, nil
	}
	var names []string
	for f := range tr.Files {
		names = append(names, f)
	}
	sort.Strings(names)
	cmd := exec.Command(sb.Git, "--git-dir="+sb.Repo, "--work-tree="+sb.Home, "check-attr", "-z", "--stdin", "filter")
	cmd.Dir = sb.Home
	cmd.Env = sb.env
	cmd.Stdin = strings.NewReader(strings.Join(names, "\x00") + "\x00")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("check-attr: %w", err)
	}
	parts := strings.Split(string(out), "\x00")
	var enc []string
	for i := 0; i+2 < len(parts); i += 3 {
		if crypt[parts[i+2]] {
			enc = append(enc, parts[i])
		}
	}
	return enc, nil
}

// checkEncryption fails the run when an encrypted path is in the wrong form
// for the profile: ciphertext where the key is held, plaintext where it is
// not. Empty files and symlinks are skipped.
func checkEncryption(m *Manifest, home string, decrypt bool) error {
	var bad []string
	for _, f := range m.Encrypted {
		p := filepath.Join(home, f)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
			continue
		}
		b := make([]byte, len(cipherMagic))
		fh, err := os.Open(p)
		if err != nil {
			return err
		}
		n, _ := fh.Read(b)
		fh.Close()
		isCipher := n == len(b) && string(b) == string(cipherMagic)
		if decrypt == isCipher {
			bad = append(bad, f)
		}
	}
	if len(bad) > 0 {
		want := "plaintext"
		if !decrypt {
			want = "ciphertext"
		}
		return fmt.Errorf("profile %s: %d encrypted paths are not %s, first: %s", m.Profile.Name, len(bad), want, bad[0])
	}
	for _, e := range m.Targets {
		if e.Ciphertext {
			m.Warnings = append(m.Warnings, "target holds ciphertext: "+e.Path)
		}
	}
	return nil
}

func write(out string, m *Manifest, targets []Entry, alt Result, replace [][2]string) error {
	dir := filepath.Join(out, m.Profile.Name)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	content := filepath.Join(dir, "content")
	if err := os.MkdirAll(content, 0o700); err != nil {
		return err
	}
	for _, e := range targets {
		if e.Kind == KindDangling {
			continue
		}
		p := filepath.Join(content, filepath.FromSlash(e.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, e.content, 0o600); err != nil {
			return err
		}
	}
	log := "$ yadm alt\n--- stdout\n" + alt.Stdout + "--- stderr\n" + alt.Stderr
	if err := os.WriteFile(filepath.Join(dir, "alt.log"), Normalize([]byte(log), replace), 0o600); err != nil {
		return err
	}
	if m.Warnings == nil {
		m.Warnings = []string{}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o600)
}
