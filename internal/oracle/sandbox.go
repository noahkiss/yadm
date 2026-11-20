package oracle

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Sandbox is one profile's private yadm installation: a home directory, a
// yadm directory with no hooks, and a data directory holding the repo clone.
type Sandbox struct {
	Root string
	Home string
	Dir  string // yadm -Y
	Data string // yadm --yadm-data
	Repo string // Data/repo.git
	Yadm string // yadm executable
	Git  string // git executable
	env  []string
}

// passEnv lists the parent variables a sandboxed yadm may inherit. Everything
// else, including every GIT_*, XDG_* and YADM_* variable, is dropped.
var passEnv = []string{"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"}

// NewSandbox creates the sandbox directories under root, which must not exist.
func NewSandbox(root, yadm, git string, p Profile) (*Sandbox, error) {
	if _, err := os.Lstat(root); err == nil {
		return nil, fmt.Errorf("sandbox %s already exists", root)
	}
	s := &Sandbox{
		Root: root,
		Home: filepath.Join(root, "home"),
		Dir:  filepath.Join(root, "yadm"),
		Data: filepath.Join(root, "data"),
		Yadm: yadm,
		Git:  git,
	}
	s.Repo = filepath.Join(s.Data, "repo.git")
	for _, d := range []string{root, s.Home, s.Dir, s.Data} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	// yadm's own config. auto-alt is off so that alt runs only when the
	// harness asks, after the profile is configured. The hooks directory is
	// absent, so no yadm hook runs.
	if err := os.WriteFile(filepath.Join(s.Dir, "config"), []byte("[yadm]\n\tauto-alt = false\n"), 0o600); err != nil {
		return nil, err
	}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			s.env = append(s.env, k+"="+v)
		}
	}
	s.env = append(s.env,
		"HOME="+s.Home,
		"USER="+p.User,
		"LOGNAME="+p.User,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
	return s, nil
}

// Result holds one command's output.
type Result struct {
	Args   []string
	Stdout string
	Stderr string
}

func (s *Sandbox) run(name string, args ...string) (Result, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = s.Home
	cmd.Env = s.env
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	r := Result{Args: append([]string{filepath.Base(name)}, args...), Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		return r, fmt.Errorf("%s: %w\n%s", strings.Join(r.Args, " "), err, r.Stderr)
	}
	return r, nil
}

// YadmCmd runs yadm against the sandbox.
func (s *Sandbox) YadmCmd(args ...string) (Result, error) {
	full := append([]string{"-Y", s.Dir, "--yadm-data", s.Data}, args...)
	return s.run(s.Yadm, full...)
}

// GitCmd runs git against the sandbox repo, never any other.
func (s *Sandbox) GitCmd(args ...string) (Result, error) {
	full := append([]string{"--git-dir=" + s.Repo, "--work-tree=" + s.Home}, args...)
	return s.run(s.Git, full...)
}

// Clone clones src into the sandbox without checking anything out.
func (s *Sandbox) Clone(src string) error {
	_, err := s.YadmCmd("clone", "--no-bootstrap", "-n", "--no-hardlinks", src)
	return err
}

// Configure applies the profile through yadm's local.* overrides.
func (s *Sandbox) Configure(p Profile) error {
	for _, c := range p.Classes {
		if _, err := s.YadmCmd("config", "--add", "local.class", c); err != nil {
			return err
		}
	}
	set := [][2]string{{"local.os", p.OS}, {"local.hostname", p.Hostname}, {"local.user", p.User}}
	if p.Arch != "" {
		set = append(set, [2]string{"local.arch", p.Arch})
	}
	for _, kv := range set {
		if _, err := s.YadmCmd("config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

// srcConfig reads the source repo's own config file, never a worktree config.
func srcConfig(git, src string) (map[string][]string, []string, error) {
	cmd := exec.Command(git, "config", "--file", filepath.Join(src, "config"), "--null", "--list")
	cmd.Env = []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "PATH=" + os.Getenv("PATH")}
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("read source repo config: %w", err)
	}
	vals := map[string][]string{}
	var order []string
	for _, rec := range strings.Split(string(out), "\x00") {
		if rec == "" {
			continue
		}
		k, v, _ := strings.Cut(rec, "\n")
		if _, ok := vals[k]; !ok {
			order = append(order, k)
		}
		vals[k] = append(vals[k], v)
	}
	return vals, order, nil
}

// InstallKey gives the sandbox the source repo's transcrypt key and every
// filter whose smudge runs transcrypt. The openssl-path key is replaced by
// openssl from PATH. Values are never logged.
func (s *Sandbox) InstallKey(src string) error {
	vals, order, err := srcConfig(s.Git, src)
	if err != nil {
		return err
	}
	if len(vals["transcrypt.password"]) == 0 && len(vals["transcrypt.cipher"]) == 0 {
		return fmt.Errorf("source repo has no transcrypt config; cannot decrypt")
	}
	cryptFilters := map[string]bool{}
	for k, v := range vals {
		if strings.HasPrefix(k, "filter.") && strings.HasSuffix(k, ".smudge") && strings.Contains(v[0], "transcrypt") {
			cryptFilters[strings.TrimSuffix(strings.TrimPrefix(k, "filter."), ".smudge")] = true
		}
	}
	if len(cryptFilters) == 0 {
		return fmt.Errorf("source repo has no transcrypt smudge filter")
	}
	cryptDir := filepath.Join(src, "crypt")
	var keys []string
	for _, k := range order {
		switch {
		case k == "transcrypt.openssl-path":
		case k == "transcrypt.crypt-dir":
			cryptDir = vals[k][0]
		case strings.HasPrefix(k, "transcrypt."):
			keys = append(keys, k)
		case strings.HasPrefix(k, "filter."):
			rest := strings.TrimPrefix(k, "filter.")
			i := strings.LastIndex(rest, ".")
			if i < 0 || !cryptFilters[rest[:i]] {
				continue
			}
			switch rest[i+1:] {
			case "smudge", "required":
				keys = append(keys, k)
			case "clean":
				if strings.Contains(vals[k][0], "transcrypt") {
					keys = append(keys, k)
				}
			}
		}
	}
	sort.Strings(keys)
	// transcrypt reads openssl-path on every smudge. The source value may
	// name a wrapper outside the sandbox, so use openssl from PATH instead.
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		return fmt.Errorf("openssl not found: %w", err)
	}
	vals["transcrypt.openssl-path"] = []string{openssl}
	keys = append(keys, "transcrypt.openssl-path")
	cfg := filepath.Join(s.Repo, "config")
	for _, k := range keys {
		for _, v := range vals[k] {
			cmd := exec.Command(s.Git, "config", "--file", cfg, "--add", k, v)
			cmd.Env = s.env
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("set %s in sandbox: %v: %s", k, err, out)
			}
		}
	}
	return copyTree(cryptDir, filepath.Join(s.Repo, "crypt"))
}

// Checkout writes every tracked file into the sandbox home.
func (s *Sandbox) Checkout() error {
	_, err := s.YadmCmd("checkout", "--", ":/")
	return err
}

// Alt runs yadm alt and returns its output.
func (s *Sandbox) Alt() (Result, error) { return s.YadmCmd("alt") }

// Perms runs yadm perms, which a machine runs after every git command.
func (s *Sandbox) Perms() error {
	_, err := s.YadmCmd("perms")
	return err
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, b, info.Mode().Perm())
		}
		return nil
	})
}
