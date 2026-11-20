// Command yadm-oracle records what stock yadm produces in $HOME for each
// machine profile. See docs/oracle.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/oracle"
)

func main() {
	var (
		repo     = flag.String("repo", "", "source git directory to clone (required; read only)")
		profiles = flag.String("profiles", "", "tab-separated profiles file (required)")
		out      = flag.String("out", "", "output directory, created 0700 (required)")
		work     = flag.String("work", "", "sandbox parent directory (default: <out>/.work)")
		yadm     = flag.String("yadm", "yadm", "stock yadm executable")
		git      = flag.String("git", "git", "git executable")
		defOS    = flag.String("default-os", "", "os for profiles with no os column value")
		only     = flag.String("only", "", "comma-separated profile names to run (default: all)")
		keep     = flag.Bool("keep", false, "keep sandboxes after the run")
	)
	flag.Parse()
	if *repo == "" || *profiles == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*repo, *profiles, *out, *work, *yadm, *git, *defOS, *only, *keep); err != nil {
		fmt.Fprintln(os.Stderr, "yadm-oracle:", err)
		os.Exit(1)
	}
}

func run(repo, profiles, out, work, yadm, git, defOS, only string, keep bool) error {
	var err error
	if repo, err = filepath.Abs(repo); err != nil {
		return err
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	if work != "" {
		if work, err = filepath.Abs(work); err != nil {
			return err
		}
	}
	for _, p := range []*string{&yadm, &git} {
		if *p, err = exec.LookPath(*p); err != nil {
			return err
		}
	}
	f, err := os.Open(profiles)
	if err != nil {
		return err
	}
	ps, err := oracle.ParseProfiles(f, defOS)
	f.Close()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, n := range strings.Split(only, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(out, 0o700); err != nil {
		return err
	}
	failed := 0
	for _, p := range ps {
		if len(want) > 0 && !want[p.Name] {
			continue
		}
		m, err := oracle.Run(oracle.Options{Repo: repo, Out: out, Work: work, Yadm: yadm, Git: git, Keep: keep, Profile: p})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: FAILED: %v\n", p.Name, err)
			failed++
			continue
		}
		keys := make([]string, 0, len(m.Counts))
		for k := range m.Counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, m.Counts[k]))
		}
		fmt.Printf("%s: %s warnings=%d\n", p.Name, strings.Join(parts, " "), len(m.Warnings))
	}
	if failed > 0 {
		return fmt.Errorf("%d profile(s) failed", failed)
	}
	return nil
}
