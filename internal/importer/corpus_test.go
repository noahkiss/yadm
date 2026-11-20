package importer

// Opt-in comparison against a real upstream-yadm repository and the oracle
// records of what stock yadm wrote for each profile (see docs/oracle.md).
//
//	YADM_CORPUS=1                 enable
//	YADM_LEGACY_REPO=<git dir>    the legacy repository; it is cloned, never written
//	YADM_ORACLE_DIR=<dir>         oracle records; default $HOME/.local/share/yadm-oracle
//	YADM_CORPUS_OUT=<dir>         where the path report goes; default a temp dir
//
// The transcrypt password is read from the legacy repository's own config
// in process. The test prints counts and paths, never file contents.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/oracle"
)

type goldenRecord struct {
	Profile      oracle.Profile `json:"profile"`
	SourceCommit string         `json:"source_commit"`
	Targets      []oracle.Entry `json:"targets"`
}

func TestCorpusAgainstOracle(t *testing.T) {
	if os.Getenv("YADM_CORPUS") != "1" {
		t.Skip("set YADM_CORPUS=1 to compare against a real repository")
	}
	orig := os.Getenv("YADM_LEGACY_REPO")
	if orig == "" {
		t.Fatal("YADM_LEGACY_REPO is not set")
	}
	odir := os.Getenv("YADM_ORACLE_DIR")
	if odir == "" {
		home, _ := os.UserHomeDir()
		odir = filepath.Join(home, ".local", "share", "yadm-oracle")
	}
	outDir := os.Getenv("YADM_CORPUS_OUT")
	if outDir == "" {
		outDir = t.TempDir()
	}

	var goldens []goldenRecord
	ents, err := os.ReadDir(odir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(odir, e.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		var g goldenRecord
		if err := json.Unmarshal(b, &g); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		goldens = append(goldens, g)
	}
	if len(goldens) == 0 {
		t.Fatal("no oracle records found")
	}
	commit := goldens[0].SourceCommit
	for _, g := range goldens {
		if g.SourceCommit != commit {
			t.Fatalf("oracle records name different source commits")
		}
	}

	// A copy of the legacy repository, at the recorded commit, with no checkout.
	work := t.TempDir()
	clone := filepath.Join(work, "legacy")
	gitT(t, "", "clone", "-q", "--no-hardlinks", "--no-checkout", orig, clone)
	gitT(t, clone, "update-ref", "--no-deref", "HEAD", commit)

	// The password goes from the original's config into this process only.
	pw, err := exec.Command("git", "config", "--file", filepath.Join(orig, "config"), "--get", "transcrypt.password").Output()
	if err != nil {
		t.Fatal("cannot read the transcrypt password from the legacy repository config")
	}
	const pwEnv = "YADM_IMPORT_CORPUS_PASSWORD"
	t.Setenv(pwEnv, strings.TrimRight(string(pw), "\n"))

	// Machines table from the oracle profiles; every class maps to an enclave of its name.
	var tsv strings.Builder
	tsv.WriteString("name\thostname\tclasses\tos\tarch\tuser\n")
	classEnclaves := map[string]model.EnclaveName{}
	for _, g := range goldens {
		p := g.Profile
		fmt.Fprintf(&tsv, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.Hostname, strings.Join(p.Classes, ","), p.OS, p.Arch, p.User)
		for _, c := range p.Classes {
			classEnclaves[strings.ToLower(c)] = model.EnclaveName(strings.ToLower(c))
		}
	}
	machines := filepath.Join(work, "machines.tsv")
	if err := os.WriteFile(machines, []byte(tsv.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var filters []string
	for f := range cryptFilters(ctx, orig) {
		filters = append(filters, f)
	}
	sealer := newFakeSealer()
	conv, err := convert(ctx, Options{
		Legacy: clone, Machines: machines, PasswordEnv: pwEnv,
		ClassEnclaves: classEnclaves, CryptFilters: filters, Sealer: sealer,
	})
	if err != nil {
		t.Fatal(err)
	}

	var report strings.Builder
	problemPaths := map[string]bool{}
	fmt.Fprintf(&report, "# import problems: %d\n", len(conv.Problems))
	for _, p := range conv.Problems {
		problemPaths[p.Path] = true
		fmt.Fprintf(&report, "problem\t%s\n", p.String())
	}
	t.Logf("import: %d mappings, %d machines, %d problems", len(conv.Mappings), conv.Machines, len(conv.Problems))

	for _, g := range goldens {
		p := g.Profile
		m := fleetMachine(t, conv, p.Name)
		mctx := model.Context{Machine: m, Home: oracle.HomeToken, User: p.User}
		got, rprobs, err := refResolve(conv, sealer, mctx, func(model.EnclaveName) bool { return p.Decrypt })
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		counts := map[string]int{}
		var lines []string
		note := func(kind, path string) {
			counts[kind]++
			if kind != "match" {
				lines = append(lines, kind+"\t"+path)
			}
		}
		seen := map[model.Target]bool{}
		for _, gt := range g.Targets {
			tg := model.Target(gt.Path)
			seen[tg] = true
			r, ok := got[tg]
			switch {
			case gt.Kind == oracle.KindDangling:
				if ok && !r.Skipped {
					note("extra-for-dangling", gt.Path)
				} else {
					note("dangling-in-golden", gt.Path)
				}
			case !ok && problemPaths[gt.Source]:
				note("missing-problem", gt.Path)
			case !ok:
				note("missing", gt.Path)
			case r.Skipped:
				if gt.Ciphertext {
					note("sealed-skip-golden-ciphertext", gt.Path)
				} else {
					note("sealed-skip", gt.Path)
				}
			default:
				sumOK := r.sum() == gt.SHA256
				modeOK := fmt.Sprintf("%04o", uint32(r.Mode)) == gt.Mode
				switch {
				case sumOK && modeOK:
					note("match", gt.Path)
				case sumOK && r.Entry.Enclave != "":
					note("mode-sealed-"+fmt.Sprintf("%04o-vs-%s", uint32(r.Mode), gt.Mode), gt.Path)
				case sumOK:
					note("mode-"+fmt.Sprintf("%04o-vs-%s", uint32(r.Mode), gt.Mode), gt.Path)
				case r.Entry.Template:
					note("content-template", gt.Path)
				default:
					note("content", gt.Path)
				}
			}
		}
		for tg, r := range got {
			if !seen[tg] && !r.Skipped {
				note("extra", string(tg))
			}
		}
		for _, x := range rprobs {
			note("resolve-problem", x)
		}
		var ks []string
		for k := range counts {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var parts []string
		for _, k := range ks {
			parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
		}
		summary := fmt.Sprintf("%s: golden=%d %s", p.Name, len(g.Targets), strings.Join(parts, " "))
		t.Log(summary)
		fmt.Fprintf(&report, "\n# %s\n", summary)
		sort.Strings(lines)
		for _, l := range lines {
			fmt.Fprintf(&report, "%s\t%s\n", p.Name, l)
		}
	}
	rp := filepath.Join(outDir, "importer-corpus.tsv")
	if err := os.WriteFile(rp, []byte(report.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("path report: %s", rp)
}

func gitT(t testing.TB, dir string, args ...string) string {
	t.Helper()
	if dir != "" {
		args = append([]string{"-C", dir}, args...)
	}
	cmd := exec.Command("git", args...)
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
