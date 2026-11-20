package importer

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

// simMachine is one machine as upstream sees it.
type simMachine struct {
	Classes        []string
	OS, Host, User string
}

func (m simMachine) model() model.Machine {
	mm := model.Machine{Name: "sim", OS: strings.ToLower(m.OS), Facts: map[string]string{"hostname": m.Host, "user": m.User}}
	for _, c := range m.Classes {
		mm.Types = append(mm.Types, model.TypeName(strings.ToLower(c)))
	}
	return mm
}

// upstreamPick models how upstream yadm chooses among alternates for one
// target, written from its documented behaviour: every matching condition
// adds 1000 plus its weight; a template beats any other file; non-template
// ties keep the first, template ties take the last. It returns the winning
// legacy path, or the plain file, or "".
func upstreamPick(paths []string, m simMachine) string {
	best, bestScore, bestTmpl := "", 0, false
	plain := ""
	for _, p := range paths {
		alt, isAlt, err := ParseAltName(p)
		if err != nil {
			panic(err)
		}
		if !isAlt {
			plain = p
			continue
		}
		score, tmpl, ok := 0, false, true
		for _, c := range alt.Conds {
			d := 0
			switch c.Key {
			case condExtension:
				continue
			case condDefault:
			case condTemplate:
				tmpl = true
			case condClass:
				ok = ok && containsFold(m.Classes, c.Value)
				d = 16
			case condOS:
				ok = ok && strings.EqualFold(c.Value, m.OS)
				d = 2
			case condHostname:
				ok = ok && strings.EqualFold(c.Value, m.Host)
				d = 32
			case condUser:
				ok = ok && strings.EqualFold(c.Value, m.User)
				d = 64
			}
			score += 1000 + d
		}
		if !ok {
			continue
		}
		switch {
		case best == "":
		case bestTmpl && (!tmpl || score < bestScore):
			continue
		case !bestTmpl && !tmpl && score <= bestScore:
			continue
		}
		best, bestScore, bestTmpl = p, score, tmpl
	}
	if best == "" {
		return plain
	}
	return best
}

func containsFold(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// TestRankMatchesUpstream generates random alternate sets and machines and
// checks that the emitted conditions pick exactly what upstream picks, with
// never more than one entry applying.
func TestRankMatchesUpstream(t *testing.T) {
	pool := []string{"default", "class.alpha", "class.beta", "os.Darwin", "os.Linux", "hostname.host-a", "hostname.host-b", "user.someone", "template"}
	rng := rand.New(rand.NewSource(7))
	machines := []simMachine{}
	for _, cls := range [][]string{nil, {"alpha"}, {"beta"}, {"alpha", "beta"}, {"beta", "alpha"}} {
		for _, os := range []string{"Darwin", "Linux"} {
			for _, h := range []string{"host-a", "host-b", "host-c"} {
				for _, u := range []string{"someone", "other"} {
					machines = append(machines, simMachine{cls, os, h, u})
				}
			}
		}
	}
	for iter := 0; iter < 400; iter++ {
		set := map[string]bool{}
		if rng.Intn(3) == 0 {
			set["f"] = true // a plain file at the target
		}
		for n := 1 + rng.Intn(5); n > 0; n-- {
			k := 1 + rng.Intn(3)
			var conds []string
			used := map[string]bool{}
			for len(conds) < k {
				c := pool[rng.Intn(len(pool))]
				key, _, _ := strings.Cut(c, ".")
				if used[key] {
					break
				}
				used[key] = true
				conds = append(conds, c)
			}
			set["f##"+strings.Join(conds, ",")] = true
		}
		var paths []string
		for p := range set {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		repo := &legacyRepo{byPath: map[string]*legacyFile{}, blobs: map[string][]byte{}}
		for i, p := range paths {
			blob := fmt.Sprintf("b%d", i)
			repo.Files = append(repo.Files, legacyFile{Path: p, Mode: "100644", Blob: blob})
			repo.blobs[blob] = []byte(p + "\n")
		}
		for i := range repo.Files {
			repo.byPath[repo.Files[i].Path] = &repo.Files[i]
		}
		pl := &planner{repo: repo, filters: map[string]bool{}, files: map[model.SourcePath]outFile{}}
		pl.run()
		if len(pl.problems) > 0 {
			t.Fatalf("%v: problems %v", paths, pl.problems)
		}
		man, err := encodeManifest(pl.entries)
		if err != nil {
			t.Fatal(err)
		}
		conv := &converted{Files: pl.files, Manifest: man}
		for _, m := range machines {
			want := upstreamPick(paths, m)
			got, probs, err := refResolve(conv, nil, model.Context{Machine: m.model()}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(probs) > 0 {
				t.Fatalf("%v on %+v: %v", paths, m, probs)
			}
			gotPath := ""
			if r, ok := got["f"]; ok {
				gotPath = strings.TrimSuffix(string(r.Content), "\n")
			}
			if gotPath != want {
				t.Fatalf("%v on %+v: got %q, upstream picks %q\nmanifest:\n%s", paths, m, gotPath, want, man)
			}
		}
	}
}
