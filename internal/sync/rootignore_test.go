package sync

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// Plain roots of the seed: one ignores the subtrees a deeper root will own,
// one ignores nothing.
const ignoreSeedRoots = `
[[root]]
path = ".config/app"
ignore = ["cache/**", "team/**"]

[[root]]
path = ".config/box"
`

// Enclave roots a later commit adds inside the plain roots. They apply only
// on members of personal. The glob entry applies on the others, which
// cannot seal for personal.
const ignoreEnclaveRoots = `
[[root]]
path = ".config/app/team"
enclave = "personal"
when = "type:personal"

[[root]]
path = ".config/box/vault"
enclave = "personal"
when = "type:personal"

[[file]]
target = ".config/box/claimed/**"
enclave = "personal"
when = "type:work"
`

// TestRootIgnoreNeverCapturedByShallowerRoot: a file under a plain root's
// ignored subtree, or under a deeper enclave root this machine has not
// accepted or that does not apply here, is never captured through the
// plain root. A named commit, a hook's unattended commit and the timer's
// sync all leave it alone, on a member before it allows the enclave root
// and on non-members. Once the member allows the root, a named commit
// seals it. No enclave plaintext reaches any object store or a
// non-member's $HOME.
func TestRootIgnoreNeverCapturedByShallowerRoot(t *testing.T) {
	a, b, c := fixture.HostA, fixture.HostB, fixture.HostC
	w := newWorld(t, func(f *fixture.Fixture) {
		p := filepath.Join(f.Root, "manifest.toml")
		man, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(man, ignoreSeedRoots...), 0o644); err != nil {
			t.Fatal(err)
		}
	}, a, b, c)
	w.syncAll(a, b, c)
	A, B, C := w.machines[a], w.machines[b], w.machines[c]
	pushRaw(t, A, sec2Manifest(t, A, func(s string) string { return s + ignoreEnclaveRoots }))
	w.syncAll(a, b, c)
	if hs := holdsOf(A.sync(), model.HoldRootUntrusted); len(hs) != 2 {
		t.Fatalf("member: want root_untrusted holds for both enclave roots, got %+v", hs)
	}

	ctx := context.Background()
	const (
		ignored  model.Target = ".config/app/team/x.toml"    // plain root ignores it; enclave root covers it
		plainIgn model.Target = ".config/app/cache/y.toml"   // plain root ignores it; no deeper root
		deeper   model.Target = ".config/box/vault/z.toml"   // plain root takes it; enclave root covers it
		claimed  model.Target = ".config/box/claimed/c.toml" // an enclave glob names it; it applies on non-members only
		shared   model.Target = ".config/box/shared.toml"    // the plain root's own: captured
	)
	paths := []model.Target{ignored, plainIgn, deeper, claimed}
	canaries := map[model.MachineID]secrecytest.Canary{}
	var all []secrecytest.Canary
	for _, m := range []*machine{A, B, C} {
		cn := secrecytest.NewCanary(t, "personal via "+string(m.id))
		canaries[m.id] = cn
		all = append(all, cn)
		for _, p := range paths {
			m.write(p, "token = \""+cn.String()+"\"\n")
		}
	}

	for _, m := range []*machine{A, B, C} {
		for _, opts := range []CommitOptions{
			{Paths: paths, Push: true},                                 // yadm commit <path>
			{Paths: paths, Unattended: true, Trigger: TriggerHook},     // post-edit hook
			{Paths: paths, Unattended: true, Trigger: TriggerStop},     // stop hook
			{Paths: []model.Target{ignored}, Push: true},               // one path at a time
			{Paths: []model.Target{deeper}, Push: true, Resolve: true}, // resolve-style named commit
		} {
			if m == A && opts.Trigger == "" && len(opts.Paths) == len(paths) {
				// Mixed with a file the plain root does capture.
				A.write(shared, "shared from host-a\n")
				opts.Paths = append([]model.Target{shared}, paths...)
			}
			rep, err := m.s.Commit(ctx, opts)
			if err != nil {
				t.Fatalf("%s: commit %+v: %v", m.id, opts, err)
			}
			for _, p := range rep.Captured {
				if p != shared {
					t.Errorf("%s: commit %+v captured %s", m.id, opts, p)
				}
			}
			for _, h := range rep.Holds {
				for _, p := range paths {
					if h.Target == p && h.Reason == model.HoldProtected {
						t.Errorf("%s: commit %+v raised a new-file hold on %s: %+v", m.id, opts, p, h)
					}
				}
			}
		}
		m.sync() // the timer
		drift, err := m.eng.Scan(ctx, apply.ScanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range drift {
			for _, p := range paths {
				// The glob entry, not a root, reports its file where it applies.
				if d.Target == p && (p != claimed || m == A) {
					t.Errorf("%s: scan reports %s as new", m.id, p)
				}
			}
		}
	}
	if !strings.Contains(w.remoteFile("files/"+string(shared)), "shared from") {
		t.Fatal("the plain root's own new file was not captured by name")
	}
	for _, p := range paths {
		if out := git(t, w.remote, "ls-tree", "-r", "--name-only", "main"); strings.Contains(out, "files/"+string(p)) {
			t.Errorf("plaintext source files/%s reached the remote", p)
		}
	}
	secrecytest.AssertRepoClean(t, w.remote, all...)
	for _, m := range []*machine{A, B, C} {
		secrecytest.AssertRepoClean(t, m.repo.Dir(), all...)
	}

	// The member allows the enclave roots: a named commit now seals the
	// file under the deeper root. The plain root's ignored file with no
	// deeper root stays refused.
	for _, r := range []model.Target{".config/app/team", ".config/box/vault"} {
		if err := A.eng.AllowRoot(ctx, A.main(), r); err != nil {
			t.Fatal(err)
		}
	}
	A.sync()
	rep, err := A.s.Commit(ctx, CommitOptions{Paths: paths, Push: true})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(rep.Captured, ignored) || !contains(rep.Captured, deeper) || contains(rep.Captured, plainIgn) || contains(rep.Captured, claimed) {
		t.Fatalf("member after allow captured %v", rep.Captured)
	}
	out := git(t, w.remote, "ls-tree", "-r", "--name-only", "main")
	for _, p := range []model.Target{ignored, deeper} {
		if !strings.Contains(out, "sealed/personal/"+string(p)) {
			t.Fatalf("%s not sealed for personal on the remote:\n%s", p, out)
		}
	}
	w.syncAll(b, c)
	secrecytest.AssertRepoClean(t, w.remote, all...)
	secrecytest.AssertRepoClean(t, A.repo.Dir(), all...)
	secrecytest.AssertTreeClean(t, B.home, canaries[a], canaries[c])
	secrecytest.AssertTreeClean(t, C.home, canaries[a], canaries[b])
}
