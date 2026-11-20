package sync

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

const sec2Settings model.Target = ".config/editor/settings.json"

func sec2Manifest(t *testing.T, m *machine, edit func(string) string) []store.Change {
	t.Helper()
	man, err := m.st.ReadPath(context.Background(), m.main(), "manifest.toml")
	if err != nil {
		t.Fatal(err)
	}
	next := edit(string(man))
	if next == string(man) {
		t.Fatal("manifest edit changed nothing")
	}
	return []store.Change{{Path: "manifest.toml", Blob: []byte(next), Mode: 0o100644}}
}

// PoC 1: a pusher removes `keep` from an entry. The victim's app-owned keys
// (machine-local until now) must not reach the remote.
func TestSec2KeepRemovalLeaksLocalKeys(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b] // A pushes; B is the victim
	A.s.Guard = &apply.Guard{List: A.allows}
	B.s.Guard = &apply.Guard{List: B.allows}
	canary := secrecytest.NewCanary(t, "app-owned key")

	appKey := func() {
		cur := B.read(sec2Settings)
		i := strings.LastIndex(cur, "}")
		B.write(sec2Settings, cur[:i]+`  ,"session": {"token": "`+canary.String()+`"}`+"\n}\n")
	}
	appKey()
	w.clock.offset += 3 * time.Hour
	r := B.sync()
	t.Logf("with keep: committed=%d holds=%d", len(r.Committed), len(r.Holds))
	secrecytest.AssertRepoClean(t, w.remote, canary) // sanity: keep holds it local

	pushRaw(t, A, sec2Manifest(t, A, func(s string) string {
		return strings.Replace(s, "keep = [\"editor.*\", \"terminal.font\", 'files\\.exclude']\n", "", 1)
	}))
	before := B.main()
	r = B.sync()
	t.Logf("after keep removal: main moved=%v guardHold=%v holds=%+v", B.main() != before, holdTask(r, HoldTaskGuard) != nil, r.Holds)
	t.Logf("target has canary after apply: %v", strings.Contains(B.read(sec2Settings), canary.String()))
	if !strings.Contains(B.read(sec2Settings), canary.String()) {
		appKey() // the app writes its key again
	}
	w.clock.offset += 3 * time.Hour
	r = B.sync()
	t.Logf("next sync: committed=%d pushed=%v holds=%+v", len(r.Committed), r.Pushed, r.Holds)
	secrecytest.AssertRepoClean(t, w.remote, canary)
}

// PoC 2: same with `drop`: a dropped key is machine-local.
func TestSec2DropRemovalLeaksLocalKeys(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, func(f *fixture.Fixture) {
		// a drop-only entry: the repo owns every key but "recent"
		p := f.Root + "/manifest.toml"
		mb, _ := os.ReadFile(p)
		mb = append(mb, []byte("\n[[file]]\ntarget = \".config/app/state.json\"\nformat = \"json\"\ndrop = [\"recent\"]\nquiet = \"0s\"\n")...)
		_ = os.WriteFile(p, mb, 0o644)
		_ = os.MkdirAll(f.Root+"/files/.config/app", 0o755)
		_ = os.WriteFile(f.Root+"/files/.config/app/state.json", []byte("{\n  \"theme\": \"dark\"\n}\n"), 0o644)
	}, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.s.Guard = &apply.Guard{List: A.allows}
	B.s.Guard = &apply.Guard{List: B.allows}
	canary := secrecytest.NewCanary(t, "dropped key")
	const tgt model.Target = ".config/app/state.json"
	live := "{\n  \"theme\": \"dark\",\n  \"recent\": \"" + canary.String() + "\"\n}\n"
	B.write(tgt, live)
	w.clock.offset += 3 * time.Hour
	B.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)

	pushRaw(t, A, sec2Manifest(t, A, func(s string) string {
		return strings.Replace(s, "drop = [\"recent\"]\nquiet = \"0s\"\n", "quiet = \"0s\"\n", 1)
	}))
	r := B.sync()
	t.Logf("after drop removal: guardHold=%v holds=%+v target=%q", holdTask(r, HoldTaskGuard) != nil, r.Holds, B.read(tgt))
	if !strings.Contains(B.read(tgt), canary.String()) {
		B.write(tgt, live) // the app writes its key again
	}
	w.clock.offset += 3 * time.Hour
	r = B.sync()
	t.Logf("next sync: committed=%d pushed=%v", len(r.Committed), r.Pushed)
	secrecytest.AssertRepoClean(t, w.remote, canary)
}

// PoC 3: a pusher takes over a file yadm never wrote. Step 1 adds a keep
// entry over it (the render equals the live file, so apply records it).
// Step 2 removes keep: apply replaces the file with the pusher's source (the
// original goes to the backup directory), and once the app writes its data
// again the next auto sync commits and pushes it.
func TestSec2PreexistingFileExfiltrated(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.s.Guard = &apply.Guard{List: A.allows}
	B.s.Guard = &apply.Guard{List: B.allows}
	canary := secrecytest.NewCanary(t, "pre-existing private file")
	const tgt model.Target = ".config/app/creds.json"
	orig := "{\n  \"auth\": \"" + canary.String() + "\"\n}\n"
	B.write(tgt, orig)
	if err := os.Chmod(B.path(tgt), 0o600); err != nil {
		t.Fatal(err)
	}

	entry := "\n[[file]]\ntarget = \".config/app/creds.json\"\nformat = \"json\"\nkeep = [\"managed\"]\nmode = 0o600\nquiet = \"0s\"\n"
	ch := sec2Manifest(t, A, func(s string) string { return s + entry })
	ch = append(ch, store.Change{Path: "files/.config/app/creds.json", Blob: []byte("{}\n"), Mode: 0o100644})
	pushRaw(t, A, ch)
	r := B.sync()
	st, _ := B.eng.State.Load()
	_, managed := st.Targets[tgt]
	t.Logf("step 1: managed=%v holds=%+v content intact=%v", managed, r.Holds, B.read(tgt) == orig)

	pushRaw(t, A, sec2Manifest(t, A, func(s string) string {
		return strings.Replace(s, "keep = [\"managed\"]\nmode = 0o600\n", "mode = 0o600\n", 1)
	}))
	r = B.sync()
	t.Logf("step 2: guardHold=%v holds=%+v content intact=%v", holdTask(r, HoldTaskGuard) != nil, r.Holds, B.read(tgt) == orig)
	st, _ = B.eng.State.Load()
	info, _ := os.Stat(B.path(tgt))
	t.Logf("step 2: main=%s applied=%s state holds=%+v mode=%v content=%q", B.main(), st.Applied, st.Holds, info.Mode(), B.read(tgt))

	// The app writes its data again.
	B.write(tgt, orig)
	w.clock.offset += 3 * time.Hour
	r = B.sync()
	t.Logf("step 3: committed=%d pushed=%v holds=%+v", len(r.Committed), r.Pushed, r.Holds)
	secrecytest.AssertRepoClean(t, w.remote, canary)
}

// PoC 4: same with `volatile`: a volatile key stays machine-local.
func TestSec2VolatileRemovalLeaksLocalKeys(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, func(f *fixture.Fixture) {
		p := f.Root + "/manifest.toml"
		mb, _ := os.ReadFile(p)
		mb = append(mb, []byte("\n[[file]]\ntarget = \".config/app/state.json\"\nformat = \"json\"\nvolatile = [\"recent\"]\nquiet = \"0s\"\n")...)
		_ = os.WriteFile(p, mb, 0o644)
		_ = os.MkdirAll(f.Root+"/files/.config/app", 0o755)
		_ = os.WriteFile(f.Root+"/files/.config/app/state.json", []byte("{\n  \"theme\": \"dark\",\n  \"recent\": \"none\"\n}\n"), 0o644)
	}, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.s.Guard = &apply.Guard{List: A.allows}
	B.s.Guard = &apply.Guard{List: B.allows}
	canary := secrecytest.NewCanary(t, "volatile key")
	const tgt model.Target = ".config/app/state.json"
	live := "{\n  \"theme\": \"dark\",\n  \"recent\": \"" + canary.String() + "\"\n}\n"
	B.write(tgt, live)
	w.clock.offset += 3 * time.Hour
	B.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)

	pushRaw(t, A, sec2Manifest(t, A, func(s string) string {
		return strings.Replace(s, "volatile = [\"recent\"]\nquiet = \"0s\"\n", "quiet = \"0s\"\n", 1)
	}))
	r := B.sync()
	if holdTask(r, HoldTaskGuard) == nil {
		t.Errorf("volatile removal not refused by the guard: %+v", r.Holds)
	}
	if !strings.Contains(B.read(tgt), canary.String()) {
		B.write(tgt, live)
	}
	w.clock.offset += 3 * time.Hour
	B.sync()
	secrecytest.AssertRepoClean(t, w.remote, canary)
}
