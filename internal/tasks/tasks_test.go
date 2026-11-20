package tasks

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		glob, target string
		want         bool
	}{
		{"**", ".zshrc", true},
		{"**", ".config/a/b", true},
		{".config/**", ".config/a/b", true},
		{".config/**", ".config", true},
		{".config/**", ".configx/a", false},
		{".config/*/list", ".config/pkg/list", true},
		{".config/*/list", ".config/a/b/list", false},
		{".config/**/list", ".config/a/b/list", true},
		{".config/**/list", ".config/list", true},
		{"*.json", "a/b.json", false},
		{"**/*.json", "a/b.json", true},
		{".ssh/config", ".ssh/config", true},
		{"[", "[", false},
	}
	for _, c := range cases {
		if got := MatchGlob(c.glob, c.target); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v", c.glob, c.target, got)
		}
	}
}

func TestSelect(t *testing.T) {
	defs := map[string]manifest.TaskDef{
		"bundle":    {On: []string{".config/packages/**"}, Command: []string{"pkg-tool"}},
		"cleanup":   {OnRemove: []string{".config/old/*"}, Command: []string{"rm-tool"}},
		"bootstrap": {FirstApply: true, On: []string{".zshrc"}, Command: []string{"boot"}},
		"both":      {On: []string{"a"}, OnRemove: []string{"b"}, Command: []string{"x"}},
		"idle":      {On: []string{"never"}, Command: []string{"x"}},
	}
	ev := Event{Commit: "c1", Changed: []model.Target{".config/packages/list", ".zshrc", "a"}, Removed: []model.Target{".config/old/x", "b"}}
	sel, err := Select(defs, ev)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Selected{}
	var order []string
	for _, s := range sel {
		got[s.Name] = s
		order = append(order, s.Name)
	}
	if !reflect.DeepEqual(order, []string{"bootstrap", "both", "bundle", "cleanup"}) {
		t.Fatalf("order = %v", order)
	}
	if got["bootstrap"].Trigger != TriggerPaths || got["bundle"].Trigger != TriggerPaths || got["cleanup"].Trigger != TriggerRemove {
		t.Errorf("triggers = %+v", got)
	}
	if b := got["both"]; b.Trigger != TriggerPaths || !reflect.DeepEqual(b.Matched, []model.Target{"a", "b"}) {
		t.Errorf("both = %+v", b)
	}

	sel, _ = Select(defs, Event{FirstApply: true})
	if len(sel) != 1 || sel[0].Name != "bootstrap" || sel[0].Trigger != TriggerFirstApply || len(sel[0].Matched) != 0 {
		t.Errorf("first apply = %+v", sel)
	}
	sel, _ = Select(defs, Event{FirstApply: true, Changed: []model.Target{".zshrc"}})
	if len(sel) != 1 || sel[0].Trigger != TriggerFirstApply || !reflect.DeepEqual(sel[0].Matched, []model.Target{".zshrc"}) {
		t.Errorf("first apply with paths = %+v", sel)
	}
	if _, err := Select(map[string]manifest.TaskDef{"bad": {On: []string{"[x"}}}, ev); err == nil {
		t.Error("bad glob: want error")
	}
}

func TestDefinitionHash(t *testing.T) {
	a := manifest.TaskDef{On: []string{"x"}, Command: []string{"c"}, Timeout: model.Duration(time.Minute)}
	h1, err := DefinitionHash(a)
	if err != nil || len(h1) != 64 {
		t.Fatalf("hash = %q, %v", h1, err)
	}
	h2, _ := DefinitionHash(a)
	b := a
	b.Command = []string{"c", "--evil"}
	h3, _ := DefinitionHash(b)
	if h1 != h2 || h1 == h3 {
		t.Error("hash not stable or not sensitive to the command")
	}
	if _, err := DefinitionHash(nil); err == nil {
		t.Error("nil: want error")
	}
}

func TestFileAllowList(t *testing.T) {
	dir := t.TempDir()
	a := FileAllowList(dir)
	if a.Allowed(extexec.KindTask, "t", "h1") {
		t.Fatal("empty list allowed something")
	}
	if err := a.Allow(extexec.KindTask, "t", "h1"); err != nil {
		t.Fatal(err)
	}
	if !a.Allowed(extexec.KindTask, "t", "h1") {
		t.Error("allowed hash refused")
	}
	if a.Allowed(extexec.KindTask, "t", "h2") || a.Allowed(extexec.KindCollector, "t", "h1") || a.Allowed(extexec.KindTask, "u", "h1") {
		t.Error("allow leaked across hash, kind or name")
	}
	// A fresh instance reads the same file.
	if !FileAllowList(dir).Allowed(extexec.KindTask, "t", "h1") {
		t.Error("not persisted")
	}
	fi, _ := os.Stat(filepath.Join(dir, AllowFile))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode())
	}
	// Re-allowing a changed definition replaces the old hash.
	a.Allow(extexec.KindTask, "t", "h2")
	if a.Allowed(extexec.KindTask, "t", "h1") || !a.Allowed(extexec.KindTask, "t", "h2") {
		t.Error("changed definition not replaced")
	}
	// A corrupt file allows nothing, and Allow does not clobber it.
	os.WriteFile(filepath.Join(dir, AllowFile), []byte("{oops"), 0o600)
	if a.Allowed(extexec.KindTask, "t", "h2") {
		t.Error("corrupt file allowed")
	}
	if err := a.Allow(extexec.KindTask, "t", "h3"); err == nil {
		t.Error("Allow overwrote a corrupt file")
	}
	if FileAllowList("").Allowed(extexec.KindTask, "t", "h") || FileAllowList("").Allow(extexec.KindTask, "t", "h") == nil {
		t.Error("empty state dir must fail closed")
	}
}

// fakeExec records requests and answers per name.
type fakeExec struct {
	err   map[string]error
	reqs  []extexec.Request
	specs []extexec.Spec
	seen  map[string][]byte // staged file contents, read during the run
}

func (f *fakeExec) Run(_ context.Context, s extexec.Spec, q extexec.Request) (extexec.Result, error) {
	f.reqs = append(f.reqs, q)
	f.specs = append(f.specs, s)
	for t, p := range q.Staged {
		b, err := os.ReadFile(p)
		if err != nil {
			return extexec.Result{}, err
		}
		if f.seen == nil {
			f.seen = map[string][]byte{}
		}
		f.seen[q.Name+":"+string(t)] = b
	}
	if e := f.err[q.Name]; e != nil {
		return extexec.Result{ExitCode: 1, Duration: time.Millisecond}, e
	}
	return extexec.Result{ExitCode: 0, Duration: time.Millisecond}, nil
}

func allowAll(t *testing.T, kind extexec.Kind, defs map[string]any) AllowList {
	t.Helper()
	a := FileAllowList(t.TempDir())
	for n, d := range defs {
		h, err := DefinitionHash(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Allow(kind, n, h); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

type fakeReloader struct {
	got []manifest.Unit
	err error
}

func (f *fakeReloader) Reload(_ context.Context, u manifest.Unit, home string) error {
	f.got = append(f.got, u)
	return f.err
}

func TestRunnerRun(t *testing.T) {
	defs := map[string]manifest.TaskDef{
		"ok":        {On: []string{"a", "b"}, OnRemove: []string{"r"}, Command: []string{"ok"}},
		"fails":     {On: []string{"a"}, Command: []string{"fails"}, Timeout: model.Duration(time.Second)},
		"untrusted": {On: []string{"a"}, Command: []string{"u"}},
	}
	allow := allowAll(t, extexec.KindTask, map[string]any{"ok": defs["ok"], "fails": defs["fails"], "untrusted": manifest.TaskDef{Command: []string{"older"}}})
	ex := &fakeExec{err: map[string]error{"fails": errors.New("fails: non-zero exit 1")}}
	units := &fakeReloader{}
	r := &Runner{Exec: ex, Allow: allow, Units: units}
	ev := Event{Commit: "c1", Changed: []model.Target{"a"}, Removed: []model.Target{"r"},
		Units: []manifest.Unit{{Target: "Library/LaunchAgents/example.helper.plist", Kind: manifest.UnitLaunchd}}}
	sel, err := Select(defs, ev)
	if err != nil {
		t.Fatal(err)
	}
	res, holds := r.Run(context.Background(), ev, sel, extexec.Request{Home: "/tmp/home-a", Source: "/src", Kind: "bogus"})
	if len(holds) != 1 || holds[0].Task != "untrusted" || holds[0].Reason != model.HoldTaskUntrusted || holds[0].ID == "" || holds[0].Since.IsZero() {
		t.Fatalf("holds = %+v", holds)
	}
	if len(res) != 3 {
		t.Fatalf("results = %+v", res)
	}
	if res[0].Task != "fails" || res[0].Error == "" || res[0].ExitCode != 1 || res[0].Commit != "c1" {
		t.Errorf("fails = %+v", res[0])
	}
	if res[1].Task != "ok" || res[1].Error != "" || res[1].Trigger != TriggerPaths {
		t.Errorf("ok = %+v", res[1])
	}
	if res[2].Task != "unit:Library/LaunchAgents/example.helper.plist" || res[2].Trigger != TriggerUnit || res[2].Error != "" {
		t.Errorf("unit = %+v", res[2])
	}
	for _, q := range ex.reqs {
		if q.Kind != extexec.KindTask || q.Commit != "c1" || q.Home != "/tmp/home-a" || q.Source != "/src" {
			t.Errorf("request = %+v", q)
		}
		if q.Name == "ok" && (!reflect.DeepEqual(q.Changed, []model.Target{"a"}) || !reflect.DeepEqual(q.Removed, []model.Target{"r"}) || q.Trigger != TriggerPaths) {
			t.Errorf("ok request = %+v", q)
		}
	}
	if ex.specs[0].Timeout != time.Second || ex.specs[1].Timeout != DefaultTaskTimeout {
		t.Errorf("timeouts = %v, %v", ex.specs[0].Timeout, ex.specs[1].Timeout)
	}
	if len(units.got) != 1 {
		t.Errorf("units reloaded = %v", units.got)
	}

	// No allow list: nothing runs. A failed unit reload is recorded.
	ex2 := &fakeExec{}
	r2 := &Runner{Exec: ex2, Units: &fakeReloader{err: errors.New("boom")}}
	res, holds = r2.Run(context.Background(), ev, sel, extexec.Request{})
	if len(ex2.reqs) != 0 || len(holds) != 3 || len(res) != 1 || res[0].Error != "boom" {
		t.Errorf("nil allow: ran %d holds %d results %+v", len(ex2.reqs), len(holds), res)
	}
}

func TestGate(t *testing.T) {
	checks := map[string]manifest.CheckDef{
		"scan":      {Paths: []string{"**"}, Command: []string{"scan"}},
		"json-lint": {Paths: []string{"**/*.json"}, Command: []string{"lint"}, Timeout: model.Duration(time.Second)},
		"ssh-only":  {Paths: []string{".ssh/*"}, Command: []string{"ssh-check"}},
	}
	allow := allowAll(t, extexec.KindCheck, map[string]any{"scan": checks["scan"], "json-lint": checks["json-lint"]})
	staged := []Staged{
		{Target: ".zshrc", Scope: model.ScopeShared, Plaintext: []byte("z")},
		{Target: ".config/app/settings.json", Scope: model.ScopeShared, Plaintext: []byte("{}")},
		{Target: ".ssh/config", Scope: "personal", Plaintext: []byte("host")},
	}
	ex := &fakeExec{err: map[string]error{"json-lint": errors.New("lint: timed out")}}
	tmp := t.TempDir()
	pass, holds, verdicts := NewGateIn(checks, ex, allow, tmp).Check(context.Background(), staged, extexec.Request{Home: "/tmp/home-a"})
	if !reflect.DeepEqual(pass, []model.Target{".zshrc"}) {
		t.Errorf("pass = %v", pass)
	}
	byTarget := map[model.Target]model.Hold{}
	for _, h := range holds {
		byTarget[h.Target] = h
	}
	if h := byTarget[".config/app/settings.json"]; h.Reason != model.HoldCheckFailed || !strings.Contains(h.Detail, "json-lint") || h.ID == "" {
		t.Errorf("json hold = %+v", h)
	}
	if h := byTarget[".ssh/config"]; h.Reason != model.HoldTaskUntrusted || h.Scope != "personal" || len(h.Next) != 1 {
		t.Errorf("ssh hold = %+v", h)
	}
	if len(verdicts) != 3+1+1 {
		t.Errorf("verdicts = %+v", verdicts)
	}
	for _, q := range ex.reqs {
		if q.Kind != extexec.KindCheck || len(q.Staged) != len(q.Changed) {
			t.Errorf("check request = %+v", q)
		}
	}
	if string(ex.seen["scan:.ssh/config"]) != "host" {
		t.Errorf("check did not see staged plaintext: %q", ex.seen)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Errorf("staged files left behind: %v", ents)
	}

	// No check matches: the target passes.
	pass, holds, _ = NewGate(map[string]manifest.CheckDef{"ssh-only": checks["ssh-only"]}, ex, allow).Check(context.Background(), staged[:1], extexec.Request{})
	if len(pass) != 1 || len(holds) != 0 {
		t.Errorf("unmatched: pass=%v holds=%v", pass, holds)
	}
	// No allow list or runner: everything is held.
	for _, g := range []Gate{NewGate(nil, ex, nil), NewGate(nil, nil, allow)} {
		pass, holds, _ = g.Check(context.Background(), staged, extexec.Request{})
		if len(pass) != 0 || len(holds) != 3 || holds[0].Reason != model.HoldCheckFailed {
			t.Errorf("fail closed: pass=%v holds=%v", pass, holds)
		}
	}
	// An invalid glob holds everything.
	bad := map[string]manifest.CheckDef{"bad": {Paths: []string{"[x"}, Command: []string{"x"}}}
	pass, _, _ = NewGate(bad, ex, allow).Check(context.Background(), staged, extexec.Request{})
	if len(pass) != 0 {
		t.Errorf("invalid glob passed %v", pass)
	}
}

// Enclave plaintext a check reads lives only in the gate's private temp
// directory while the check runs, and is gone afterwards, on success, failure
// and timeout alike. The real runner is used so the timeout path kills the
// check and still removes the files.
func TestGateSecrecy(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	bin := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(bin, name)
		os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755)
		return p
	}
	// The check proves it saw the canary by exit status, and copies nothing out.
	seen := write("seen", `grep -rq YADM-CANARY "$TMPROOT" || exit 9
[ -z "$(find "$TMPROOT" -type f ! -perm 600)" ] || exit 8
[ -z "$(find "$TMPROOT" -mindepth 1 -type d ! -perm 700)" ] || exit 7`)
	fail := write("fail", `exit 1`)
	hang := write("hang", `sleep 30`)
	tmp := t.TempDir()
	t.Setenv("TMPROOT", tmp)
	staged := []Staged{{Target: ".config/notes/private.md", Scope: "personal", Plaintext: append([]byte("note "), canary.Bytes()...)}}
	for name, cmd := range map[string]string{"seen": seen, "fail": fail, "hang": hang} {
		t.Run(name, func(t *testing.T) {
			checks := map[string]manifest.CheckDef{name: {Command: []string{cmd}, Timeout: model.Duration(300 * time.Millisecond)}}
			if name == "seen" {
				checks[name] = manifest.CheckDef{Command: []string{cmd}, Timeout: model.Duration(5 * time.Second)}
			}
			allow := allowAll(t, extexec.KindCheck, map[string]any{name: checks[name]})
			home := t.TempDir()
			pass, holds, _ := NewGateIn(checks, extexec.NewRunner(), allow, tmp).Check(context.Background(), staged, extexec.Request{Home: home})
			if name == "seen" && len(pass) != 1 {
				t.Fatalf("check did not pass: %+v", holds)
			}
			if name != "seen" && (len(pass) != 0 || len(holds) != 1) {
				t.Fatalf("check passed: pass=%v holds=%v", pass, holds)
			}
			for _, h := range holds {
				if bytes.Contains([]byte(h.Detail), canary.Bytes()) {
					t.Error("hold detail carries plaintext")
				}
			}
			if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
				t.Errorf("staged dir left behind: %v", ents)
			}
			secrecytest.AssertTreeClean(t, tmp, canary)
			secrecytest.AssertTreeClean(t, home, canary)
		})
	}
}

// fakeCommander records argv and never runs anything.
type fakeCommander struct {
	argv [][]string
	fail map[string]error
}

func (f *fakeCommander) Run(_ context.Context, argv []string) ([]byte, error) {
	f.argv = append(f.argv, argv)
	return []byte("out"), f.fail[argv[1]+" "+argv[len(argv)-1]]
}

func TestReloaders(t *testing.T) {
	ctx := context.Background()
	home := "/tmp/home-a"
	plist := manifest.Unit{Target: "Library/LaunchAgents/example.helper.plist", Kind: manifest.UnitLaunchd}
	svc := manifest.Unit{Target: ".config/systemd/user/example.service", Kind: manifest.UnitSystemd}

	c := &fakeCommander{fail: map[string]error{"bootout " + home + "/" + string(plist.Target): errors.New("not loaded")}}
	r, err := NewReloader("darwin", c, 501)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reload(ctx, plist, home); err != nil {
		t.Fatalf("launchd: %v", err)
	}
	want := [][]string{
		{"launchctl", "bootout", "gui/501", home + "/Library/LaunchAgents/example.helper.plist"},
		{"launchctl", "bootstrap", "gui/501", home + "/Library/LaunchAgents/example.helper.plist"},
	}
	if !reflect.DeepEqual(c.argv, want) {
		t.Errorf("launchd argv = %v", c.argv)
	}
	if err := r.Reload(ctx, svc, home); err == nil {
		t.Error("darwin reloaded a systemd unit")
	}
	if err := r.Reload(ctx, manifest.Unit{Target: "../escape.plist", Kind: manifest.UnitLaunchd}, home); err == nil {
		t.Error("escaping target accepted")
	}
	c.fail = map[string]error{"bootstrap " + home + "/" + string(plist.Target): errors.New("exit 5")}
	if err := r.Reload(ctx, plist, home); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Errorf("bootstrap failure: %v", err)
	}

	c = &fakeCommander{}
	r, _ = NewReloader("linux", c, 0)
	if err := r.Reload(ctx, svc, home); err != nil {
		t.Fatal(err)
	}
	want = [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "restart", "example.service"}}
	if !reflect.DeepEqual(c.argv, want) {
		t.Errorf("systemd argv = %v", c.argv)
	}
	if err := r.Reload(ctx, plist, home); err == nil {
		t.Error("linux reloaded a launchd unit")
	}
	if _, err := NewReloader("plan9", c, 0); err == nil {
		t.Error("unsupported OS accepted")
	}
	if _, err := SystemReloader("windows"); err == nil {
		t.Error("SystemReloader(windows) accepted")
	}
}
