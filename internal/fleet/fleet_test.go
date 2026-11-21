package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

func fixtureFleet(t *testing.T) *File {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixture.Dir(), "source", FileName))
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseFixture(t *testing.T) {
	f := fixtureFleet(t)
	if got := f.Enclaves(); !reflect.DeepEqual(got, []model.EnclaveName{"client", "personal"}) {
		t.Errorf("Enclaves = %v", got)
	}
	m := f.Machines[fixture.HostC]
	if m.ID != fixture.HostC || m.Name != "host-c" || !m.HasType("client") || m.Facts["shell"] != "bash" {
		t.Errorf("machine = %+v", m)
	}
	c := f.Collectors["client-tools"]
	if c.Publish != (Publish{Mode: PublishSealed, Enclave: "client"}) || c.When != "type:client" {
		t.Errorf("collector = %+v", c)
	}
	if p := f.Collectors["packages"]; p.Publish.Mode != PublishPlain || p.Timeout.D() != 30*time.Second {
		t.Errorf("packages = %+v", p)
	}
	if f.Vocabulary().Collectors["packages"] != true || !f.Vocabulary().FactKeys["proxy"] {
		t.Error("vocabulary incomplete")
	}
	if v := f.Vocabulary(); !reflect.DeepEqual(v.Enclaves, map[string]bool{"personal": true, "client": true}) {
		t.Errorf("vocabulary enclaves = %v", v.Enclaves)
	}
}

// Collector conditions run through package cond: compound expressions and
// facts work, and an unknown name fails.
func TestCollectorWhenUsesCond(t *testing.T) {
	f := fixtureFleet(t)
	v := f.Vocabulary()
	var _ cond.Vocabulary = v
	host := func(id model.MachineID) model.Context { return model.Context{Machine: f.Machines[id]} }
	for _, c := range []struct {
		when string
		id   model.MachineID
		want bool
	}{
		{"", fixture.HostB, true},
		{"type:work & os:linux", fixture.HostC, true},
		{"type:work & os:linux", fixture.HostB, false},
		{"!type:client & fact:proxy", fixture.HostB, true},
		{"machine:laptop-a | type:client", fixture.HostA, true},
	} {
		got, err := matchWhen(c.when, v, host(c.id))
		if err != nil || got != c.want {
			t.Errorf("%q on %s = %v, %v; want %v", c.when, c.id, got, err, c.want)
		}
	}
	if _, err := matchWhen("type:nosuch", v, host(fixture.HostA)); err == nil {
		t.Error("unknown type accepted")
	}
}

// TestCollectorApplies: `task list` reads a collector's `when` the way collect
// does; a machine outside it, an unknown name or a bad `when` does not apply.
func TestCollectorApplies(t *testing.T) {
	f := fixtureFleet(t)
	host := func(id model.MachineID) model.Context { return model.Context{Machine: f.Machines[id]} }
	f.Collectors["work-only"] = CollectorDef{Command: []string{"true"}, When: "type:work & os:linux"}
	f.Collectors["everywhere"] = CollectorDef{Command: []string{"true"}}
	f.Collectors["broken"] = CollectorDef{Command: []string{"true"}, When: "type:nosuch"}
	for _, c := range []struct {
		name string
		id   model.MachineID
		want bool
	}{
		{"work-only", fixture.HostC, true},
		{"work-only", fixture.HostB, false},
		{"everywhere", fixture.HostA, true},
		{"broken", fixture.HostA, false},
		{"missing", fixture.HostA, false},
	} {
		if got := f.CollectorApplies(c.name, host(c.id)); got != c.want {
			t.Errorf("%s on %s = %v; want %v", c.name, c.id, got, c.want)
		}
	}
}

const base = `schema = 1
[types.personal]
enclave = true
[types.work]
[machines.m-1]
name = "host-a"
nicknames = ["laptop-a"]
types = ["personal"]
`

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"no schema":          strings.Replace(base, "schema = 1\n", "", 1),
		"bad schema":         strings.Replace(base, "schema = 1", "schema = 2", 1),
		"unknown top key":    base + "extra = 1\n",
		"unknown type key":   strings.Replace(base, "enclave = true", "enclave = true\ncolour = 1", 1),
		"unknown mach key":   base + "hostname = \"x\"\n",
		"unknown type":       base + "[machines.m-2]\nname = \"b\"\ntypes = [\"ghost\"]\n",
		"no types":           base + "[machines.m-2]\nname = \"b\"\ntypes = []\n",
		"no name":            base + "[machines.m-2]\ntypes = [\"work\"]\n",
		"dup name":           base + "[machines.m-2]\nname = \"host-a\"\ntypes = [\"work\"]\n",
		"nick is other name": base + "[machines.m-2]\nname = \"b\"\nnicknames = [\"host-a\"]\ntypes = [\"work\"]\n",
		"name is other id":   base + "[machines.m-2]\nname = \"m-1\"\ntypes = [\"work\"]\n",
		"own dup nickname":   base + "[machines.m-2]\nname = \"b\"\nnicknames = [\"b\"]\ntypes = [\"work\"]\n",
		"bad type name":      base + "[types.\"a/b\"]\n",
		"bad name chars":     base + "[machines.m-2]\nname = \"has space\"\ntypes = [\"work\"]\n",
		"dup machine type":   base + "[machines.m-2]\nname = \"b\"\ntypes = [\"work\", \"work\"]\n",
		"collector no cmd":   base + "[collectors.c]\ncommand = []\n",
		"collector publish":  base + "[collectors.c]\ncommand = [\"x\"]\npublish = \"public\"\n",
		"sealed non-enclave": base + "[collectors.c]\ncommand = [\"x\"]\npublish = \"sealed:work\"\n",
		"sealed unknown":     base + "[collectors.c]\ncommand = [\"x\"]\npublish = \"sealed:ghost\"\n",
		"bad timeout":        base + "[collectors.c]\ncommand = [\"x\"]\ntimeout = \"soon\"\n",
		"unknown coll key":   base + "[collectors.c]\ncommand = [\"x\"]\nshell = true\n",
		"duplicate key":      base + "[machines.m-1]\nname = \"again\"\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatalf("base: %v", err)
	}
	if _, err := Parse(nil); err == nil {
		t.Error("empty file: want error")
	}
}

func TestParseDefaultsPublishLocal(t *testing.T) {
	f, err := Parse([]byte(base + "[collectors.c]\ncommand = [\"x\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Collectors["c"].Publish.Mode != PublishLocal {
		t.Errorf("publish = %+v", f.Collectors["c"].Publish)
	}
}

func TestLookup(t *testing.T) {
	f := fixtureFleet(t)
	for _, k := range []string{"m-a1b2c3", "host-a", "laptop-a"} {
		m, err := f.Lookup(k)
		if err != nil || m.ID != fixture.HostA {
			t.Errorf("Lookup(%q) = %v, %v", k, m.ID, err)
		}
	}
	if _, err := f.Lookup("nobody"); !errors.Is(err, ErrUnknownMachine) {
		t.Errorf("unknown: %v", err)
	}
	// A hand-built file can be ambiguous; Lookup must refuse to guess.
	amb := &File{Machines: map[model.MachineID]model.Machine{
		"m-1": {Name: "x"}, "m-2": {Name: "y", Nicknames: []string{"x"}},
	}}
	if _, err := amb.Lookup("x"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("ambiguous: %v", err)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg", IdentityFile)
	id := Identity{Machine: "m-a1b2c3", Remote: "git@git.example.invalid:user/dotfiles.git", Notify: []string{"yadm-notify"}}
	if err := SaveIdentity(p, id); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode())
	}
	got, err := LoadIdentity(p)
	if err != nil || !reflect.DeepEqual(got, id) {
		t.Fatalf("LoadIdentity = %+v, %v", got, err)
	}
	for name, src := range map[string]string{
		"unknown key": "machine = \"m-1\"\nhost = \"x\"\n",
		"no machine":  "remote = \"r\"\n",
		"empty argv":  "machine = \"m-1\"\nnotify = [\"\"]\n",
	} {
		q := filepath.Join(t.TempDir(), IdentityFile)
		os.WriteFile(q, []byte(src), 0o600)
		if _, err := LoadIdentity(q); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := LoadIdentity(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent: %v", err)
	}
	a, _ := NewMachineID()
	b, _ := NewMachineID()
	if a == b || !namePattern.MatchString(string(a)) || len(a) != 14 {
		t.Errorf("NewMachineID = %q, %q", a, b)
	}
}

// fakeRunner answers from a table keyed by collector name.
type fakeRunner struct {
	res  map[string]extexec.Result
	err  map[string]error
	reqs []extexec.Request
	spec []extexec.Spec
}

func (r *fakeRunner) Run(_ context.Context, s extexec.Spec, q extexec.Request) (extexec.Result, error) {
	r.reqs = append(r.reqs, q)
	r.spec = append(r.spec, s)
	return r.res[q.Name], r.err[q.Name]
}

func collectFleet(t *testing.T) *File {
	f, err := Parse([]byte(base + `[machines.m-2]
name = "host-b"
types = ["work"]
os = "linux"
[collectors.pkgs]
command = ["pkg-tool", "list"]
publish = "plain"
[collectors.data]
command = ["data-tool"]
timeout = "5s"
[collectors.broken]
command = ["broken-tool"]
publish = "plain"
[collectors.private]
command = ["p-tool"]
when = "type:personal"
publish = "sealed:personal"
[collectors.untrusted]
command = ["u-tool"]
`))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCollect(t *testing.T) {
	f := collectFleet(t)
	r := &fakeRunner{
		res: map[string]extexec.Result{
			"pkgs":    {Items: []string{"a", "b"}},
			"data":    {Response: &extexec.Response{OK: true, Data: json.RawMessage(`{"v":1}`)}},
			"broken":  {Items: []string{"partial"}, ExitCode: 2},
			"private": {Items: []string{"secret-item"}},
		},
		err: map[string]error{"broken": errors.New("broken-tool: non-zero exit 2")},
	}
	mctx := model.Context{Machine: f.Machines["m-1"], Home: "/tmp/home-a"}
	allowed := func(name string, _ CollectorDef) bool { return name != "untrusted" }
	facts, skipped, err := CollectWith(context.Background(), f, mctx, r, allowed, extexec.Request{Source: "/src", Commit: "c1", Kind: "bogus", Name: "bogus"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(skipped, []string{"untrusted"}) {
		t.Errorf("skipped = %v", skipped)
	}
	if got := facts["pkgs"]; !reflect.DeepEqual(got.Items, []string{"a", "b"}) || got.Error != "" || got.CollectedAt.IsZero() {
		t.Errorf("pkgs = %+v", got)
	}
	if got := facts["data"]; string(got.Data) != `{"v":1}` {
		t.Errorf("data = %+v", got)
	}
	if got := facts["broken"]; got.Error == "" || got.Items != nil {
		t.Errorf("broken = %+v", got)
	}
	if _, ok := facts["untrusted"]; ok {
		t.Error("untrusted collector ran")
	}
	for i, q := range r.reqs {
		if q.Kind != extexec.KindCollector || q.Machine.ID != "m-1" || q.Home != "/tmp/home-a" || q.Source != "/src" || q.Commit != "c1" {
			t.Errorf("request %d = %+v", i, q)
		}
		want := DefaultCollectorTimeout
		if q.Name == "data" {
			want = 5 * time.Second
		}
		if r.spec[i].Timeout != want {
			t.Errorf("%s timeout = %s", q.Name, r.spec[i].Timeout)
		}
	}

	// A machine outside the `when` never runs the collector.
	r2 := &fakeRunner{}
	facts, _, _ = Collect(context.Background(), f, model.Context{Machine: f.Machines["m-2"]}, r2, allowed)
	if _, ok := facts["private"]; ok {
		t.Error("private collector ran on a machine its when excludes")
	}

	// A nil allow function allows nothing.
	r3 := &fakeRunner{}
	_, skipped, _ = Collect(context.Background(), f, mctx, r3, nil)
	if len(r3.reqs) != 0 || len(skipped) != 5 {
		t.Errorf("nil allow: ran %d, skipped %v", len(r3.reqs), skipped)
	}
}

func TestCollectCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := Collect(ctx, collectFleet(t), model.Context{}, &fakeRunner{}, func(string, CollectorDef) bool { return true })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

// End to end through the real runner: line output is normalized.
func TestCollectRealRunner(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	os.WriteFile(tool, []byte("#!/bin/sh\nprintf 'b\\n a\\n\\nb\\n'\n"), 0o755)
	f, err := Parse([]byte(base + "[collectors.c]\ncommand = [\"" + tool + "\"]\ntimeout = \"5s\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	facts, _, err := Collect(context.Background(), f, model.Context{Machine: f.Machines["m-1"], Home: t.TempDir()}, extexec.NewRunner(), func(string, CollectorDef) bool { return true })
	if err != nil || !reflect.DeepEqual(facts["c"].Items, []string{"a", "b"}) {
		t.Fatalf("facts = %+v, %v", facts, err)
	}
}

// fakeSealer reversibly "seals" by hex-encoding with a prefix. It is enough to
// prove routing: the canary must never appear in clear outside Sealed.
type fakeSealer struct{ members map[model.EnclaveName]bool }

func (s fakeSealer) CanOpen(e model.EnclaveName) bool { return s.members[e] }
func (s fakeSealer) SealValue(e model.EnclaveName, k string, pt []byte) (string, error) {
	out := make([]byte, len(pt))
	for i, c := range pt {
		out[i] = c ^ 0x5a
	}
	return "sealed:" + string(e) + ":" + string(bytes.ToUpper([]byte(hexStr(out)))), nil
}
func (s fakeSealer) OpenValue(e model.EnclaveName, k, tok string) ([]byte, error) {
	h := strings.TrimPrefix(tok, "sealed:"+string(e)+":")
	b := unhex(strings.ToLower(h))
	for i := range b {
		b[i] ^= 0x5a
	}
	return b, nil
}

func hexStr(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func unhex(s string) []byte {
	v := func(c byte) byte {
		if c >= 'a' {
			return c - 'a' + 10
		}
		return c - '0'
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = v(s[2*i])<<4 | v(s[2*i+1])
	}
	return out
}

// A sealed collector's output, including its error text, never reaches the
// plain part of a status record, and never reaches a non-member's tree or a
// repository's object store. When the machine cannot seal, the fact is
// dropped rather than published plain.
func TestPublishedSecrecy(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	f := collectFleet(t)
	facts := map[string]model.ObservedFact{
		"pkgs":    {Collector: "pkgs", Items: []string{"tool-one"}},
		"data":    {Collector: "data", Items: []string{"local-only"}},
		"private": {Collector: "private", Items: []string{canary.String()}, Error: "stderr echoed " + canary.String()},
		"gone":    {Collector: "gone", Items: []string{"undeclared"}},
	}
	for _, tc := range []struct {
		name   string
		sealer FactSealer
	}{
		{"member", fakeSealer{members: map[model.EnclaveName]bool{"personal": true}}},
		{"non-member", fakeSealer{}},
		{"nil", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, sealed, problems := Published(f, facts, tc.sealer)
			if !reflect.DeepEqual(keys(plain), []string{"pkgs"}) {
				t.Errorf("plain = %v", keys(plain))
			}
			if tc.name == "member" {
				if len(sealed) != 1 || len(problems) != 0 {
					t.Fatalf("sealed=%v problems=%v", sealed, problems)
				}
				st := model.Status{Sealed: sealed}
				got, err := OpenSealed(st, "personal", tc.sealer.(fakeSealer))
				if err != nil || got["private"].Items[0] != canary.String() {
					t.Errorf("OpenSealed = %v, %v", got, err)
				}
				if _, err := OpenSealed(st, "personal", fakeSealer{}); err == nil {
					t.Error("non-member opened sealed facts")
				}
			} else if len(sealed) != 0 || len(problems) != 1 {
				t.Errorf("sealed=%v problems=%v", sealed, problems)
			}
			for _, p := range problems {
				if strings.Contains(p.Error(), canary.String()) {
					t.Error("problem text carries plaintext")
				}
			}

			// What every machine can read: the status record in a status ref.
			st := model.Status{Schema: model.StatusSchema, Machine: "m-1", Observed: plain, Sealed: sealed}
			b, _ := json.Marshal(st)
			home := t.TempDir()
			os.WriteFile(filepath.Join(home, "status.json"), b, 0o644)
			secrecytest.AssertTreeClean(t, home, canary)
			repo := t.TempDir()
			git(t, repo, "init", "-q")
			os.WriteFile(filepath.Join(repo, "status.json"), b, 0o644)
			git(t, repo, "add", "status.json")
			git(t, repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "status")
			secrecytest.AssertRepoClean(t, repo, canary)
		})
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func keys(m map[string]model.ObservedFact) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDiffObserved(t *testing.T) {
	st := map[model.MachineID]model.Status{
		"m-1": {Observed: map[string]model.ObservedFact{"pkgs": {Items: []string{"a", "b"}}}},
		"m-2": {Observed: map[string]model.ObservedFact{"pkgs": {Items: []string{"b", "c"}}}},
		"m-3": {Observed: map[string]model.ObservedFact{"pkgs": {Items: []string{"a", "b", "c"}}}},
		"m-4": {},
		"m-5": {Observed: map[string]model.ObservedFact{"pkgs": {Error: "timed out"}}},
	}
	d, err := DiffObserved(st, "pkgs")
	if err != nil {
		t.Fatal(err)
	}
	want := ObservedDiff{
		Collector: "pkgs",
		Union:     []string{"a", "b", "c"},
		Missing:   map[model.MachineID][]string{"m-1": {"c"}, "m-2": {"a"}, "m-3": {}},
		Unknown:   []model.MachineID{"m-4", "m-5"},
	}
	if !reflect.DeepEqual(d, want) {
		t.Errorf("diff = %+v\nwant %+v", d, want)
	}
	if _, err := DiffObserved(st, ""); err == nil {
		t.Error("empty collector: want error")
	}
	empty, _ := DiffObserved(nil, "pkgs")
	b, _ := json.Marshal(empty)
	if string(b) != `{"collector":"pkgs","union":[],"missing":{},"unknown":[]}` {
		t.Errorf("empty diff JSON = %s", b)
	}
}

func TestListAndPublishDue(t *testing.T) {
	f := fixtureFleet(t)
	at := time.Date(2030, 1, 2, 12, 0, 0, 0, time.UTC)
	st := map[model.MachineID]model.Status{
		fixture.HostA: {Machine: fixture.HostA, LastSync: at.Add(-time.Hour)},
		fixture.HostB: {Machine: fixture.HostB, LastSync: at.Add(-25 * time.Hour)},
		"m-ghost":     {Machine: "m-ghost", LastSync: at},
	}
	rows := List(f, st, at)
	got := map[model.MachineID]bool{}
	for _, r := range rows {
		got[r.Machine.ID] = r.Stale
	}
	want := map[model.MachineID]bool{fixture.HostA: false, fixture.HostB: true, fixture.HostC: true, "m-ghost": false}
	if !reflect.DeepEqual(got, want) || rows[0].Machine.ID != "m-a1b2c3" || rows[0].Machine.Name != "host-a" {
		t.Errorf("List = %+v", rows)
	}

	last := &model.Status{LastSync: at}
	if PublishDue(last, false, at.Add(59*time.Minute)) {
		t.Error("due too early")
	}
	if !PublishDue(last, false, at.Add(time.Hour)) || !PublishDue(last, true, at) || !PublishDue(nil, false, at) {
		t.Error("not due when it should be")
	}
}

func TestMemoryStatusRefs(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	var refs StatusRefs = NewMemoryStatusRefs("m-1", map[model.MachineID]model.Status{"m-2": {Machine: "m-2"}})
	if err := refs.Publish(ctx, model.Status{Machine: "m-2"}); err == nil {
		t.Error("published another machine's status")
	}
	if err := refs.Publish(ctx, model.Status{Machine: "m-1", LastSync: at}); err != nil {
		t.Fatal(err)
	}
	if err := refs.Publish(ctx, model.Status{Machine: "m-1", LastSync: at.Add(-time.Second)}); err == nil {
		t.Error("accepted a non-fast-forward")
	}
	all, _ := refs.ReadAll(ctx)
	if len(all) != 2 || !all["m-1"].LastSync.Equal(at) {
		t.Errorf("ReadAll = %v", all)
	}
	if StatusRef("m-1") != "refs/yadm/status/m-1" {
		t.Error("StatusRef")
	}
}

func TestParseRejectsBadCollectorWhen(t *testing.T) {
	_, err := Parse([]byte(base + `[collectors.weird]
command = ["w-tool"]
when = "nonsense"
`))
	if err == nil {
		t.Fatal("a collector with an invalid when must be rejected at parse time")
	}
}
