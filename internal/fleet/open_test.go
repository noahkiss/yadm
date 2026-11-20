package fleet

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// A member opens another machine's sealed facts and reads them in place of a
// forged plain value; a non-member reads exactly the plain facts.
func TestOpenAllAndVisible(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	f := collectFleet(t)
	member := fakeSealer{members: map[model.EnclaveName]bool{"personal": true}}
	_, sealed, _ := Published(f, map[string]model.ObservedFact{
		"private": {Collector: "private", Items: []string{canary.String()}},
	}, member)
	// A token for a collector the fleet file does not declare sealed for its
	// enclave is ignored, even though it opens.
	extra, _ := json.Marshal(map[string]model.ObservedFact{"pkgs": {Items: []string{"smuggled"}}})
	tok, _ := member.SealValue("other", sealedFactsKey, extra)
	sealed["other"] = []byte(tok)
	plain := map[string]model.ObservedFact{
		"pkgs":    {Collector: "pkgs", Items: []string{"tool-one"}},
		"private": {Collector: "private", Items: []string{"forged"}},
	}
	st := model.Status{Machine: "m-2", Observed: plain, Sealed: sealed}
	both := fakeSealer{members: map[model.EnclaveName]bool{"personal": true, "other": true}}

	opened, problems := OpenAll(f, st, both)
	if len(problems) != 0 || len(opened) != 1 || opened["personal"]["private"].Items[0] != canary.String() {
		t.Fatalf("OpenAll = %+v, %v", opened, problems)
	}
	vis := Visible(f, st, both, opened)
	if vis["private"].Items[0] != canary.String() || vis["pkgs"].Items[0] != "tool-one" {
		t.Fatalf("member view = %+v", vis)
	}

	for _, o := range []FactOpener{fakeSealer{}, nil} {
		opened, problems := OpenAll(f, st, o)
		if opened != nil || problems != nil {
			t.Fatalf("non-member OpenAll = %+v, %v", opened, problems)
		}
		if vis := Visible(f, st, o, opened); !reflect.DeepEqual(vis, plain) {
			t.Fatalf("non-member view = %+v", vis)
		}
		all, _ := WithVisible(f, map[model.MachineID]model.Status{"m-2": st}, o)
		b, _ := json.Marshal(all)
		if strings.Contains(string(b), canary.String()) || !reflect.DeepEqual(all["m-2"], st) {
			t.Fatalf("non-member WithVisible changed the record: %s", b)
		}
	}

	// A member's diff counts the opened facts.
	all, _ := WithVisible(f, map[model.MachineID]model.Status{"m-2": st}, member)
	d, err := DiffObserved(all, "private")
	if err != nil || len(d.Unknown) != 0 || len(d.Union) != 1 || d.Union[0] != canary.String() {
		t.Fatalf("member diff = %+v, %v", d, err)
	}

	// A token that fails to open is a problem without plaintext.
	bad := st
	bad.Sealed = map[model.EnclaveName][]byte{"personal": []byte("garbage")}
	if _, problems := OpenAll(f, bad, member); len(problems) != 1 || strings.Contains(problems[0].Error(), canary.String()) {
		t.Fatalf("bad token problems = %v", problems)
	}
}
