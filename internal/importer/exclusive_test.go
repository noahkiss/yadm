package importer

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
)

func TestCheckExclusive(t *testing.T) {
	fl := &fleet.File{
		Schema: fleet.Schema,
		Types:  map[model.TypeName]fleet.TypeDef{"work": {}, "personal": {}},
		Machines: map[model.MachineID]model.Machine{
			"m-a": {ID: "m-a", Name: "host-a", Types: []model.TypeName{"work", "personal"}, Facts: map[string]string{"hostname": "Host-A.example"}},
			"m-b": {ID: "m-b", Name: "host-b", Types: []model.TypeName{"personal"}, Facts: map[string]string{"hostname": "host-b.example"}},
		},
	}
	exclusive := "schema = 1\n" +
		"[[file]]\ntarget = \"x\"\nsource = \"files/x##class.work\"\nwhen = \"type:work\"\n" +
		"[[file]]\ntarget = \"x\"\nsource = \"files/x##class.personal\"\nwhen = \"type:personal & !type:work\"\n"
	if probs := checkExclusive([]byte(exclusive), fl); len(probs) > 0 {
		t.Errorf("exclusive manifest: %v", probs)
	}
	overlap := "schema = 1\n" +
		"[[file]]\ntarget = \"x\"\nsource = \"files/x##class.work\"\nwhen = \"type:work\"\n" +
		"[[file]]\ntarget = \"x\"\nsource = \"files/x##hostname.host-a.example\"\nwhen = \"fact:hostname=host-a.example\"\n"
	probs := checkExclusive([]byte(overlap), fl)
	if len(probs) != 1 || probs[0].Path != "x" || !strings.Contains(probs[0].Reason, "host-a") {
		t.Errorf("overlap: got %v, want one problem for x on host-a", probs)
	}
	unknown := "schema = 1\n[[file]]\ntarget = \"x\"\nwhen = \"type:client\"\n"
	if probs := checkExclusive([]byte(unknown), fl); len(probs) != 1 || !strings.Contains(probs[0].Reason, "client") {
		t.Errorf("unknown type: got %v", probs)
	}
}

func TestModeFor(t *testing.T) {
	cases := []struct {
		target string
		exec   bool
		want   fs.FileMode
	}{
		{".config/app/conf", false, 0},
		{"bin/tool", true, 0},
		{".ssh/config", false, 0o600},
		{".ssh/hook", true, 0o700},
		{".gnupg/gpg.conf", false, 0o600},
		{".sshrc", false, 0},
	}
	for _, tc := range cases {
		if got := modeFor(tc.target, tc.exec); got != tc.want {
			t.Errorf("%s exec=%v: %#o, want %#o", tc.target, tc.exec, got, tc.want)
		}
	}
}
