package cli

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
)

// TestMachineShowsKeys: yadm machine prints this machine's public keys and
// a ready enclave add line, in JSON and in text.
func TestMachineShowsKeys(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	want := fx.Identities[fixture.HostA].Member()
	md := decode[machineData](t, yadmOK(t, "machine").Data)
	if md.Recipient != want.Recipient || md.SignKey != want.SignKey {
		t.Fatalf("machine keys: %q %q", md.Recipient, md.SignKey)
	}
	out, _, code := yadmRaw(t, "--json=false", "machine")
	if code != ExitOK || !strings.Contains(out, "recipient "+want.Recipient) || !strings.Contains(out, "enclave add host-a --enclave <enclave> --recipient "+want.Recipient+" --sign-key "+want.SignKey) {
		t.Fatalf("machine text:\n%s", out)
	}
	if !strings.Contains(out, "enclave personal: member\n") || !strings.Contains(out, "enclave client: not a member\n") {
		t.Fatalf("machine text enclaves:\n%s", out)
	}
}
