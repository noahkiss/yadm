// Package secrecytest is the test harness for the secrecy guarantee: an
// enclave's plaintext never reaches a machine outside that enclave, and never
// reaches the git object store.
//
// Use it in every test that touches encryption, key handling or what a
// machine receives:
//
//	c := secrecytest.NewCanary(t, "personal")
//	// ... put c.Bytes() into an enclave file in a fixture, sync, apply as a non-member ...
//	secrecytest.AssertTreeClean(t, nonMemberHome, c)
//	secrecytest.AssertRepoClean(t, sourceClone, c)
//	secrecytest.AssertRepoClean(t, bareRemote, c)
//
// AssertRepoClean reads every object through git (so compressed and packed
// objects are inflated), every ref including notes, the reflogs, the config
// and the raw files under .git. It also fails when the repository enables a
// textconv cache or holds a refs/notes/textconv ref, because a cached textconv
// writes plaintext into the object store.
package secrecytest
