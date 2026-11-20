// Package fixture builds the synthetic multi-machine source repository from
// testdata/fixture for tests. Every name and byte in it is fake.
//
// Inputs under testdata/fixture:
//
//   - source/: the plaintext part of a source tree (fleet.toml, manifest.toml,
//     files/...). Placeholders `@@SEAL:<enclave>:<keypath>@@` and
//     `@@REGION:<enclave>:<label>@@` mark sealed values and regions.
//   - enclave-plain/<enclave>/<target>: whole files to seal into
//     sealed/<enclave>/<target>.
//   - value-plain/<enclave>/<keypath> and region-plain/<enclave>/<label>: the
//     plaintext of sealed values and regions.
//
// Every `@@CANARY@@` in plaintext inputs becomes the enclave's canary, so a
// test can prove with package secrecytest that the plaintext stays inside
// the enclave.
//
// Build generates fresh identities for every fixture machine and the recovery
// identity, writes each enclave's key log under keys/<enclave>/ (created by
// the enclave's first member, which adds the others), seals the enclave
// inputs into sealed/<enclave>/ and replaces the placeholders. Canary
// plaintext exists only in memory; nothing under Root holds it.
package fixture
