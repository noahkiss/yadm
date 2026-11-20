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
// Build needs package crypt. Until crypt is implemented, Build skips the test.
package fixture
