#!/bin/sh
# GoReleaser runs this after each binary it builds (see .goreleaser.yaml):
#
#   macos-sign.sh <goos> <binary> <identifier>
#
# It signs a darwin binary with the identity in YADM_SIGN_IDENTITY, with
# hardened runtime and a secure timestamp, which notarization requires. The
# identifier is fixed rather than left to default to the file name: macOS keys
# launch constraints and privacy grants to the signature's designated
# requirement, so it must stay the same on every release.
#
# Other targets, and every target when YADM_SIGN_IDENTITY is unset (a local
# snapshot), pass through unsigned. The release workflow sets the variable and
# asserts every darwin binary is signed, so an unsigned release cannot ship.
# YADM_SIGN_KEYCHAIN, when set, names the keychain that holds the identity.
set -eu

[ "$#" -eq 3 ] || { echo "usage: macos-sign.sh <goos> <binary> <identifier>" >&2; exit 2; }
goos=$1
bin=$2
id=$3

[ "$goos" = darwin ] || exit 0
if [ -z "${YADM_SIGN_IDENTITY:-}" ]; then
  echo "macos-sign: YADM_SIGN_IDENTITY is unset; ${bin} stays unsigned" >&2
  exit 0
fi

set -- --force --options runtime --timestamp --identifier "$id" --sign "$YADM_SIGN_IDENTITY"
if [ -n "${YADM_SIGN_KEYCHAIN:-}" ]; then
  set -- "$@" --keychain "$YADM_SIGN_KEYCHAIN"
fi
codesign "$@" "$bin"
codesign --verify --strict --verbose=2 "$bin"
