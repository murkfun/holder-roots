#!/usr/bin/env bash
# Rebuild the batch proof verifier from the circuit and compare it with contracts/src/verifiers/BatchVerifier.sol (the
# deployed, verified source): compiles circuits/batch with nargo, writes its verification key and the Solidity
# UltraHonk verifier with bb (optimized assembly, the deployed build), names the contract BatchVerifier, and compares
# the result byte for byte. Exit 0 when identical. Works in a temporary copy; nothing here is changed.
#
#   scripts/build-verifier.sh            needs nargo 1.0.0 and bb 6.0.0 on the PATH (or in ~/.nargo/bin, ~/.bb)
#   scripts/build-verifier.sh --keep     keep the temporary directory (prints its path)
#
# Install: nargo with noirup (`noirup -v 1.0.0`), bb with bbup (`bbup -v 6.0.0`), or the release tarballs of
# github.com/noir-lang/noir and github.com/AztecProtocol/aztec-packages.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:$HOME/.nargo/bin:$HOME/.bb"
NARGO_VERSION=1.0.0
BB_VERSION=6.0.0

command -v nargo >/dev/null || { echo "nargo not found (nargo $NARGO_VERSION)" >&2; exit 2; }
command -v bb >/dev/null || { echo "bb not found (bb $BB_VERSION)" >&2; exit 2; }
have_nargo=$(nargo --version | sed -n 's/^nargo version = //p')
have_bb=$(bb --version | tr -d 'v[:space:]')
[ "$have_nargo" = "$NARGO_VERSION" ] || { echo "nargo $have_nargo, need $NARGO_VERSION" >&2; exit 2; }
[ "$have_bb" = "$BB_VERSION" ] || { echo "bb $have_bb, need $BB_VERSION" >&2; exit 2; }

tmp=$(mktemp -d)
[ "${1:-}" = "--keep" ] && echo "working in $tmp" || trap 'rm -rf "$tmp"' EXIT
cp -r circuits "$tmp/"
(
  cd "$tmp/circuits/batch"
  nargo compile
  bb write_vk -b target/batch.json -o target/batch_vk -t evm
  bb write_solidity_verifier -k target/batch_vk/vk -o target/BatchVerifier.sol -t evm --optimized
)
sed -e "s/contract HonkVerifier /contract BatchVerifier /" "$tmp/circuits/batch/target/BatchVerifier.sol" > "$tmp/BatchVerifier.sol"
if cmp -s "$tmp/BatchVerifier.sol" contracts/src/verifiers/BatchVerifier.sol; then
  echo "OK: circuits/batch builds exactly contracts/src/verifiers/BatchVerifier.sol (nargo $NARGO_VERSION, bb $BB_VERSION)"
else
  echo "DIFF: the verifier built from circuits/batch differs from contracts/src/verifiers/BatchVerifier.sol" >&2
  diff <(head -c 2000 "$tmp/BatchVerifier.sol") <(head -c 2000 contracts/src/verifiers/BatchVerifier.sol) >&2 || true
  exit 1
fi
