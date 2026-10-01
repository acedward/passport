#!/usr/bin/env bash
# ed25519-lax-twin.sh — build the LAX TWIN of the account contract for the ed25519 safety
# matrix (src/tests/ed25519-safety.ts), project 00047. TEST-ONLY: never deploy it.
#
# The twin is contracts/account.compact with exactly these checks removed:
#   * the seam's `R is the identity` assert and its `ed25519Verify` assert;
#   * the activation's `require_live_ed25519_key` (so an identity key can be enrolled);
#   * the two shielded withdrawals' C2 assert (`held coin colour does not match the withdrawn
#     colour`), so a prover whose witness returns a coin of another colour gets a preimage.
# Everything else — arguments, message rendering, ledger operations — is identical, so a
# proof preimage the twin produces for a MALICIOUS call (a forged signature, a substituted key,
# a coin of another token) has exactly the shape the strict circuit expects, and the strict
# circuit's IR can be run on it (a proof server's /check, or /prove): that is how the matrix
# tests what a prover who skips the client could still submit.
#
# `ED25519_TWIN=c2-mutant` builds the MUTATION CHECK instead: the strict contract with ONLY the
# C2 asserts removed (contracts/managed/account-c2-mutant), on which the matrix's C2 case must be
# ACCEPTED — the test fails without the fix.
#
# usage: scripts/ed25519-lax-twin.sh   (writes contracts/managed/account-lax, JS and ZKIR only)
#   env: COMPACTC_TOOLCHAIN / COMPACTC_IMAGE as scripts/compile-account.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
twin="${ED25519_TWIN:-lax}"
case "$twin" in
  lax) out="contracts/managed/account-lax" ;;
  c2-mutant) out="contracts/managed/account-c2-mutant" ;;
  *) echo "ED25519_TWIN must be lax or c2-mutant" >&2; exit 64 ;;
esac
work="${out}-src"
rm -rf "$work" && mkdir -p "$work"
cp -R contracts/modules "$work/modules"
node - "$work/account.compact" "$twin" <<'JS'
const fs = require('node:fs');
let src = fs.readFileSync('contracts/account.compact', 'utf8');
const c2 = ['  assert(coin.color == color, "held coin colour does not match the withdrawn colour");\n', '', 2];
const cuts = process.argv[3] === 'c2-mutant' ? [c2] : [
  ['  assert((curve25519PointX(sig.r) as Bytes<32>) != pad(32, ""), "R is the identity");\n', '', 1],
  ['  assert(ed25519Verify<n>(msg, sig, pk), "invalid signature");\n', '', 1],
  ['  require_live_ed25519_key(pk);\n  assert(derive_boot_commitment_with_ed25519(salt, pk) == boot, "boot commitment mismatch");\n',
   '  assert(derive_boot_commitment_with_ed25519(salt, pk) == boot, "boot commitment mismatch");\n', 1],
  c2,
];
for (const [cut, repl, count] of cuts) {
  if (src.split(cut).length !== count + 1) throw new Error(`expected exactly ${count}: ${cut}`);
  src = src.split(cut).join(repl);
}
fs.writeFileSync(process.argv[2], `// ${process.argv[3].toUpperCase()} TWIN: test only (scripts/ed25519-lax-twin.sh). Never deploy.\n` + src);
JS
PIN="0.35.0 (debb05f94 2026-09-29)"
# The same fail-closed toolchain check as scripts/compile-account.sh (scripts/verify-compactc.sh).
case "${COMPACTC_TOOLCHAIN:-path}" in
  path) bin="$(command -v compactc)" || { echo "no compactc on PATH" >&2; exit 70; }
        dir="$(cd "$(dirname "$bin")" && pwd -P)" ;;
  host) case "$(uname -m)" in arm64|aarch64) arch=aarch64 ;; x86_64|amd64) arch=x86_64 ;; *) arch="$(uname -m)" ;; esac
        dir="$HOME/.compact/versions/0.35.0/$arch-$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
  *) echo "COMPACTC_TOOLCHAIN must be path or host" >&2; exit 64 ;;
esac
bash scripts/verify-compactc.sh "$dir"
[[ "$("$dir/compactc" --version)" == "$PIN" ]] || { echo "compactc is not $PIN" >&2; exit 70; }
COMPACT_PATH=node_modules "$dir/compactc" --skip-zk --feature-zkir-v3 --compact-path node_modules:contracts/managed \
  "$work/account.compact" "$out"
node scripts/pin-contract-runtime.mjs "$out"
