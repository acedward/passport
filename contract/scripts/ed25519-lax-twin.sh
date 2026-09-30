#!/usr/bin/env bash
# ed25519-lax-twin.sh — build the LAX TWIN of the account contract for the ed25519 safety
# matrix (src/tests/ed25519-safety.ts), project 00047. TEST-ONLY: never deploy it.
#
# The twin is contracts/account.compact with exactly three checks removed:
#   * the seam's `R is the identity` assert and its `ed25519Verify` assert;
#   * the activation's `require_live_ed25519_key` (so an identity key can be enrolled).
# Everything else — arguments, message rendering, ledger operations — is identical, so a
# proof preimage the twin produces for a MALICIOUS call (a forged signature, a substituted key)
# has exactly the shape the strict circuit expects, and the strict circuit's IR can be run on it
# (a proof server's /check, or /prove): that is how the matrix tests what a prover who skips the
# client could still submit.
#
# usage: scripts/ed25519-lax-twin.sh   (writes contracts/managed/account-lax, JS and ZKIR only)
#   env: COMPACTC_TOOLCHAIN / COMPACTC_IMAGE as scripts/compile-account.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
work="contracts/managed/account-lax-src"
rm -rf "$work" && mkdir -p "$work"
cp -R contracts/modules "$work/modules"
node - "$work/account.compact" <<'JS'
const fs = require('node:fs');
let src = fs.readFileSync('contracts/account.compact', 'utf8');
const cuts = [
  ['  assert((curve25519PointX(sig.r) as Bytes<32>) != pad(32, ""), "R is the identity");\n', ''],
  ['  assert(ed25519Verify<n>(msg, sig, pk), "invalid signature");\n', ''],
  ['  require_live_ed25519_key(pk);\n  assert(derive_boot_commitment_with_ed25519(salt, pk) == boot, "boot commitment mismatch");\n',
   '  assert(derive_boot_commitment_with_ed25519(salt, pk) == boot, "boot commitment mismatch");\n'],
];
for (const [cut, repl] of cuts) {
  if (src.split(cut).length !== 2) throw new Error(`expected exactly one: ${cut}`);
  src = src.replace(cut, repl);
}
fs.writeFileSync(process.argv[2], '// LAX TWIN: test only (scripts/ed25519-lax-twin.sh). Never deploy.\n' + src);
JS
PIN="0.35.0 (debb05f94 2026-09-29)"
case "${COMPACTC_TOOLCHAIN:-path}" in
  path) [[ "$(compactc --version)" == "$PIN" ]] || { echo "compactc is not $PIN" >&2; exit 70; }
        COMPACT_PATH=node_modules compactc --skip-zk --feature-zkir-v3 --compact-path node_modules:contracts/managed \
          "$work/account.compact" contracts/managed/account-lax ;;
  host) COMPACT_PATH=node_modules compact compile +0.35.0 --skip-zk --feature-zkir-v3 --compact-path node_modules:contracts/managed \
          "$work/account.compact" contracts/managed/account-lax ;;
  *) echo "COMPACTC_TOOLCHAIN must be path or host" >&2; exit 64 ;;
esac
node scripts/pin-contract-runtime.mjs contracts/managed/account-lax
