#!/usr/bin/env bash
# ed25519-lax-twin.sh — build the LAX TWIN of the account contract for the ed25519 safety
# matrix (src/tests/ed25519-safety.ts), project 00047. TEST-ONLY: never deploy it.
#
# The twin is contracts/account.compact with exactly these checks removed:
#   * the seam's `R is the identity` assert and its `ed25519Verify` assert;
#   * the activation's `require_live_ed25519_key` (so an identity key can be enrolled);
#   * the two shielded withdrawals' C2 assert (`held coin colour does not match the withdrawn
#     colour`), so a prover whose witness returns a coin of another colour gets a preimage;
#   * the first line's label-shape assert (Q36: `the site label must be printable words with
#     single spaces`), so a label the circuit refuses (leading spaces) still gets a preimage.
# Everything else — arguments, message rendering, ledger operations — is identical, so a
# proof preimage the twin produces for a MALICIOUS call (a forged signature, a substituted key,
# a coin of another token) has exactly the shape the strict circuit expects, and the strict
# circuit's IR can be run on it (a proof server's /check, or /prove): that is how the matrix
# tests what a prover who skips the client could still submit.
#
# MUTATION CHECKS (each the strict contract with exactly one fix taken out; the matrix's case for
# that fix must be ACCEPTED on it, so the case fails without the fix):
#   ED25519_TWIN=c2-mutant        without the C2 asserts           contracts/managed/account-c2-mutant
#   ED25519_TWIN=q36-mutant       without the "Site: " marker (the
#                                 label is a bare first line)      contracts/managed/account-q36-mutant
#   ED25519_TWIN=q36-shape-mutant without the label-shape assert   contracts/managed/account-q36-shape-mutant
#
# usage: scripts/ed25519-lax-twin.sh   (writes contracts/managed/account-lax, JS and ZKIR only)
#   env: COMPACTC_TOOLCHAIN / COMPACTC_IMAGE as scripts/compile-account.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
twin="${ED25519_TWIN:-lax}"
case "$twin" in
  lax) out="contracts/managed/account-lax" ;;
  c2-mutant|q36-mutant|q36-shape-mutant) out="contracts/managed/account-$twin" ;;
  *) echo "ED25519_TWIN must be lax, c2-mutant, q36-mutant or q36-shape-mutant" >&2; exit 64 ;;
esac
work="${out}-src"
rm -rf "$work" && mkdir -p "$work"
cp -R contracts/modules "$work/modules"
node - "$work/account.compact" "$twin" <<'JS'
const fs = require('node:fs');
let src = fs.readFileSync('contracts/account.compact', 'utf8');
const c2 = ['  assert(coin.color == color, "held coin colour does not match the withdrawn colour");\n', '', 2];
const shape = ['  assert(r[2] && label[0] != 32, "display: the site label must be printable words with single spaces");\n', '', 1];
const marker = ['  return [...pad(6, "Site: "), ...label];\n', '  return [...label, 32, 32, 32, 32, 32, 32];\n', 1];
const cuts = {
  'c2-mutant': [c2],
  'q36-mutant': [marker],
  'q36-shape-mutant': [shape],
  lax: [
    ['  assert((curve25519PointX(sig.r) as Bytes<32>) != pad(32, ""), "R is the identity");\n', '', 1],
    ['  assert(ed25519Verify<n>(msg, sig, pk), "invalid signature");\n', '', 1],
    ['  require_live_ed25519_key(pk);\n  assert(derive_boot_commitment_with_ed25519(salt, pk) == boot, "boot commitment mismatch");\n',
     '  assert(derive_boot_commitment_with_ed25519(salt, pk) == boot, "boot commitment mismatch");\n', 1],
    c2,
    shape,
  ],
}[process.argv[3]];
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
