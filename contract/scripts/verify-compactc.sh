#!/usr/bin/env bash
# verify-compactc.sh — FAIL CLOSED unless the Compact 0.35.0 toolchain in <dir> is the pinned
# release, project 00047 (audit C9a).
#
# A compiler is trusted only when BOTH hold:
#   1. <dir>/artifact.zip is the release archive for this platform, by its SHA-256 (the
#      compactc-v0.35.0 release @ debb05f9 publishes no checksum file; these are GitHub's
#      per-asset sha256 values, each re-checked against a download, as in
#      docker/compactc-0.35.0.Dockerfile);
#   2. every binary a compile runs (compactc, compactc.bin, zkir, zkir-v3) is byte-identical to
#      the archive's own copy, so an extracted binary changed after the download is refused too.
# Anything that cannot be checked — an unknown platform, a missing archive, no unzip, no SHA-256
# tool — is an error, never a skip. The `compact` CLI keeps the archive beside the binaries in
# ~/.compact/versions/0.35.0/<arch>-<os>/; the pinned Docker image keeps it in /opt/compactc.
#
# usage: scripts/verify-compactc.sh <dir>     exit 0 = verified; 70 = refused
set -euo pipefail

dir="${1:?usage: verify-compactc.sh <toolchain dir>}"
fail() { echo "error: compactc 0.35.0 not verified: $*" >&2; exit 70; }

case "$(uname -m)" in
  arm64|aarch64) arch=aarch64 ;;
  x86_64|amd64) arch=x86_64 ;;
  *) fail "unknown machine '$(uname -m)': no pinned archive digest to check" ;;
esac
case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "unknown OS '$(uname -s)': no pinned archive digest to check" ;;
esac
case "$arch-$os" in
  aarch64-darwin) want=5898b3d916b2b26f2c110b55a4a4121c22c88eefbd076994e8c3dd3e56c571fc ;;
  x86_64-darwin) want=adfd3738965d758897d8038b86a5c32e5bd20fb437fc0f1cbc01c8d816b0e212 ;;
  aarch64-linux) want=3f74ec6fc98ccca7365c5c915f6015d8893db4527faafe04a90bc36effc40a3a ;;
  x86_64-linux) want=70f22fb8209cc5a8504b2b3d91796cfdab2d71d88807ceef12fab87fed03bae2 ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 | cut -d ' ' -f 1; }
else
  fail "no sha256sum or shasum on PATH"
fi
command -v unzip >/dev/null 2>&1 || fail "no unzip on PATH (needed to compare the binaries with the archive)"

zip="$dir/artifact.zip"
[[ -f "$zip" ]] || fail "$zip is missing, so its digest cannot be checked (reinstall with \`compact update 0.35.0\`, or use COMPACTC_TOOLCHAIN=docker)"
got="$(sha < "$zip")"
[[ "$got" == "$want" ]] || fail "$zip sha256 $got, expected $want ($arch-$os)"
for f in compactc compactc.bin zkir zkir-v3; do
  [[ -f "$dir/$f" ]] || fail "$dir/$f is missing"
  inzip="$(unzip -p "$zip" "$f" | sha)"
  ondisk="$(sha < "$dir/$f")"
  [[ "$inzip" == "$ondisk" ]] || fail "$dir/$f differs from the verified archive's copy"
done
echo "compactc 0.35.0 verified: $zip ($arch-$os) sha256 $got; compactc, compactc.bin, zkir, zkir-v3 match it"
