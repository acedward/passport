#!/usr/bin/env bash
# test-verify-compactc.sh — the audit C9a test: the toolchain check fails CLOSED.
#
# From a verified Compact 0.35.0 install (default: this host's `compact` CLI install), it builds
# throwaway copies and requires scripts/verify-compactc.sh to:
#   * accept the real install;
#   * refuse a copy without its release archive (the case the old host branch silently skipped);
#   * refuse a copy whose archive is another file;
#   * refuse a copy whose zkir-v3 was changed after extraction;
#   * refuse a copy with a binary missing;
# and requires scripts/compile-account.sh (host toolchain) to stop with exit 70, before
# compiling anything, when HOME points at a toolchain without its archive.
#
# usage: scripts/test-verify-compactc.sh [verified toolchain dir]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
case "$(uname -m)" in arm64|aarch64) arch=aarch64 ;; x86_64|amd64) arch=x86_64 ;; *) arch="$(uname -m)" ;; esac
platform="$arch-$(uname -s | tr '[:upper:]' '[:lower:]')"
real="${1:-$HOME/.compact/versions/0.35.0/$platform}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pass=0
ok() { echo "  ✓ $1"; pass=$((pass + 1)); }
no() { echo "  ✗ $1" >&2; exit 1; }

expect() { # expect <exit code> <label> <dir>
  set +e
  out="$(bash scripts/verify-compactc.sh "$3" 2>&1)"
  code=$?
  set -e
  [[ "$code" == "$1" ]] && ok "$2 (exit $code: ${out:0:90})" || no "$2: exit $code, expected $1 ($out)"
}

copy() { mkdir -p "$tmp/$1" && cp -p "$real"/{compactc,compactc.bin,zkir,zkir-v3} "$tmp/$1/"; }

echo "── verify-compactc.sh on $real"
expect 0 'the real install is accepted' "$real"
copy noarchive
expect 70 'no release archive: refused, not skipped' "$tmp/noarchive"
copy wrongarchive && head -c 1024 /dev/urandom > "$tmp/wrongarchive/artifact.zip"
expect 70 'another archive: refused (digest)' "$tmp/wrongarchive"
copy tampered && cp -p "$real/artifact.zip" "$tmp/tampered/" && chmod u+w "$tmp/tampered/zkir-v3" && printf 'x' >> "$tmp/tampered/zkir-v3"
expect 70 'a binary changed after extraction: refused' "$tmp/tampered"
copy missing && cp -p "$real/artifact.zip" "$tmp/missing/" && rm -f "$tmp/missing/zkir"
expect 70 'a binary missing: refused' "$tmp/missing"

echo "── compile-account.sh (host) with a toolchain that has no archive"
mkdir -p "$tmp/home/.compact/versions/0.35.0/$platform"
cp -p "$real"/{compactc,compactc.bin,zkir,zkir-v3} "$tmp/home/.compact/versions/0.35.0/$platform/"
before="$(ls -l contracts/managed/account/contract/index.js 2>/dev/null || true)"
set +e
out="$(HOME="$tmp/home" COMPACTC_TOOLCHAIN=host bash scripts/compile-account.sh --skip-zk 2>&1)"
code=$?
set -e
after="$(ls -l contracts/managed/account/contract/index.js 2>/dev/null || true)"
[[ "$code" == 70 && "$out" == *"artifact.zip is missing"* && "$before" == "$after" ]] \
  && ok "it stops with exit 70 before compiling (${out##*error: })" \
  || no "compile-account.sh: exit $code ($out)"
echo "◆ test-verify-compactc: PASS ($pass checks)"
