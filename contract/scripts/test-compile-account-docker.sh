#!/usr/bin/env bash
# test-compile-account-docker.sh — the audit R2-9 test: the docker toolchain RUNS the compiler it
# verified (/opt/compactc/compactc), never whatever `compactc` comes first on the image's PATH.
#
# From the pinned image (COMPACTC_IMAGE, default passport-compactc:0.35.0; scripts/compile-account.sh
# builds it on demand), it builds a throwaway SHADOWED image: the same /opt/compactc, verified and
# untouched, plus a fake `compactc` FIRST on PATH. The fake answers `--version` with the pinned
# version line, so a version check made through PATH passes, and otherwise compiles nothing, prints
# a marker and exits 0: the silent substitution the finding describes (a reused tag with another
# PATH). Then it requires:
#   * the fake really is first on the shadowed image's PATH (the test is not vacuous);
#   * scripts/compile-account.sh (COMPACTC_TOOLCHAIN=docker, --skip-zk) on the shadowed image
#     compiles with the REAL compiler: exit 0, no marker in its output, the contract module freshly
#     written (it recompiles contracts/account.compact into contracts/managed/account, keyless).
# The throwaway image is removed on exit.
#
# usage: scripts/test-compile-account-docker.sh [compile script]   (default scripts/compile-account.sh;
#        another copy of the script, placed in scripts/, shows the result before the fix)
#   env  COMPACTC_IMAGE  the pinned image (default passport-compactc:0.35.0)
#        SHADOW_TAG      the throwaway image's tag (default passport-compactc-shadowed:r2-9-<pid>)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
script="${1:-scripts/compile-account.sh}"
base="${COMPACTC_IMAGE:-passport-compactc:0.35.0}"
shadow="${SHADOW_TAG:-passport-compactc-shadowed:r2-9-$$}"
PIN="0.35.0 (debb05f94 2026-09-29)"
MARK="SHADOW-COMPACTC-RAN"
tmp="$(mktemp -d)"
trap 'docker image rm -f "$shadow" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
pass=0
ok() { echo "  ✓ $1"; pass=$((pass + 1)); }
no() { echo "  ✗ $1" >&2; exit 1; }

if ! docker image inspect "$base" >/dev/null 2>&1; then
  docker build -f docker/compactc-0.35.0.Dockerfile -t "$base" docker
fi
echo "── a shadowed image: $base plus a fake compactc first on PATH ($shadow)"
docker build -q -t "$shadow" - >/dev/null <<EOF
FROM $base
RUN mkdir -p /shadow && printf '%s\n' '#!/bin/sh' \
    'if [ "\$1" = "--version" ]; then echo "$PIN"; exit 0; fi' \
    'echo "$MARK \$*"; exit 0' > /shadow/compactc && chmod +x /shadow/compactc
ENV PATH="/shadow:\${PATH}"
EOF
first="$(docker run --rm --network none "$shadow" sh -c 'command -v compactc')"
[[ "$first" == /shadow/compactc ]] && ok "the image's PATH runs the fake first ($first)" || no "the fake is not first on PATH ($first)"
[[ "$(docker run --rm --network none "$shadow" compactc --version)" == "$PIN" ]] \
  && ok 'the fake answers --version with the pinned line (a PATH-based version check passes)' || no 'the fake does not answer --version'

echo "── $script, COMPACTC_TOOLCHAIN=docker, on the shadowed image"
touch "$tmp/start"
sleep 1
set +e
out="$(COMPACTC_TOOLCHAIN=docker COMPACTC_IMAGE="$shadow" bash "$script" --skip-zk 2>&1)"
code=$?
set -e
fresh="$(find contracts/managed/account/contract/index.js -newer "$tmp/start" 2>/dev/null || true)"
[[ "$out" != *"$MARK"* ]] && ok 'the fake never ran' || no "the compile ran the fake compactc from PATH: $(grep "$MARK" <<<"$out" | head -1)"
[[ "$code" == 0 && -n "$fresh" ]] && ok "the verified /opt/compactc/compactc compiled the contract (exit 0, module rewritten)" \
  || no "compile exit $code, module rewritten: ${fresh:-no} ($(tail -3 <<<"$out"))"
echo "◆ test-compile-account-docker: PASS ($pass checks)"
