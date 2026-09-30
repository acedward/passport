#!/usr/bin/env bash
# compile-account.sh — compile contracts/account.compact with the pinned Compact toolchain
# 0.35.0 (`--feature-zkir-v3`), project 00047.
#
# WHY 0.35.0. It is the first release whose standard library has `ed25519Verify<#n>`,
# `sha512` and the Curve25519 types (ZKIR 3.1, behind `--feature-zkir-v3`), which the
# `_with_ed25519` arm is written in. The other arms compile unchanged, but EVERY circuit's
# verifier key changes (docs/ED25519-ARM.md, "Toolchain"): accounts already deployed are
# unaffected, new deployments get the new keys.
#
# WHAT IS PINNED.
#   * the compiler: `compactc --version` must print exactly $PIN (commit debb05f94). The
#     docker toolchain is built from docker/compactc-0.35.0.Dockerfile, which checks the
#     release archive's SHA-256; the host toolchain (`compact compile +0.35.0`) is checked
#     by its version line and, where the `compact` CLI keeps it, by the archive's digest.
#   * the runtime: the generated module requires compact-runtime 0.20.0, while compact-js
#     2.5.5-rc.8 and midnight-js 5.0.0-beta.7 keep 0.19.0. scripts/pin-contract-runtime.mjs
#     points the generated module (and only it) at the npm alias
#     `@midnight-ntwrk/compact-runtime-0.20` (= compact-runtime 0.20.0, integrity-pinned in
#     package-lock.json). Both runtimes share one onchain-runtime-v4 4.0.0-rc.3.
#
# The ERC20 vault package (contracts/erc20-vault) stays on 0.34.0: it is deployed and
# frozen, and this contract embeds its verifier-key fingerprints (FR-022). 0.35.0 compiles
# against the 0.34.0 callee artefacts unchanged.
#
# usage: scripts/compile-account.sh [--skip-zk]
#   env  COMPACTC_TOOLCHAIN  host (default when `compact` is on PATH) | docker | path
#                            (path: `compactc` on PATH, e.g. inside the pinned image)
#        COMPACTC_IMAGE      docker image (default passport-compactc:0.35.0; built on demand)
#        MIDNIGHT_PP         SRS directory for key generation (docker toolchain; default
#                            ~/.cache/midnight/zk-params)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

PIN="0.35.0 (debb05f94 2026-09-29)"
IMAGE="${COMPACTC_IMAGE:-passport-compactc:0.35.0}"
TOOLCHAIN="${COMPACTC_TOOLCHAIN:-}"
if [[ -z "$TOOLCHAIN" ]]; then
  if command -v compact >/dev/null 2>&1; then TOOLCHAIN=host; else TOOLCHAIN=docker; fi
fi

flags=(--feature-zkir-v3)
[[ "${1:-}" == "--skip-zk" ]] && flags+=(--skip-zk)

bash scripts/link-callees.sh

case "$TOOLCHAIN" in
  host)
    got="$(compact compile +0.35.0 --version)"
    [[ "$got" == "$PIN" ]] || { echo "error: compactc +0.35.0 is '$got', expected '$PIN'" >&2; exit 70; }
    # The `compact` CLI keeps the downloaded release archive beside the binaries, in
    # ~/.compact/versions/0.35.0/<arch>-<os>/artifact.zip: check its digest where it exists.
    for dir in "$HOME"/.compact/versions/0.35.0/*/; do
      zip="${dir}artifact.zip"; [[ -f "$zip" ]] || continue
      case "$(basename "$dir")" in
        aarch64-darwin) want=5898b3d916b2b26f2c110b55a4a4121c22c88eefbd076994e8c3dd3e56c571fc ;;
        x86_64-darwin) want=adfd3738965d758897d8038b86a5c32e5bd20fb437fc0f1cbc01c8d816b0e212 ;;
        aarch64-linux) want=3f74ec6fc98ccca7365c5c915f6015d8893db4527faafe04a90bc36effc40a3a ;;
        x86_64-linux) want=70f22fb8209cc5a8504b2b3d91796cfdab2d71d88807ceef12fab87fed03bae2 ;;
        *) continue ;;
      esac
      got_sha="$(shasum -a 256 "$zip" | cut -d ' ' -f 1)"
      [[ "$got_sha" == "$want" ]] || { echo "error: $zip sha256 $got_sha, expected $want" >&2; exit 70; }
    done
    COMPACT_PATH=node_modules compact compile +0.35.0 "${flags[@]}" \
      --compact-path node_modules:contracts/managed contracts/account.compact contracts/managed/account
    ;;
  docker)
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
      docker build -f docker/compactc-0.35.0.Dockerfile -t "$IMAGE" docker
    fi
    got="$(docker run --rm --network none "$IMAGE" compactc --version)"
    [[ "$got" == "$PIN" ]] || { echo "error: $IMAGE compactc is '$got', expected '$PIN'" >&2; exit 70; }
    params=()
    if [[ " ${flags[*]} " != *" --skip-zk "* ]]; then
      pp="${MIDNIGHT_PP:-$HOME/.cache/midnight/zk-params}"
      params=(-v "$pp:/params:ro" -e MIDNIGHT_PP=/params)
    fi
    # The callee bundles are symlinks into the vault package (link-callees.sh), so the
    # container sees the repository at the SAME absolute path as the host does.
    for callee in contracts/erc20-vault/managed/Erc20Vault contracts/erc20-vault/managed/SignetSigner; do
      real="$(cd "$callee" && pwd -P)"
      [[ "$real" == "$here"/* ]] || params+=(-v "$real:$real:ro")
    done
    docker run --rm --network none "${params[@]}" -v "$here:$here" -w "$here" -e COMPACT_PATH=node_modules \
      "$IMAGE" compactc "${flags[@]}" --compact-path node_modules:contracts/managed \
      contracts/account.compact contracts/managed/account
    ;;
  path)
    got="$(compactc --version)"
    [[ "$got" == "$PIN" ]] || { echo "error: compactc on PATH is '$got', expected '$PIN'" >&2; exit 70; }
    COMPACT_PATH=node_modules compactc "${flags[@]}" --compact-path node_modules:contracts/managed \
      contracts/account.compact contracts/managed/account
    ;;
  *) echo "error: COMPACTC_TOOLCHAIN must be host, docker or path" >&2; exit 64 ;;
esac

node scripts/pin-contract-runtime.mjs contracts/managed/account
