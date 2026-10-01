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
#   * the compiler, FAIL CLOSED (audit C9a): scripts/verify-compactc.sh must verify the
#     toolchain before anything is compiled — the release archive (`artifact.zip`) present and
#     equal to the pinned SHA-256 for this platform, and every binary a compile runs byte-equal
#     to the archive's copy — and `compactc --version` must print exactly $PIN (commit
#     debb05f94). A toolchain it cannot check is refused, never skipped. The host toolchain is
#     the `compact` CLI's install of 0.35.0 (~/.compact/versions/0.35.0/<arch>-<os>/, which
#     keeps the archive), run directly from that verified directory; the docker toolchain is
#     docker/compactc-0.35.0.Dockerfile, which checks the archive's SHA-256 while it builds and
#     keeps it in /opt/compactc so the same check runs in the container; `path` is a verified
#     directory on PATH (inside that image). Every branch RUNS the compiler it verified, by its
#     full path, never a `compactc` looked up on PATH again (audit R2-9): in the docker branch,
#     /opt/compactc/compactc of the image id resolved once from the tag, so neither a PATH that
#     puts another `compactc` first nor a tag moved between the steps can swap the compiler (the
#     wrapper itself puts its own directory first on PATH for compactc.bin, zkir and zkir-v3).
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
    case "$(uname -m)" in arm64|aarch64) arch=aarch64 ;; x86_64|amd64) arch=x86_64 ;; *) arch="$(uname -m)" ;; esac
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    dir="$HOME/.compact/versions/0.35.0/$arch-$os"
    bash scripts/verify-compactc.sh "$dir"
    got="$("$dir/compactc" --version)"
    [[ "$got" == "$PIN" ]] || { echo "error: $dir/compactc is '$got', expected '$PIN'" >&2; exit 70; }
    COMPACT_PATH=node_modules "$dir/compactc" "${flags[@]}" \
      --compact-path node_modules:contracts/managed contracts/account.compact contracts/managed/account
    ;;
  docker)
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
      docker build -f docker/compactc-0.35.0.Dockerfile -t "$IMAGE" docker
    fi
    # The tag is resolved ONCE: the check, the version and the compile all run this image id.
    img="$(docker image inspect -f '{{.Id}}' "$IMAGE")" || { echo "error: cannot resolve $IMAGE" >&2; exit 70; }
    # The same fail-closed check, inside the image (an image built from an older Dockerfile has
    # no /opt/compactc/artifact.zip and is refused: rebuild it).
    docker run --rm --network none -v "$here/scripts/verify-compactc.sh:/verify-compactc.sh:ro" "$img" \
      bash /verify-compactc.sh /opt/compactc \
      || { echo "error: $IMAGE is not a verified compactc 0.35.0 (rebuild: docker build -f docker/compactc-0.35.0.Dockerfile -t $IMAGE docker)" >&2; exit 70; }
    # Run the verified directory's compiler by its full path, never `compactc` from the image's PATH.
    got="$(docker run --rm --network none "$img" /opt/compactc/compactc --version)"
    [[ "$got" == "$PIN" ]] || { echo "error: $IMAGE /opt/compactc/compactc is '$got', expected '$PIN'" >&2; exit 70; }
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
    # ${params[@]+…}: an empty array under `set -u` is an error in bash 3.2 (macOS), e.g. --skip-zk.
    docker run --rm --network none ${params[@]+"${params[@]}"} -v "$here:$here" -w "$here" -e COMPACT_PATH=node_modules \
      "$img" /opt/compactc/compactc "${flags[@]}" --compact-path node_modules:contracts/managed \
      contracts/account.compact contracts/managed/account
    ;;
  path)
    bin="$(command -v compactc)" || { echo "error: no compactc on PATH" >&2; exit 70; }
    dir="$(cd "$(dirname "$bin")" && pwd -P)"
    bash scripts/verify-compactc.sh "$dir"
    got="$("$dir/compactc" --version)"
    [[ "$got" == "$PIN" ]] || { echo "error: $dir/compactc is '$got', expected '$PIN'" >&2; exit 70; }
    COMPACT_PATH=node_modules "$dir/compactc" "${flags[@]}" --compact-path node_modules:contracts/managed \
      contracts/account.compact contracts/managed/account
    ;;
  *) echo "error: COMPACTC_TOOLCHAIN must be host, docker or path" >&2; exit 64 ;;
esac

node scripts/pin-contract-runtime.mjs contracts/managed/account
