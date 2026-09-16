#!/usr/bin/env bash
# link-callees.sh — put the compiled callee artefacts where the compiler and the runtime
# look for them (project 00034 PR-G).
#
# The account calls the ERC20 vault fork, and the vault calls the Signet singleton. Two
# rules decide this layout, and neither is ours to choose:
#
#   * the compiler resolves a declared contract type (`contract Erc20Vault { … }`) to
#     <compact-path>/<TypeName>, so the artefact DIRECTORY NAME is the type name;
#   * the generated JavaScript of a caller imports its callee by relative path
#     (../../SignetSigner/contract/index.js), so every bundle in one call tree has to sit
#     side by side under one artefact root — here contracts/managed/.
#
# Both are symlinks into the vault package's own managed/, which is where they are built
# (`contracts/erc20-vault`: `npm run compile`). Linking rather than copying is what keeps
# ONE build of the vault in this repository: the account is compiled against the very bytes
# the vault deploy fingerprints (spec FR-022), and 700 MB of proving keys are not copied.
#
# contracts/managed/ is git-ignored, so this runs as part of `npm run compile`.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
managed="$here/contracts/managed"
vault_managed="$here/contracts/erc20-vault/managed"

mkdir -p "$managed"

# WHY A DIRECTORY OF LINKS RATHER THAN A LINKED DIRECTORY. `nodeZkConfigRegistry` — the
# provider that lets a caller's prover reach its CALLEE's keys — walks the artefact root
# with `readdir({withFileTypes: true})` and keeps only entries whose `isDirectory()` is
# true. A symlink's Dirent answers `isSymbolicLink()`, not `isDirectory()`, so a bundle
# linked as one directory is INVISIBLE to it: the compile succeeds, the deploy succeeds,
# and the first call fails with `ZKArtifactNotFoundError: No ZK artifact bundle matches the
# deployed verifier key` — which reads like a stale build and is not one. Measured on the
# G4 stack, 2026-09-16. The bundle CHECK one level down (`isArtifactBundle`) uses `fs.stat`,
# which does follow symlinks, so a real directory whose children are links is seen.
for name in Erc20Vault SignetSigner; do
  src="$vault_managed/$name"
  if [[ ! -d "$src" ]]; then
    echo "error: $src is missing — compile the vault first:" >&2
    echo "       (cd contracts/erc20-vault && npm install && npm run compile)" >&2
    exit 66
  fi
  rm -rf "$managed/$name"
  mkdir -p "$managed/$name"
  for child in "$src"/*; do
    ln -s "$child" "$managed/$name/$(basename "$child")"
  done
  echo "linked contracts/managed/$name/{$(ls "$src" | tr '\n' ',' | sed 's/,$//')} -> $src"
done
