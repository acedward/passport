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

for name in Erc20Vault SignetSigner; do
  if [[ ! -d "$vault_managed/$name" ]]; then
    echo "error: $vault_managed/$name is missing — compile the vault first:" >&2
    echo "       (cd contracts/erc20-vault && npm install && npm run compile)" >&2
    exit 66
  fi
  rm -rf "$managed/$name"
  ln -s "../erc20-vault/managed/$name" "$managed/$name"
  echo "linked contracts/managed/$name -> ../erc20-vault/managed/$name"
done
