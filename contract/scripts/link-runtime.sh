#!/usr/bin/env bash
# link-runtime.sh — one Compact runtime instance across the two packages of this repository
# (project 00034 PR-G).
#
# THE PROBLEM. The account and the ERC20 vault are separate npm packages with separate
# `node_modules`, and both depend on `@midnight-ntwrk/compact-runtime`, which wraps a WASM
# module (`@midnightntwrk/onchain-runtime-v4`). Two copies mean two WASM instances and two
# sets of classes, so an object built by one is not `instanceof` the other's class. The
# account's own `src/wallet/bridge.ts` and `src/tests/bridge-offline.ts` hold the vault's
# compiled module, and a cross-contract call in the simulator executes the CALLEE's
# generated JavaScript — which resolves its runtime from the vault package. The symptom is
# unhelpful:
#
#   CompactError: 'contractState' parameter ContractState (…) has unexpected type
#
# thrown by `coerceToChargedState`, whose three `instanceof` checks all fail against a
# perfectly good ContractState of the other instance. The vault package's own
# `package.json` carries an `overrides` block for the same class of problem inside ONE
# package ("two runtime instances break WASM class identity"); this is that problem across
# two.
#
# THE FIX. Replace the vault package's copies of the two runtime packages with symlinks to
# the account's, which is what a workspace layout would have done. Node resolves a package
# through its realpath, so both trees then load one module instance. Versions must match
# exactly — if they ever diverge, this script refuses rather than silently pinning one side
# to the other's runtime.
#
# It is idempotent, it is safe to run after any `npm install` (which restores the copies),
# and it runs automatically before the offline bridge suite.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
account_modules="$here/node_modules"
vault_modules="$here/contracts/erc20-vault/node_modules"

if [[ ! -d "$vault_modules" ]]; then
  echo "the vault package has no node_modules — nothing to link" >&2
  exit 0
fi

for pkg in @midnight-ntwrk/compact-runtime @midnightntwrk/onchain-runtime-v4; do
  src="$account_modules/$pkg"
  dst="$vault_modules/$pkg"
  if [[ ! -d "$src" ]]; then
    echo "error: the account package has no $pkg — run npm install first" >&2
    exit 66
  fi
  if [[ -L "$dst" ]]; then
    echo "already linked: $pkg"
    continue
  fi
  if [[ -d "$dst" ]]; then
    a="$(node -p "require('$src/package.json').version")"
    b="$(node -p "require('$dst/package.json').version")"
    if [[ "$a" != "$b" ]]; then
      echo "error: $pkg is $a in the account package and $b in the vault package." >&2
      echo "       Align the two pins before linking; one runtime is a requirement, not a tidy-up." >&2
      exit 67
    fi
    rm -rf "$dst"
  fi
  mkdir -p "$(dirname "$dst")"
  ln -s "$src" "$dst"
  echo "linked $pkg -> the account package's copy"
done
