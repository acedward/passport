# Gate 0 — cross-contract mechanisms the Passport vault bridge depends on

Throwaway spike for project **00034** (`plans/00034-sub-gate0-c2c-spike.md` in
the planning workspace, spec requirement **FR-023**, success criterion
**SC-008**). It answers three questions with transaction hashes on a ledger-9
localnet, before any of the ERC20 vault fork (PR-F) or the account bridge
circuits (PR-G) are written.

| Probe | Question | Contracts |
|---|---|---|
| **G0** | Does a **depth-2** chain — root → callee → Signet singleton — land as one transaction? | `Root.forward` → `Mid.request` → `SignetSigner.signBidirectional` |
| **G0N** | Does the client re-entrancy guard refuse a cycle, and is a true `A → B → A` even buildable? | `Root.forward_to(Root)` |
| **G1** | Can a **callee** `mintShieldedToken` addressed to the **root**, claimed by the root's `receiveShielded` in the same transaction? | `Root2.claim_minted` → `Mint.mint_to` |
| **G1N** | Is the claim load-bearing (unclaimed mint refused), and does minting in a callee work at all (wallet-addressed mint lands)? | `Root2.claim_minted_noclaim`, `Root2.mint_to_wallet` |
| **G1B** | Can the root send a coin to a callee that claims it **and** calls onward, in one transaction? (the withdraw shape, FR-027) | `Root.pay_and_forward` → `Mid.take_and_request` → singleton |

Nothing here needs a secret, an EVM chain, Sepolia, stagenet or Sig Network's
fakenet MPC: `signBidirectional` only emits an event, and the mint needs no EVM.

## Provenance

- The harness (`src/node/*`, `src/tests/{runner,evidence}.ts`,
  `src/tests/value-client/*`, `src/wallet/hex.ts`) and the compose file are
  copied from `experiments/cross-contract-calls` in this repository (the
  Passport C2C experiment, FINDINGS 2026-09-03), with the endpoints moved to
  ports ≥ 10000 and a unique compose project name, because the host runs other
  stacks.
- `contracts/mid.compact`'s request construction is `submitSignatureRequest`
  from `sig-net/midnight-integration` `packages/test-caller-contract` @
  `79ce225`, trimmed to one request shape with the deployer / initialise /
  verify machinery removed.
- The Signet singleton is **not** compiled here: the published
  `@sig-net/midnight-contract@0.22.0-rc.1` `dist/managed` bundle (prover keys
  included) is copied to `contracts/managed/SignetSigner`, following the recipe
  in the sig-net ERC20 vault's own `package.json`. The declared contract type
  name IS the directory name, for both the compiler and the generated JS.

## Run

```sh
./run-gate0.sh compile        # offline: four contracts with real proving keys
./run-gate0.sh up             # localnet (claim the shared stack first!)
./run-gate0.sh probes         # g0 g0n g1 g1n g1b, in order
./run-gate0.sh down           # docker compose down -v
```

Prerequisites: Docker, Node ≥ 22, `compact` on PATH with toolchain 0.34.0,
openssl. **Host rule**: one localnet stack at a time — claim it in the
project's questions file before `up` and release it after `down`.

Probes write `evidence/*.json` here and, when `GATE0_EVIDENCE_DIR` is set (the
run script sets it), the same JSON into the project evidence folder.

## Pins

compactc 0.34.0 `--feature-zkir-v3` (language 0.26, verifier-key tag v7) ·
compact-runtime 0.19.0 · compact-js 2.5.5-rc.8 · midnight-js 5.0.0-beta.7 ·
ledger-v9 1.0.0-rc.3 · `@sig-net/midnight` and `@sig-net/midnight-contract`
0.22.0-rc.1 · node `2.1.0-2e92c4ae642c` · indexer-standalone `4.4.0-rc.2` ·
proof-server `9.0.0-rc.6`.

## Offline probes

`g0v` (verifier-key comparison) and `g0o` (runtime-level execution of every call
tree, modelled on the Passport C2C experiment's P1) need no Docker and no
network. They exist so the expensive half of the gate — the shared localnet —
is only spent on questions the runtime cannot already answer, and so an on-node
failure can be attributed to the network or the ledger rather than the circuits.
