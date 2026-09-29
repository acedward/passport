# Vendored Compact sources

| File | Source | Licence | SHA-256 |
|---|---|---|---|
| `signet-contract.compact` | sig-net/midnight-integration `packages/signet-contract/src/signet-contract.compact` @ `v0.23.0` (`43b74e4a9432a2c0a51f312df2c5c5f03f2f6b82`), with a provenance header prepended (see its first lines) | MIT | — |
| `TokenMetadata.compact` | acedward/mip-0018-midnight-contracts `contracts/TokenMetadata.compact` @ `7d9f6596d66e3953eb6b14ce152f09169de61eda`, the reference module of MIP-0018 — copied **byte for byte**, with its own SPDX header. Project 00038 imports it into the vault (`import "./vendor/TokenMetadata" prefix TM_;`). It is a `module` with no ledger field. | Apache-2.0 | `1f1f9424f2dda6e60d6755389a6fa2822250a9a42ac3e5a391526393f82ca078` |

`tests/mip18-build-gate.test.ts` re-checks the `TokenMetadata.compact` hash.
