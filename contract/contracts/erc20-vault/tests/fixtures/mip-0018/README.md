# MIP-0018 reference corpus (vendored, unchanged)

Copied byte for byte from the MIP-0018 reference implementation,
[`acedward/mip-0018-midnight-contracts`](https://github.com/acedward/mip-0018-midnight-contracts)
@ `7d9f6596d66e3953eb6b14ce152f09169de61eda`, licensed **Apache-2.0** (the reference's `LICENSE`).
They are test data only: `tests/token-metadata-codec.test.ts` checks this package's independent
codec (`src/token-metadata.ts`) against them.

| File here | Source file | SHA-256 |
|---|---|---|
| `simulator-events.json` | `fixtures/simulator/events.json`: 66 events the reference contracts emitted in the Compact simulator (compactc 0.34.0, runtime 0.19.0), each with its 256-byte payload and decoded fields | `a397b8c3389e5534de54100e077d379e44705be5c10263b00b866599f0cff6af` |
| `negative-payloads.json` | `fixtures/simulator/negative-payloads.json`: 32 hand-built payloads with the verdict a v1 consumer must reach (2 ignored, 14 rejected with a reason, 16 applied) | `5ab25c550a4ffdbbbee0cb6413d308d6685ab6b61b047c596306c2d496c125dc` |

The same commit's `contracts/TokenMetadata.compact` is vendored at `src/vendor/TokenMetadata.compact`
(SHA-256 `1f1f9424f2dda6e60d6755389a6fa2822250a9a42ac3e5a391526393f82ca078`).
