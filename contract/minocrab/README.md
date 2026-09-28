# The Passport account's EVM-signed circuits in MinoCrab

This directory ports circuits of `contracts/account.compact` to [MinoCrab](https://github.com/sig-net/minocrab),
a Rust eDSL that emits ZKIR v3. Each ported circuit replaces one compactc circuit's ZKIR and keys.
The contract source, its compiled JavaScript, its witnesses and its ledger layout do not change.

| Circuit | compactc 0.34.0 | MinoCrab | Gate |
|---|---|---|---|
| `append_inbox_with_evm` | k18, 160,236 rows | **k17, 85,637 rows** | 34 probes, 0 disagreements |
| `withdraw_shielded_with_evm` | k18, 182,809 rows | **k17, 94,639 rows** | 33 probes, 0 disagreements |

The k and row counts come from Midnight's own cost model, and compactc 0.34.0's bundled
`zkir-v3 mock-compile` gives the same numbers.

## Pins

- MinoCrab `sig-net/minocrab` @ `9f4d6a62abeb882fc2987d43cd6e0ba0cfb279cd`, which pins midnight-ledger `04c9c5d9`.
- The contract: `contracts/account.compact`, sha256 `44cff904f6ed58440b2534f64c429e0d422bfae082dbe8c82465002fb50e9fcf`.
- The baseline: compactc 0.34.0 with `--feature-zkir-v3`. Its ZKIR hashes are pinned in
  `passport-account-minocrab/tests/support/baseline.rs`.
- The toolchain: Rust 1.95.0 (`rust-toolchain.toml`) in the `rust:1.95-bookworm` image, pinned by digest in
  `docker/Dockerfile`.

## Layout

The crate `passport-account-minocrab` has one module per Compact module that the ported circuits use:

| Module | Ports |
|---|---|
| `byte_codec` | `modules/ByteCodec.compact`: big-endian ABI words |
| `eip712` | `modules/Eip712.compact`: frozen type hashes, domain separator, struct hashes, digests |
| `evm` | the stdlib's secp256k1 surface: the Ethereum address, ECDSA, `require_live_k256_key` |
| `seam` | the signing path: challenge DSTs and challenges, the device entry, `require_authorised_with_evm` |
| `zswap` | the stdlib's `sendShielded` to a user recipient, folded as compactc folds it |
| `account` | the ledger block and the exported circuits |

Almost all of the row savings come from two changes:

- **Hash preimages.** compactc builds every keccak and SHA-256 preimage byte by byte. The port hands
  each hash chip the preimage's existing limbs with an alignment.
- **Big-endian words.** compactc reverses bytes by exploding them. The port uses one native
  `reverse_bytes`, or one `div_mod`.

## Running it (Docker)

```sh
scripts/gate.sh test                      # unit tests + the EIP-712 fixture check (no baseline needed)
COMPACTC_BASELINE_DIR=<managed/account/zkir> GATE_OUT_DIR=<out> scripts/gate.sh gate
scripts/gate.sh emit <out-dir>            # write the ported circuits' .zkir, print their SHA-256
```

`COMPACTC_BASELINE_DIR` is the `zkir/` directory of `npm run compile:account` (compactc 0.34.0).
The gate refuses any baseline file whose hash is not the pinned one.

## The differential gate

`tests/gate.rs` runs every probe through both artifacts with MinoCrab's transcript executor. The
executor walks the ZKIR and runs the Impact VM over a live ledger state. Honest probes must be
accepted by both, and the gate checks five things for each one:

1. the same typed input and output schema;
2. the same public-input vector and `pi_skips` on the reference preimage;
3. Midnight's `IrSource::check` accepts both;
4. a byte-identical preimage, including the communications commitment over the outputs;
5. the same post-state after replay through `QueryContext::query`.

Every tamper probe must be refused by both artifacts, in the same way. The tamper sweep covers:

- bad and foreign signatures;
- wrong or stale nonces;
- an unknown device (empty set, wrong use counter, stale epoch);
- every EIP-712 domain field and the primary type;
- a wrong entry, amount, recipient, colour or witness coin;
- the point at infinity;
- `s = 0` and `r = 0`;
- counter overflows.

A mutant port with the signature check removed makes the gate fail. That run is recorded in the
project evidence.

## Caveats

- MinoCrab is unaudited, and upstream calls it "vibe coded". The gate is the safety net: it shows
  that the port and compactc agree on every probe it runs. It does not prove them equal on every
  input.
- Nothing MinoCrab produces had run on a live network before this project. The stagenet check is a
  later phase (P3 of AA 00040).
