# The Passport account's EVM-signed circuits in MinoCrab

This directory ports circuits of `contracts/account.compact` to [MinoCrab](https://github.com/sig-net/minocrab),
a Rust eDSL that emits ZKIR v3. Each ported circuit replaces one compactc circuit's ZKIR and keys.
The contract source, its compiled JavaScript, its witnesses and its ledger layout do not change.

| Circuit | compactc 0.34.0 | MinoCrab | Gate |
|---|---|---|---|
| `append_inbox_with_evm` | k18, 160,236 rows | **k17, 85,637 rows** | 34 probes, 0 disagreements |
| `rotate_enc_key_with_evm` | k18, 147,602 rows | **k17, 73,002 rows** | 43 probes, 0 disagreements |
| `add_device_with_evm` | k18, 147,648 rows | **k17, 73,048 rows** | 46 probes, 0 disagreements |
| `remove_device_with_evm` | k18, 151,466 rows | **k17, 76,883 rows** | 49 probes, 0 disagreements |
| `withdraw_shielded_with_evm` | k18, 182,809 rows | **k17, 94,639 rows** | 33 probes, 0 disagreements |
| `withdraw_unshielded_with_evm` | k18, 161,623 rows | **k17, 73,453 rows** | 45 probes, 0 disagreements |
| `withdraw_shielded_to_contract_with_evm` | k18, 188,532 rows | **k17, 100,362 rows** | 45 probes, 0 disagreements |

The k and row counts come from Midnight's own cost model, and compactc 0.34.0's bundled
`zkir-v3 mock-compile` gives the same numbers.

The keys come from compactc 0.34.0's own `zkir-v3 compile-many` against `bls_midnight_2p17`
(`contract/scripts/minocrab/keygen.sh`). They are not committed: `keys/SHA256SUMS` and
`keys/manifest.json` record them. On proof server 9.0.0-rc.6 a MinoCrab proof of each circuit takes
0.52–0.57× the compactc time, with half the prover key (285 MB instead of 570 MB) and about half the
peak memory, and it verifies with Midnight's verifier (`tests/proof_verify.rs`).

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
| `device` | the enc-key and device-lifecycle chips behind `rotate_enc_key`, `add_device` and `remove_device` |
| `eip712` | `modules/Eip712.compact`: frozen type hashes, domain separator, struct hashes, digests |
| `evm` | the stdlib's secp256k1 surface: the Ethereum address, ECDSA, `require_live_k256_key` |
| `seam` | the signing path: challenge DSTs and challenges, the device entry, `require_authorised_with_evm` |
| `zswap` | the stdlib's `sendShielded` to a user or a contract recipient, folded as compactc folds it |
| `account` | the ledger block and the exported circuits |
| `withdrawals` | `withdraw_unshielded` and `withdraw_shielded_to_contract` (`_with_evm`): their challenges and digests, the unshielded mirror's debit, and `sendUnshielded` to a user address as compactc folds it |

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
- for the device and enc-key circuits (`tests/lanes/l_dev.rs`, run by the same gate): the same word
  signed as another of the three operations or bound to another one's challenge DST, an entry
  already present, the `Uint<8>` count overflow, and the last-device and authorising-device rules
  (a mutant without the authorising-device check fails the gate);
- a wrong entry, amount, recipient, colour or witness coin;
- the point at infinity;
- `s = 0` and `r = 0`;
- for the withdrawals (`tests/lane_wd/`, run by the same gate): an empty or other-colour unshielded
  mirror, an overdraft, a recipient swapped for the account's own address, and a signature for
  another withdrawal type over the same words; a to-contract withdrawal to the account itself (the
  guarded auto-receive claim fires) is an honest probe;
- counter overflows.

A mutant port with the signature check removed makes the gate fail. That run is recorded in the
project evidence.

**The recipient tag decides what compactc emits.** `sendShielded` and `sendUnshielded` end with an
"auto-receive when sending to self" branch. For a literal `left(user key)` (`withdraw_shielded`) or
`right(user address)` (`withdraw_unshielded`), compactc folds the branch away entirely; for a literal
`right(contract)` (`withdraw_shielded_to_contract`) it keeps a guarded receive claim whose guard is
the bare `recipient == self` test. A guarded-off Impact still occupies public-input slots, so each
port mirrors exactly what compactc emits (`zswap::send_shielded_to_user`,
`zswap::send_shielded_to_contract`, `withdrawals::send_unshielded_to_user`), and a mutant that uses
the generic stdlib gadget fails the gate.

**The split run (`tests/lane_wd/split.rs`).** MinoCrab's executor cannot apply an honest
`withdraw_unshielded_with_evm` transcript for either artifact: its op decoder rebuilds `Bytes<32>`
atoms without normalising them, so the unused arm of the token type and of the recipient is 32 zero
bytes instead of the empty atom, and the ledger's typed effects decode refuses it (compact-runtime
normalises these values in production, and the public inputs are the same either way). When both
artifacts fail exactly there, the probe runs both circuits without their trailing kernel-effects
block through the ordinary checks (reads, mirror write, post-state), then walks both full circuits
on the reads the executor gathered and compares their public inputs, `pi_skips`, outputs and
`IrSource::check`.

## Caveats

- MinoCrab is unaudited, and upstream calls it "vibe coded". The gate is the safety net: it shows
  that the port and compactc agree on every probe it runs. It does not prove them equal on every
  input.
- Nothing MinoCrab produced had run on a live network before this project. AA 00040 checked the
  ports on Midnight stagenet (`contract/scripts/minocrab/stagenet-check.ts`). One account was deployed
  with the compactc keys, and maintenance updates replaced all 7 ported circuits' verifier keys; the
  indexer read-back is byte-equal to MinoCrab's. `append_inbox`, `withdraw_shielded` and
  `rotate_enc_key` then landed, proven with their MinoCrab keys. The live `add_device` call was
  refused at submission with the ledger's balance check (`Custom error: 138`, a fee-side error, not a
  proof error). That is still under investigation, and the other live calls wait for it.
