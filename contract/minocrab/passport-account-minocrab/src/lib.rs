//! The Passport account's EVM-signed circuits (`contracts/account.compact`, sha256 `44cff904…`),
//! ported to the MinoCrab Rust eDSL (`sig-net/minocrab` @ `9f4d6a6`). AA project 00040.
//!
//! # What this is
//!
//! A MinoCrab circuit here REPLACES one compactc circuit's ZKIR and keys. Everything else about the
//! contract stays compactc's: the same `account.compact`, the same compiled JavaScript, the same
//! witnesses, the same ledger layout. So each port must be the SAME STATEMENT as the circuit it
//! replaces — same typed inputs and outputs, and the same public-input stream (the Impact op
//! transcript, the binding input and the communications commitment) on every preimage — while the
//! instruction stream underneath is free to differ. That is MinoCrab's equivalence criterion
//! (`notes/ledger-abi.org` §6), and `tests/gate.rs` holds every port to it against the compactc
//! artifact.
//!
//! # Where the rows go
//!
//! compactc builds every EIP-712 preimage byte by byte: each 32-byte word is exploded into bytes
//! and the `Bytes<N>` preimage is reconstituted 31 bytes at a time, and each `v as Bytes<8>`
//! big-endian word is a reversal by explosion. That is 79–87% of the rows of every `_with_evm`
//! circuit. Here each keccak/SHA-256 preimage is handed to the hash chip as an ALIGNMENT plus the
//! values' existing limbs (the chip packs the bytes in-chip), and the big-endian words and the
//! 20-byte slices are one `reverse_bytes` or one `div_mod` each.
//!
//! # Module map (one module per Compact module the ported circuits use)
//!
//! - [`byte_codec`] — `modules/ByteCodec.compact`: the big-endian ABI words.
//! - [`eip712`] — `modules/Eip712.compact`: frozen type hashes, the domain separator, the
//!   struct hashes and digests the wallet signs.
//! - [`evm`] — the stdlib's secp256k1 surface as `account.compact` uses it: the Ethereum address
//!   of a device key, ECDSA verification, and `require_live_k256_key`.
//! - [`seam`] — the account's signing path: the per-circuit challenge DSTs and challenges, the
//!   rolling device entry, and `require_authorised_with_evm` (the device-set check, the entry roll,
//!   the nonce and round bumps).
//! - [`zswap`] — the stdlib's `sendShielded` specialised to a user (`left`) or, for L-WD, a contract
//!   (`right`) recipient, as compactc folds each.
//! - [`account`] — the ledger block and the exported circuits.
//! - [`withdrawals`] — P4 lane L-WD: `withdraw_unshielded_with_evm` and
//!   `withdraw_shielded_to_contract_with_evm`, their challenges and digests, the unshielded
//!   mirror's debit and `sendUnshielded` to a user as compactc folds it.
//!
//! `modules/ZswapPrimitives.compact` (the coin commitment/nullifier transcriptions used by the swap
//! circuit) is not needed by any circuit ported here: the withdrawals go through the stdlib's
//! `sendShielded`, whose MinoCrab gadgets live in `minocrab-std`.

pub mod account;
pub mod byte_codec;
pub mod eip712;
pub mod evm;
pub mod seam;
pub mod withdrawals;
pub mod zswap;

/// A ported circuit's builder (the `#[circuit]` macro's zero-argument function).
pub type CircuitBuilder = fn() -> minocrab::v3::Compiled3;

/// The circuits this crate ports, by their Compact export name, with the builder that emits each.
pub fn ported() -> Vec<(&'static str, CircuitBuilder)> {
    vec![
        ("append_inbox_with_evm", account::Account::append_inbox_with_evm),
        (
            "withdraw_shielded_with_evm",
            account::Account::withdraw_shielded_with_evm,
        ),
        // L-WD (P4)
        (
            "withdraw_unshielded_with_evm",
            withdrawals::withdraw_unshielded_with_evm,
        ),
        (
            "withdraw_shielded_to_contract_with_evm",
            withdrawals::withdraw_shielded_to_contract_with_evm,
        ),
    ]
}
