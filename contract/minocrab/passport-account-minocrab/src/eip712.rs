//! `modules/Eip712.compact` — the EIP-712 codec of the `evm` arm (byte contract
//! `docs/AUTH-EIP712-PASSPORT-EVM-V1.md`).
//!
//! ```text
//! digest = keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)
//! domainSeparator = keccak256(domainType ‖ nameHash ‖ versionHash ‖ addressWord(alias(account)) ‖ salt)
//! alias(account)  = slice<20>(keccak256(account), 12)
//! structHash      = keccak256(typeHash ‖ account ‖ addressWord(owner) ‖ uint64Word(authNonce) ‖ <fields> ‖ challenge)
//! ```
//!
//! THE PREIMAGES ARE LISTS OF 32-BYTE WORDS, handed to the keccak chip as an alignment of `Bytes<32>`
//! atoms plus each word's `[hi, lo]` limbs — the chip packs the bytes, so a k-word preimage costs
//! the words' construction and nothing per byte. compactc's `slice<N>([...a, ...b])` builds the
//! same bytes by explosion. The byte string hashed is identical either way: a `Bytes<32>` atom's
//! FAB bytes are the value's 32 bytes in string order. (The keccak helpers are transcribed from
//! minocrab-contracts `manager.rs`, where the same shape was proven PI-equal against compactc.)
//!
//! All ten frozen hashes are the Compact module's, byte for byte; `tests` recomputes each from its
//! type string.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr};
use minocrab_std::v3::{Vis3, B32};

use crate::byte_codec::{address_word, b32_const, low20, uint_word};

// ── Frozen constants (AUTH-EIP712-PASSPORT-EVM-V1) ──────────────────────────────────────────────

/// keccak256("EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)")
pub const DOMAIN_TYPE: [u8; 32] = [
    0x36, 0xc2, 0x5d, 0xe3, 0xe5, 0x41, 0xd5, 0xd9, 0x70, 0xf6, 0x6e, 0x42, 0x10, 0xd7, 0x28, 0x72, 0x12, 0x20, 0xff,
    0xf5, 0xc0, 0x77, 0xcc, 0x6c, 0xd0, 0x08, 0xb3, 0xa0, 0xc6, 0x2a, 0xda, 0xb7,
];
/// keccak256("Midnight Passport Account")
pub const DOMAIN_NAME: [u8; 32] = [
    0x64, 0xd1, 0xc9, 0x23, 0xe5, 0x9d, 0xa2, 0x0d, 0x02, 0xc9, 0x2d, 0xc0, 0xd6, 0xca, 0xa0, 0x86, 0x8c, 0xb5, 0xc8,
    0xab, 0x17, 0xee, 0x06, 0x58, 0xaa, 0xfc, 0x5f, 0x0b, 0x72, 0xd5, 0x6c, 0x85,
];
/// keccak256("1")
pub const DOMAIN_VERSION: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c, 0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50, 0xf5, 0xa9, 0x51,
    0x63, 0x7e, 0x03, 0x07, 0xcd, 0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];
/// keccak256("WithdrawUnshielded(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipient,bytes32 challenge)")
pub const TYPE_WITHDRAW_UNSHIELDED: [u8; 32] = [
    0x3a, 0xac, 0xc3, 0x6e, 0x8b, 0x18, 0xcc, 0xfd, 0x9f, 0x41, 0x61, 0x29, 0xbb, 0x89, 0x18, 0xb1, 0x7f, 0x3e, 0xf1,
    0xe9, 0x0f, 0x51, 0x83, 0xb5, 0xd5, 0x2f, 0x91, 0xc0, 0xfd, 0xbb, 0x2d, 0xf8,
];
/// keccak256("WithdrawShielded(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipientCoinPublicKey,bytes32 challenge)")
pub const TYPE_WITHDRAW_SHIELDED: [u8; 32] = [
    0x7f, 0xc8, 0x13, 0x61, 0x46, 0x96, 0x96, 0xce, 0x1c, 0x85, 0x15, 0x67, 0x3e, 0x5c, 0x2c, 0xaf, 0xa8, 0xc2, 0x58,
    0xa1, 0x4a, 0x1f, 0x8a, 0xba, 0x37, 0x37, 0x30, 0xf8, 0x85, 0x34, 0x02, 0xb6,
];
/// keccak256("WithdrawShieldedToContract(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipientContract,bytes32 challenge)")
pub const TYPE_WITHDRAW_SHIELDED_TO_CONTRACT: [u8; 32] = [
    0x68, 0xbd, 0x67, 0xf8, 0xe1, 0xf8, 0x1f, 0xad, 0x3d, 0xc1, 0x2a, 0x5b, 0x0d, 0xdb, 0x47, 0x0f, 0xea, 0xe4, 0xa2,
    0xdb, 0x53, 0x8d, 0xe9, 0x04, 0x80, 0x20, 0x4b, 0xea, 0x9e, 0xaf, 0x40, 0x23,
];
/// keccak256("AppendInbox(bytes32 account,address owner,uint64 authNonce,bytes32 entryHash,bytes32 challenge)")
pub const TYPE_APPEND_INBOX: [u8; 32] = [
    0x3e, 0x6b, 0xc4, 0x42, 0xf4, 0x8f, 0xa4, 0x29, 0xc9, 0x4e, 0xe6, 0x37, 0x0d, 0xa2, 0xf6, 0xb0, 0xd1, 0x07, 0x8d,
    0xe1, 0x66, 0xb6, 0x62, 0xb8, 0x0e, 0xf8, 0x77, 0xfc, 0x11, 0xb3, 0xe5, 0x52,
];
/// keccak256("RotateEncKey(bytes32 account,address owner,uint64 authNonce,bytes32 newKey,bytes32 challenge)")
pub const TYPE_ROTATE_ENC_KEY: [u8; 32] = [
    0x5a, 0x2c, 0x31, 0xc1, 0x8a, 0x54, 0xb8, 0x84, 0x94, 0x88, 0xbc, 0xae, 0x5a, 0xf2, 0x29, 0x3b, 0xdc, 0xde, 0x10,
    0x18, 0x78, 0xe4, 0xc3, 0x6e, 0x78, 0x3d, 0xaa, 0x60, 0xa1, 0x29, 0x52, 0xa1,
];
/// keccak256("AddDevice(bytes32 account,address owner,uint64 authNonce,bytes32 newEntry,bytes32 challenge)")
pub const TYPE_ADD_DEVICE: [u8; 32] = [
    0x8f, 0xcd, 0x6e, 0x27, 0xa8, 0x8f, 0x18, 0x3f, 0xb4, 0xc2, 0xab, 0xfd, 0x19, 0x05, 0xa7, 0x91, 0xdd, 0xb0, 0x45,
    0x88, 0xb7, 0x85, 0xe9, 0x73, 0xc4, 0xdb, 0xfc, 0x12, 0xab, 0xb4, 0xd7, 0xe4,
];
/// keccak256("RemoveDevice(bytes32 account,address owner,uint64 authNonce,bytes32 entry,bytes32 challenge)")
pub const TYPE_REMOVE_DEVICE: [u8; 32] = [
    0xc1, 0x32, 0x90, 0x1a, 0xc5, 0xa7, 0x12, 0xb2, 0xc6, 0x27, 0xc8, 0xe9, 0xeb, 0x6c, 0xd5, 0x87, 0x96, 0x6f, 0xb0,
    0x21, 0x4e, 0x7b, 0xe3, 0x6c, 0xc0, 0xe3, 0x63, 0xe3, 0xb0, 0x54, 0x17, 0xd4,
];

// ── keccak over words ────────────────────────────────────────────────────────────────────────────

pub(crate) fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

/// keccak256 over a list of 32-byte words (`keccak256<Bytes<32·k>>(w0 ‖ … ‖ wk)`).
pub fn keccak_words<V: Vis3>(c: &mut Circuit3, words: &[&B32<V>]) -> B32<V> {
    let alignment = Alignment(words.iter().map(|_| atom(32)).collect());
    let mut limbs = Vec::with_capacity(words.len() * 2);
    for w in words {
        limbs.push(w.hi.erase());
        limbs.push(w.lo.erase());
    }
    let digest = c.keccak256(alignment, &limbs);
    B32::from_typed(c, digest)
}

// ── Domain ───────────────────────────────────────────────────────────────────────────────────────

/// `evm_account_alias(account)` — the low 20 bytes of keccak256 over the 32-byte Midnight address,
/// the account's EVM-shaped `verifyingContract`.
pub fn account_alias<V: Vis3>(c: &mut Circuit3, account: &B32<V>) -> Wire3<FieldT, V> {
    let digest = keccak_words(c, &[account]);
    low20(c, &digest)
}

/// `evm_domain_separator_for(account, salt)`.
pub fn domain_separator<V: Vis3>(c: &mut Circuit3, account: &B32<V>, salt: &B32<V>) -> B32<V> {
    c.region("eip712: domain separator", |c| {
        let alias = account_alias(c, account);
        let alias_word = address_word(c, alias);
        let dt = b32_const(c, &DOMAIN_TYPE);
        let dn = b32_const(c, &DOMAIN_NAME);
        let dv = b32_const(c, &DOMAIN_VERSION);
        keccak_words(c, &[&dt, &dn, &dv, &alias_word, salt])
    })
}

// ── Struct hashes ────────────────────────────────────────────────────────────────────────────────

/// The frame every Passport type shares — `typeHash, account, owner, authNonce, <fields>,
/// challenge` — hashed as one word list. `fields` are the operation's action words, already
/// encoded (a `bytes32` as itself, a `uint128` through [`uint_word`]).
pub fn struct_hash<V: Vis3>(
    c: &mut Circuit3,
    type_hash: &[u8; 32],
    account: &B32<V>,
    owner: Wire3<FieldT, V>,
    auth_nonce: Wire3<FieldT, V>,
    fields: &[&B32<V>],
    challenge: &B32<V>,
) -> B32<V> {
    c.region("eip712: struct hash", |c| {
        let th = b32_const(c, type_hash);
        let owner_word = address_word(c, owner);
        let nonce_word = uint_word(c, auth_nonce);
        let mut words: Vec<&B32<V>> = vec![&th, account, &owner_word, &nonce_word];
        words.extend_from_slice(fields);
        words.push(challenge);
        keccak_words(c, &words)
    })
}

// ── Digests ──────────────────────────────────────────────────────────────────────────────────────

/// `eip712_digest(separator, structHash)` — `keccak256<Bytes<66>>(0x19 ‖ 0x01 ‖ separator ‖
/// structHash)`.
pub fn eip712_digest<V: Vis3>(c: &mut Circuit3, separator: &B32<V>, struct_hash: &B32<V>) -> B32<V> {
    let alignment = Alignment(vec![atom(2), atom(32), atom(32)]);
    // Bytes 0x19, 0x01 in string order: the LE limb value 0x19 + 0x01·256.
    let prefix = V::from_public(c.constant(Fr::from(0x0119u64)));
    let digest = c.keccak256(
        alignment,
        &[
            prefix.erase(),
            separator.hi.erase(),
            separator.lo.erase(),
            struct_hash.hi.erase(),
            struct_hash.lo.erase(),
        ],
    );
    B32::from_typed(c, digest)
}

/// `evm_digest_append_inbox(account, salt, owner, authNonce, entryHash, challenge)`.
pub fn digest_append_inbox<V: Vis3>(
    c: &mut Circuit3,
    account: &B32<V>,
    salt: &B32<V>,
    owner: Wire3<FieldT, V>,
    auth_nonce: Wire3<FieldT, V>,
    entry_hash: &B32<V>,
    challenge: &B32<V>,
) -> B32<V> {
    let sep = domain_separator(c, account, salt);
    let sh = struct_hash(
        c,
        &TYPE_APPEND_INBOX,
        account,
        owner,
        auth_nonce,
        &[entry_hash],
        challenge,
    );
    eip712_digest(c, &sep, &sh)
}

/// `evm_digest_withdraw_shielded(account, salt, owner, authNonce, color, amount,
/// recipientCoinPublicKey, challenge)`.
#[allow(clippy::too_many_arguments)]
pub fn digest_withdraw_shielded<V: Vis3>(
    c: &mut Circuit3,
    account: &B32<V>,
    salt: &B32<V>,
    owner: Wire3<FieldT, V>,
    auth_nonce: Wire3<FieldT, V>,
    color: &B32<V>,
    amount: Wire3<FieldT, V>,
    recipient_coin_public_key: &B32<V>,
    challenge: &B32<V>,
) -> B32<V> {
    let sep = domain_separator(c, account, salt);
    let amount_word = uint_word(c, amount);
    let sh = struct_hash(
        c,
        &TYPE_WITHDRAW_SHIELDED,
        account,
        owner,
        auth_nonce,
        &[color, &amount_word, recipient_coin_public_key],
        challenge,
    );
    eip712_digest(c, &sep, &sh)
}
