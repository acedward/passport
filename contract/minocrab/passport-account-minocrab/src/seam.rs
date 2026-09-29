//! The account's signing path for the `evm` arm (`account.compact`, MIP-0013 as the Passport
//! implements it):
//!
//! - the per-circuit challenge: `persistentHash([DST_CIRCUIT, self, address, ...args,
//!   ...witness_values, auth_nonce])`, where `DST_CIRCUIT = persistentHash<[Bytes<64>]>([pad(64,
//!   "midnight:account:auth:evm:v1:<circuit>")])`;
//! - the rolling device entry: `persistentHash([pad(32, "midnight:account:device:evm:v1"), self,
//!   address, device_epoch, use_counter])`;
//! - [`require_authorised_with_evm`]: the device-set membership check, the entry roll (remove the
//!   entry at `use_counter`, insert the one at `use_counter + 1`), the ECDSA check over the
//!   caller's EIP-712 digest, then `auth_nonce += 1` and `round += 1`.
//!
//! LEDGER-OP ORDER IS THE CONTRACT. Every read and write below happens in the order compactc's
//! artifact performs it (the vm-code in the compiled `contract/index.js`), including the
//! re-reads compactc does not merge — `kernel.self()` and `device_epoch` are read once per
//! derivation — because the op stream IS the public-input stream the gate compares.
//!
//! `DST_CIRCUIT` is a constant, so it is computed here, at circuit-build time (SHA-256 over the 64
//! padded bytes, which is what `persistentHash` over a lone `Bytes<64>` is), where compactc hashes
//! it in-circuit on every call. The challenge value is unchanged, and the gate's honest cases
//! would fail if it were not (the reference artifact would refuse the signature).

use minocrab::v3::AnyWire3;
use minocrab::v3::{Circuit3, FieldT, Secp256k1PointT, Wire3};
use minocrab::{Alignment, Private, Public};
use minocrab_std::v3::kernel;
use minocrab_std::v3::{is_true, Secp256k1EcdsaSignature, Uint, B32};
use sha2::{Digest, Sha256};

use crate::account::{DeviceEntry, ACCOUNT};
use crate::byte_codec::b32_const;
use crate::eip712::atom;
use crate::evm::{ecdsa_verify, require_live_k256_key};

/// `pad(32, "midnight:account:device:evm:v1")`.
pub const DST_DEVICE_EVM: &str = "midnight:account:device:evm:v1";

/// `pad(n, s)` — `s`'s bytes, zero-padded to `n`.
pub fn pad<const N: usize>(s: &str) -> [u8; N] {
    assert!(s.len() <= N, "pad({N}, {s:?}) overflows");
    let mut out = [0u8; N];
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

/// `persistentHash<[Bytes<64>]>([pad(64, "midnight:account:auth:evm:v1:<circuit>")])` — the
/// circuit's challenge DST, as bytes.
pub fn challenge_dst_bytes(circuit: &str) -> [u8; 32] {
    let tag = format!("midnight:account:auth:evm:v1:{circuit}");
    let padded: [u8; 64] = pad(&tag);
    Sha256::digest(padded).into()
}

/// The challenge DST as a constant `B32`.
pub fn challenge_dst(c: &mut Circuit3, circuit: &str) -> B32<Private> {
    b32_const(c, &challenge_dst_bytes(circuit))
}

/// `challenge_append_inbox_with_evm(self, address, entry, nonce)`:
/// `persistentHash<[Bytes<32>, ContractAddress, Bytes<20>, Bytes<192>, Uint<64>]>`.
pub fn challenge_append_inbox(
    c: &mut Circuit3,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    entry: &[Wire3<FieldT, Private>],
    nonce: Wire3<FieldT, Private>,
) -> B32<Private> {
    c.region("seam: challenge", |c| {
        let dst = challenge_dst(c, "append_inbox");
        let alignment = Alignment(vec![atom(32), atom(32), atom(20), atom(192), atom(8)]);
        let mut slots = vec![
            dst.hi.erase(),
            dst.lo.erase(),
            me.hi.erase(),
            me.lo.erase(),
            address.erase(),
        ];
        slots.extend(entry.iter().map(|w| w.erase()));
        slots.push(nonce.erase());
        let digest = c.persistent_hash(alignment, &slots);
        B32::from_typed(c, digest)
    })
}

// ── L-DEV (P4): the enc-key and device-lifecycle challenges ─────────────────────────────────────
//
// `rotate_enc_key`, `add_device` and `remove_device` share ONE preimage shape,
// `persistentHash<[Bytes<32>, ContractAddress, Bytes<20>, Bytes<32>, Uint<64>]>([dst, self_addr,
// address, <word>, nonce_value])`; only the DST tag and the meaning of the `Bytes<32>` differ
// (`new_key`, `new_entry`, `entry`).

/// The shared body of the three one-word challenges.
fn challenge_one_word(
    c: &mut Circuit3,
    circuit: &str,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    word: &B32<Private>,
    nonce: Wire3<FieldT, Private>,
) -> B32<Private> {
    c.region("seam: challenge", |c| {
        let dst = challenge_dst(c, circuit);
        let alignment = Alignment(vec![atom(32), atom(32), atom(20), atom(32), atom(8)]);
        let digest = c.persistent_hash(
            alignment,
            &[
                dst.hi.erase(),
                dst.lo.erase(),
                me.hi.erase(),
                me.lo.erase(),
                address.erase(),
                word.hi.erase(),
                word.lo.erase(),
                nonce.erase(),
            ],
        );
        B32::from_typed(c, digest)
    })
}

/// `challenge_rotate_enc_key_with_evm(self, address, new_key, nonce)`.
pub fn challenge_rotate_enc_key(
    c: &mut Circuit3,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    new_key: &B32<Private>,
    nonce: Wire3<FieldT, Private>,
) -> B32<Private> {
    challenge_one_word(c, "rotate_enc_key", me, address, new_key, nonce)
}

/// `challenge_add_device_with_evm(self, address, new_entry, nonce)`.
pub fn challenge_add_device(
    c: &mut Circuit3,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    new_entry: &B32<Private>,
    nonce: Wire3<FieldT, Private>,
) -> B32<Private> {
    challenge_one_word(c, "add_device", me, address, new_entry, nonce)
}

/// `challenge_remove_device_with_evm(self, address, entry, nonce)`.
pub fn challenge_remove_device(
    c: &mut Circuit3,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    entry: &B32<Private>,
    nonce: Wire3<FieldT, Private>,
) -> B32<Private> {
    challenge_one_word(c, "remove_device", me, address, entry, nonce)
}

// ── end L-DEV ────────────────────────────────────────────────────────────────────────────────────

/// The `QualifiedShieldedCoinInfo` a challenge binds — `nonce, color, value, mt_index`.
#[derive(Clone, Copy)]
pub struct CoinSlots<V: minocrab_std::v3::Vis3> {
    pub nonce: B32<V>,
    pub color: B32<V>,
    pub value: Wire3<FieldT, V>,
    pub mt_index: Wire3<FieldT, V>,
}

/// `challenge_withdraw_shielded_with_evm(self, address, recipient, color, amount, coin, nonce)`:
/// `persistentHash<[Bytes<32>, ContractAddress, Bytes<20>, ZswapCoinPublicKey, Bytes<32>,
/// Uint<128>, QualifiedShieldedCoinInfo, Uint<64>]>`.
#[allow(clippy::too_many_arguments)]
pub fn challenge_withdraw_shielded(
    c: &mut Circuit3,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    recipient: &B32<Private>,
    color: &B32<Private>,
    amount: Wire3<FieldT, Private>,
    coin: &CoinSlots<Private>,
    nonce: Wire3<FieldT, Private>,
) -> B32<Private> {
    c.region("seam: challenge", |c| {
        let dst = challenge_dst(c, "withdraw_shielded");
        let alignment = Alignment(vec![
            atom(32),
            atom(32),
            atom(20),
            atom(32),
            atom(32),
            atom(16),
            atom(32),
            atom(32),
            atom(16),
            atom(8),
            atom(8),
        ]);
        let slots = [
            dst.hi.erase(),
            dst.lo.erase(),
            me.hi.erase(),
            me.lo.erase(),
            address.erase(),
            recipient.hi.erase(),
            recipient.lo.erase(),
            color.hi.erase(),
            color.lo.erase(),
            amount.erase(),
            coin.nonce.hi.erase(),
            coin.nonce.lo.erase(),
            coin.color.hi.erase(),
            coin.color.lo.erase(),
            coin.value.erase(),
            coin.mt_index.erase(),
            nonce.erase(),
        ];
        let digest = c.persistent_hash(alignment, &slots);
        B32::from_typed(c, digest)
    })
}

/// `derive_device_entry_with_evm(self, address, epoch, counter)`:
/// `persistentHash<[Bytes<32>, ContractAddress, Bytes<20>, Uint<32>, Uint<64>]>`.
pub fn device_entry_evm(
    c: &mut Circuit3,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    epoch: Wire3<FieldT, Private>,
    counter: Wire3<FieldT, Private>,
) -> B32<Private> {
    c.region("seam: device entry", |c| {
        let dst: B32<Private> = b32_const(c, &pad::<32>(DST_DEVICE_EVM));
        let alignment = Alignment(vec![atom(32), atom(32), atom(20), atom(4), atom(8)]);
        let digest = c.persistent_hash(
            alignment,
            &[
                dst.hi.erase(),
                dst.lo.erase(),
                me.hi.erase(),
                me.lo.erase(),
                address.erase(),
                epoch.erase(),
                counter.erase(),
            ],
        );
        B32::from_typed(c, digest)
    })
}

/// `kernel.self().bytes` as a private operand (the hashes it enters are private).
pub fn self_bytes(c: &mut Circuit3) -> B32<Private> {
    kernel::self_address(c).bytes().private()
}

/// `(v + 1) as Uint<64>` — the add, then the cast's range check (a counter at `2^64 - 1` makes the
/// proof unsatisfiable, as in compactc).
pub fn succ_u64<V: minocrab_std::v3::Vis3>(c: &mut Circuit3, v: Wire3<FieldT, V>) -> Uint<64, V> {
    let one = V::from_public(c.constant(1u64));
    let sum = c.add(v, one);
    Uint::<64, V>::from_field_checked(c, sum)
}

/// `bump_round()` — `round = (round + 1) as Uint<64>`.
pub fn bump_round(c: &mut Circuit3) {
    let r = ACCOUNT.round.read(c).stale(c);
    let next = succ_u64(c, r.field());
    ACCOUNT.round.write(c, &next);
}

/// `require_authorised_with_evm(pk, use_counter, sig, digest, address)`.
///
/// `address` is the caller's `secp256k1EthereumAddress(pk)` — the same value it put in the
/// struct's `owner` field — exactly as in the Compact source (one address derivation per call).
pub fn require_authorised_with_evm(
    c: &mut Circuit3,
    pk: Wire3<Secp256k1PointT, Private>,
    use_counter: Uint<64, Private>,
    sig: &Secp256k1EcdsaSignature<Private>,
    digest: &B32<Private>,
    address: Wire3<FieldT, Private>,
) {
    c.region("seam: require_authorised_with_evm", |c| {
        require_live_k256_key(c, pk);

        // const entry = disclose(derive_device_entry_with_evm(kernel.self(), address, device_epoch,
        //                                                     use_counter));
        let me = self_bytes(c);
        let epoch = ACCOUNT.device_epoch.read(c).stale(c);
        let entry = device_entry_evm(c, &me, address, epoch.field().private(), use_counter.field());
        let entry: B32<Public> = minocrab::v3::Disclose::disclose_as::<DeviceEntry>(entry, c);

        // assert(devices.member(entry), "unknown device entry"); devices.remove(entry);
        let known = ACCOUNT.devices.member(c, &entry);
        c.assert(is_true(*known).message("unknown device entry"));
        ACCOUNT.devices.remove(c, &entry);

        // devices.insert(disclose(derive_device_entry_with_evm(kernel.self(), address,
        //                                                      device_epoch, use_counter + 1)));
        let me2 = self_bytes(c);
        let epoch2 = ACCOUNT.device_epoch.read(c).stale(c);
        let next_counter = succ_u64(c, use_counter.field());
        let next = device_entry_evm(c, &me2, address, epoch2.field().private(), next_counter.field());
        let next: B32<Public> = minocrab::v3::Disclose::disclose_as::<DeviceEntry>(next, c);
        ACCOUNT.devices.insert(c, &next);

        // assert(secp256k1EcdsaVerify(digest, sig, pk), "invalid signature");
        let ok = ecdsa_verify(c, digest, sig, pk);
        c.assert_with(ok, Some("invalid signature"));

        // auth_nonce = (auth_nonce + 1) as Uint<64>;
        let n = ACCOUNT.auth_nonce.read(c).stale(c);
        let n1 = succ_u64(c, n.field());
        ACCOUNT.auth_nonce.write(c, &n1);

        bump_round(c);
    })
}

/// A public operand of a hash that mixes in private values.
pub fn private_field(w: Wire3<FieldT, Public>) -> Wire3<FieldT, Private> {
    w.private()
}

/// Keep `AnyWire3` in the public API for lanes that build their own preimages.
pub type Slot = AnyWire3<Private>;
