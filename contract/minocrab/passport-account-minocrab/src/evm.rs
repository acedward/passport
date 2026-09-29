//! The stdlib's secp256k1 surface as `account.compact` uses it.
//!
//! - [`ethereum_address`] — `secp256k1EthereumAddress(pk)`: assert `pk` is not the identity, then
//!   `slice<20>(keccak256(BE(x) ‖ BE(y)), 12)`. compactc (and `minocrab-std`'s transcription of
//!   it) builds the 64-byte preimage by exploding both coordinates into single bytes; here each
//!   coordinate is `into_bytes32` → one native `reverse_bytes` → its two limbs, hashed as two
//!   `Bytes<32>` atoms, and the 20-byte slice is one `div_mod`. Same bytes in, same digest, same
//!   20 bytes out.
//! - [`ecdsa_verify`] — `secp256k1EcdsaVerify(digest, sig, pk)`, `minocrab-std`'s gadget unchanged
//!   (already the stdlib's shape instruction for instruction).
//! - [`require_live_k256_key`] — the account's own guard against the point at infinity, on the
//!   COORDINATES (see the Compact source for why not on the identity flag).

use minocrab::v3::{Circuit3, FieldT, Secp256k1PointT, Secp256k1ScalarT, Wire3};
use minocrab::Public;
use minocrab_std::v3::{Secp256k1EcdsaSignature, Vis3, B32};

use crate::byte_codec::low20;
use crate::eip712::keccak_words;

/// `secp256k1EthereumAddress(pk): Bytes<20>` — the `Bytes<20>`'s single limb.
pub fn ethereum_address<V: Vis3>(c: &mut Circuit3, pk: Wire3<Secp256k1PointT, V>) -> Wire3<FieldT, V> {
    c.region("evm: ethereum address", |c| {
        // pk != default<Secp256k1Point>, the stdlib's assert (language 0.26.0). default<Secp256k1Point>
        // is generator · 0, built as compactc builds it.
        let zero = c.constant(0u64);
        let zero_bytes = c.into_bytes32(zero);
        let zero_scalar: Wire3<Secp256k1ScalarT, Public> = c.from_bytes32(zero_bytes);
        let identity = c.ec_mul_generator(zero_scalar);
        let is_identity = c.test_eq(pk, V::from_public(identity));
        let not_identity = c.not(is_identity);
        c.assert_with(
            not_identity,
            Some("secp256k1EthereumAddress: the identity has no address"),
        );

        // keccak256(BE(x) ‖ BE(y)): the canonical LE 32-byte form of each coordinate, reversed.
        let (x, y) = c.into_coordinates(pk);
        let x_le = c.into_bytes32(x);
        let x_be = c.reverse_bytes(x_le);
        let x_word = B32::from_typed(c, x_be);
        let y_le = c.into_bytes32(y);
        let y_be = c.reverse_bytes(y_le);
        let y_word = B32::from_typed(c, y_be);
        let digest = keccak_words(c, &[&x_word, &y_word]);
        low20(c, &digest)
    })
}

/// `secp256k1EcdsaVerify(digest, sig, pk)` — the verification bit (not asserted here).
pub fn ecdsa_verify<V: Vis3>(
    c: &mut Circuit3,
    digest: &B32<V>,
    sig: &Secp256k1EcdsaSignature<V>,
    pk: Wire3<Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    c.region("evm: ecdsa verify", |c| {
        minocrab_std::v3::secp256k1_ecdsa_verify(c, digest, sig, pk)
    })
}

/// `require_live_k256_key(pk)` — `assert(!(x as Bytes<32> == 0 && y as Bytes<32> == 0))`.
pub fn require_live_k256_key<V: Vis3>(c: &mut Circuit3, pk: Wire3<Secp256k1PointT, V>) {
    c.region("evm: live key", |c| {
        let (x, y) = c.into_coordinates(pk);
        let xb = c.into_bytes32(x);
        let xw = B32::from_typed(c, xb);
        let yb = c.into_bytes32(y);
        let yw = B32::from_typed(c, yb);
        let x0 = is_zero(c, &xw);
        let y0 = is_zero(c, &yw);
        let both = c.mul(x0, y0);
        let live = c.not(both);
        c.assert_with(live, Some("device key is the point at infinity"));
    })
}

fn is_zero<V: Vis3>(c: &mut Circuit3, b: &B32<V>) -> Wire3<FieldT, V> {
    let zero = V::from_public(c.constant(0u64));
    let hi0 = c.test_eq(b.hi, zero);
    let lo0 = c.test_eq(b.lo, zero);
    c.mul(hi0, lo0)
}
