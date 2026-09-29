//! `modules/ByteCodec.compact` — the big-endian 32-byte ABI words every EIP-712 preimage of the
//! `evm` arm is assembled from.
//!
//! A `Bytes<32>` is two FAB limbs, `B32 { hi: byte 31, lo: bytes 0..30 little-endian }`. The
//! encoders below build that pair directly, which is where they differ from compactc's lowering (a
//! byte explosion and rebuild) and not in the bytes they produce:
//!
//! - an integer word is the value's little-endian bytes behind a zero head, REVERSED — one native
//!   `reverse_bytes` (transcribed from minocrab-contracts `evm::numeric_word`);
//! - an address word is `addr · 2^96` split at bit 152 — one `div_mod` (transcribed from
//!   minocrab-contracts `evm::address_word`).
//!
//! Every encoder is correct for any limb below 2^248, and the callers only ever pass values whose
//! width the circuit has already constrained (a `Uint<64>`, a `Uint<128>`, a `Bytes<20>`).

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::Fr;
use minocrab_std::v3::{pow2_const, Vis3, B32};

/// `uint64Word(v)` / `uint128Word(v)` — an integer limb as a 32-byte big-endian ABI word.
pub fn uint_word<V: Vis3>(c: &mut Circuit3, value: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // value's LE bytes sit at string positions 0..15 of `B32 { hi: 0, lo: value }`; the native
        // reversal moves them, reversed, to the tail — exactly the BE ABI rendering.
        let zero = V::from_public(c.constant(0u64));
        let padded = B32 { hi: zero, lo: value };
        let typed = padded.to_typed(c);
        let rev = c.reverse_bytes(typed);
        B32::from_typed(c, rev)
    })
}

/// `addressWord(addr)` — 12 zero bytes, then the 20-byte address. `addr` is the `Bytes<20>`'s
/// single limb.
pub fn address_word<V: Vis3>(c: &mut Circuit3, addr: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // The word is addr·2^96 (a 12-byte shift): hi byte = addr >> 152, lo = the rest shifted.
        let (hi, low152) = c.div_mod_power_of_two(addr, 152);
        let shift96 = V::from_public(pow2_const(c, 12));
        let lo = c.mul(low152, shift96);
        B32 { hi, lo }
    })
}

/// A frozen 32-byte constant (byte 0 first) as a `B32` of two constant limbs.
pub fn b32_const<V: Vis3>(c: &mut Circuit3, bytes: &[u8; 32]) -> B32<V> {
    B32 {
        hi: V::from_public(c.constant(Fr::from(u64::from(bytes[31])))),
        lo: V::from_public(c.constant(Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"))),
    }
}

/// `slice<20>(digest, 12)` — bytes 12..31 of a 32-byte value as the single `Bytes<20>` limb:
/// bytes 12..30 come off the low limb (`div_mod` at bit 96), byte 31 is the high limb, rejoined at
/// byte position 19. Transcribed from minocrab-contracts `manager::evm_domain_separator_for`.
pub fn low20<V: Vis3>(c: &mut Circuit3, digest: &B32<V>) -> Wire3<FieldT, V> {
    let (rest, _low12) = c.div_mod_power_of_two(digest.lo, 96);
    let shift152 = V::from_public(pow2_const(c, 19));
    let hi_shifted = c.mul(digest.hi, shift152);
    c.add(rest, hi_shifted)
}
