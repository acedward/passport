//! Off-circuit primitives: FAB encodings, the SHA-256 `persistentHash`, keccak, and ECDSA signing
//! through Midnight's own off-circuit instruction implementations. Transcribed from
//! minocrab-contracts `tests/vault/prims.rs` (the vault harness's reference model), which is where
//! each of these was first checked against a compactc artifact.
#![allow(dead_code)]

use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::k256;
use midnight_onchain_state::state::StateValue;
use midnight_storage::arena::Sp;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_hash;
use midnight_transient_crypto::repr::FieldRepr;
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
use minocrab::Fr;
use minocrab_zkir::v3::{IrType, IrValue};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

pub fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![atom(n)]),
    )
    .unwrap()
}

pub fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

/// The FAB limbs of a `Bytes<n>` (leftover chunk first).
pub fn bytes_limbs(n: u32, bytes: &[u8]) -> Vec<Fr> {
    let mut out = Vec::new();
    ValueReprAlignedValue(bytesn_value(n, bytes)).field_repr(&mut out);
    out
}

/// [hi, lo] Fr slot pair of a Bytes<32>.
pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (Fr::from(u64::from(bytes[31])), Fr::from_le_bytes(&bytes[..31]).unwrap())
}

/// A `Bytes<20>` as its single limb.
pub fn b20(bytes: &[u8; 20]) -> Fr {
    Fr::from_le_bytes(bytes).unwrap()
}

/// A `Uint<128>` as its single limb.
pub fn u128_limb(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).unwrap()
}

/// `upgradeFromTransient(transientHash(limbs))`.
pub fn transient_upgrade(limbs: &[Fr]) -> [u8; 32] {
    let f = transient_hash(limbs);
    let mut le = f.as_le_bytes();
    le.resize(32, 0);
    let mut out = [0u8; 32];
    out[..31].copy_from_slice(&le[..31]);
    out
}

pub fn natives(v: &IrValue) -> Vec<Fr> {
    encode_offcircuit(v)
        .into_iter()
        .map(|x| match x {
            IrValue::Native(f) => f,
            other => panic!("encode produced non-native {other:?}"),
        })
        .collect()
}

/// SHA-256 over the FAB binary of `limbs` laid out per `segments` — the off-circuit
/// `persistentHash`.
pub fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments)
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

pub fn pad<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

/// A secp256k1 scalar from its 32-byte BIG-endian form.
pub fn scalar_be(be: &[u8; 32]) -> IrValue {
    let mut le = *be;
    le.reverse();
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &le).unwrap()
}

pub fn scalar_u64(v: u64) -> IrValue {
    let mut le = [0u8; 32];
    le[..8].copy_from_slice(&v.to_le_bytes());
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &le).unwrap()
}

pub fn generator() -> IrValue {
    IrValue::Secp256k1Point(k256::K256::generator())
}

pub fn point_of(d: &IrValue) -> IrValue {
    ec_mul_offcircuit(&generator(), d).unwrap()
}

/// The point at infinity (`G · 0`).
pub fn identity_point() -> IrValue {
    ec_mul_offcircuit(&generator(), &scalar_u64(0)).unwrap()
}

/// A base-field coordinate as 32 big-endian bytes.
fn coord_be(x: &IrValue) -> [u8; 32] {
    let IrValue::Bytes32(mut le) = into_bytes32_offcircuit(x).unwrap() else {
        panic!("into_bytes32 yields Bytes32")
    };
    le.reverse();
    le
}

/// `secp256k1EthereumAddress(pk)` off-circuit: keccak256(BE(x) ‖ BE(y))[12..32].
pub fn eth_address(pk: &IrValue) -> [u8; 20] {
    let (x, y) = into_coordinates_offcircuit(pk).unwrap();
    let mut pre = coord_be(&x).to_vec();
    pre.extend_from_slice(&coord_be(&y));
    let h = keccak(&pre);
    h[12..32].try_into().unwrap()
}

/// Sign `digest` (a big-endian integer) with secret `d` and nonce `k`; returns (r, s) as
/// secp256k1 scalars — the circuit-input form of `Secp256k1EcdsaSignature`.
pub fn sign(digest: &[u8; 32], d: &IrValue, k: &IrValue) -> (IrValue, IrValue) {
    let z = scalar_be(digest);
    let r_point = ec_mul_offcircuit(&generator(), k).unwrap();
    let (x, _y) = into_coordinates_offcircuit(&r_point).unwrap();
    let IrValue::Bytes32(x_le) = into_bytes32_offcircuit(&x).unwrap() else {
        panic!("into_bytes32 yields Bytes32")
    };
    let r = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &x_le).unwrap();
    let rd = mul_offcircuit(&r, d).unwrap();
    let z_rd = add_offcircuit(&z, &rd).unwrap();
    let k_inv = inv_offcircuit(k).unwrap();
    let s = mul_offcircuit(&k_inv, &z_rd).unwrap();
    (r, s)
}

/// `-s mod n` — the high-S twin of a signature.
pub fn negate_scalar(s: &IrValue) -> IrValue {
    let minus_one = {
        // n - 1, big-endian
        let n_minus_1: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae,
            0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
        ];
        scalar_be(&n_minus_1)
    };
    mul_offcircuit(s, &minus_one).unwrap()
}

/// `coinCommitment(coin, recipient)` off-circuit.
pub fn coin_commitment_of(nonce: &[u8; 32], color: &[u8; 32], value: u128, is_left: bool, data: &[u8; 32]) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cc[v1]").unwrap();
    let (n_hi, n_lo) = b32_slots(nonce);
    let (c_hi, c_lo) = b32_slots(color);
    let (d_hi, d_lo) = b32_slots(data);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[
            prefix,
            n_hi,
            n_lo,
            c_hi,
            c_lo,
            u128_limb(value),
            Fr::from(u64::from(is_left)),
            d_hi,
            d_lo,
        ],
    )
}

/// `coinNullifier(coin, addr)` off-circuit.
pub fn coin_nullifier_of(nonce: &[u8; 32], color: &[u8; 32], value: u128, addr: &[u8; 32]) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cn[v1]").unwrap();
    let (n_hi, n_lo) = b32_slots(nonce);
    let (c_hi, c_lo) = b32_slots(color);
    let (a_hi, a_lo) = b32_slots(addr);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[
            prefix,
            n_hi,
            n_lo,
            c_hi,
            c_lo,
            u128_limb(value),
            Fr::from(0u64),
            a_hi,
            a_lo,
        ],
    )
}

/// A deterministic 64-bit generator (splitmix64) — the gate needs reproducible probes, not
/// cryptographic randomness.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        out
    }
}
