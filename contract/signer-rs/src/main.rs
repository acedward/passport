//! Independent Rust signer for the account authorisation seam, both arms.
//!
//! Demonstrates the AUTH-4 boundary and conformance test 7 against the two
//! co-resident arms of account.compact: a signer that reproduces each arm's
//! challenge construction with its own hash and curve stack — the ledger's
//! Rust crates for the encoding; midnight-curves for JubJub, the k256 crate
//! for secp256k1 — and no TypeScript, WASM, npm, node, indexer, prover, or
//! contract runtime.
//!
//! Arm jubjub (MIP-0013 §5). Challenge preimage (§5.1), for a gated
//! circuit:
//!
//!   persistentHash([DST_CIRCUIT, self, sig_r, pk, ...args, auth_nonce, grind_nonce])
//!
//! with DST_CIRCUIT = persistentHash of the tag
//! "midnight:account:auth:v1:<circuit>" zero-padded to 64 bytes (the hashed
//! arm of the #249 derivation). The signer grinds grind_nonce until the
//! hash, read little-endian, is strictly below the JubJub subgroup order
//! (§5.2), then emits (R, s, grind_nonce) with s = r + c·sk.
//!
//! Arm evm. The device is an ordinary Ethereum EOA, the identity the account
//! enrols is its 20-byte address, and what it signs is EIP-712 typed data:
//!
//!   challenge = persistentHash([DST_CIRCUIT, self, address, ...args, auth_nonce])
//!   digest    = keccak256(0x1901 || domainSeparator || structHash)
//!
//! with DST_CIRCUIT over "midnight:account:auth:evm:v1:<circuit>" and the
//! challenge carried as the LAST field of the operation's EIP-712 struct. The
//! keccak layer is written out in `sign_evm` from the frozen type strings
//! alone, so this binary reproduces the byte contract independently of the
//! TypeScript codec, of ethers, and of the contract's own oracles.
//!
//! Arm k256. Challenge preimage, for a gated circuit:
//!
//!   persistentHash([DST_CIRCUIT, self, pk_x, pk_y, ...args, auth_nonce])
//!
//! with DST_CIRCUIT over the arm-marked tag
//! "midnight:account:auth:k1:v1:<circuit>". There is no signature term (an
//! ECDSA message must not depend on its own signature) and no grinding
//! nonce (secp256k1EcdsaVerify reduces the 32-byte challenge mod the curve
//! order natively). The signature is ECDSA over the ENVELOPE digest
//! SHA-256(prefix(envelope) || challenge), never the challenge itself
//! (`envelope_digest` below: envelope 0 has an empty prefix, envelope 1 the
//! dApp-connector `signData` prefix), passed to k256 as a prehash; k256
//! emits the low-S normalised form by default and the contract accepts
//! both S forms (see the malleability note in account.compact).
//!
//! persistentHash is SHA-256 over the compiler's field-aligned binary
//! encoding: this binary reproduces that encoding with the ledger's own fab
//! machinery (`AlignedValue` → `binary_repr` → `PersistentHashWriter`),
//! mirroring the element encodings the compiled contract uses:
//!
//!   Bytes<n>        → one bytes(n) atom, trailing zeros stripped
//!   ContractAddress → Bytes<32>
//!   UserAddress     → Bytes<32>
//!   JubjubPoint     → two field atoms (x, y), minimal little-endian
//!   k256 coordinate → Bytes<32>, the little-endian encoding of the affine
//!                     coordinate (secp256k1PointX/Y(pk) as Bytes<32>) —
//!                     the byte-reverse of its SEC1 big-endian form
//!   Uint<n>         → one bytes(n/8) atom, minimal little-endian
//!
//! Protocol: one JSON request on stdin, one JSON response on stdout. Every
//! request carries the arm.
//!
//!   {"cmd":"keygen","arm":"jubjub"}
//!     → {"sk":"0x…","pk":{"x":"0x…","y":"0x…"}}
//!   {"cmd":"sign","arm":"jubjub","circuit":"withdraw_unshielded","sk":"0x…",
//!    "contract_address":"…64 hex…","color":"…64 hex…","amount":"500",
//!    "recipient":"…64 hex…","auth_nonce":"3"}
//!     → {"pk":{…},"sig_r":{…},"sig_s":"0x…","grind_nonce":"17",
//!        "challenge":"…64 hex…","attempts":18}
//!   {"cmd":"sign","arm":"k256",…same fields…}
//!     → {"pk":{…},"sig":{"r":"0x…","s":"0x…"},"challenge":"…64 hex…"}
//!   {"cmd":"sign","arm":"evm",…same fields…,"evm_domain_salt":"…64 hex…"}
//!     → {"pk":{…},"address":"0x…20 bytes…","sig":{…},"challenge":"…",
//!        "account_alias":"0x…","domain_separator":"…","struct_hash":"…",
//!        "digest":"…"}
//!
//! All bigint fields are 0x-prefixed big-endian hex; raw byte strings are
//! plain hex.

use std::io::Read;

use anyhow::{anyhow, bail, Context, Result};
use ff::Field as _;
use group::Group as _;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_base_crypto::hash::PersistentHashWriter;
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::{Fr as JubjubScalar, JubjubSubgroup};
use midnight_transient_crypto::curve::EmbeddedGroupAffine;
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use serde::Deserialize;
use serde_json::json;

/// JubJub prime-order subgroup order r_J, little-endian (MIP-0013 §2).
const JUBJUB_R_LE: [u8; 32] = [
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e,
];

// ── Field-aligned encoding elements (mirror of the compact-runtime types) ───

struct Element {
    atoms: Vec<ValueAtom>,
    alignment: Vec<AlignmentSegment>,
}

fn strip_trailing_zeros(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    v
}

/// Bytes<N>: one bytes(N) atom, trailing zeros stripped (CompactTypeBytes).
fn el_bytes(length: u32, data: &[u8]) -> Element {
    Element {
        atoms: vec![ValueAtom(strip_trailing_zeros(data.to_vec()))],
        alignment: vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length })],
    }
}

/// Uint<8·N>: one bytes(N) atom, minimal little-endian
/// (CompactTypeUnsignedInteger's toValue is the field encoding).
fn el_uint(byte_length: u32, value: u128) -> Element {
    Element {
        atoms: vec![ValueAtom(strip_trailing_zeros(
            value.to_le_bytes().to_vec(),
        ))],
        alignment: vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: byte_length,
        })],
    }
}

/// JubjubPoint: two field atoms (x, y), minimal little-endian
/// (CompactTypeJubjubPoint).
fn el_point(p: &EmbeddedGroupAffine) -> Result<Element> {
    let x = p.x().ok_or_else(|| anyhow!("point at infinity"))?;
    let y = p.y().ok_or_else(|| anyhow!("point at infinity"))?;
    Ok(Element {
        atoms: vec![
            ValueAtom(strip_trailing_zeros(x.as_le_bytes())),
            ValueAtom(strip_trailing_zeros(y.as_le_bytes())),
        ],
        alignment: vec![
            AlignmentSegment::Atom(AlignmentAtom::Field),
            AlignmentSegment::Atom(AlignmentAtom::Field),
        ],
    })
}

/// persistentHash over a tuple of elements: SHA-256 of the field-aligned
/// binary encoding — the exact code path of onchain-runtime's
/// `persistentHash(alignment, value)`.
fn persistent_hash(elements: &[Element]) -> Result<[u8; 32]> {
    let value = Value(elements.iter().flat_map(|e| e.atoms.clone()).collect());
    let alignment = Alignment(elements.iter().flat_map(|e| e.alignment.clone()).collect());
    let aligned =
        AlignedValue::new(value, alignment).ok_or_else(|| anyhow!("invalid alignment"))?;
    let mut hasher = PersistentHashWriter::default();
    ValueReprAlignedValue(aligned).binary_repr(&mut hasher);
    Ok(hasher.finalize().0)
}

/// DST_CIRCUIT: persistentHash of the arm's tag zero-padded to 64 bytes.
fn circuit_dst(arm: &Arm, circuit: &str) -> Result<[u8; 32]> {
    let tag = match arm {
        Arm::Jubjub => format!("midnight:account:auth:v1:{circuit}"),
        Arm::K256 => format!("midnight:account:auth:k1:v1:{circuit}"),
        Arm::Evm => format!("midnight:account:auth:evm:v1:{circuit}"),
    };
    if tag.len() > 64 {
        bail!("circuit tag longer than 64 bytes: {tag}");
    }
    let mut padded = [0u8; 64];
    padded[..tag.len()].copy_from_slice(tag.as_bytes());
    persistent_hash(&[el_bytes(64, &padded)])
}

// ── Arm jubjub: scalars and points ──────────────────────────────────────────

fn hash_below_r(hash_le: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        match hash_le[i].cmp(&JUBJUB_R_LE[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

fn jubjub_scalar_from_hex(hex_be: &str) -> Result<JubjubScalar> {
    let clean = hex_be.trim_start_matches("0x");
    let bytes = hex::decode(format!("{:0>64}", clean)).context("bad scalar hex")?;
    let mut le: [u8; 32] = bytes.as_slice().try_into().context("scalar not 32 bytes")?;
    le.reverse();
    let scalar: Option<JubjubScalar> = JubjubScalar::from_bytes(&le).into();
    scalar.ok_or_else(|| anyhow!("scalar out of range"))
}

fn jubjub_scalar_to_hex(s: &JubjubScalar) -> String {
    let mut b = s.to_bytes();
    b.reverse();
    format!("0x{}", hex::encode(b))
}

fn jubjub_point_json(p: &EmbeddedGroupAffine) -> Result<serde_json::Value> {
    let x = p.x().ok_or_else(|| anyhow!("point at infinity"))?;
    let y = p.y().ok_or_else(|| anyhow!("point at infinity"))?;
    let to_hex = |f: midnight_transient_crypto::curve::Fr| {
        let mut b = f.as_le_bytes();
        b.reverse();
        format!("0x{}", hex::encode(b))
    };
    Ok(json!({ "x": to_hex(x), "y": to_hex(y) }))
}

// ── Arm k256: keys and coordinates ──────────────────────────────────────────

/// The two Bytes<32> coordinate encodings the contract binds the key as:
/// little-endian affine x and y, i.e. the byte-reverse of the SEC1
/// big-endian coordinates (in-circuit: secp256k1PointX/Y(pk) as Bytes<32>).
fn pk_coords_le(vk: &VerifyingKey) -> Result<([u8; 32], [u8; 32])> {
    let point = vk.to_encoded_point(false);
    let x = point.x().ok_or_else(|| anyhow!("point at infinity"))?;
    let y = point.y().ok_or_else(|| anyhow!("point at infinity"))?;
    let mut x_le: [u8; 32] = (*x).into();
    let mut y_le: [u8; 32] = (*y).into();
    x_le.reverse();
    y_le.reverse();
    Ok((x_le, y_le))
}

fn k256_signing_key_from_hex(hex_be: &str) -> Result<SigningKey> {
    let clean = hex_be.trim_start_matches("0x");
    let bytes = hex::decode(format!("{:0>64}", clean)).context("bad scalar hex")?;
    SigningKey::from_slice(&bytes).map_err(|_| anyhow!("scalar out of range"))
}

fn k256_point_json(vk: &VerifyingKey) -> Result<serde_json::Value> {
    let point = vk.to_encoded_point(false);
    let x = point.x().ok_or_else(|| anyhow!("point at infinity"))?;
    let y = point.y().ok_or_else(|| anyhow!("point at infinity"))?;
    Ok(json!({
        "x": format!("0x{}", hex::encode(x)),
        "y": format!("0x{}", hex::encode(y)),
    }))
}

fn bytes32_from_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("bad hex")?;
    bytes.as_slice().try_into().context("expected 32 bytes")
}

// ── Requests ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Arm {
    Jubjub,
    K256,
    Evm,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
enum Request {
    Keygen { arm: Arm },
    Sign(SignRequest),
}

#[derive(Deserialize)]
struct SignRequest {
    arm: Arm,
    circuit: String,
    sk: String,
    contract_address: String,
    color: String,
    amount: String,
    recipient: String,
    auth_nonce: String,
    /// k256 envelope id (see `envelope_digest`): 0 = no prefix (default),
    /// 1 = the dApp-connector `signData` envelope (the
    /// `ecdsa_secp256k1_sha256` scheme of the connector specification).
    /// Ignored by the jubjub arm.
    #[serde(default)]
    envelope: u8,
    /// Arm evm only: the account's constructor-sealed `evm_domain_salt`, the
    /// EIP-712 domain's `salt` field (64 hex characters). Ignored by the other
    /// two arms, which have no domain.
    #[serde(default)]
    evm_domain_salt: String,
}

/// The connector's mandatory signing prefix for a 32-byte payload
/// (connector specification, section "Signing").
const CONNECTOR_ENVELOPE_PREFIX: &[u8; 27] = b"midnight_signed_message:32:";

/// The digest a k256 device signs for a challenge, by envelope id. Mirrors
/// the contract's exported `envelope_digest` pure circuit:
///   0  SHA-256(challenge)
///   1  SHA-256("midnight_signed_message:32:" || challenge)
/// persistentHash over Bytes is SHA-256 of the raw concatenation, so both
/// are plain SHA-256 and bit-equal to the circuit's output.
fn envelope_digest(envelope: u8, challenge: &[u8; 32]) -> Result<[u8; 32]> {
    match envelope {
        0 => persistent_hash(&[el_bytes(32, challenge)]),
        1 => persistent_hash(&[
            el_bytes(27, CONNECTOR_ENVELOPE_PREFIX),
            el_bytes(32, challenge),
        ]),
        other => bail!("unknown k256 envelope id {other}"),
    }
}

fn main() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input).context("invalid request JSON")?;

    let response = match request {
        Request::Keygen { arm: Arm::Jubjub } => {
            let sk = JubjubScalar::random(&mut rand::rngs::OsRng);
            let pk = EmbeddedGroupAffine(JubjubSubgroup::generator() * sk);
            json!({ "sk": jubjub_scalar_to_hex(&sk), "pk": jubjub_point_json(&pk)? })
        }
        Request::Keygen { arm: Arm::K256 } => {
            let sk = SigningKey::random(&mut rand::rngs::OsRng);
            json!({
                "sk": format!("0x{}", hex::encode(sk.to_bytes())),
                "pk": k256_point_json(sk.verifying_key())?,
            })
        }
        Request::Keygen { arm: Arm::Evm } => {
            // The same curve as k256; what differs is the identity the account
            // enrols, so the keygen also reports the Ethereum address.
            let sk = SigningKey::random(&mut rand::rngs::OsRng);
            let (x_be, y_be) = pk_coords_be(sk.verifying_key())?;
            json!({
                "sk": format!("0x{}", hex::encode(sk.to_bytes())),
                "pk": k256_point_json(sk.verifying_key())?,
                "address": format!("0x{}", hex::encode(ethereum_address(&x_be, &y_be))),
            })
        }
        Request::Sign(req) => match req.arm {
            Arm::Jubjub => sign_jubjub(&req)?,
            Arm::K256 => sign_k256(&req)?,
            Arm::Evm => sign_evm(&req)?,
        },
    };
    println!("{response}");
    Ok(())
}

struct CallParams {
    contract_address: [u8; 32],
    color: [u8; 32],
    recipient: [u8; 32],
    amount: u128,
    auth_nonce: u64,
}

fn call_params(req: &SignRequest) -> Result<CallParams> {
    if req.circuit != "withdraw_unshielded" {
        bail!("this reference signer implements the withdraw_unshielded challenge only");
    }
    Ok(CallParams {
        contract_address: bytes32_from_hex(&req.contract_address)?,
        color: bytes32_from_hex(&req.color)?,
        recipient: bytes32_from_hex(&req.recipient)?,
        amount: req.amount.parse().context("bad amount")?,
        auth_nonce: req.auth_nonce.parse().context("bad auth_nonce")?,
    })
}

fn sign_jubjub(req: &SignRequest) -> Result<serde_json::Value> {
    let p = call_params(req)?;
    let sk = jubjub_scalar_from_hex(&req.sk)?;
    let pk = EmbeddedGroupAffine(JubjubSubgroup::generator() * sk);
    let dst = circuit_dst(&Arm::Jubjub, &req.circuit)?;

    // §5.3: fresh nonce scalar, R = r·G, then grind the challenge (§5.2).
    let r = JubjubScalar::random(&mut rand::rngs::OsRng);
    let sig_r = EmbeddedGroupAffine(JubjubSubgroup::generator() * r);

    let mut grind_nonce: u64 = 0;
    let challenge_bytes = loop {
        let h = persistent_hash(&[
            el_bytes(32, &dst),
            el_bytes(32, &p.contract_address),
            el_point(&sig_r)?,
            el_point(&pk)?,
            el_bytes(32, &p.color),
            el_uint(16, p.amount),
            el_bytes(32, &p.recipient),
            el_uint(8, u128::from(p.auth_nonce)),
            el_uint(8, u128::from(grind_nonce)),
        ])?;
        if hash_below_r(&h) {
            break h;
        }
        grind_nonce += 1;
        anyhow::ensure!(grind_nonce < 10_000, "grinding did not converge");
    };

    let c: Option<JubjubScalar> = JubjubScalar::from_bytes(&challenge_bytes).into();
    let c = c.ok_or_else(|| anyhow!("ground challenge not a scalar"))?;
    let s = r + c * sk;

    // Local verification of the §4 equation before emitting.
    let lhs = JubjubSubgroup::generator() * s;
    let pk_sub: JubjubSubgroup = pk.0;
    let rhs = sig_r.0 + pk_sub * c;
    anyhow::ensure!(lhs == rhs, "self-verification failed");

    Ok(json!({
        "pk": jubjub_point_json(&pk)?,
        "sig_r": jubjub_point_json(&sig_r)?,
        "sig_s": jubjub_scalar_to_hex(&s),
        "grind_nonce": grind_nonce.to_string(),
        "challenge": hex::encode(challenge_bytes),
        "attempts": grind_nonce + 1,
    }))
}

fn sign_k256(req: &SignRequest) -> Result<serde_json::Value> {
    let p = call_params(req)?;
    let sk = k256_signing_key_from_hex(&req.sk)?;
    let vk = sk.verifying_key();
    let (pk_x, pk_y) = pk_coords_le(vk)?;
    let dst = circuit_dst(&Arm::K256, &req.circuit)?;

    // The challenge is a plain digest: no signature commitment, no
    // grinding. The key is bound as its little-endian coordinate bytes and
    // auth_nonce comes last.
    let challenge = persistent_hash(&[
        el_bytes(32, &dst),
        el_bytes(32, &p.contract_address),
        el_bytes(32, &pk_x),
        el_bytes(32, &pk_y),
        el_bytes(32, &p.color),
        el_uint(16, p.amount),
        el_bytes(32, &p.recipient),
        el_uint(8, u128::from(p.auth_nonce)),
    ])?;

    // The signature covers the envelope digest, never the challenge itself.
    let digest = envelope_digest(req.envelope, &challenge)?;

    // ECDSA over the digest as a prehash (RFC 6979 deterministic nonce).
    // k256 emits the low-S normalised form; the contract's verifier accepts
    // either form, so the signature travels as produced.
    let sig: Signature = sk
        .sign_prehash(&digest)
        .map_err(|_| anyhow!("signing failed"))?;

    // Local verification before emitting (k256's verifier, which insists on
    // the low-S form its signer produces).
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| anyhow!("self-verification failed"))?;

    let (sig_r, sig_s) = sig.split_bytes();
    Ok(json!({
        "pk": k256_point_json(vk)?,
        "sig": {
            "r": format!("0x{}", hex::encode(sig_r)),
            "s": format!("0x{}", hex::encode(sig_s)),
        },
        "challenge": hex::encode(challenge),
        "digest": hex::encode(digest),
        "envelope": req.envelope,
    }))
}

// ── Arm evm: EIP-712 over secp256k1 ─────────────────────────────────────────
//
// The third arm signs neither the challenge nor an envelope of it: the
// challenge is ONE FIELD of a per-operation EIP-712 struct, and the wallet
// signs keccak256(0x1901 || domainSeparator || structHash). Everything below
// keccak is written out here rather than imported, so this binary is a genuinely
// independent implementation of `docs/AUTH-EIP712-PASSPORT-EVM-V1.md` — the
// type strings and the frozen constants are the only shared inputs, exactly
// what a third party would be handed.
//
// Two layers, and they are independent:
//
//   * the CHALLENGE CORE is the k256 arm's SHA-256 preimage with the key
//     encoded as the device's 20-byte Ethereum address instead of its two
//     affine coordinates — so it goes through the same fab machinery as the
//     other two arms, and a drift in the compiler's encoding is caught here;
//   * the EIP-712 LAYER is keccak over big-endian ABI words, which has nothing
//     to do with Midnight's encoding at all.

/// The device's affine coordinates, big-endian (SEC1 order) — the encoding
/// keccak takes for the Ethereum address, and the byte-reverse of the
/// little-endian pair the k256 arm binds.
fn pk_coords_be(vk: &VerifyingKey) -> Result<([u8; 32], [u8; 32])> {
    let point = vk.to_encoded_point(false);
    let x = point.x().ok_or_else(|| anyhow!("point at infinity"))?;
    let y = point.y().ok_or_else(|| anyhow!("point at infinity"))?;
    Ok(((*x).into(), (*y).into()))
}

fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `secp256k1EthereumAddress(pk)`: the low 20 bytes of keccak256(x || y).
fn ethereum_address(x_be: &[u8; 32], y_be: &[u8; 32]) -> [u8; 20] {
    let h = keccak256(&[x_be, y_be]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..]);
    out
}

/// A 20-byte address as an ABI `address` word: twelve zero bytes, then the
/// address.
fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address);
    out
}

/// An unsigned integer as a big-endian 32-byte word.
fn uint_word(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

const DOMAIN_ENCODE_TYPE: &str =
    "EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)";
const DOMAIN_NAME: &str = "Midnight Passport Account";
const DOMAIN_VERSION: &str = "1";
const TYPE_WITHDRAW_UNSHIELDED: &str = "WithdrawUnshielded(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipient,bytes32 challenge)";

/// The account's EVM-shaped `verifyingContract`: the low 20 bytes of keccak256
/// over its 32-byte Midnight address.
fn account_alias(account: &[u8; 32]) -> [u8; 20] {
    let h = keccak256(&[account]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..]);
    out
}

fn domain_separator(account: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    keccak256(&[
        &keccak256(&[DOMAIN_ENCODE_TYPE.as_bytes()]),
        &keccak256(&[DOMAIN_NAME.as_bytes()]),
        &keccak256(&[DOMAIN_VERSION.as_bytes()]),
        &address_word(&account_alias(account)),
        salt,
    ])
}

fn eip712_digest(separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[&[0x19u8, 0x01u8], separator, struct_hash])
}

fn sign_evm(req: &SignRequest) -> Result<serde_json::Value> {
    let p = call_params(req)?;
    let salt = bytes32_from_hex(&req.evm_domain_salt)
        .context("arm evm needs the account's evm_domain_salt")?;
    let sk = k256_signing_key_from_hex(&req.sk)?;
    let vk = sk.verifying_key();
    let (x_be, y_be) = pk_coords_be(vk)?;
    let address = ethereum_address(&x_be, &y_be);
    let dst = circuit_dst(&Arm::Evm, &req.circuit)?;

    // The challenge core: the k256 preimage with the key as the address.
    let challenge = persistent_hash(&[
        el_bytes(32, &dst),
        el_bytes(32, &p.contract_address),
        el_bytes(20, &address),
        el_bytes(32, &p.color),
        el_uint(16, p.amount),
        el_bytes(32, &p.recipient),
        el_uint(8, u128::from(p.auth_nonce)),
    ])?;

    // The EIP-712 struct the wallet displays, with the challenge as its last
    // field. Eight words for this type: the type hash plus seven fields.
    let struct_hash = keccak256(&[
        &keccak256(&[TYPE_WITHDRAW_UNSHIELDED.as_bytes()]),
        &p.contract_address,
        &address_word(&address),
        &uint_word(u128::from(p.auth_nonce)),
        &p.color,
        &uint_word(p.amount),
        &p.recipient,
        &challenge,
    ]);
    let separator = domain_separator(&p.contract_address, &salt);
    let digest = eip712_digest(&separator, &struct_hash);

    let sig: Signature = sk
        .sign_prehash(&digest)
        .map_err(|_| anyhow!("signing failed"))?;
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| anyhow!("self-verification failed"))?;

    let (sig_r, sig_s) = sig.split_bytes();
    Ok(json!({
        "pk": k256_point_json(vk)?,
        "address": format!("0x{}", hex::encode(address)),
        "sig": {
            "r": format!("0x{}", hex::encode(sig_r)),
            "s": format!("0x{}", hex::encode(sig_s)),
        },
        "challenge": hex::encode(challenge),
        "account_alias": format!("0x{}", hex::encode(account_alias(&p.contract_address))),
        "domain_separator": hex::encode(separator),
        "struct_hash": hex::encode(struct_hash),
        "digest": hex::encode(digest),
    }))
}

// ── By-hand oracle checks ───────────────────────────────────────────────────
//
// Every preimage of the k256 arm is a tuple of Bytes atoms (the key is
// bound as coordinate bytes, so no Field atoms appear). For such tuples the
// field-aligned binary encoding reduces to each element zero-padded to its
// declared length, concatenated in order — so the tests recompute the DST,
// the device entry, and the challenge as plain SHA-256 over that
// concatenation, independently of the fab machinery, and pin the sk = 1
// public key against the SEC1 generator constants. The jubjub arm's
// preimages carry Field atoms (point coordinates), so only its DST (a pure
// Bytes tuple) has a by-hand oracle; its end-to-end challenge equality is
// covered by crossimpl-offline against the compiled contract.

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const GX_BE: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const GY_BE: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    fn pad_to(length: usize, data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        assert!(v.len() <= length);
        v.resize(length, 0);
        v
    }

    fn sha256_concat(parts: &[Vec<u8>]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    fn coord_le(hex_be: &str) -> [u8; 32] {
        let mut b: [u8; 32] = hex::decode(hex_be).unwrap().try_into().unwrap();
        b.reverse();
        b
    }

    #[test]
    fn generator_coordinates_for_sk_one() {
        let sk = k256_signing_key_from_hex("0x01").unwrap();
        let (x_le, y_le) = pk_coords_le(sk.verifying_key()).unwrap();
        assert_eq!(x_le, coord_le(GX_BE));
        assert_eq!(y_le, coord_le(GY_BE));
    }

    #[test]
    fn dst_is_sha256_of_the_padded_tag_for_both_arms() {
        let k256_by_hand = sha256_concat(&[pad_to(
            64,
            b"midnight:account:auth:k1:v1:withdraw_unshielded",
        )]);
        assert_eq!(
            circuit_dst(&Arm::K256, "withdraw_unshielded").unwrap(),
            k256_by_hand
        );
        let jubjub_by_hand =
            sha256_concat(&[pad_to(64, b"midnight:account:auth:v1:withdraw_unshielded")]);
        assert_eq!(
            circuit_dst(&Arm::Jubjub, "withdraw_unshielded").unwrap(),
            jubjub_by_hand
        );
    }

    #[test]
    fn k256_device_entry_v2_matches_the_by_hand_derivation_for_both_envelopes() {
        // derive_device_entry_with_k256(self, pk, envelope, epoch, counter)
        // for the sk = 1 key:
        // [DST_DEVICE(32), self(32), x_le(32), y_le(32), envelope(1), epoch(4), counter(8)].
        // Vectors recomputed externally (Python hashlib over the same
        // concatenation) and asserted against the compiled circuit in
        // unit-offline.ts, pinning the encoding against joint drift.
        let self_addr = [0x11u8; 32];
        let (x_le, y_le) = (coord_le(GX_BE), coord_le(GY_BE));
        for (envelope, pinned) in [
            (0u8, "f88e6a3085478879ae9e3859c59493a60b2d443c1608f6bcedbdb7ee1a8f5d66"),
            (1u8, "ae28feb6281f2e2f9d9a0fcda699bb2b3e349d1f20eff7b578afb489b3115d51"),
        ] {
            let via_fab = persistent_hash(&[
                el_bytes(32, &pad_to(32, b"midnight:account:device:k1:v2")),
                el_bytes(32, &self_addr),
                el_bytes(32, &x_le),
                el_bytes(32, &y_le),
                el_uint(1, u128::from(envelope)),
                el_uint(4, 0),
                el_uint(8, 0),
            ])
            .unwrap();
            let by_hand = sha256_concat(&[
                pad_to(32, b"midnight:account:device:k1:v2"),
                self_addr.to_vec(),
                x_le.to_vec(),
                y_le.to_vec(),
                vec![envelope],
                vec![0u8; 4],
                vec![0u8; 8],
            ]);
            assert_eq!(via_fab, by_hand);
            assert_eq!(hex::encode(via_fab), pinned, "envelope {envelope}");
        }
    }

    #[test]
    fn k256_boot_commitment_v2_matches_the_by_hand_derivation_for_both_envelopes() {
        // derive_boot_commitment_with_k256(salt, pk, envelope) for sk = 1:
        // [DST_BOOT(32), salt(32), x_le(32), y_le(32), envelope(1)].
        let salt = [0x22u8; 32];
        let (x_le, y_le) = (coord_le(GX_BE), coord_le(GY_BE));
        for (envelope, pinned) in [
            (0u8, "bec19e88c6ea0afb279841ca7bfca1aa50a0c046cfff30ea29c819b41d564e63"),
            (1u8, "14697f9fb98a39cf19fae28e53dd556109237ae719599198937988939f75463b"),
        ] {
            let via_fab = persistent_hash(&[
                el_bytes(32, &pad_to(32, b"midnight:account:boot:k1:v2")),
                el_bytes(32, &salt),
                el_bytes(32, &x_le),
                el_bytes(32, &y_le),
                el_uint(1, u128::from(envelope)),
            ])
            .unwrap();
            let by_hand = sha256_concat(&[
                pad_to(32, b"midnight:account:boot:k1:v2"),
                salt.to_vec(),
                x_le.to_vec(),
                y_le.to_vec(),
                vec![envelope],
            ]);
            assert_eq!(via_fab, by_hand);
            assert_eq!(hex::encode(via_fab), pinned, "envelope {envelope}");
        }
    }

    #[test]
    fn envelope_digests_match_by_hand_and_the_runtime() {
        // Both envelope digests are plain SHA-256 of the raw concatenation
        // (a Bytes atom carries no framing). Pinned vectors are recomputed
        // externally (Python hashlib) and match the compiled circuit's
        // `envelope_digest`, asserted in unit-offline.ts.
        let challenge = [0xc7u8; 32];
        let none = envelope_digest(0, &challenge).unwrap();
        assert_eq!(none, sha256_concat(&[challenge.to_vec()]));
        assert_eq!(
            hex::encode(none),
            "fdd64f7423a9bc064e56a085573bf51ff5ea77e8d99322ca7afb7bb58c2b72c1"
        );
        let connector = envelope_digest(1, &challenge).unwrap();
        assert_eq!(
            connector,
            sha256_concat(&[CONNECTOR_ENVELOPE_PREFIX.to_vec(), challenge.to_vec()])
        );
        assert_eq!(
            hex::encode(connector),
            "0b389c2c1700fac274dc17f4ec007f807238d66600d14333e6f2f21ae3695364"
        );
        assert!(envelope_digest(2, &challenge).is_err());
    }

    #[test]
    fn k256_challenge_matches_the_by_hand_derivation_and_the_signature_verifies() {
        let sk = k256_signing_key_from_hex("0x01").unwrap();
        let vk = sk.verifying_key();
        let (x_le, y_le) = pk_coords_le(vk).unwrap();
        let contract_address = [0x22u8; 32];
        let color = [0u8; 32];
        let recipient = [0x33u8; 32];
        let amount: u128 = 500;
        let auth_nonce: u64 = 3;

        let dst = circuit_dst(&Arm::K256, "withdraw_unshielded").unwrap();
        let via_fab = persistent_hash(&[
            el_bytes(32, &dst),
            el_bytes(32, &contract_address),
            el_bytes(32, &x_le),
            el_bytes(32, &y_le),
            el_bytes(32, &color),
            el_uint(16, amount),
            el_bytes(32, &recipient),
            el_uint(8, u128::from(auth_nonce)),
        ])
        .unwrap();
        let by_hand = sha256_concat(&[
            dst.to_vec(),
            contract_address.to_vec(),
            x_le.to_vec(),
            y_le.to_vec(),
            color.to_vec(),
            amount.to_le_bytes().to_vec(),
            recipient.to_vec(),
            auth_nonce.to_le_bytes().to_vec(),
        ]);
        assert_eq!(via_fab, by_hand);
        // Vector recomputed externally (Python hashlib over the same
        // concatenation), pinning the encoding against joint drift.
        assert_eq!(
            hex::encode(via_fab),
            "c2f2a3cdfd003b74b8f9aae21018d3d0a6a0abfd5a2eb5bc070c45b8b521d7b8"
        );

        let sig: Signature = sk.sign_prehash(&via_fab).unwrap();
        assert!(vk.verify_prehash(&via_fab, &sig).is_ok());
    }

    #[test]
    fn evm_eip712_constants_match_the_frozen_byte_contract() {
        // The ten constants AUTH-EIP712-PASSPORT-EVM-V1 freezes, recomputed
        // here from the type strings. If the strings are ever edited, this
        // fails before any signature is produced.
        assert_eq!(
            hex::encode(keccak256(&[DOMAIN_ENCODE_TYPE.as_bytes()])),
            "36c25de3e541d5d970f66e4210d728721220fff5c077cc6cd008b3a0c62adab7"
        );
        assert_eq!(
            hex::encode(keccak256(&[DOMAIN_NAME.as_bytes()])),
            "64d1c923e59da20d02c92dc0d6caa0868cb5c8ab17ee0658aafc5f0b72d56c85"
        );
        assert_eq!(
            hex::encode(keccak256(&[DOMAIN_VERSION.as_bytes()])),
            "c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6"
        );
        assert_eq!(
            hex::encode(keccak256(&[TYPE_WITHDRAW_UNSHIELDED.as_bytes()])),
            "3aacc36e8b18ccfd9f416129bb8918b17f3ef1e90f5183b5d52f91c0fdbb2df8"
        );
    }

    #[test]
    fn evm_address_of_the_generator_is_the_well_known_one() {
        // sk = 1: the Ethereum address of the secp256k1 generator, a value
        // every EVM stack agrees on.
        let sk = k256_signing_key_from_hex("0x01").unwrap();
        let (x_be, y_be) = pk_coords_be(sk.verifying_key()).unwrap();
        assert_eq!(
            hex::encode(ethereum_address(&x_be, &y_be)),
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn evm_challenge_core_is_the_k256_preimage_with_the_address() {
        // The evm challenge is a pure Bytes tuple, so its field-aligned
        // encoding is each element zero-padded to its declared width — the
        // Bytes<20> address included. Recomputed by hand, as for k256.
        let dst = circuit_dst(&Arm::Evm, "withdraw_unshielded").unwrap();
        let self_addr = [0x11u8; 32];
        let address = [0xabu8; 20];
        let color = [0u8; 32];
        let recipient = [0x33u8; 32];
        let via_fab = persistent_hash(&[
            el_bytes(32, &dst),
            el_bytes(32, &self_addr),
            el_bytes(20, &address),
            el_bytes(32, &color),
            el_uint(16, 500),
            el_bytes(32, &recipient),
            el_uint(8, 3),
        ])
        .unwrap();
        let by_hand = sha256_concat(&[
            dst.to_vec(),
            self_addr.to_vec(),
            address.to_vec(),
            color.to_vec(),
            pad_to(16, &500u128.to_le_bytes()[..2]),
            recipient.to_vec(),
            pad_to(8, &[3u8]),
        ]);
        assert_eq!(via_fab, by_hand);
        assert_eq!(
            hex::encode(circuit_dst(&Arm::Evm, "withdraw_unshielded").unwrap()),
            hex::encode(sha256_concat(&[pad_to(
                64,
                b"midnight:account:auth:evm:v1:withdraw_unshielded"
            )]))
        );
    }

    #[test]
    fn jubjub_signature_selfverifies_over_a_ground_challenge() {
        // End-to-end sanity of the jubjub signing flow with a fixed sk;
        // challenge bit-exactness against the compiled contract is
        // crossimpl-offline's job.
        let req = SignRequest {
            arm: Arm::Jubjub,
            circuit: "withdraw_unshielded".into(),
            sk: "0x05".into(),
            contract_address: hex::encode([0x22u8; 32]),
            color: hex::encode([0u8; 32]),
            amount: "500".into(),
            recipient: hex::encode([0x33u8; 32]),
            auth_nonce: "3".into(),
            envelope: 0,
            evm_domain_salt: String::new(),
        };
        let out = sign_jubjub(&req).unwrap();
        assert!(out.get("sig_s").is_some());
        assert!(out.get("grind_nonce").is_some());
        let challenge = out.get("challenge").unwrap().as_str().unwrap();
        let challenge_bytes: [u8; 32] = hex::decode(challenge).unwrap().try_into().unwrap();
        assert!(hash_below_r(&challenge_bytes));
    }
}
