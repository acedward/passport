//! The off-circuit model of the account: its ledger state (as the `StateValue` the Impact VM runs
//! against), an EVM device key, and the EIP-712 / challenge / device-entry constructions a wallet
//! and a relayer compute. Written from `account.compact` and `modules/Eip712.compact`, NOT from the
//! port — and checked against the ethers-generated fixture vectors (`kat_eip712`), so a wrong model
//! shows up as the reference artifact refusing an honest call, never as a false pass.
#![allow(dead_code)]

use midnight_base_crypto::fab::AlignedValue;
use midnight_onchain_state::state::StateValue;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::{Array, HashMap};
use minocrab::Fr;
use minocrab_zkir::v3::IrValue;

use super::prims::*;

// ── the ledger state ─────────────────────────────────────────────────────────────────────────────

/// `account.compact`'s ledger, one field per declaration index.
#[derive(Clone, Debug)]
pub struct AccountState {
    pub round: u64,
    pub enc_key: [u8; 32],
    pub inbox: Vec<(u64, [u8; 192])>,
    pub inbox_count: u64,
    pub spec_version: u32,
    pub devices: Vec<[u8; 32]>,
    pub device_epoch: u32,
    pub device_count: u8,
    pub auth_nonce: u64,
    pub boot: [u8; 32],
    pub booted: bool,
    pub evm_domain_salt: [u8; 32],
    pub vault: [u8; 32],
    pub vault_address: [u8; 32],
}

impl AccountState {
    /// An activated account: one enrolled device, the given counters.
    pub fn activated(salt: [u8; 32]) -> Self {
        AccountState {
            round: 1,
            enc_key: [0x5e; 32],
            inbox: Vec::new(),
            inbox_count: 0,
            spec_version: 1,
            devices: Vec::new(),
            device_epoch: 0,
            device_count: 1,
            auth_nonce: 0,
            boot: [0u8; 32],
            booted: true,
            evm_domain_salt: salt,
            vault: [0u8; 32],
            vault_address: [0u8; 32],
        }
    }

    pub fn state(&self) -> StateValue {
        let u = |n: u32, v: u64| cell(bytesn_value(n, &v.to_le_bytes()[..n as usize]));
        let b32 = |b: &[u8; 32]| cell(bytesn_value(32, b));
        let mut inbox: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
        for (k, v) in &self.inbox {
            inbox = inbox.insert(bytesn_value(8, &k.to_le_bytes()), cell(bytesn_value(192, v)));
        }
        let mut devices: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
        for d in &self.devices {
            devices = devices.insert(bytesn_value(32, d), StateValue::Null);
        }
        let balances: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
        StateValue::Array(Array::from(vec![
            u(8, self.round),
            b32(&self.enc_key),
            StateValue::Map(inbox),
            u(8, self.inbox_count),
            StateValue::Map(balances),
            u(4, u64::from(self.spec_version)),
            StateValue::Map(devices),
            u(4, u64::from(self.device_epoch)),
            u(1, u64::from(self.device_count)),
            u(8, self.auth_nonce),
            b32(&self.boot),
            u(1, u64::from(self.booted)),
            b32(&self.evm_domain_salt),
            b32(&self.vault),
            b32(&self.vault_address),
        ]))
    }
}

// ── the device key ───────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Key {
    pub d: IrValue,
    pub pk: IrValue,
    pub address: [u8; 20],
}

impl Key {
    pub fn from_be(secret: &[u8; 32]) -> Key {
        let d = scalar_be(secret);
        let pk = point_of(&d);
        let address = eth_address(&pk);
        Key { d, pk, address }
    }

    /// ECDSA over `digest` with a nonce derived from `seed` (any nonzero scalar is fine for a test
    /// signature; RFC 6979 is a wallet's concern, not the circuit's).
    pub fn sign(&self, digest: &[u8; 32], seed: u64) -> (IrValue, IrValue) {
        let mut k = [0u8; 32];
        k[..8].copy_from_slice(&seed.max(1).to_be_bytes());
        k[31] = 0x5a;
        sign(digest, &self.d, &scalar_be(&k))
    }
}

/// A deterministic TEST key: the secret is SHA-256 of a tag, so no key material is written down
/// anywhere. Only the gate's honest probes use it; it controls nothing on any network.
pub fn test_key(tag: &str) -> Key {
    use sha2::{Digest, Sha256};
    let secret: [u8; 32] = Sha256::digest(format!("aa00040 gate test key: {tag}").as_bytes()).into();
    Key::from_be(&secret)
}

/// A secp256k1 point from its big-endian affine coordinates.
pub fn point_from_be(x: &[u8; 32], y: &[u8; 32]) -> IrValue {
    use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
    use midnight_zkir_v3::ir_instructions::from_coordinates::from_coordinates_offcircuit;
    use minocrab_zkir::v3::IrType;
    let base = |be: &[u8; 32]| {
        let mut le = *be;
        le.reverse();
        from_bytes32_offcircuit(&IrType::Secp256k1Base, &le).unwrap()
    };
    from_coordinates_offcircuit(&base(x), &base(y)).unwrap()
}

// ── EIP-712 (modules/Eip712.compact, over plain bytes) ──────────────────────────────────────────

pub const DOMAIN_TYPE_STR: &str = "EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)";
pub const APPEND_INBOX_STR: &str =
    "AppendInbox(bytes32 account,address owner,uint64 authNonce,bytes32 entryHash,bytes32 challenge)";
pub const WITHDRAW_SHIELDED_STR: &str = "WithdrawShielded(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipientCoinPublicKey,bytes32 challenge)";

/// The domain's free parameters, so the tamper sweep can move each one.
#[derive(Clone)]
pub struct Domain {
    pub type_str: String,
    pub name: String,
    pub version: String,
}

impl Default for Domain {
    fn default() -> Self {
        Domain {
            type_str: DOMAIN_TYPE_STR.into(),
            name: "Midnight Passport Account".into(),
            version: "1".into(),
        }
    }
}

pub fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub fn uint_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

pub fn alias(account: &[u8; 32]) -> [u8; 20] {
    keccak(account)[12..32].try_into().unwrap()
}

pub fn domain_separator(dom: &Domain, account: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut pre = keccak(dom.type_str.as_bytes()).to_vec();
    pre.extend_from_slice(&keccak(dom.name.as_bytes()));
    pre.extend_from_slice(&keccak(dom.version.as_bytes()));
    pre.extend_from_slice(&address_word(&alias(account)));
    pre.extend_from_slice(salt);
    keccak(&pre)
}

pub fn struct_hash(
    type_str: &str,
    account: &[u8; 32],
    owner: &[u8; 20],
    nonce: u64,
    fields: &[[u8; 32]],
    challenge: &[u8; 32],
) -> [u8; 32] {
    let mut pre = keccak(type_str.as_bytes()).to_vec();
    pre.extend_from_slice(account);
    pre.extend_from_slice(&address_word(owner));
    pre.extend_from_slice(&uint_word(u128::from(nonce)));
    for f in fields {
        pre.extend_from_slice(f);
    }
    pre.extend_from_slice(challenge);
    keccak(&pre)
}

pub fn eip712_digest(separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut pre = vec![0x19, 0x01];
    pre.extend_from_slice(separator);
    pre.extend_from_slice(struct_hash);
    keccak(&pre)
}

// ── the account's signing path (account.compact) ─────────────────────────────────────────────────

/// `persistentHash<[Bytes<64>]>([pad(64, "midnight:account:auth:evm:v1:<circuit>")])`, through
/// the FAB route (not the port's shortcut).
pub fn challenge_dst(circuit: &str) -> [u8; 32] {
    let tag: [u8; 64] = pad(&format!("midnight:account:auth:evm:v1:{circuit}"));
    fab_sha256(vec![atom(64)], &bytes_limbs(64, &tag))
}

/// `derive_device_entry_with_evm(self, address, epoch, counter)`.
pub fn device_entry(me: &[u8; 32], address: &[u8; 20], epoch: u32, counter: u64) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&pad::<32>("midnight:account:device:evm:v1"));
    let (s_hi, s_lo) = b32_slots(me);
    fab_sha256(
        vec![atom(32), atom(32), atom(20), atom(4), atom(8)],
        &[
            d_hi,
            d_lo,
            s_hi,
            s_lo,
            b20(address),
            Fr::from(u64::from(epoch)),
            Fr::from(counter),
        ],
    )
}

pub fn challenge_append_inbox(me: &[u8; 32], address: &[u8; 20], entry: &[u8; 192], nonce: u64) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&challenge_dst("append_inbox"));
    let (s_hi, s_lo) = b32_slots(me);
    let mut limbs = vec![d_hi, d_lo, s_hi, s_lo, b20(address)];
    limbs.extend(bytes_limbs(192, entry));
    limbs.push(Fr::from(nonce));
    fab_sha256(vec![atom(32), atom(32), atom(20), atom(192), atom(8)], &limbs)
}

/// A qualified coin: nonce, colour, value, Merkle-tree index.
#[derive(Clone, Copy, Debug)]
pub struct Coin {
    pub nonce: [u8; 32],
    pub color: [u8; 32],
    pub value: u128,
    pub mt_index: u64,
}

impl Coin {
    pub fn private_transcript(&self) -> Vec<Fr> {
        let (n_hi, n_lo) = b32_slots(&self.nonce);
        let (c_hi, c_lo) = b32_slots(&self.color);
        vec![n_hi, n_lo, c_hi, c_lo, u128_limb(self.value), Fr::from(self.mt_index)]
    }
}

#[allow(clippy::too_many_arguments)]
pub fn challenge_withdraw_shielded(
    me: &[u8; 32],
    address: &[u8; 20],
    recipient: &[u8; 32],
    color: &[u8; 32],
    amount: u128,
    coin: &Coin,
    nonce: u64,
) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&challenge_dst("withdraw_shielded"));
    let (s_hi, s_lo) = b32_slots(me);
    let (r_hi, r_lo) = b32_slots(recipient);
    let (c_hi, c_lo) = b32_slots(color);
    let mut limbs = vec![
        d_hi,
        d_lo,
        s_hi,
        s_lo,
        b20(address),
        r_hi,
        r_lo,
        c_hi,
        c_lo,
        u128_limb(amount),
    ];
    limbs.extend(coin.private_transcript());
    limbs.push(Fr::from(nonce));
    fab_sha256(
        vec![
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
        ],
        &limbs,
    )
}

// ── the circuit calls ────────────────────────────────────────────────────────────────────────────

/// `append_inbox_with_evm(entry, pk, use_counter, sig)` as encoded circuit inputs.
#[derive(Clone)]
pub struct AppendCall {
    pub entry: [u8; 192],
    pub pk: IrValue,
    pub use_counter: u64,
    pub r: IrValue,
    pub s: IrValue,
}

impl AppendCall {
    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = bytes_limbs(192, &self.entry);
        v.extend(natives(&self.pk));
        v.push(Fr::from(self.use_counter));
        v.extend(natives(&self.r));
        v.extend(natives(&self.s));
        v
    }
}

/// What a wallet signs for `append_inbox_with_evm`, with every free parameter exposed.
#[derive(Clone)]
pub struct AppendSigning {
    pub account: [u8; 32],
    pub salt: [u8; 32],
    pub nonce: u64,
    pub entry: [u8; 192],
    pub domain: Domain,
    pub type_str: String,
    /// The challenge's own view of the account (`kernel.self()`), normally `account`.
    pub challenge_self: [u8; 32],
}

impl AppendSigning {
    pub fn honest(account: [u8; 32], salt: [u8; 32], nonce: u64, entry: [u8; 192]) -> Self {
        AppendSigning {
            account,
            salt,
            nonce,
            entry,
            domain: Domain::default(),
            type_str: APPEND_INBOX_STR.into(),
            challenge_self: account,
        }
    }

    pub fn digest(&self, owner: &[u8; 20]) -> [u8; 32] {
        let challenge = challenge_append_inbox(&self.challenge_self, owner, &self.entry, self.nonce);
        let sep = domain_separator(&self.domain, &self.account, &self.salt);
        let sh = struct_hash(
            &self.type_str,
            &self.account,
            owner,
            self.nonce,
            &[keccak(&self.entry)],
            &challenge,
        );
        eip712_digest(&sep, &sh)
    }
}

/// `withdraw_shielded_with_evm(recipient, color, amount, pk, use_counter, sig)` as encoded circuit
/// inputs, plus the `held_coin` witness.
#[derive(Clone)]
pub struct WithdrawCall {
    pub recipient: [u8; 32],
    pub color: [u8; 32],
    pub amount: u128,
    pub pk: IrValue,
    pub use_counter: u64,
    pub r: IrValue,
    pub s: IrValue,
    pub coin: Coin,
}

impl WithdrawCall {
    pub fn inputs(&self) -> Vec<Fr> {
        let (r_hi, r_lo) = b32_slots(&self.recipient);
        let (c_hi, c_lo) = b32_slots(&self.color);
        let mut v = vec![r_hi, r_lo, c_hi, c_lo, u128_limb(self.amount)];
        v.extend(natives(&self.pk));
        v.push(Fr::from(self.use_counter));
        v.extend(natives(&self.r));
        v.extend(natives(&self.s));
        v
    }
}

#[derive(Clone)]
pub struct WithdrawSigning {
    pub account: [u8; 32],
    pub salt: [u8; 32],
    pub nonce: u64,
    pub recipient: [u8; 32],
    pub color: [u8; 32],
    pub amount: u128,
    pub coin: Coin,
    pub domain: Domain,
    pub type_str: String,
}

impl WithdrawSigning {
    pub fn digest(&self, owner: &[u8; 20]) -> [u8; 32] {
        let challenge = challenge_withdraw_shielded(
            &self.account,
            owner,
            &self.recipient,
            &self.color,
            self.amount,
            &self.coin,
            self.nonce,
        );
        let sep = domain_separator(&self.domain, &self.account, &self.salt);
        let sh = struct_hash(
            &self.type_str,
            &self.account,
            owner,
            self.nonce,
            &[self.color, uint_word(self.amount), self.recipient],
            &challenge,
        );
        eip712_digest(&sep, &sh)
    }
}
