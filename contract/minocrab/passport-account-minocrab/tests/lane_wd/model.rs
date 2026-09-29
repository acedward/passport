//! Lane L-WD's additions to the off-circuit model (`support/model.rs`): the unshielded mirror in
//! the ledger state, and what a wallet signs for `withdraw_unshielded_with_evm` and
//! `withdraw_shielded_to_contract_with_evm`. Written from `account.compact` and
//! `modules/Eip712.compact`, NOT from the port, and checked against the ethers fixture vectors
//! (`kat_withdraw_types`).

use midnight_base_crypto::fab::AlignedValue;
use midnight_onchain_state::state::StateValue;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap;
use minocrab::Fr;
use minocrab_zkir::v3::IrValue;

use crate::support::model::*;
use crate::support::prims::*;

pub const WITHDRAW_UNSHIELDED_STR: &str = "WithdrawUnshielded(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipient,bytes32 challenge)";
pub const WITHDRAW_TO_CONTRACT_STR: &str = "WithdrawShieldedToContract(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipientContract,bytes32 challenge)";

/// `AccountState::state()` with field 4, `unshielded_balances: Map<Bytes<32>, Uint<128>>`,
/// holding `balances`.
pub fn state_with_balances(st: &AccountState, balances: &[([u8; 32], u128)]) -> StateValue {
    let state = st.state();
    let StateValue::Array(ref fields) = state else {
        unreachable!("the account state is an array")
    };
    let mut map: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
    for (color, value) in balances {
        map = map.insert(bytesn_value(32, color), cell(bytesn_value(16, &value.to_le_bytes())));
    }
    StateValue::Array(fields.insert(4, StateValue::Map(map)).expect("field 4 exists"))
}

// ── withdraw_unshielded_with_evm ─────────────────────────────────────────────────────────────────

/// `challenge_withdraw_unshielded_with_evm(self, address, color, amount, recipient, nonce)`.
pub fn challenge_withdraw_unshielded(
    me: &[u8; 32],
    address: &[u8; 20],
    color: &[u8; 32],
    amount: u128,
    recipient: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&challenge_dst("withdraw_unshielded"));
    let (s_hi, s_lo) = b32_slots(me);
    let (c_hi, c_lo) = b32_slots(color);
    let (r_hi, r_lo) = b32_slots(recipient);
    fab_sha256(
        vec![atom(32), atom(32), atom(20), atom(32), atom(16), atom(32), atom(8)],
        &[
            d_hi,
            d_lo,
            s_hi,
            s_lo,
            b20(address),
            c_hi,
            c_lo,
            u128_limb(amount),
            r_hi,
            r_lo,
            Fr::from(nonce),
        ],
    )
}

/// `withdraw_unshielded_with_evm(color, amount, recipient, pk, use_counter, sig)` as encoded
/// circuit inputs.
#[derive(Clone)]
pub struct UnshieldedCall {
    pub color: [u8; 32],
    pub amount: u128,
    pub recipient: [u8; 32],
    pub pk: IrValue,
    pub use_counter: u64,
    pub r: IrValue,
    pub s: IrValue,
}

impl UnshieldedCall {
    pub fn inputs(&self) -> Vec<Fr> {
        let (c_hi, c_lo) = b32_slots(&self.color);
        let (r_hi, r_lo) = b32_slots(&self.recipient);
        let mut v = vec![c_hi, c_lo, u128_limb(self.amount), r_hi, r_lo];
        v.extend(natives(&self.pk));
        v.push(Fr::from(self.use_counter));
        v.extend(natives(&self.r));
        v.extend(natives(&self.s));
        v
    }
}

/// What a wallet signs for `withdraw_unshielded_with_evm`, every free parameter exposed.
#[derive(Clone)]
pub struct UnshieldedSigning {
    pub account: [u8; 32],
    pub salt: [u8; 32],
    pub nonce: u64,
    pub color: [u8; 32],
    pub amount: u128,
    pub recipient: [u8; 32],
    pub domain: Domain,
    pub type_str: String,
    /// The challenge's own view of the account (`kernel.self()`), normally `account`.
    pub challenge_self: [u8; 32],
}

impl UnshieldedSigning {
    pub fn digest(&self, owner: &[u8; 20]) -> [u8; 32] {
        let challenge = challenge_withdraw_unshielded(
            &self.challenge_self,
            owner,
            &self.color,
            self.amount,
            &self.recipient,
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

// ── withdraw_shielded_to_contract_with_evm ───────────────────────────────────────────────────────

/// `challenge_withdraw_shielded_to_contract_with_evm(self, address, recipient, color, amount,
/// coin, nonce)`.
#[allow(clippy::too_many_arguments)]
pub fn challenge_withdraw_to_contract(
    me: &[u8; 32],
    address: &[u8; 20],
    recipient: &[u8; 32],
    color: &[u8; 32],
    amount: u128,
    coin: &Coin,
    nonce: u64,
) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&challenge_dst("withdraw_shielded_to_contract"));
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

/// `withdraw_shielded_to_contract_with_evm(recipient, color, amount, pk, use_counter, sig)` as
/// encoded circuit inputs, plus the `held_coin` witness.
#[derive(Clone)]
pub struct ToContractCall {
    pub recipient: [u8; 32],
    pub color: [u8; 32],
    pub amount: u128,
    pub pk: IrValue,
    pub use_counter: u64,
    pub r: IrValue,
    pub s: IrValue,
    pub coin: Coin,
}

impl ToContractCall {
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
pub struct ToContractSigning {
    pub account: [u8; 32],
    pub salt: [u8; 32],
    pub nonce: u64,
    pub recipient: [u8; 32],
    pub color: [u8; 32],
    pub amount: u128,
    pub coin: Coin,
    pub domain: Domain,
    pub type_str: String,
    pub challenge_self: [u8; 32],
}

impl ToContractSigning {
    pub fn digest(&self, owner: &[u8; 20]) -> [u8; 32] {
        let challenge = challenge_withdraw_to_contract(
            &self.challenge_self,
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
