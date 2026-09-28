//! `contracts/account.compact` — the ledger block and the ported exported circuits.
//!
//! Ledger block (declaration order = field index; compactc keeps all fifteen in ONE state array,
//! so every path is a single index):
//! ```text
//! export ledger round: Uint<64>;                          //  0
//! export ledger enc_key: Bytes<32>;                       //  1
//! export ledger inbox: Map<Uint<64>, Bytes<192>>;         //  2
//! export ledger inbox_count: Uint<64>;                    //  3
//! export ledger unshielded_balances: Map<Bytes<32>, Uint<128>>; // 4
//! export ledger spec_version: Uint<32>;                   //  5
//! export ledger devices: Set<Bytes<32>>;                  //  6
//! export ledger device_epoch: Uint<32>;                   //  7
//! export ledger device_count: Uint<8>;                    //  8
//! export ledger auth_nonce: Uint<64>;                     //  9
//! export ledger boot: Bytes<32>;                          // 10
//! export ledger booted: Boolean;                          // 11
//! export sealed ledger evm_domain_salt: Bytes<32>;        // 12
//! export sealed ledger vault: Erc20Vault;                 // 13
//! export sealed ledger vault_address: ContractAddress;    // 14
//! witness held_coin(color: Bytes<32>): QualifiedShieldedCoinInfo;
//! ```

use minocrab::v3::{Circuit3, Disclose, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_std::v3::{
    contract, label, Bool, BytesN, CircuitArg, CoinColor, CoinNonce, ContractAddress, Discloses, Ledger, LedgerCell,
    LedgerMap, LedgerSet, Maybe, QualifiedShieldedCoinInfo3, Secp256k1EcdsaSignature, Secp256k1Point, Secp256k1Scalar,
    ShieldedCoinInfo3, Uint, ZswapCoinPublicKey, B32,
};

use crate::eip712::{digest_append_inbox, digest_withdraw_shielded};
use crate::evm::ethereum_address;
use crate::seam::{
    challenge_append_inbox, challenge_withdraw_shielded, require_authorised_with_evm, self_bytes, succ_u64, CoinSlots,
};
use crate::zswap::send_shielded_to_user;

label! {
    pub DeviceEntry = "device entry";
    pub InboxEntry = "inbox entry";
    pub SpentCoin = "spent coin";
    pub Recipient = "recipient";
    pub Amount = "amount";
}

/// THE LEDGER BLOCK — declaration order is the field index, one for one with `account.compact`.
/// The ported circuits touch fields 0, 2, 3, 6, 7, 9 and 12; the rest are declared so the indices
/// line up (`vault`, a contract reference, is stored as its address).
#[derive(Ledger)]
pub struct Account {
    pub round: LedgerCell<Uint<64, Public>>,
    pub enc_key: LedgerCell<B32<Public>>,
    pub inbox: LedgerMap<Uint<64, Public>, BytesN<Public, 192>>,
    pub inbox_count: LedgerCell<Uint<64, Public>>,
    pub unshielded_balances: LedgerMap<B32<Public>, Uint<128, Public>>,
    pub spec_version: LedgerCell<Uint<32, Public>>,
    pub devices: LedgerSet<B32<Public>>,
    pub device_epoch: LedgerCell<Uint<32, Public>>,
    pub device_count: LedgerCell<Uint<8, Public>>,
    pub auth_nonce: LedgerCell<Uint<64, Public>>,
    pub boot: LedgerCell<B32<Public>>,
    pub booted: LedgerCell<Bool<Public>>,
    pub evm_domain_salt: LedgerCell<B32<Public>>,
    pub vault: LedgerCell<ContractAddress<Public>>,
    pub vault_address: LedgerCell<ContractAddress<Public>>,
}

/// `Maybe<ShieldedCoinInfo>` — the change coin a withdrawal returns.
pub type Change = Maybe<ShieldedCoinInfo3<Public>, Public>;

/// The contract's ledger block.
pub const ACCOUNT: Account = Account::new();

/// `Secp256k1EcdsaSignature { r: Secp256k1Scalar, s: Secp256k1Scalar }` as an argument.
#[derive(CircuitArg)]
pub struct SignatureArg {
    pub r: Secp256k1Scalar<Private>,
    pub s: Secp256k1Scalar<Private>,
}

impl SignatureArg {
    fn wires(self) -> Secp256k1EcdsaSignature<Private> {
        Secp256k1EcdsaSignature {
            r: self.r.scalar(),
            s: self.s.scalar(),
        }
    }
}

/// `witness held_coin(color: Bytes<32>): QualifiedShieldedCoinInfo` — six private inputs, each
/// range-constrained to its field's width, as compactc checks a witness's return value.
fn held_coin(c: &mut Circuit3) -> CoinSlots<Private> {
    let nonce = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    let nonce = nonce.constrain_input(c);
    let color = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    let color = color.constrain_input(c);
    let value = Uint::<128, Private>::from_field_unchecked(c.witness::<FieldT>()).constrain_input(c);
    let mt_index = Uint::<64, Private>::from_field_unchecked(c.witness::<FieldT>()).constrain_input(c);
    CoinSlots {
        nonce,
        color,
        value: value.field(),
        mt_index: mt_index.field(),
    }
}

fn public_b32(w: B32<Public>) -> B32<Private> {
    w.private()
}

fn public_field(w: Wire3<FieldT, Public>) -> Wire3<FieldT, Private> {
    w.private()
}

#[contract]
impl Account {
    /// ```text
    /// export circuit append_inbox_with_evm(entry: Bytes<192>, pk: Secp256k1Point,
    ///                                      use_counter: Uint<64>, sig: Secp256k1EcdsaSignature): []
    /// ```
    #[circuit]
    pub fn append_inbox_with_evm(
        c: &mut Circuit3,
        entry: BytesN<Private, 192>,
        pk: Secp256k1Point,
        use_counter: Uint<64>,
        sig: SignatureArg,
    ) -> Discloses<(DeviceEntry, InboxEntry)> {
        let pk = pk.point();
        let sig = sig.wires();

        // const address = secp256k1EthereumAddress(pk);
        let address = ethereum_address(c, pk);

        // const challenge = challenge_append_inbox_with_evm(kernel.self(), address, entry, auth_nonce);
        let me = self_bytes(c);
        let nonce = ACCOUNT.auth_nonce.read(c).field();
        let challenge = challenge_append_inbox(c, &me, address, entry.limbs(), public_field(nonce));

        // const digest = evm_digest_append_inbox(kernel.self().bytes, evm_domain_salt, address,
        //                                        auth_nonce, keccak256<Bytes<192>>(entry), challenge);
        let account = self_bytes(c);
        let salt = public_b32(*ACCOUNT.evm_domain_salt.read(c));
        let nonce2 = ACCOUNT.auth_nonce.read(c).field();
        let entry_hash = {
            let alignment = minocrab::Alignment(vec![crate::eip712::atom(192)]);
            let limbs: Vec<_> = entry.limbs().iter().map(|w| w.erase()).collect();
            let d = c.keccak256(alignment, &limbs);
            B32::from_typed(c, d)
        };
        let digest = digest_append_inbox(
            c,
            &account,
            &salt,
            address,
            public_field(nonce2),
            &entry_hash,
            &challenge,
        );

        require_authorised_with_evm(c, pk, use_counter, &sig, &digest, address);

        // do_append_inbox(entry): inbox.insert(inbox_count, disclose(entry)); inbox_count += 1;
        let entry: BytesN<Public, 192> = entry.disclose_as::<InboxEntry>(c);
        let count = ACCOUNT.inbox_count.read(c).stale(c);
        ACCOUNT.inbox.insert(c, &count, &entry);
        let count2 = ACCOUNT.inbox_count.read(c).stale(c);
        let next = succ_u64(c, count2.field());
        ACCOUNT.inbox_count.write(c, &next);

        Discloses::of(())
    }

    /// ```text
    /// export circuit withdraw_shielded_with_evm(recipient: ZswapCoinPublicKey, color: Bytes<32>,
    ///                                           amount: Uint<128>, pk: Secp256k1Point,
    ///                                           use_counter: Uint<64>, sig: Secp256k1EcdsaSignature
    ///                                           ): Maybe<ShieldedCoinInfo>
    /// ```
    #[circuit(output = "change")]
    pub fn withdraw_shielded_with_evm(
        c: &mut Circuit3,
        recipient: ZswapCoinPublicKey<Private>,
        color: CoinColor<Private>,
        amount: Uint<128>,
        pk: Secp256k1Point,
        use_counter: Uint<64>,
        sig: SignatureArg,
    ) -> Discloses<(DeviceEntry, SpentCoin, Recipient, Amount), Change> {
        let pk = pk.point();
        let sig = sig.wires();

        // const coin = held_coin(color);   (the witness runs BEFORE the challenge — AUTH-10)
        let coin = held_coin(c);

        // const address = secp256k1EthereumAddress(pk);
        let address = ethereum_address(c, pk);

        // const challenge = challenge_withdraw_shielded_with_evm(kernel.self(), address, recipient,
        //                                                        color, amount, coin, auth_nonce);
        let me = self_bytes(c);
        let nonce = ACCOUNT.auth_nonce.read(c).field();
        let challenge = challenge_withdraw_shielded(
            c,
            &me,
            address,
            &recipient.bytes(),
            &color.bytes(),
            amount.field(),
            &coin,
            public_field(nonce),
        );

        // const digest = evm_digest_withdraw_shielded(kernel.self().bytes, evm_domain_salt, address,
        //                                             auth_nonce, color, amount, recipient.bytes,
        //                                             challenge);
        let account = self_bytes(c);
        let salt = public_b32(*ACCOUNT.evm_domain_salt.read(c));
        let nonce2 = ACCOUNT.auth_nonce.read(c).field();
        let digest = digest_withdraw_shielded(
            c,
            &account,
            &salt,
            address,
            public_field(nonce2),
            &color.bytes(),
            amount.field(),
            &recipient.bytes(),
            &challenge,
        );

        require_authorised_with_evm(c, pk, use_counter, &sig, &digest, address);

        // return do_withdraw_shielded(recipient, amount, coin):
        //   sendShielded(disclose(coin), left(disclose(recipient)), disclose(amount)) → change
        let input = QualifiedShieldedCoinInfo3 {
            nonce: CoinNonce(coin.nonce.disclose_as::<SpentCoin>(c)),
            color: CoinColor(coin.color.disclose_as::<SpentCoin>(c)),
            value: coin.value.disclose_as::<SpentCoin>(c),
            mt_index: coin.mt_index.disclose_as::<SpentCoin>(c),
        };
        let recipient = recipient.disclose_as::<Recipient>(c);
        let amount = amount.disclose_as::<Amount>(c);
        Discloses::of(send_shielded_to_user(c, &input, &recipient, amount))
    }
}
