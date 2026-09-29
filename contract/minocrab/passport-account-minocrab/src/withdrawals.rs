//! Lane L-WD (AA 00040 P4): the two remaining EVM-signed withdrawals of `account.compact`.
//!
//! - `withdraw_unshielded_with_evm`: debit the unshielded mirror, then `sendUnshielded` to a user
//!   address.
//! - `withdraw_shielded_to_contract_with_evm`: spend a held shielded coin to a CONTRACT
//!   (`right(recipient)`), returning `[sent, change]`.
//!
//! Both reuse P1's signing path unchanged (`seam::require_authorised_with_evm`, the EIP-712 codec,
//! `evm::ethereum_address`). What is new here is each circuit's challenge and digest, the
//! unshielded mirror's debit, and the two stdlib sends specialised the way compactc folds them for
//! a LITERAL recipient tag:
//!
//! - `sendUnshielded(c, a, right<ContractAddress, UserAddress>(r))`: compactc folds the
//!   "auto-receive when sending to self" test (`recipient.is_left && …`) to false and emits
//!   NOTHING for it — no guarded `kernel.self()` read, no guarded `incUnshieldedInputs`.
//!   `minocrab-std`'s `kernel::send_unshielded` takes a runtime `Either` and always emits both
//!   (guarded off), which would add public-input slots, so [`send_unshielded_to_user`] is its body
//!   without that branch.
//! - `sendShielded(coin, right<ZswapCoinPublicKey, ContractAddress>(r), v)`: the auto-receive test
//!   `!recipient.is_left && recipient.right.bytes == selfAddr.bytes` keeps its runtime half, so the
//!   guarded receive claim stays, but its guard is the bare byte equality (no `is_left` select) and
//!   the commitment has no recipient select. See [`crate::zswap::send_shielded_to_contract`].
//!
//! These two circuits are free `#[circuit]` functions rather than members of `account.rs`'s
//! `#[contract]` block only so that the P4 lanes (which ran in parallel) touch disjoint files; the
//! builders are the same either way, and `crate::ported()` lists them.

use minocrab::v3::{Circuit3, Disclose, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, Fr, Private, Public};
use minocrab_ledger::{emit, kernel_claim_unshielded_coin_spend, ImpactElem, LedgerValue};
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    circuit, is_true, label, Bool, CircuitOut, CoinColor, CoinNonce, ContractAddress, Discloses, LedgerRepr, Maybe,
    QualifiedShieldedCoinInfo3, Secp256k1EcdsaSignature, Secp256k1Point, ShieldedCoinInfo3, Uint, UserAddress, Vis3,
    B32,
};

use crate::account::{held_coin, Amount, DeviceEntry, Recipient, SignatureArg, SpentCoin, ACCOUNT};
use crate::byte_codec::uint_word;
use crate::eip712::{
    atom, domain_separator, eip712_digest, struct_hash, TYPE_WITHDRAW_SHIELDED_TO_CONTRACT, TYPE_WITHDRAW_UNSHIELDED,
};
use crate::evm::ethereum_address;
use crate::seam::{challenge_dst, require_authorised_with_evm, self_bytes, CoinSlots};
use crate::zswap::send_shielded_to_contract;

label! {
    pub Color = "color";
}

// ── challenges (account.compact, arm evm) ───────────────────────────────────────────────────────

/// `challenge_withdraw_unshielded_with_evm(self, address, color, amount, recipient, nonce)`:
/// `persistentHash<[Bytes<32>, ContractAddress, Bytes<20>, Bytes<32>, Uint<128>, UserAddress,
/// Uint<64>]>`.
#[allow(clippy::too_many_arguments)]
pub fn challenge_withdraw_unshielded(
    c: &mut Circuit3,
    me: &B32<Private>,
    address: Wire3<FieldT, Private>,
    color: &B32<Private>,
    amount: Wire3<FieldT, Private>,
    recipient: &B32<Private>,
    nonce: Wire3<FieldT, Private>,
) -> B32<Private> {
    c.region("seam: challenge", |c| {
        let dst = challenge_dst(c, "withdraw_unshielded");
        let alignment = Alignment(vec![
            atom(32),
            atom(32),
            atom(20),
            atom(32),
            atom(16),
            atom(32),
            atom(8),
        ]);
        let slots = [
            dst.hi.erase(),
            dst.lo.erase(),
            me.hi.erase(),
            me.lo.erase(),
            address.erase(),
            color.hi.erase(),
            color.lo.erase(),
            amount.erase(),
            recipient.hi.erase(),
            recipient.lo.erase(),
            nonce.erase(),
        ];
        let digest = c.persistent_hash(alignment, &slots);
        B32::from_typed(c, digest)
    })
}

/// `challenge_withdraw_shielded_to_contract_with_evm(self, address, recipient, color, amount,
/// coin, nonce)`: `persistentHash<[Bytes<32>, ContractAddress, Bytes<20>, ContractAddress,
/// Bytes<32>, Uint<128>, QualifiedShieldedCoinInfo, Uint<64>]>` — `withdraw_shielded`'s layout with
/// a contract recipient and its own DST.
#[allow(clippy::too_many_arguments)]
pub fn challenge_withdraw_shielded_to_contract(
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
        let dst = challenge_dst(c, "withdraw_shielded_to_contract");
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

// ── digests (modules/Eip712.compact) ─────────────────────────────────────────────────────────────

/// `evm_digest_withdraw_unshielded(account, salt, owner, authNonce, color, amount, recipient,
/// challenge)`.
#[allow(clippy::too_many_arguments)]
pub fn digest_withdraw_unshielded<V: Vis3>(
    c: &mut Circuit3,
    account: &B32<V>,
    salt: &B32<V>,
    owner: Wire3<FieldT, V>,
    auth_nonce: Wire3<FieldT, V>,
    color: &B32<V>,
    amount: Wire3<FieldT, V>,
    recipient: &B32<V>,
    challenge: &B32<V>,
) -> B32<V> {
    let sep = domain_separator(c, account, salt);
    let amount_word = uint_word(c, amount);
    let sh = struct_hash(
        c,
        &TYPE_WITHDRAW_UNSHIELDED,
        account,
        owner,
        auth_nonce,
        &[color, &amount_word, recipient],
        challenge,
    );
    eip712_digest(c, &sep, &sh)
}

/// `evm_digest_withdraw_shielded_to_contract(account, salt, owner, authNonce, color, amount,
/// recipientContract, challenge)`.
#[allow(clippy::too_many_arguments)]
pub fn digest_withdraw_shielded_to_contract<V: Vis3>(
    c: &mut Circuit3,
    account: &B32<V>,
    salt: &B32<V>,
    owner: Wire3<FieldT, V>,
    auth_nonce: Wire3<FieldT, V>,
    color: &B32<V>,
    amount: Wire3<FieldT, V>,
    recipient_contract: &B32<V>,
    challenge: &B32<V>,
) -> B32<V> {
    let sep = domain_separator(c, account, salt);
    let amount_word = uint_word(c, amount);
    let sh = struct_hash(
        c,
        &TYPE_WITHDRAW_SHIELDED_TO_CONTRACT,
        account,
        owner,
        auth_nonce,
        &[color, &amount_word, recipient_contract],
        challenge,
    );
    eip712_digest(c, &sep, &sh)
}

// ── the unshielded mirror and send ──────────────────────────────────────────────────────────────

/// `debit_unshielded(color, amount)` (MIP-0012 §5):
///
/// ```text
/// assert(unshielded_balances.member(color), "no balance for color");
/// const bal = unshielded_balances.lookup(color);
/// assert(bal >= amount, "insufficient balance");
/// unshielded_balances.insert(color, ((bal - amount) as Uint<128>));
/// ```
///
/// compactc emits the `bal >= amount` assert twice (once for the source's assert, once for the
/// subtraction's own underflow check, the comparison shared); asserting the same bit twice is the
/// same statement, so it is asserted once here. The cast emits no range check, as in compactc:
/// `bal` is a stored `Uint<128>` and `amount ≤ bal`.
pub fn debit_unshielded(c: &mut Circuit3, color: &B32<Public>, amount: Uint<128, Public>) {
    let known = ACCOUNT.unshielded_balances.member(c, color);
    c.assert(is_true(*known).message("no balance for color"));
    let bal = ACCOUNT.unshielded_balances.lookup(c, color).stale(c);
    let short = c.less_than(bal.field(), amount.field(), 128);
    let enough = c.not(short);
    c.assert(is_true(Bool::<Public>::from_field_unchecked(enough)).message("insufficient balance"));
    let neg = c.neg(amount.field());
    let rest = c.add(bal.field(), neg);
    ACCOUNT
        .unshielded_balances
        .insert(c, color, &Uint::<128, Public>::from_field_unchecked(rest));
}

/// `sendUnshielded(color, amount, right<ContractAddress, UserAddress>(recipient))`, as compactc
/// folds it for a literal `right` recipient:
///
/// ```text
/// kernel.incUnshieldedOutputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(color), recipient, amount);
/// // `recipient.is_left && …` is false: the auto-receive branch is gone.
/// ```
///
/// The claim's key is the token type and the recipient side by side: `[1, color, 0, 0]` then
/// `[0, 0, 0, recipient]` (the tag, the unused `ContractAddress` arm, the user address), the
/// constants inline as compactc pushes them.
pub fn send_unshielded_to_user(
    c: &mut Circuit3,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
    recipient: &UserAddress<Public>,
) {
    c.region("kernel: sendUnshielded(right)", |c| {
        let token = kernel::unshielded(c, color);
        kernel::inc_unshielded_outputs(c, &token, amount);

        let token_value = token.ledger_value();
        let r = recipient.bytes();
        let mut atoms = token_value.atoms().to_vec();
        let mut elems = token_value.elems().to_vec();
        atoms.extend([
            AlignmentAtom::Bytes { length: 1 },
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Bytes { length: 32 },
        ]);
        elems.extend([
            ImpactElem::Imm(Fr::from(0u64)),
            ImpactElem::Imm(Fr::from(0u64)),
            ImpactElem::Imm(Fr::from(0u64)),
            ImpactElem::Wire(r.hi),
            ImpactElem::Wire(r.lo),
        ]);
        let key = LedgerValue::new(atoms, elems);
        let amt = amount.ledger_value(c);
        emit(c, &kernel_claim_unshielded_coin_spend(&key, &amt));
    })
}

// ── the circuits' return value ───────────────────────────────────────────────────────────────────

/// `[ShieldedCoinInfo, Maybe<ShieldedCoinInfo>]` — the sent coin, then the change.
pub struct SentAndChange {
    pub sent: ShieldedCoinInfo3<Public>,
    pub change: Maybe<ShieldedCoinInfo3<Public>, Public>,
}

impl CircuitOut for SentAndChange {
    const SLOTS: usize = <ShieldedCoinInfo3<Public> as CircuitOut>::SLOTS
        + <Maybe<ShieldedCoinInfo3<Public>, Public> as CircuitOut>::SLOTS;

    fn emit(self, c: &mut Circuit3, label: &str) {
        self.sent.emit(c, &format!("{label} sent"));
        self.change.emit(c, &format!("{label} change"));
    }
}

fn signature(sig: SignatureArg) -> Secp256k1EcdsaSignature<Private> {
    Secp256k1EcdsaSignature {
        r: sig.r.scalar(),
        s: sig.s.scalar(),
    }
}

// ── the exported circuits ────────────────────────────────────────────────────────────────────────

/// ```text
/// export circuit withdraw_unshielded_with_evm(color: Bytes<32>, amount: Uint<128>,
///                                             recipient: UserAddress, pk: Secp256k1Point,
///                                             use_counter: Uint<64>, sig: Secp256k1EcdsaSignature): []
/// ```
#[circuit]
pub fn withdraw_unshielded_with_evm(
    c: &mut Circuit3,
    color: CoinColor<Private>,
    amount: Uint<128>,
    recipient: UserAddress<Private>,
    pk: Secp256k1Point,
    use_counter: Uint<64>,
    sig: SignatureArg,
) -> Discloses<(DeviceEntry, Color, Amount, Recipient)> {
    let pk = pk.point();
    let sig = signature(sig);

    // const address = secp256k1EthereumAddress(pk);
    let address = ethereum_address(c, pk);

    // const challenge = challenge_withdraw_unshielded_with_evm(kernel.self(), address, color,
    //                                                          amount, recipient, auth_nonce);
    let me = self_bytes(c);
    let nonce = ACCOUNT.auth_nonce.read(c).field();
    let challenge = challenge_withdraw_unshielded(
        c,
        &me,
        address,
        &color.bytes(),
        amount.field(),
        &recipient.bytes(),
        nonce.private(),
    );

    // const digest = evm_digest_withdraw_unshielded(kernel.self().bytes, evm_domain_salt, address,
    //                                               auth_nonce, color, amount, recipient.bytes,
    //                                               challenge);
    let account = self_bytes(c);
    let salt = ACCOUNT.evm_domain_salt.read(c).private();
    let nonce2 = ACCOUNT.auth_nonce.read(c).field();
    let digest = digest_withdraw_unshielded(
        c,
        &account,
        &salt,
        address,
        nonce2.private(),
        &color.bytes(),
        amount.field(),
        &recipient.bytes(),
        &challenge,
    );

    require_authorised_with_evm(c, pk, use_counter, &sig, &digest, address);

    // do_withdraw_unshielded(color, amount, recipient):
    //   const c = disclose(color); const a = disclose(amount);
    //   debit_unshielded(c, a);
    //   sendUnshielded(c, a, right<ContractAddress, UserAddress>(disclose(recipient)));
    let color = color.disclose_as::<Color>(c);
    let amount = amount.disclose_as::<Amount>(c);
    debit_unshielded(c, &color.bytes(), amount);
    let recipient = recipient.disclose_as::<Recipient>(c);
    send_unshielded_to_user(c, color, amount, &recipient);

    Discloses::of(())
}

/// ```text
/// export circuit withdraw_shielded_to_contract_with_evm(recipient: ContractAddress, color: Bytes<32>,
///                                                       amount: Uint<128>, pk: Secp256k1Point,
///                                                       use_counter: Uint<64>,
///                                                       sig: Secp256k1EcdsaSignature
///                                                       ): [ShieldedCoinInfo, Maybe<ShieldedCoinInfo>]
/// ```
#[circuit(output = "sent and change")]
pub fn withdraw_shielded_to_contract_with_evm(
    c: &mut Circuit3,
    recipient: ContractAddress<Private>,
    color: CoinColor<Private>,
    amount: Uint<128>,
    pk: Secp256k1Point,
    use_counter: Uint<64>,
    sig: SignatureArg,
) -> Discloses<(DeviceEntry, SpentCoin, Recipient, Amount), SentAndChange> {
    let pk = pk.point();
    let sig = signature(sig);

    // const coin = held_coin(color);   (the witness runs BEFORE the challenge — AUTH-10)
    let coin = held_coin(c);

    // const address = secp256k1EthereumAddress(pk);
    let address = ethereum_address(c, pk);

    // const challenge = challenge_withdraw_shielded_to_contract_with_evm(kernel.self(), address,
    //                                         recipient, color, amount, coin, auth_nonce);
    let me = self_bytes(c);
    let nonce = ACCOUNT.auth_nonce.read(c).field();
    let challenge = challenge_withdraw_shielded_to_contract(
        c,
        &me,
        address,
        &recipient.bytes(),
        &color.bytes(),
        amount.field(),
        &coin,
        nonce.private(),
    );

    // const digest = evm_digest_withdraw_shielded_to_contract(kernel.self().bytes, evm_domain_salt,
    //                                         address, auth_nonce, color, amount, recipient.bytes,
    //                                         challenge);
    let account = self_bytes(c);
    let salt = ACCOUNT.evm_domain_salt.read(c).private();
    let nonce2 = ACCOUNT.auth_nonce.read(c).field();
    let digest = digest_withdraw_shielded_to_contract(
        c,
        &account,
        &salt,
        address,
        nonce2.private(),
        &color.bytes(),
        amount.field(),
        &recipient.bytes(),
        &challenge,
    );

    require_authorised_with_evm(c, pk, use_counter, &sig, &digest, address);

    // return do_withdraw_shielded_to_contract(recipient, amount, coin):
    //   const result = sendShielded(disclose(coin), right(disclose(recipient)), disclose(amount));
    //   return [disclose(result.sent), result.change];
    let input = QualifiedShieldedCoinInfo3 {
        nonce: CoinNonce(coin.nonce.disclose_as::<SpentCoin>(c)),
        color: CoinColor(coin.color.disclose_as::<SpentCoin>(c)),
        value: coin.value.disclose_as::<SpentCoin>(c),
        mt_index: coin.mt_index.disclose_as::<SpentCoin>(c),
    };
    let recipient = recipient.disclose_as::<Recipient>(c);
    let amount = amount.disclose_as::<Amount>(c);
    let result = send_shielded_to_contract(c, &input, &recipient, amount);
    Discloses::of(SentAndChange {
        sent: result.sent,
        change: result.change,
    })
}
