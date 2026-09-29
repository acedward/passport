//! The stdlib's `sendShielded`, specialised to a USER recipient
//! (`left<ZswapCoinPublicKey, ContractAddress>(pk)`), as compactc folds it. (Lane L-WD adds the
//! CONTRACT-recipient variant, [`send_shielded_to_contract`], at the end of this file.)
//!
//! `minocrab-std`'s `kernel::send_shielded` takes the recipient as a runtime `Either`, so it always
//! emits the "auto-receive when sending to self" claim under the guard `!is_left && right == self`.
//! compactc sees a LITERAL `left(...)` here, folds that guard to false and emits nothing at all for
//! the branch. A guarded-off Impact still occupies public-input slots (zeros, and an entry in
//! `pi_skips`), so calling the generic gadget would move the public-input stream. This is the
//! gadget's body with the branch removed, and with the output commitment's `is_left` tag and data
//! as compactc emits them (`1`, the recipient's key).
//!
//! Everything else is `minocrab-std`'s, unchanged: the nullifier and commitment gadgets, the
//! claims, the derived nonces (transcribed below because the std helpers are private), and the
//! change handling.
//!
//! ```text
//! const selfAddr = kernel.self();
//! kernel.claimZswapNullifier(coinNullifier(downcastQualifiedCoin(input), selfAddr));
//! const change = input.value - value;                       // asserts no underflow
//! const output = ShieldedCoinInfo{ nonce: evolve(input.nonce), color: input.color, value };
//! kernel.claimZswapCoinSpend(coinCommitment(output, left(pk)));
//! if (change == 0) return { change: none, sent: output };
//! const changeCoin = { nonce: evolve/2(input.nonce), color: input.color, value: change };
//! kernel.claimZswapCoinSpend(coinCommitment(changeCoin, right(selfAddr)));
//! kernel.claimZswapCoinReceive(coinCommitment(changeCoin, right(selfAddr)));
//! return { change: some(changeCoin), sent: output };
//! ```

use minocrab::v3::AnyWire3;
use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Public};
use minocrab_std::v3::hash::{degrade_to_transient, upgrade_from_transient};
use minocrab_std::v3::kernel::{self, claim_zswap_coin_receive, claim_zswap_coin_spend, claim_zswap_nullifier};
use minocrab_std::v3::{
    coin_commitment_to, coin_commitment_to_contract, coin_nullifier_contract, is_true, Bool, CoinColor, CoinNonce,
    Maybe, QualifiedShieldedCoinInfo3, ShieldedCoinInfo3, Uint, ZswapCoinPublicKey, B32,
};
// L-WD (P4): the contract-recipient variant below.
use minocrab_std::v3::{ContractAddress, ShieldedSendResult};

const NONCE_EVOLVE: &[u8] = b"midnight:kernel:nonce_evolve";
const NONCE_EVOLVE_CHANGE: &[u8] = b"midnight:kernel:nonce_evolve/2";

/// `upgradeFromTransient(transientHash([<domain> as Field, degradeToTransient(nonce)]))`
/// (minocrab-std `kernel::derived_nonce`, transcribed).
fn derived_nonce(c: &mut Circuit3, domain: &[u8], nonce: &CoinNonce<Public>) -> CoinNonce<Public> {
    let degraded = degrade_to_transient(c, &nonce.bytes());
    let h = c.transient_hash(&[
        AnyWire3::immediate(Fr::from_le_bytes(domain).expect("≤31 bytes fit")),
        degraded.erase(),
    ]);
    CoinNonce(upgrade_from_transient(c, h))
}

/// Compact's checked `a - b` on `Uint<128>` (minocrab-std `kernel::checked_sub`, transcribed).
fn checked_sub(c: &mut Circuit3, a: Wire3<FieldT, Public>, b: Wire3<FieldT, Public>) -> Wire3<FieldT, Public> {
    let underflow = c.less_than(a, b, 128);
    let ok = c.not(underflow);
    c.assert(is_true(Bool::<Public>::from_field_unchecked(ok)).message("subtraction would underflow"));
    let neg = c.neg(b);
    c.add(a, neg)
}

/// `sendShielded(input, left(recipient), value).change` — the only part of the result the
/// account's withdrawals return.
pub fn send_shielded_to_user(
    c: &mut Circuit3,
    input: &QualifiedShieldedCoinInfo3<Public>,
    recipient: &ZswapCoinPublicKey<Public>,
    value: Uint<128, Public>,
) -> Maybe<ShieldedCoinInfo3<Public>, Public> {
    c.region("zswap: sendShielded(left)", |c| {
        let me = kernel::self_address(c).bytes();
        let spent = input.downcast();
        let nul = coin_nullifier_contract(c, &spent, &me);
        claim_zswap_nullifier(c, &nul);

        let change = checked_sub(c, input.value, value.field());

        let output = ShieldedCoinInfo3 {
            nonce: derived_nonce(c, NONCE_EVOLVE, &input.nonce),
            color: input.color,
            value: value.field(),
        };
        let cm = coin_commitment_to(c, &output, AnyWire3::immediate(1u64), &recipient.bytes());
        claim_zswap_coin_spend(c, &cm);

        let spent_it_all = c.test_eq(change, 0u64);
        let has_change = c.not(spent_it_all);
        let change_coin = ShieldedCoinInfo3 {
            nonce: derived_nonce(c, NONCE_EVOLVE_CHANGE, &input.nonce),
            color: input.color,
            value: change,
        };
        let change_cm = coin_commitment_to_contract(c, &change_coin, &me);
        c.when(has_change, |c| {
            claim_zswap_coin_spend(c, &change_cm);
            claim_zswap_coin_receive(c, &change_cm);
        });

        // `none<ShieldedCoinInfo>()` is the default coin: the payload is the change coin selected
        // against zero, and the tag is `has_change`.
        let none_unless = |c: &mut Circuit3, w| c.cond_select(spent_it_all, 0u64, w);
        let value = ShieldedCoinInfo3 {
            nonce: CoinNonce(B32 {
                hi: none_unless(c, change_coin.nonce.bytes().hi),
                lo: none_unless(c, change_coin.nonce.bytes().lo),
            }),
            color: CoinColor(B32 {
                hi: none_unless(c, change_coin.color.bytes().hi),
                lo: none_unless(c, change_coin.color.bytes().lo),
            }),
            value: none_unless(c, change_coin.value),
        };
        Maybe {
            is_some: Bool::from_field_unchecked(has_change),
            value,
        }
    })
}

// ── L-WD (P4): `sendShielded` to a CONTRACT recipient ────────────────────────────────────────────

/// `sendShielded(input, right<ZswapCoinPublicKey, ContractAddress>(recipient), value)` — the whole
/// `ShieldedSendResult` (`withdraw_shielded_to_contract` returns both the sent coin and the change).
///
/// compactc sees a literal `right(...)`, so it folds `recipient.is_left` to 0 everywhere, but the
/// auto-receive test keeps its runtime half:
///
/// ```text
/// if (!recipient.is_left && recipient.right.bytes == selfAddr.bytes) {   // == `right.bytes == self`
///   kernel.claimZswapCoinReceive(coinCommitment(output, recipient));
/// }
/// ```
///
/// So, against `minocrab-std`'s generic `kernel::send_shielded`: the output commitment has no
/// recipient select (tag `0` inline, the contract address as data, hashed twice as compactc
/// inlines two `coinCommitment` calls), and the receive claim's guard is the bare byte equality
/// `cond_select(hi == self.hi, lo == self.lo, 0)` with no `is_left` select around it. The guarded
/// claim stays in the op stream either way (a guarded-off Impact still occupies public-input
/// slots), which is why it cannot be dropped the way [`send_shielded_to_user`] drops it. The change
/// handling is [`send_shielded_to_user`]'s, unchanged.
pub fn send_shielded_to_contract(
    c: &mut Circuit3,
    input: &QualifiedShieldedCoinInfo3<Public>,
    recipient: &ContractAddress<Public>,
    value: Uint<128, Public>,
) -> ShieldedSendResult<Public> {
    c.region("zswap: sendShielded(right)", |c| {
        let me = kernel::self_address(c).bytes();
        let spent = input.downcast();
        let nul = coin_nullifier_contract(c, &spent, &me);
        claim_zswap_nullifier(c, &nul);

        let change = checked_sub(c, input.value, value.field());

        let output = ShieldedCoinInfo3 {
            nonce: derived_nonce(c, NONCE_EVOLVE, &input.nonce),
            color: input.color,
            value: value.field(),
        };
        let to = recipient.bytes();
        let cm = coin_commitment_to_contract(c, &output, &to);
        claim_zswap_coin_spend(c, &cm);

        // Auto-receive when sending to self: `recipient.bytes == selfAddr.bytes`, compactc's `&&`
        // of the two limb tests as one `cond_select`.
        let same_hi = c.test_eq(to.hi, me.hi);
        let same_lo = c.test_eq(to.lo, me.lo);
        let mine = c.cond_select(same_hi, same_lo, 0u64);
        let cm_again = coin_commitment_to_contract(c, &output, &to);
        c.when(mine, |c| {
            claim_zswap_coin_receive(c, &cm_again);
        });

        let spent_it_all = c.test_eq(change, 0u64);
        let has_change = c.not(spent_it_all);
        let change_coin = ShieldedCoinInfo3 {
            nonce: derived_nonce(c, NONCE_EVOLVE_CHANGE, &input.nonce),
            color: input.color,
            value: change,
        };
        let change_cm = coin_commitment_to_contract(c, &change_coin, &me);
        c.when(has_change, |c| {
            claim_zswap_coin_spend(c, &change_cm);
            claim_zswap_coin_receive(c, &change_cm);
        });

        let none_unless = |c: &mut Circuit3, w| c.cond_select(spent_it_all, 0u64, w);
        let change_value = ShieldedCoinInfo3 {
            nonce: CoinNonce(B32 {
                hi: none_unless(c, change_coin.nonce.bytes().hi),
                lo: none_unless(c, change_coin.nonce.bytes().lo),
            }),
            color: CoinColor(B32 {
                hi: none_unless(c, change_coin.color.bytes().hi),
                lo: none_unless(c, change_coin.color.bytes().lo),
            }),
            value: none_unless(c, change_coin.value),
        };
        ShieldedSendResult {
            change: Maybe {
                is_some: Bool::from_field_unchecked(has_change),
                value: change_value,
            },
            sent: output,
        }
    })
}
