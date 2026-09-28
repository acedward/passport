//! Lane L-WD's part of THE DIFFERENTIAL GATE (AA 00040 P4): `withdraw_unshielded_with_evm` and
//! `withdraw_shielded_to_contract_with_evm` against the compactc 0.34.0 artifacts they replace,
//! with the same probe runner, the same agreement criteria (`support/probe.rs`) and the same
//! report (`report` in `gate.rs`) as P1's circuits.
//!
//! Each circuit gets HONEST calls the reference accepts and a TAMPER SWEEP it refuses: amounts,
//! recipients, colours, the witness coin, nonces, signatures, devices, every EIP-712 domain field,
//! the primary type (the other withdrawal types share this struct layout, so only the type hash
//! tells them apart), and the counter overflows. The recipient-branch folding (the hazard P1
//! found) is exercised directly: an unshielded withdrawal to a user address equal to the
//! account's own address (compactc emits no auto-receive for a `right` recipient) and a
//! to-contract withdrawal to the account itself (the auto-receive claim fires).

pub mod model;
pub mod split;

use minocrab_sim::v3::cost;
use minocrab_zkir::v3::IrSource;
use passport_account_minocrab::withdrawals;

use crate::report;
use crate::support::baseline::{self, hex};
use crate::support::model::*;
use crate::support::prims::*;
use crate::support::probe::{self, ProbeResult};
use model::*;

/// The baseline is the pinned artifact (checked by `baseline::load`), and Midnight's cost model
/// gives it the 00034 G2 k and rows (`baseline::PINS`).
fn load_baseline(circuit: &str) -> IrSource {
    let ir = baseline::load(circuit);
    let (_, k, rows) = baseline::pin(circuit);
    assert_eq!(
        cost(&ir),
        (k, rows),
        "{circuit}: Midnight's cost model disagrees with the 00034 measurement"
    );
    ir
}

fn h32(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// The model's struct hashes and digests for the two withdrawal types reproduce the ethers
/// fixture vectors (`contract/src/tests/fixtures/passport-evm-v1.json`, `kat:WithdrawUnshielded`
/// and `kat:WithdrawShieldedToContract`), and the frozen type strings hash to the port's constants.
#[test]
fn kat_withdraw_types() {
    let owner: [u8; 20] = {
        let h = h32("2c7536e3605d9c16a7a3d7b1898e529396a65c23000000000000000000000000");
        h[..20].try_into().unwrap()
    };
    let account = [0xaa; 32];
    let salt = [0xdd; 32];
    let sep = domain_separator(&Domain::default(), &account, &salt);
    let fields = [[0xcc; 32], uint_word(4_000_000), [0xcc; 32]];
    for (type_str, want_sh, want_digest) in [
        (
            WITHDRAW_UNSHIELDED_STR,
            "451b7ecd0dacc195fc099376f7429ee98be1fb911d008d98dfb3647c08ef32db",
            "630d41df82d29f2a3e3b38a0536ff486cce4aa1ce69c2c454e4bf9648d934dfd",
        ),
        (
            WITHDRAW_TO_CONTRACT_STR,
            "9f36019fa0191981fe3083d13c5bbe8a6a43caee8eb276269f0ed8cd7f90d922",
            "9c067209dd3cfe3852f309ce67a3d438d3d95ea24a0461508e56b36c410c6126",
        ),
    ] {
        let sh = struct_hash(type_str, &account, &owner, 7, &fields, &[0x11; 32]);
        assert_eq!(hex(&sh), want_sh, "{type_str}: struct hash");
        assert_eq!(hex(&eip712_digest(&sep, &sh)), want_digest, "{type_str}: digest");
    }
    use passport_account_minocrab::eip712 as e;
    assert_eq!(e::TYPE_WITHDRAW_UNSHIELDED, keccak(WITHDRAW_UNSHIELDED_STR.as_bytes()));
    assert_eq!(
        e::TYPE_WITHDRAW_SHIELDED_TO_CONTRACT,
        keccak(WITHDRAW_TO_CONTRACT_STR.as_bytes())
    );
}

// ── withdraw_unshielded_with_evm ─────────────────────────────────────────────────────────────────

struct UnshieldedCase {
    state: AccountState,
    balances: Vec<([u8; 32], u128)>,
    me: [u8; 32],
    call: UnshieldedCall,
    signing: UnshieldedSigning,
}

/// An honest call: the device's entry at `counter` is enrolled, the mirror holds `balance` of the
/// colour, and the wallet signs exactly what the state says.
fn unshielded_honest(
    rng: &mut Rng,
    key: &Key,
    counter: u64,
    nonce: u64,
    balance: u128,
    amount: u128,
) -> UnshieldedCase {
    let me: [u8; 32] = rng.bytes();
    let salt: [u8; 32] = rng.bytes();
    let mut state = AccountState::activated(salt);
    state.auth_nonce = nonce;
    state.round = (nonce % 1_000_000) + 1;
    state.devices.push(device_entry(&me, &key.address, 0, counter));
    let color: [u8; 32] = rng.bytes();
    let recipient: [u8; 32] = rng.bytes();
    let signing = UnshieldedSigning {
        account: me,
        salt,
        nonce,
        color,
        amount,
        recipient,
        domain: Domain::default(),
        type_str: WITHDRAW_UNSHIELDED_STR.into(),
        challenge_self: me,
    };
    let (r, s) = key.sign(&signing.digest(&key.address), rng.next_u64());
    UnshieldedCase {
        state,
        balances: vec![(color, balance)],
        me,
        call: UnshieldedCall {
            color,
            amount,
            recipient,
            pk: key.pk.clone(),
            use_counter: counter,
            r,
            s,
        },
        signing,
    }
}

/// Re-sign `case.signing` (after a test moved one of its fields) with `key`.
fn resign_unshielded(case: &mut UnshieldedCase, key: &Key, seed: u64) {
    let (r, s) = key.sign(&case.signing.digest(&key.address), seed);
    case.call.r = r;
    case.call.s = s;
}

/// Through the split run (`split.rs`, Q6): the executor cannot apply an honest unshielded
/// withdrawal's kernel effects, for either artifact.
fn probe_unshielded(
    name: &str,
    expect: bool,
    ours: &IrSource,
    theirs: &IrSource,
    case: &UnshieldedCase,
) -> ProbeResult {
    split::run(
        name,
        expect,
        ours,
        theirs,
        state_with_balances(&case.state, &case.balances),
        case.me,
        &case.call.inputs(),
        &[],
    )
}

#[test]
#[allow(clippy::vec_init_then_push)]
fn gate_withdraw_unshielded_with_evm() {
    let circuit = "withdraw_unshielded_with_evm";
    let theirs = load_baseline(circuit);
    let ours = withdrawals::withdraw_unshielded_with_evm().ir;
    let key = test_key("enrolled");
    let other = test_key("unenrolled");
    let mut rng = Rng(0x0040_1dd0);
    let mut probes = Vec::new();

    // honest
    probes.push(probe_unshielded(
        "honest: partial withdrawal (balance 1,000,000, amount 400,000)",
        true,
        &ours,
        &theirs,
        &unshielded_honest(&mut rng, &key, 0, 0, 1_000_000, 400_000),
    ));
    probes.push(probe_unshielded(
        "honest: the whole balance (the mirror goes to 0)",
        true,
        &ours,
        &theirs,
        &unshielded_honest(&mut rng, &key, 1, 1, 1_000_000, 1_000_000),
    ));
    probes.push(probe_unshielded(
        "honest: zero amount",
        true,
        &ours,
        &theirs,
        &unshielded_honest(&mut rng, &key, 2, 2, 5, 0),
    ));
    probes.push(probe_unshielded(
        "honest: balance 2^128-1, 1 unit withdrawn",
        true,
        &ours,
        &theirs,
        &unshielded_honest(&mut rng, &key, 0, 9, u128::MAX, 1),
    ));
    probes.push(probe_unshielded(
        "honest: amount 2^128-1 (the whole of a full mirror)",
        true,
        &ours,
        &theirs,
        &unshielded_honest(&mut rng, &key, 4, 10, u128::MAX, u128::MAX),
    ));
    for i in 0..6 {
        let balance = u128::from(rng.next_u64()) + 1;
        let amount = u128::from(rng.next_u64()) % (balance + 1);
        let counter = rng.next_u64() % 1000;
        let nonce = rng.next_u64() % 1000;
        let c = unshielded_honest(&mut rng, &key, counter, nonce, balance, amount);
        probes.push(probe_unshielded(
            &format!("honest: random #{i} (balance {balance}, amount {amount}, counter {counter}, nonce {nonce})"),
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = unshielded_honest(&mut rng, &key, 3, 3, 900, 100);
        c.call.s = negate_scalar(&c.call.s);
        probes.push(probe_unshielded(
            "honest: high-S twin of a valid signature",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = unshielded_honest(&mut rng, &key, 5, 6, 700, 300);
        c.balances.push((rng.bytes(), 12_345));
        c.balances.push((rng.bytes(), 0));
        probes.push(probe_unshielded(
            "honest: other colours in the mirror stay untouched",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = unshielded_honest(&mut rng, &key, 6, 7, 800, 200);
        c.signing.recipient = c.me;
        c.call.recipient = c.me;
        resign_unshielded(&mut c, &key, 31);
        probes.push(probe_unshielded(
            "honest: user recipient whose bytes are the account's own address (no auto-receive: `right` arm)",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = unshielded_honest(&mut rng, &key, 1, 1, 500, 50);
        c.state.devices.push(device_entry(&c.me, &other.address, 0, 0));
        c.state.device_count = 2;
        probes.push(probe_unshielded(
            "honest: a second device is enrolled too",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }

    // tamper sweep
    let t = |rng: &mut Rng| unshielded_honest(rng, &key, 2, 4, 1_000, 400);
    {
        let mut c = t(&mut rng);
        c.balances.clear();
        probes.push(probe_unshielded(
            "tamper: no balance for the colour (empty mirror)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.balances = vec![(rng.bytes(), 1_000)];
        probes.push(probe_unshielded(
            "tamper: no balance for the colour (only another colour held)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = unshielded_honest(&mut rng, &key, 2, 4, 1_000, 1_001);
        resign_unshielded(&mut c, &key, 32);
        probes.push(probe_unshielded(
            "tamper: amount above the balance (signed honestly)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = unshielded_honest(&mut rng, &key, 2, 4, 0, 1);
        resign_unshielded(&mut c, &key, 33);
        probes.push(probe_unshielded(
            "tamper: a zero balance, 1 unit asked (signed honestly)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.amount = 401;
        probes.push(probe_unshielded(
            "tamper: wrong amount (signed 400, called 401)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.recipient[5] ^= 1;
        probes.push(probe_unshielded("tamper: wrong recipient", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.call.recipient = c.me;
        probes.push(probe_unshielded(
            "tamper: recipient swapped for the account's own address",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let mut other_colour = c.call.color;
        other_colour[0] ^= 1;
        c.balances.push((other_colour, 1_000));
        c.call.color = other_colour;
        probes.push(probe_unshielded(
            "tamper: wrong colour (another held colour, signed for the first)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let (r, s) = key.sign(&rng.bytes::<32>(), 7);
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_unshielded(
            "tamper: bad signature (over another digest)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let (r, s) = other.sign(&c.signing.digest(&key.address), 9);
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_unshielded(
            "tamper: signed by another key, enrolled key presented",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let (r, s) = other.sign(&c.signing.digest(&other.address), 9);
        c.call.pk = other.pk.clone();
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_unshielded(
            "tamper: wrong signer address (valid signature by an unenrolled key)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.nonce = 5;
        resign_unshielded(&mut c, &key, 34);
        probes.push(probe_unshielded(
            "tamper: wrong nonce (signed n+1)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.nonce = 3;
        resign_unshielded(&mut c, &key, 35);
        probes.push(probe_unshielded(
            "tamper: stale nonce (signed n-1, a replay)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.devices.clear();
        c.state.device_count = 0;
        probes.push(probe_unshielded(
            "tamper: unknown device (empty device set)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.use_counter = 3;
        probes.push(probe_unshielded(
            "tamper: unknown device (wrong use counter)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.device_epoch = 1;
        probes.push(probe_unshielded(
            "tamper: unknown device (entry from an older epoch)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.salt[0] ^= 1;
        resign_unshielded(&mut c, &key, 36);
        probes.push(probe_unshielded(
            "tamper: EIP-712 domain salt",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.account = rng.bytes();
        resign_unshielded(&mut c, &key, 37);
        probes.push(probe_unshielded(
            "tamper: EIP-712 domain verifyingContract/account (another account)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.domain.name = "Midnight Passport Account ".into();
        resign_unshielded(&mut c, &key, 38);
        probes.push(probe_unshielded(
            "tamper: EIP-712 domain name",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.domain.version = "2".into();
        resign_unshielded(&mut c, &key, 39);
        probes.push(probe_unshielded(
            "tamper: EIP-712 domain version",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.domain.type_str =
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)".into();
        resign_unshielded(&mut c, &key, 40);
        probes.push(probe_unshielded(
            "tamper: EIP-712 domain type (chainId added)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.type_str = WITHDRAW_SHIELDED_STR.into();
        resign_unshielded(&mut c, &key, 41);
        probes.push(probe_unshielded(
            "tamper: EIP-712 primary type (a WithdrawShielded signature over the same words)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.type_str = WITHDRAW_TO_CONTRACT_STR.into();
        resign_unshielded(&mut c, &key, 42);
        probes.push(probe_unshielded(
            "tamper: EIP-712 primary type (a WithdrawShieldedToContract signature over the same words)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.challenge_self = rng.bytes();
        resign_unshielded(&mut c, &key, 43);
        probes.push(probe_unshielded(
            "tamper: challenge bound to another account",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.pk = identity_point();
        probes.push(probe_unshielded(
            "tamper: device key is the point at infinity",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.s = scalar_u64(0);
        probes.push(probe_unshielded("tamper: signature s = 0", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.call.r = scalar_u64(0);
        probes.push(probe_unshielded("tamper: signature r = 0", false, &ours, &theirs, &c));
    }
    {
        let c = unshielded_honest(&mut rng, &key, u64::MAX, 4, 1_000, 400);
        probes.push(probe_unshielded(
            "tamper: use counter at 2^64-1 (the roll overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let c = unshielded_honest(&mut rng, &key, 2, u64::MAX, 1_000, 400);
        probes.push(probe_unshielded(
            "tamper: auth_nonce at 2^64-1 (the bump overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.round = u64::MAX;
        probes.push(probe_unshielded(
            "tamper: round at 2^64-1 (the bump overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }

    report(circuit, &ours, &theirs, &probes);
}

// ── withdraw_shielded_to_contract_with_evm ───────────────────────────────────────────────────────

struct ToContractCase {
    state: AccountState,
    me: [u8; 32],
    call: ToContractCall,
    signing: ToContractSigning,
}

fn to_contract_honest(rng: &mut Rng, key: &Key, counter: u64, nonce: u64, value: u128, amount: u128) -> ToContractCase {
    let me: [u8; 32] = rng.bytes();
    let salt: [u8; 32] = rng.bytes();
    let mut state = AccountState::activated(salt);
    state.auth_nonce = nonce;
    state.round = (nonce % 1_000_000) + 1;
    state.devices.push(device_entry(&me, &key.address, 0, counter));
    let color: [u8; 32] = rng.bytes();
    let coin = Coin {
        nonce: rng.bytes(),
        color,
        value,
        mt_index: rng.next_u64() % 100_000,
    };
    let recipient: [u8; 32] = rng.bytes();
    let signing = ToContractSigning {
        account: me,
        salt,
        nonce,
        recipient,
        color,
        amount,
        coin,
        domain: Domain::default(),
        type_str: WITHDRAW_TO_CONTRACT_STR.into(),
        challenge_self: me,
    };
    let (r, s) = key.sign(&signing.digest(&key.address), rng.next_u64());
    ToContractCase {
        state,
        me,
        call: ToContractCall {
            recipient,
            color,
            amount,
            pk: key.pk.clone(),
            use_counter: counter,
            r,
            s,
            coin,
        },
        signing,
    }
}

fn resign_to_contract(case: &mut ToContractCase, key: &Key, seed: u64) {
    let (r, s) = key.sign(&case.signing.digest(&key.address), seed);
    case.call.r = r;
    case.call.s = s;
}

/// Send to the account itself: the recipient in both the call and what the wallet signs.
fn to_self(case: &mut ToContractCase, key: &Key, seed: u64) {
    case.signing.recipient = case.me;
    case.call.recipient = case.me;
    resign_to_contract(case, key, seed);
}

fn probe_to_contract(
    name: &str,
    expect: bool,
    ours: &IrSource,
    theirs: &IrSource,
    case: &ToContractCase,
) -> ProbeResult {
    probe::run(
        name,
        expect,
        ours,
        theirs,
        case.state.state(),
        case.me,
        &case.call.inputs(),
        &case.call.coin.private_transcript(),
    )
}

#[test]
#[allow(clippy::vec_init_then_push)]
fn gate_withdraw_shielded_to_contract_with_evm() {
    let circuit = "withdraw_shielded_to_contract_with_evm";
    let theirs = load_baseline(circuit);
    let ours = withdrawals::withdraw_shielded_to_contract_with_evm().ir;
    let key = test_key("enrolled");
    let other = test_key("unenrolled");
    let mut rng = Rng(0x0040_c0de);
    let mut probes = Vec::new();

    // honest
    probes.push(probe_to_contract(
        "honest: partial spend (change returned)",
        true,
        &ours,
        &theirs,
        &to_contract_honest(&mut rng, &key, 0, 0, 1_000_000, 400_000),
    ));
    probes.push(probe_to_contract(
        "honest: whole coin (no change)",
        true,
        &ours,
        &theirs,
        &to_contract_honest(&mut rng, &key, 1, 1, 1_000_000, 1_000_000),
    ));
    probes.push(probe_to_contract(
        "honest: zero amount (all change)",
        true,
        &ours,
        &theirs,
        &to_contract_honest(&mut rng, &key, 2, 2, 5, 0),
    ));
    probes.push(probe_to_contract(
        "honest: 2^128-1 coin, 1 unit sent",
        true,
        &ours,
        &theirs,
        &to_contract_honest(&mut rng, &key, 0, 9, u128::MAX, 1),
    ));
    for i in 0..6 {
        let value = u128::from(rng.next_u64()) + 1;
        let amount = u128::from(rng.next_u64()) % value;
        let counter = rng.next_u64() % 1000;
        let nonce = rng.next_u64() % 1000;
        let c = to_contract_honest(&mut rng, &key, counter, nonce, value, amount);
        probes.push(probe_to_contract(
            &format!("honest: random #{i} (value {value}, amount {amount}, counter {counter}, nonce {nonce})"),
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = to_contract_honest(&mut rng, &key, 3, 3, 900, 100);
        c.call.s = negate_scalar(&c.call.s);
        probes.push(probe_to_contract(
            "honest: high-S twin of a valid signature",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = to_contract_honest(&mut rng, &key, 4, 5, 1_000, 250);
        to_self(&mut c, &key, 51);
        probes.push(probe_to_contract(
            "honest: to the account itself, partial (the guarded auto-receive fires, with change)",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = to_contract_honest(&mut rng, &key, 5, 6, 1_000, 1_000);
        to_self(&mut c, &key, 52);
        probes.push(probe_to_contract(
            "honest: to the account itself, whole coin (auto-receive, no change)",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = to_contract_honest(&mut rng, &key, 6, 7, 1_000, 300);
        c.call.recipient = c.me;
        c.call.recipient[0] ^= 1;
        c.signing.recipient = c.call.recipient;
        resign_to_contract(&mut c, &key, 53);
        probes.push(probe_to_contract(
            "honest: recipient one byte off the account's own address (low limb differs: no auto-receive)",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = to_contract_honest(&mut rng, &key, 7, 8, 1_000, 300);
        c.call.recipient = c.me;
        c.call.recipient[31] ^= 1;
        c.signing.recipient = c.call.recipient;
        resign_to_contract(&mut c, &key, 54);
        probes.push(probe_to_contract(
            "honest: recipient differs from the account only in byte 31 (high limb differs: no auto-receive)",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = to_contract_honest(&mut rng, &key, 8, 9, 2_000, 700);
        c.call.coin.color = rng.bytes();
        c.signing.coin = c.call.coin;
        resign_to_contract(&mut c, &key, 55);
        probes.push(probe_to_contract(
            "honest: the witness coin's colour differs from the colour argument (both signed)",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }

    // tamper sweep
    let t = |rng: &mut Rng| to_contract_honest(rng, &key, 2, 4, 1_000, 400);
    {
        let mut c = to_contract_honest(&mut rng, &key, 2, 4, 1_000, 1_001);
        resign_to_contract(&mut c, &key, 61);
        probes.push(probe_to_contract(
            "tamper: amount above the coin's value (signed honestly)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.amount = 401;
        probes.push(probe_to_contract(
            "tamper: wrong amount (signed 400, called 401)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.recipient[5] ^= 1;
        probes.push(probe_to_contract("tamper: wrong recipient", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.call.recipient = c.me;
        probes.push(probe_to_contract(
            "tamper: recipient swapped for the account itself (signed for another contract)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.color[0] ^= 1;
        probes.push(probe_to_contract(
            "tamper: wrong colour argument",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.coin.color[1] ^= 1;
        probes.push(probe_to_contract(
            "tamper: witness returns another coin (colour)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.coin.mt_index += 1;
        probes.push(probe_to_contract(
            "tamper: witness returns another coin (mt_index)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.coin.nonce[3] ^= 1;
        probes.push(probe_to_contract(
            "tamper: witness returns another coin (nonce)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.coin.value = 2_000;
        probes.push(probe_to_contract(
            "tamper: witness inflates the coin's value",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let (r, s) = key.sign(&rng.bytes::<32>(), 7);
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_to_contract(
            "tamper: bad signature (over another digest)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let (r, s) = other.sign(&c.signing.digest(&key.address), 9);
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_to_contract(
            "tamper: signed by another key, enrolled key presented",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let (r, s) = other.sign(&c.signing.digest(&other.address), 9);
        c.call.pk = other.pk.clone();
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_to_contract(
            "tamper: wrong signer address (valid signature by an unenrolled key)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.nonce = 5;
        resign_to_contract(&mut c, &key, 62);
        probes.push(probe_to_contract(
            "tamper: wrong nonce (signed n+1)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.nonce = 3;
        resign_to_contract(&mut c, &key, 63);
        probes.push(probe_to_contract(
            "tamper: stale nonce (signed n-1, a replay)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.devices.clear();
        probes.push(probe_to_contract(
            "tamper: unknown device (empty device set)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.use_counter = 1;
        probes.push(probe_to_contract(
            "tamper: unknown device (wrong use counter)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.device_epoch = 2;
        probes.push(probe_to_contract(
            "tamper: unknown device (entry from an older epoch)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.salt[31] ^= 0x80;
        resign_to_contract(&mut c, &key, 64);
        probes.push(probe_to_contract(
            "tamper: EIP-712 domain salt",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.domain.name = "Midnight Passport".into();
        resign_to_contract(&mut c, &key, 65);
        probes.push(probe_to_contract(
            "tamper: EIP-712 domain name",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.domain.version = "0".into();
        resign_to_contract(&mut c, &key, 66);
        probes.push(probe_to_contract(
            "tamper: EIP-712 domain version",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.account = rng.bytes();
        resign_to_contract(&mut c, &key, 67);
        probes.push(probe_to_contract(
            "tamper: EIP-712 domain verifyingContract/account (another account)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.type_str = WITHDRAW_SHIELDED_STR.into();
        resign_to_contract(&mut c, &key, 68);
        probes.push(probe_to_contract(
            "tamper: EIP-712 primary type (a WithdrawShielded signature over the same words)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.challenge_self = rng.bytes();
        resign_to_contract(&mut c, &key, 69);
        probes.push(probe_to_contract(
            "tamper: challenge bound to another account",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.pk = identity_point();
        probes.push(probe_to_contract(
            "tamper: device key is the point at infinity",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.s = scalar_u64(0);
        probes.push(probe_to_contract("tamper: signature s = 0", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.call.r = scalar_u64(0);
        probes.push(probe_to_contract("tamper: signature r = 0", false, &ours, &theirs, &c));
    }
    {
        let c = to_contract_honest(&mut rng, &key, u64::MAX, 4, 1_000, 400);
        probes.push(probe_to_contract(
            "tamper: use counter at 2^64-1 (the roll overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let c = to_contract_honest(&mut rng, &key, 2, u64::MAX, 1_000, 400);
        probes.push(probe_to_contract(
            "tamper: auth_nonce at 2^64-1 (the bump overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.round = u64::MAX;
        probes.push(probe_to_contract(
            "tamper: round at 2^64-1 (the bump overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }

    report(circuit, &ours, &theirs, &probes);
}
