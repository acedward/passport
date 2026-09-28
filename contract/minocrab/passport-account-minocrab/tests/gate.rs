//! THE DIFFERENTIAL GATE (AA 00040, plan P1.4): each ported circuit against the compactc 0.34.0
//! artifact it replaces (`account.compact` sha256 `44cff904…`).
//!
//! Per circuit: a set of HONEST calls the reference accepts and a TAMPER SWEEP it refuses, every
//! one run through both artifacts by Midnight's transcript executor over a live ledger state (see
//! `support/probe.rs` for exactly what "agree" means). The gate passes only with ZERO
//! disagreements, and it writes its report (probe list, counts, k and rows of both sides, the
//! port's ZKIR hash) to `$GATE_OUT_DIR/gate-<circuit>.json` when that is set.
//!
//! Needs `--features compactc-baseline` and `COMPACTC_BASELINE_DIR` (scripts/gate.sh gate).

mod support;

// P4 lane L-WD: withdraw_unshielded_with_evm, withdraw_shielded_to_contract_with_evm.
mod lane_wd;

use minocrab_sim::v3::cost;
use minocrab_zkir::v3::IrSource;
use passport_account_minocrab::account::Account;
use sha2::{Digest, Sha256};
use support::baseline::{self, hex};
use support::model::*;
use support::prims::*;
use support::probe::{self, ProbeResult};

const MINOCRAB_REV: &str = "9f4d6a62abeb882fc2987d43cd6e0ba0cfb279cd";

fn zkir_sha(ir: &IrSource) -> String {
    hex(&Sha256::digest(
        minocrab_zkir::v3::to_zkir_string(ir).unwrap().as_bytes(),
    ))
}

fn report(circuit: &str, ours: &IrSource, theirs: &IrSource, probes: &[ProbeResult]) {
    let (ok, tk) = (cost(ours), cost(theirs));
    let disagreements = probes.iter().filter(|p| !p.ok()).count();
    let accepted = probes.iter().filter(|p| p.expect_accept).count();
    let value = serde_json::json!({
        "circuit": circuit,
        "minocrab_rev": MINOCRAB_REV,
        "compactc_baseline_zkir_sha256": baseline::pin(circuit).0,
        "minocrab_zkir_sha256": zkir_sha(ours),
        "compactc": { "k": tk.0, "rows": tk.1, "instructions": theirs.instructions.len() },
        "minocrab": { "k": ok.0, "rows": ok.1, "instructions": ours.instructions.len() },
        "probes_total": probes.len(),
        "probes_honest": accepted,
        "probes_tamper": probes.len() - accepted,
        "disagreements": disagreements,
        "verdict": if disagreements == 0 { "PASS" } else { "FAIL" },
        "probes": probes.iter().map(ProbeResult::json).collect::<Vec<_>>(),
    });
    println!(
        "GATE {circuit}: k {} -> {}, rows {} -> {}, probes {}, disagreements {disagreements}",
        tk.0,
        ok.0,
        tk.1,
        ok.1,
        probes.len()
    );
    for p in probes.iter().filter(|p| !p.ok()) {
        println!("  DISAGREE {}: {:?}", p.name, p.disagreements);
    }
    if let Ok(dir) = std::env::var("GATE_OUT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            format!("{dir}/gate-{circuit}.json"),
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();
    }
    assert_eq!(
        disagreements, 0,
        "{circuit}: the gate found {disagreements} disagreement(s)"
    );
}

// ── P0.4: the baseline is the pinned artifact, and its k/rows are the 00034 measurement ─────────

#[test]
fn p0_baseline() {
    let mut rows = Vec::new();
    for circuit in ["append_inbox_with_evm", "withdraw_shielded_with_evm"] {
        let ir = baseline::load(circuit);
        let (sha, k, n) = baseline::pin(circuit);
        let (ck, cn) = cost(&ir);
        println!("P0.4 {circuit}: sha256 {sha} ok; k {ck} rows {cn} (00034: k {k} rows {n})");
        assert_eq!(
            (ck, cn),
            (k, n),
            "{circuit}: Midnight's cost model disagrees with the 00034 measurement"
        );
        rows.push(
            serde_json::json!({"circuit": circuit, "zkir_sha256": sha, "k": ck, "rows": cn, "matches_00034": true}),
        );
    }
    if let Ok(dir) = std::env::var("GATE_OUT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            format!("{dir}/p0-baseline.json"),
            serde_json::to_string_pretty(&rows).unwrap(),
        )
        .unwrap();
    }
}

// ── append_inbox_with_evm ────────────────────────────────────────────────────────────────────────

struct AppendCase {
    state: AccountState,
    me: [u8; 32],
    call: AppendCall,
}

/// An honest call: the device's entry at `counter` is enrolled, and the wallet signs exactly what
/// the state says.
fn append_honest(rng: &mut Rng, key: &Key, counter: u64, nonce: u64, epoch: u32, inbox_count: u64) -> AppendCase {
    let me: [u8; 32] = rng.bytes();
    let salt: [u8; 32] = rng.bytes();
    let entry: [u8; 192] = rng.bytes();
    let mut state = AccountState::activated(salt);
    state.auth_nonce = nonce;
    state.round = (nonce % 1_000_000) + 1;
    state.device_epoch = epoch;
    state.inbox_count = inbox_count;
    for i in 0..inbox_count.min(3) {
        state.inbox.push((i, rng.bytes()));
    }
    state.devices.push(device_entry(&me, &key.address, epoch, counter));
    let digest = AppendSigning::honest(me, salt, nonce, entry).digest(&key.address);
    let (r, s) = key.sign(&digest, rng.next_u64());
    AppendCase {
        state,
        me,
        call: AppendCall {
            entry,
            pk: key.pk.clone(),
            use_counter: counter,
            r,
            s,
        },
    }
}

fn resign_append(case: &mut AppendCase, key: &Key, signing: &AppendSigning, seed: u64) {
    let digest = signing.digest(&key.address);
    let (r, s) = key.sign(&digest, seed);
    case.call.r = r;
    case.call.s = s;
}

fn probe_append(name: &str, expect: bool, ours: &IrSource, theirs: &IrSource, case: &AppendCase) -> ProbeResult {
    probe::run(
        name,
        expect,
        ours,
        theirs,
        case.state.state(),
        case.me,
        &case.call.inputs(),
        &[],
    )
}

#[test]
#[allow(clippy::vec_init_then_push)]
fn gate_append_inbox_with_evm() {
    let circuit = "append_inbox_with_evm";
    let theirs = baseline::load(circuit);
    let ours = Account::append_inbox_with_evm().ir;
    let key = test_key("enrolled");
    let other = test_key("unenrolled");
    let mut rng = Rng(0x0040_a99e);
    let mut probes = Vec::new();

    // honest
    let base = append_honest(&mut rng, &key, 0, 0, 0, 0);
    probes.push(probe_append(
        "honest: first call (counter 0, nonce 0, empty inbox)",
        true,
        &ours,
        &theirs,
        &base,
    ));
    for i in 0..8 {
        let counter = rng.next_u64() % 1000;
        let nonce = rng.next_u64() % 1000;
        let epoch = (rng.next_u64() % 3) as u32;
        let count = rng.next_u64() % 50;
        let c = append_honest(&mut rng, &key, counter, nonce, epoch, count);
        probes.push(probe_append(
            &format!("honest: random #{i} (counter {counter}, nonce {nonce}, epoch {epoch}, inbox {count})"),
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = append_honest(&mut rng, &key, 3, 5, 0, 2);
        c.call.s = negate_scalar(&c.call.s);
        probes.push(probe_append(
            "honest: high-S twin of a valid signature",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = append_honest(&mut rng, &key, 1, 1, 0, 1);
        c.state.devices.push(device_entry(&c.me, &other.address, 0, 0));
        c.state.device_count = 2;
        probes.push(probe_append(
            "honest: a second device is enrolled too",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }

    // tamper sweep
    let t = |rng: &mut Rng| append_honest(rng, &key, 2, 4, 0, 1);
    {
        let mut c = t(&mut rng);
        let (r, s) = key.sign(&rng.bytes::<32>(), 7);
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_append(
            "tamper: bad signature (over another digest)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let digest = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry).digest(&key.address);
        let (r, s) = other.sign(&digest, 9);
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_append(
            "tamper: signed by another key, enrolled key presented",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let digest = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry).digest(&other.address);
        let (r, s) = other.sign(&digest, 9);
        c.call.pk = other.pk.clone();
        c.call.r = r;
        c.call.s = s;
        probes.push(probe_append(
            "tamper: wrong signer address (valid signature by an unenrolled key)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 5, c.call.entry);
        resign_append(&mut c, &key, &s, 11);
        probes.push(probe_append(
            "tamper: wrong nonce (signed n+1)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 3, c.call.entry);
        resign_append(&mut c, &key, &s, 11);
        probes.push(probe_append(
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
        probes.push(probe_append(
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
        probes.push(probe_append(
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
        let s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        resign_append(&mut c, &key, &s, 12);
        probes.push(probe_append(
            "tamper: unknown device (entry from an older epoch)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.entry[100] ^= 1;
        probes.push(probe_append(
            "tamper: wrong entry (one byte changed after signing)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let mut s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        s.salt[0] ^= 1;
        resign_append(&mut c, &key, &s, 13);
        probes.push(probe_append("tamper: EIP-712 domain salt", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        let mut s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        s.account = rng.bytes();
        resign_append(&mut c, &key, &s, 14);
        probes.push(probe_append(
            "tamper: EIP-712 domain verifyingContract/account (another account)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let mut s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        s.domain.name = "Midnight Passport Account ".into();
        resign_append(&mut c, &key, &s, 15);
        probes.push(probe_append("tamper: EIP-712 domain name", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        let mut s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        s.domain.version = "2".into();
        resign_append(&mut c, &key, &s, 16);
        probes.push(probe_append(
            "tamper: EIP-712 domain version",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let mut s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        s.domain.type_str =
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)".into();
        resign_append(&mut c, &key, &s, 17);
        probes.push(probe_append(
            "tamper: EIP-712 domain type (chainId added)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let mut s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        s.type_str =
            "RotateEncKey(bytes32 account,address owner,uint64 authNonce,bytes32 newKey,bytes32 challenge)".into();
        resign_append(&mut c, &key, &s, 18);
        probes.push(probe_append(
            "tamper: EIP-712 primary type (a RotateEncKey signature)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        let mut s = AppendSigning::honest(c.me, c.state.evm_domain_salt, 4, c.call.entry);
        s.challenge_self = rng.bytes();
        resign_append(&mut c, &key, &s, 19);
        probes.push(probe_append(
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
        probes.push(probe_append(
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
        probes.push(probe_append("tamper: signature s = 0", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.call.r = scalar_u64(0);
        probes.push(probe_append("tamper: signature r = 0", false, &ours, &theirs, &c));
    }
    {
        let mut c = append_honest(&mut rng, &key, u64::MAX, 4, 0, 1);
        c.call.use_counter = u64::MAX;
        probes.push(probe_append(
            "tamper: use counter at 2^64-1 (the roll overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let c = append_honest(&mut rng, &key, 2, u64::MAX, 0, 1);
        probes.push(probe_append(
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
        probes.push(probe_append(
            "tamper: round at 2^64-1 (the bump overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.inbox_count = u64::MAX;
        probes.push(probe_append(
            "tamper: inbox_count at 2^64-1 (the bump overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }

    report(circuit, &ours, &theirs, &probes);
}

// ── withdraw_shielded_with_evm ───────────────────────────────────────────────────────────────────

struct WithdrawCase {
    state: AccountState,
    me: [u8; 32],
    call: WithdrawCall,
    signing: WithdrawSigning,
}

fn withdraw_honest(rng: &mut Rng, key: &Key, counter: u64, nonce: u64, value: u128, amount: u128) -> WithdrawCase {
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
    let signing = WithdrawSigning {
        account: me,
        salt,
        nonce,
        recipient,
        color,
        amount,
        coin,
        domain: Domain::default(),
        type_str: WITHDRAW_SHIELDED_STR.into(),
    };
    let (r, s) = key.sign(&signing.digest(&key.address), rng.next_u64());
    WithdrawCase {
        state,
        me,
        call: WithdrawCall {
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

fn resign_withdraw(case: &mut WithdrawCase, key: &Key, seed: u64) {
    let (r, s) = key.sign(&case.signing.digest(&key.address), seed);
    case.call.r = r;
    case.call.s = s;
}

fn probe_withdraw(name: &str, expect: bool, ours: &IrSource, theirs: &IrSource, case: &WithdrawCase) -> ProbeResult {
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
fn gate_withdraw_shielded_with_evm() {
    let circuit = "withdraw_shielded_with_evm";
    let theirs = baseline::load(circuit);
    let ours = Account::withdraw_shielded_with_evm().ir;
    let key = test_key("enrolled");
    let other = test_key("unenrolled");
    let mut rng = Rng(0x0040_3d1a);
    let mut probes = Vec::new();

    // honest
    probes.push(probe_withdraw(
        "honest: partial spend (change returned)",
        true,
        &ours,
        &theirs,
        &withdraw_honest(&mut rng, &key, 0, 0, 1_000_000, 400_000),
    ));
    probes.push(probe_withdraw(
        "honest: whole coin (no change)",
        true,
        &ours,
        &theirs,
        &withdraw_honest(&mut rng, &key, 1, 1, 1_000_000, 1_000_000),
    ));
    probes.push(probe_withdraw(
        "honest: zero amount (all change)",
        true,
        &ours,
        &theirs,
        &withdraw_honest(&mut rng, &key, 2, 2, 5, 0),
    ));
    probes.push(probe_withdraw(
        "honest: 2^128-1 coin, 1 unit sent",
        true,
        &ours,
        &theirs,
        &withdraw_honest(&mut rng, &key, 0, 9, u128::MAX, 1),
    ));
    for i in 0..6 {
        let value = u128::from(rng.next_u64()) + 1;
        let amount = u128::from(rng.next_u64()) % value;
        let counter = rng.next_u64() % 1000;
        let nonce = rng.next_u64() % 1000;
        let c = withdraw_honest(&mut rng, &key, counter, nonce, value, amount);
        probes.push(probe_withdraw(
            &format!("honest: random #{i} (value {value}, amount {amount}, counter {counter}, nonce {nonce})"),
            true,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = withdraw_honest(&mut rng, &key, 3, 3, 900, 100);
        c.call.s = negate_scalar(&c.call.s);
        probes.push(probe_withdraw(
            "honest: high-S twin of a valid signature",
            true,
            &ours,
            &theirs,
            &c,
        ));
    }

    // tamper sweep
    let t = |rng: &mut Rng| withdraw_honest(rng, &key, 2, 4, 1_000, 400);
    {
        let mut c = withdraw_honest(&mut rng, &key, 2, 4, 1_000, 1_001);
        resign_withdraw(&mut c, &key, 21);
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw("tamper: wrong recipient", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.call.color[0] ^= 1;
        probes.push(probe_withdraw(
            "tamper: wrong colour argument",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.coin.mt_index += 1;
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
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
        resign_withdraw(&mut c, &key, 22);
        probes.push(probe_withdraw(
            "tamper: wrong nonce (signed n+1)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.state.devices.clear();
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
            "tamper: unknown device (wrong use counter)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.salt[31] ^= 0x80;
        resign_withdraw(&mut c, &key, 23);
        probes.push(probe_withdraw("tamper: EIP-712 domain salt", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.signing.domain.name = "Midnight Passport".into();
        resign_withdraw(&mut c, &key, 24);
        probes.push(probe_withdraw("tamper: EIP-712 domain name", false, &ours, &theirs, &c));
    }
    {
        let mut c = t(&mut rng);
        c.signing.domain.version = "0".into();
        resign_withdraw(&mut c, &key, 25);
        probes.push(probe_withdraw(
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
        resign_withdraw(&mut c, &key, 26);
        probes.push(probe_withdraw(
            "tamper: EIP-712 domain verifyingContract/account (another account)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.signing.type_str = "WithdrawShieldedToContract(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipientContract,bytes32 challenge)".into();
        resign_withdraw(&mut c, &key, 27);
        probes.push(probe_withdraw(
            "tamper: EIP-712 primary type (a to-contract signature)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }
    {
        let mut c = t(&mut rng);
        c.call.pk = identity_point();
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw("tamper: signature s = 0", false, &ours, &theirs, &c));
    }
    {
        let c = withdraw_honest(&mut rng, &key, 2, u64::MAX, 1_000, 400);
        probes.push(probe_withdraw(
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
        probes.push(probe_withdraw(
            "tamper: round at 2^64-1 (the bump overflows)",
            false,
            &ours,
            &theirs,
            &c,
        ));
    }

    report(circuit, &ours, &theirs, &probes);
}
