//! THE DIFFERENTIAL GATE, lane L-DEV (AA 00040 P4): `rotate_enc_key_with_evm`,
//! `add_device_with_evm` and `remove_device_with_evm` against the compactc 0.34.0 artifacts they
//! replace (`account.compact` sha256 `44cff904…`). A child module of `tests/gate.rs` (declared
//! there with `#[path]`), so it shares the gate's `support` machinery and its `report`, and runs
//! under the same `scripts/gate.sh gate`.
//!
//! The three circuits share one shape: the `evm` seam over an EIP-712 struct with ONE `bytes32`
//! action word (`newKey`, `newEntry`, `entry`), then a custody chip. The off-circuit model below is
//! written from `account.compact` and `modules/Eip712.compact` (the FAB `persistentHash` route for
//! the challenges and entries, the plain-bytes keccak route for EIP-712), never from the port.
//!
//! Per circuit: honest calls the reference accepts, then a tamper sweep it refuses — the P1.4 list
//! (bad/foreign signature, wrong signer, wrong/stale nonce, unknown device, every EIP-712 domain
//! field, the primary type, the point at infinity, `r = 0`, `s = 0`, counter overflows), plus the
//! cross-operation substitutions this family invites (the same word signed as ANOTHER of the three
//! operations, or bound to another operation's challenge DST), plus each chip's own refusals
//! (a present entry, the count overflow, the last-device and authorising-device rules).

use minocrab::Fr;
use minocrab_sim::v3::cost;
use minocrab_zkir::v3::{IrSource, IrValue};
use passport_account_minocrab::account::Account;

use crate::support::baseline;
use crate::support::model::*;
use crate::support::prims::*;
use crate::support::probe::{self, ProbeResult};

pub const ROTATE_ENC_KEY_STR: &str =
    "RotateEncKey(bytes32 account,address owner,uint64 authNonce,bytes32 newKey,bytes32 challenge)";
pub const ADD_DEVICE_STR: &str =
    "AddDevice(bytes32 account,address owner,uint64 authNonce,bytes32 newEntry,bytes32 challenge)";
pub const REMOVE_DEVICE_STR: &str =
    "RemoveDevice(bytes32 account,address owner,uint64 authNonce,bytes32 entry,bytes32 challenge)";

const ALL: [Op; 3] = [Op::Rotate, Op::Add, Op::Remove];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Rotate,
    Add,
    Remove,
}

impl Op {
    fn circuit(self) -> &'static str {
        match self {
            Op::Rotate => "rotate_enc_key_with_evm",
            Op::Add => "add_device_with_evm",
            Op::Remove => "remove_device_with_evm",
        }
    }

    /// The challenge DST's tag suffix (`midnight:account:auth:evm:v1:<tag>`).
    fn tag(self) -> &'static str {
        match self {
            Op::Rotate => "rotate_enc_key",
            Op::Add => "add_device",
            Op::Remove => "remove_device",
        }
    }

    fn type_str(self) -> &'static str {
        match self {
            Op::Rotate => ROTATE_ENC_KEY_STR,
            Op::Add => ADD_DEVICE_STR,
            Op::Remove => REMOVE_DEVICE_STR,
        }
    }

    fn port(self) -> IrSource {
        match self {
            Op::Rotate => Account::rotate_enc_key_with_evm().ir,
            Op::Add => Account::add_device_with_evm().ir,
            Op::Remove => Account::remove_device_with_evm().ir,
        }
    }

    fn others(self) -> Vec<Op> {
        ALL.into_iter().filter(|o| *o != self).collect()
    }
}

// ── the model ────────────────────────────────────────────────────────────────────────────────────

/// `challenge_<op>_with_evm(self, address, word, nonce)`:
/// `persistentHash<[Bytes<32>, ContractAddress, Bytes<20>, Bytes<32>, Uint<64>]>`.
pub fn challenge_one_word(tag: &str, me: &[u8; 32], address: &[u8; 20], word: &[u8; 32], nonce: u64) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&challenge_dst(tag));
    let (s_hi, s_lo) = b32_slots(me);
    let (w_hi, w_lo) = b32_slots(word);
    fab_sha256(
        vec![atom(32), atom(32), atom(20), atom(32), atom(8)],
        &[d_hi, d_lo, s_hi, s_lo, b20(address), w_hi, w_lo, Fr::from(nonce)],
    )
}

/// What a wallet signs for one of the three operations, with every free parameter exposed.
#[derive(Clone)]
struct Signing {
    account: [u8; 32],
    salt: [u8; 32],
    nonce: u64,
    word: [u8; 32],
    domain: Domain,
    type_str: String,
    /// The DST tag the challenge is built with (normally the operation's own).
    challenge_tag: String,
    /// The challenge's view of the account (`kernel.self()`), normally `account`.
    challenge_self: [u8; 32],
}

impl Signing {
    fn honest(op: Op, account: [u8; 32], salt: [u8; 32], nonce: u64, word: [u8; 32]) -> Self {
        Signing {
            account,
            salt,
            nonce,
            word,
            domain: Domain::default(),
            type_str: op.type_str().into(),
            challenge_tag: op.tag().into(),
            challenge_self: account,
        }
    }

    fn digest(&self, owner: &[u8; 20]) -> [u8; 32] {
        let challenge = challenge_one_word(&self.challenge_tag, &self.challenge_self, owner, &self.word, self.nonce);
        let sep = domain_separator(&self.domain, &self.account, &self.salt);
        let sh = struct_hash(
            &self.type_str,
            &self.account,
            owner,
            self.nonce,
            &[self.word],
            &challenge,
        );
        eip712_digest(&sep, &sh)
    }
}

/// One call: the ledger state, the account address, the circuit arguments and what was signed.
#[derive(Clone)]
struct Case {
    state: AccountState,
    me: [u8; 32],
    /// The call's `Bytes<32>` argument (`new_key` / `new_entry` / `entry`).
    word: [u8; 32],
    /// Raw limbs for the word, overriding `word` (a malformed argument).
    raw_word: Option<(Fr, Fr)>,
    pk: IrValue,
    use_counter: u64,
    r: IrValue,
    s: IrValue,
    signing: Signing,
}

impl Case {
    fn inputs(&self) -> Vec<Fr> {
        let (hi, lo) = self.raw_word.unwrap_or_else(|| b32_slots(&self.word));
        let mut v = vec![hi, lo];
        v.extend(natives(&self.pk));
        v.push(Fr::from(self.use_counter));
        v.extend(natives(&self.r));
        v.extend(natives(&self.s));
        v
    }

    /// Re-sign `self.signing` with `key`.
    fn resign(&mut self, key: &Key, seed: u64) {
        let (r, s) = key.sign(&self.signing.digest(&key.address), seed);
        self.r = r;
        self.s = s;
    }

    /// Set the word on BOTH sides (the call and the signature) and re-sign.
    fn set_word(&mut self, key: &Key, word: [u8; 32], seed: u64) {
        self.word = word;
        self.signing.word = word;
        self.resign(key, seed);
    }

    /// The caller's entry at `counter` (its pre-roll entry when `counter == use_counter`).
    fn caller_entry(&self, key: &Key, counter: u64) -> [u8; 32] {
        device_entry(&self.me, &key.address, self.state.device_epoch, counter)
    }

    fn probe(&self, name: &str, expect: bool, ours: &IrSource, theirs: &IrSource) -> ProbeResult {
        probe::run(
            name,
            expect,
            ours,
            theirs,
            self.state.state(),
            self.me,
            &self.inputs(),
            &[],
        )
    }
}

/// An honest call: the caller's entry at `counter` is enrolled, the wallet signs exactly what the
/// state says. For `Remove` a second device (another key, counter 0) is enrolled and is the entry
/// removed, so the account keeps its caller; for `Add` the new entry is another key's entry at the
/// current epoch and counter 0 (what an honest client enrols); for `Rotate` a random key.
fn honest(op: Op, rng: &mut Rng, key: &Key, counter: u64, nonce: u64, epoch: u32) -> Case {
    let me: [u8; 32] = rng.bytes();
    let salt: [u8; 32] = rng.bytes();
    let mut state = AccountState::activated(salt);
    state.auth_nonce = nonce;
    state.round = (nonce % 1_000_000) + 1;
    state.device_epoch = epoch;
    state.enc_key = rng.bytes();
    state.devices.push(device_entry(&me, &key.address, epoch, counter));
    let second = test_key("second device");
    let word = match op {
        Op::Rotate => rng.bytes(),
        Op::Add => device_entry(&me, &second.address, epoch, 0),
        Op::Remove => {
            let entry = device_entry(&me, &second.address, epoch, rng.next_u64() % 100);
            state.devices.push(entry);
            state.device_count = 2;
            entry
        }
    };
    let signing = Signing::honest(op, me, salt, nonce, word);
    let (r, s) = key.sign(&signing.digest(&key.address), rng.next_u64());
    Case {
        state,
        me,
        word,
        raw_word: None,
        pk: key.pk.clone(),
        use_counter: counter,
        r,
        s,
        signing,
    }
}

// ── the sweep ────────────────────────────────────────────────────────────────────────────────────

/// The probes every one of the three circuits gets: honest calls, then the P1.4 tamper sweep and
/// the cross-operation substitutions.
#[allow(clippy::vec_init_then_push)]
fn common_probes(op: Op, ours: &IrSource, theirs: &IrSource, rng: &mut Rng) -> Vec<ProbeResult> {
    let key = test_key("enrolled");
    let other = test_key("unenrolled");
    let mut probes = Vec::new();

    // honest
    probes.push(honest(op, rng, &key, 0, 0, 0).probe(
        "honest: first call (counter 0, nonce 0, epoch 0)",
        true,
        ours,
        theirs,
    ));
    for i in 0..8 {
        let counter = rng.next_u64() % 1000;
        let nonce = rng.next_u64() % 1000;
        let epoch = (rng.next_u64() % 3) as u32;
        let c = honest(op, rng, &key, counter, nonce, epoch);
        probes.push(c.probe(
            &format!("honest: random #{i} (counter {counter}, nonce {nonce}, epoch {epoch})"),
            true,
            ours,
            theirs,
        ));
    }
    {
        let mut c = honest(op, rng, &key, 3, 5, 0);
        c.s = negate_scalar(&c.s);
        probes.push(c.probe("honest: high-S twin of a valid signature", true, ours, theirs));
    }
    {
        let mut c = honest(op, rng, &key, 1, 1, 0);
        c.state.devices.push(device_entry(&c.me, &other.address, 0, 7));
        c.state.device_count += 1;
        probes.push(c.probe("honest: another device is enrolled too", true, ours, theirs));
    }
    {
        let c = honest(op, rng, &key, 17, (1 << 40) + 3, 2);
        probes.push(c.probe("honest: large nonce (2^40 + 3), epoch 2", true, ours, theirs));
    }

    // tamper sweep
    let t = |rng: &mut Rng| honest(op, rng, &key, 2, 4, 0);
    {
        let mut c = t(rng);
        let (r, s) = key.sign(&rng.bytes::<32>(), 7);
        c.r = r;
        c.s = s;
        probes.push(c.probe("tamper: bad signature (over another digest)", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        let (r, s) = other.sign(&c.signing.digest(&key.address), 9);
        c.r = r;
        c.s = s;
        probes.push(c.probe(
            "tamper: signed by another key, enrolled key presented",
            false,
            ours,
            theirs,
        ));
    }
    {
        let mut c = t(rng);
        c.pk = other.pk.clone();
        c.resign(&other, 9);
        probes.push(c.probe(
            "tamper: wrong signer address (valid signature by an unenrolled key)",
            false,
            ours,
            theirs,
        ));
    }
    {
        let mut c = t(rng);
        c.signing.nonce = 5;
        c.resign(&key, 11);
        probes.push(c.probe("tamper: wrong nonce (signed n+1)", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.signing.nonce = 3;
        c.resign(&key, 11);
        probes.push(c.probe("tamper: stale nonce (signed n-1, a replay)", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.state.devices.clear();
        c.state.device_count = 0;
        probes.push(c.probe("tamper: unknown device (empty device set)", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.use_counter = 3;
        probes.push(c.probe("tamper: unknown device (wrong use counter)", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.state.device_epoch = 1;
        probes.push(c.probe(
            "tamper: unknown device (entry from an older epoch)",
            false,
            ours,
            theirs,
        ));
    }
    {
        let mut c = t(rng);
        c.word[7] ^= 1;
        probes.push(c.probe(
            "tamper: wrong word (one byte of the Bytes<32> argument changed after signing)",
            false,
            ours,
            theirs,
        ));
    }
    {
        let mut c = t(rng);
        c.signing.salt[0] ^= 1;
        c.resign(&key, 13);
        probes.push(c.probe("tamper: EIP-712 domain salt", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.signing.account = rng.bytes();
        c.resign(&key, 14);
        probes.push(c.probe(
            "tamper: EIP-712 domain verifyingContract/account (another account)",
            false,
            ours,
            theirs,
        ));
    }
    {
        let mut c = t(rng);
        c.signing.domain.name = "Midnight Passport Account ".into();
        c.resign(&key, 15);
        probes.push(c.probe("tamper: EIP-712 domain name", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.signing.domain.version = "2".into();
        c.resign(&key, 16);
        probes.push(c.probe("tamper: EIP-712 domain version", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.signing.domain.type_str =
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)".into();
        c.resign(&key, 17);
        probes.push(c.probe("tamper: EIP-712 domain type (chainId added)", false, ours, theirs));
    }
    for o in op.others() {
        let mut c = t(rng);
        c.signing.type_str = o.type_str().into();
        c.resign(&key, 18);
        probes.push(c.probe(
            &format!(
                "tamper: EIP-712 primary type of {} (same word, same challenge)",
                o.circuit()
            ),
            false,
            ours,
            theirs,
        ));
        let mut c = t(rng);
        c.signing.challenge_tag = o.tag().into();
        c.resign(&key, 19);
        probes.push(c.probe(
            &format!("tamper: challenge built with {}'s DST", o.circuit()),
            false,
            ours,
            theirs,
        ));
        let mut c = t(rng);
        c.signing.type_str = o.type_str().into();
        c.signing.challenge_tag = o.tag().into();
        c.resign(&key, 20);
        probes.push(c.probe(
            &format!(
                "tamper: a complete, valid {} authorisation of the same word, presented here",
                o.circuit()
            ),
            false,
            ours,
            theirs,
        ));
    }
    {
        let mut c = t(rng);
        c.signing.challenge_self = rng.bytes();
        c.resign(&key, 21);
        probes.push(c.probe("tamper: challenge bound to another account", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.pk = identity_point();
        probes.push(c.probe("tamper: device key is the point at infinity", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.s = scalar_u64(0);
        probes.push(c.probe("tamper: signature s = 0", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.r = scalar_u64(0);
        probes.push(c.probe("tamper: signature r = 0", false, ours, theirs));
    }
    {
        let c = honest(op, rng, &key, u64::MAX, 4, 0);
        probes.push(c.probe(
            "tamper: use counter at 2^64-1 (the roll overflows)",
            false,
            ours,
            theirs,
        ));
    }
    {
        let c = honest(op, rng, &key, 2, u64::MAX, 0);
        probes.push(c.probe("tamper: auth_nonce at 2^64-1 (the bump overflows)", false, ours, theirs));
    }
    {
        let mut c = t(rng);
        c.state.round = u64::MAX;
        probes.push(c.probe("tamper: round at 2^64-1 (the bump overflows)", false, ours, theirs));
    }
    {
        // A `Bytes<32>` argument whose high limb is not a byte: the typed input's range check.
        let mut c = t(rng);
        let (_, lo) = b32_slots(&c.word);
        c.raw_word = Some((Fr::from(256u64), lo));
        probes.push(c.probe(
            "tamper: malformed Bytes<32> argument (high limb 256)",
            false,
            ours,
            theirs,
        ));
    }
    probes
}

fn gate(op: Op, seed: u64, extra: impl FnOnce(&IrSource, &IrSource, &mut Rng, &mut Vec<ProbeResult>)) {
    let circuit = op.circuit();
    let theirs = baseline::load(circuit);
    let ours = op.port();
    let mut rng = Rng(seed);
    let mut probes = common_probes(op, &ours, &theirs, &mut rng);
    extra(&ours, &theirs, &mut rng, &mut probes);
    super::report(circuit, &ours, &theirs, &probes);
}

// ── P0.4 for this lane: the baseline is the pinned artifact, and its k/rows the 00034 numbers ───

#[test]
fn p0_baseline_l_dev() {
    let mut rows = Vec::new();
    for op in ALL {
        let circuit = op.circuit();
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
            format!("{dir}/p0-baseline-l-dev.json"),
            serde_json::to_string_pretty(&rows).unwrap(),
        )
        .unwrap();
    }
}

// ── rotate_enc_key_with_evm ──────────────────────────────────────────────────────────────────────

#[test]
fn gate_rotate_enc_key_with_evm() {
    gate(Op::Rotate, 0x0040_de01, |ours, theirs, rng, probes| {
        let key = test_key("enrolled");
        {
            let mut c = honest(Op::Rotate, rng, &key, 4, 9, 0);
            let current = c.state.enc_key;
            c.set_word(&key, current, 30);
            probes.push(c.probe("honest: rotate to the key already set (idempotent)", true, ours, theirs));
        }
        {
            let mut c = honest(Op::Rotate, rng, &key, 5, 10, 1);
            c.set_word(&key, [0u8; 32], 31);
            probes.push(c.probe("honest: rotate to the all-zero key", true, ours, theirs));
        }
        {
            let mut c = honest(Op::Rotate, rng, &key, 6, 11, 0);
            c.set_word(&key, [0xff; 32], 32);
            probes.push(c.probe("honest: rotate to the all-0xff key", true, ours, theirs));
        }
    });
}

// ── add_device_with_evm ──────────────────────────────────────────────────────────────────────────

#[test]
fn gate_add_device_with_evm() {
    gate(Op::Add, 0x0040_de02, |ours, theirs, rng, probes| {
        let key = test_key("enrolled");
        {
            let mut c = honest(Op::Add, rng, &key, 3, 3, 0);
            c.set_word(&key, rng.bytes(), 40);
            probes.push(c.probe(
                "honest: enrol an opaque entry (another arm's, or dead weight)",
                true,
                ours,
                theirs,
            ));
        }
        {
            // The seam consumes the caller's entry at `use_counter` before the chip runs, so
            // enrolling that very entry again is accepted — the revocation bypass the contract's
            // own comment documents (README erratum 8). The port must accept it too.
            let mut c = honest(Op::Add, rng, &key, 3, 4, 0);
            let pre_roll = c.caller_entry(&key, 3);
            c.set_word(&key, pre_roll, 41);
            probes.push(c.probe(
                "honest: enrol the caller's own just-consumed entry (erratum 8)",
                true,
                ours,
                theirs,
            ));
        }
        {
            let mut c = honest(Op::Add, rng, &key, 3, 5, 0);
            c.state.device_count = 254;
            probes.push(c.probe("honest: device_count 254 -> 255 (the ceiling)", true, ours, theirs));
        }
        {
            let mut c = honest(Op::Add, rng, &key, 3, 6, 0);
            c.state.device_count = 255;
            probes.push(c.probe(
                "tamper: device_count at 255 (the bump overflows Uint<8>)",
                false,
                ours,
                theirs,
            ));
        }
        {
            let mut c = honest(Op::Add, rng, &key, 3, 7, 0);
            let present = device_entry(&c.me, &test_key("present").address, 0, 2);
            c.state.devices.push(present);
            c.state.device_count = 2;
            c.set_word(&key, present, 42);
            probes.push(c.probe(
                "tamper: entry already present (another device's live entry)",
                false,
                ours,
                theirs,
            ));
        }
        {
            // The seam has just inserted the caller's post-roll entry.
            let mut c = honest(Op::Add, rng, &key, 3, 8, 0);
            let post_roll = c.caller_entry(&key, 4);
            c.set_word(&key, post_roll, 43);
            probes.push(c.probe(
                "tamper: entry already present (the caller's own post-roll entry)",
                false,
                ours,
                theirs,
            ));
        }
    });
}

// ── remove_device_with_evm ───────────────────────────────────────────────────────────────────────

#[test]
fn gate_remove_device_with_evm() {
    gate(Op::Remove, 0x0040_de03, |ours, theirs, rng, probes| {
        let key = test_key("enrolled");
        {
            let mut c = honest(Op::Remove, rng, &key, 8, 12, 0);
            c.state.device_count = 255;
            probes.push(c.probe("honest: device_count 255 -> 254", true, ours, theirs));
        }
        {
            // A mis-derived entry (not any key's) counts toward device_count and can be removed.
            let mut c = honest(Op::Remove, rng, &key, 8, 13, 0);
            let junk: [u8; 32] = rng.bytes();
            c.state.devices.push(junk);
            c.state.device_count = 3;
            c.set_word(&key, junk, 50);
            probes.push(c.probe("honest: remove a dead-weight entry (count 3 -> 2)", true, ours, theirs));
        }
        {
            // The caller's entry at another live counter: removable, the caller keeps its roll.
            let mut c = honest(Op::Remove, rng, &key, 8, 14, 0);
            let twin = c.caller_entry(&key, 20);
            c.state.devices.push(twin);
            c.state.device_count = 3;
            c.set_word(&key, twin, 51);
            probes.push(c.probe(
                "honest: remove the caller's own entry at another counter",
                true,
                ours,
                theirs,
            ));
        }
        {
            let mut c = honest(Op::Remove, rng, &key, 8, 15, 0);
            c.state.device_count = 1;
            probes.push(c.probe(
                "tamper: last device (device_count 1, entry present)",
                false,
                ours,
                theirs,
            ));
        }
        {
            let mut c = honest(Op::Remove, rng, &key, 8, 16, 0);
            c.state.device_count = 0;
            probes.push(c.probe("tamper: device_count 0", false, ours, theirs));
        }
        {
            // AUTH-5: the authorising device's post-roll entry is off limits.
            let mut c = honest(Op::Remove, rng, &key, 8, 17, 0);
            let post_roll = c.caller_entry(&key, 9);
            c.set_word(&key, post_roll, 52);
            probes.push(c.probe(
                "tamper: remove the authorising device (its post-roll entry, AUTH-5)",
                false,
                ours,
                theirs,
            ));
        }
        {
            // AUTH-5 under a count that would allow it: three devices, the caller's post-roll entry.
            let mut c = honest(Op::Remove, rng, &key, 8, 18, 0);
            c.state.devices.push(rng.bytes());
            c.state.device_count = 3;
            let post_roll = c.caller_entry(&key, 9);
            c.set_word(&key, post_roll, 53);
            probes.push(c.probe(
                "tamper: remove the authorising device with three enrolled (AUTH-5)",
                false,
                ours,
                theirs,
            ));
        }
        {
            // The seam consumed the pre-roll entry, so it is no longer a member.
            let mut c = honest(Op::Remove, rng, &key, 8, 19, 0);
            let pre_roll = c.caller_entry(&key, 8);
            c.set_word(&key, pre_roll, 54);
            probes.push(c.probe(
                "tamper: remove the caller's pre-roll entry (consumed by the seam)",
                false,
                ours,
                theirs,
            ));
        }
        {
            let mut c = honest(Op::Remove, rng, &key, 8, 20, 0);
            c.set_word(&key, rng.bytes(), 55);
            probes.push(c.probe("tamper: remove an entry that is not in the set", false, ours, theirs));
        }
    });
}
