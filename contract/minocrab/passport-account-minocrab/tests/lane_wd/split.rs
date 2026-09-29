//! THE SPLIT RUN — how the gate compares an honest `withdraw_unshielded_with_evm` call
//! (questions file, Q6).
//!
//! MinoCrab's executor (`minocrab_sim::v3::exec` @ `9f4d6a6`) cannot settle an honest unshielded
//! withdrawal for EITHER artifact: its op decoder rebuilds each `Bytes<32>` atom from its field
//! limbs without normalising it, so the unused arm of `left(color)` (the token type) and of
//! `right(user)` (the recipient) is 32 zero bytes rather than the empty atom, and the ledger's typed
//! effects decode (`TokenType`, `PublicAddress`) refuses it with `InvalidBuiltinDecode("()")` —
//! after the whole program has run in verify mode, every read validated. In production the ops are
//! built by compact-runtime (whose `CompactTypeBytes.toValue` trims trailing zeros) and travel
//! beside the proof, so the chain never decodes one from field elements. The public inputs are
//! identical either way.
//!
//! So when — and only when — BOTH artifacts fail with exactly that decode, the probe is re-run in
//! two parts:
//!
//! 1. **the state part**: both circuits with their trailing kernel-effects block removed (every
//!    `Impact` from the first `swap` after the last read; the block reads nothing and writes only
//!    the effects), through the ordinary probe — all five agreement checks, including the
//!    post-state replay;
//! 2. **the full circuits on the executor's reads**: the reads the executor gathered in part 1 are
//!    the full circuit's reads (none follows the removed block), so both FULL circuits are walked
//!    on them: the same `public_transcript_inputs`, the state part's transcript a prefix of it, and
//!    `call_compatibility` (schemas, `pis`, `pi_skips`, outputs, `IrSource::check` on both) on the
//!    complete preimage, communications commitment included.
//!
//! Any other outcome (one side accepted, a different refusal, a tamper) goes through the ordinary
//! probe unchanged, so this can only ever ADD checks to a call the ordinary probe could not finish.

use std::sync::Arc;

use midnight_onchain_state::state::StateValue;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::ProofPreimage;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use minocrab::Fr;
use minocrab_sim::v3::exec::{self, Call, ExecError, Executed};
use minocrab_sim::v3::{simulate_with, Mode};
use minocrab_zkir::v3::{Instruction, IrSource, Operand};

use crate::support::probe::{self, call_compatibility, Outcome, ProbeResult};

/// The executor's refusal the split run exists for, and nothing else.
const EFFECTS_DECODE: &str = "Decode(InvalidBuiltinDecode(\"()\"))";

fn effects_decode_only(r: &Result<Executed, ExecError>) -> bool {
    matches!(r, Err(ExecError::NotApplied { why }) if why == EFFECTS_DECODE)
}

/// `ir` without its trailing kernel-effects block: every `Impact` from the first `swap` (opcode
/// `0x40`, how each kernel effect opens) after the circuit's last read. Returns the circuit and how
/// many `Impact` instructions were dropped.
pub fn without_kernel_effects_tail(ir: &IrSource) -> (IrSource, usize) {
    let ins = &ir.instructions;
    let last_read = ins
        .iter()
        .rposition(|i| matches!(i, Instruction::PublicInput { .. }))
        .expect("the circuit reads the ledger");
    let swap = Operand::Immediate(Fr::from(0x40u64));
    let start = (last_read..ins.len())
        .find(|&k| matches!(&ins[k], Instruction::Impact { inputs, .. } if inputs.first() == Some(&swap)))
        .expect("the circuit ends in a kernel-effects block");
    let kept: Vec<Instruction> = ins
        .iter()
        .enumerate()
        .filter(|(k, i)| *k < start || !matches!(i, Instruction::Impact { .. }))
        .map(|(_, i)| i.clone())
        .collect();
    let dropped = ins.len() - kept.len();
    let mut out = ir.clone();
    out.instructions = Arc::new(kept);
    (out, dropped)
}

/// `transient_commit` over the raw inputs then the encoded outputs (the list `simulate` checks a
/// supplied commitment against; `exec::comm_commitment`, transcribed because it is private).
fn comm_commitment(inputs: &[Fr], outputs: &[minocrab_zkir::v3::IrValue], rand: Fr) -> Fr {
    let mut list: Vec<Fr> = inputs.to_vec();
    for value in outputs {
        for v in encode_offcircuit(value) {
            list.push(v.try_into().expect("an encoded output is a native value"));
        }
    }
    transient_commit(&list[..], rand)
}

/// One probe, through the split run when (and only when) both artifacts stop at the effects
/// decode; otherwise exactly `probe::run`.
#[allow(clippy::too_many_arguments)]
pub fn run(
    name: &str,
    expect_accept: bool,
    ours: &IrSource,
    theirs: &IrSource,
    state: StateValue,
    self_addr: [u8; 32],
    inputs: &[Fr],
    private: &[Fr],
) -> ProbeResult {
    let rand = Fr::from(0x00c0_ffee_u64);
    let mut call = Call::new(inputs, private).with_comm_rand(rand);
    call.binding_input = Fr::from(0x0b1d_u64);
    let ctx = exec::context(state.clone(), self_addr);
    let (r, p) = (exec::execute(theirs, &call, &ctx), exec::execute(ours, &call, &ctx));
    if !(effects_decode_only(&r) && effects_decode_only(&p)) {
        return probe::run(name, expect_accept, ours, theirs, state, self_addr, inputs, private);
    }

    let mut d: Vec<String> = Vec::new();
    if !expect_accept {
        d.push("probe mis-specified: a refusal probe reached the effects decode (it passes every assert)".into());
    }

    // 1. the state part
    let (theirs_t, dropped_t) = without_kernel_effects_tail(theirs);
    let (ours_t, dropped_o) = without_kernel_effects_tail(ours);
    if dropped_t != dropped_o {
        d.push(format!(
            "kernel-effects blocks differ in length: compactc {dropped_t} impacts, minocrab {dropped_o}"
        ));
    }
    let part = probe::run(
        &format!("{name} [state part]"),
        true,
        &ours_t,
        &theirs_t,
        state,
        self_addr,
        inputs,
        private,
    );
    d.extend(part.disagreements.iter().map(|x| format!("state part: {x}")));
    let executed = match exec::execute(&theirs_t, &call, &ctx) {
        Ok(e) => e,
        Err(e) => {
            d.push(format!("state part: the reference is refused: {e}"));
            return result(name, expect_accept, d, 0);
        }
    };

    // 2. the full circuits on the executor's reads
    let pre = ProofPreimage {
        inputs: inputs.to_vec(),
        private_transcript: private.to_vec(),
        public_transcript_inputs: Vec::new(),
        public_transcript_outputs: exec::outputs_of(&executed.reads),
        binding_input: call.binding_input,
        communications_commitment: None,
        key_location: call.key_location.clone(),
    };
    let walk = |ir: &IrSource, who: &str, d: &mut Vec<String>| match simulate_with(ir, &pre, Mode::Gather) {
        Ok(run) => {
            if !run.assert_failures.is_empty() || !run.walk_failures.is_empty() {
                d.push(format!(
                    "full circuit ({who}): asserts {:?}, walk failures {:?}",
                    run.assert_failures, run.walk_failures
                ));
            }
            if run.consumed_public != pre.public_transcript_outputs.len() {
                d.push(format!(
                    "full circuit ({who}): consumed {} of {} read limbs",
                    run.consumed_public,
                    pre.public_transcript_outputs.len()
                ));
            }
            Some(run)
        }
        Err(e) => {
            d.push(format!("full circuit ({who}): the walk fails: {e}"));
            None
        }
    };
    let (Some(rt), Some(ro)) = (walk(theirs, "compactc", &mut d), walk(ours, "minocrab", &mut d)) else {
        return result(name, expect_accept, d, 0);
    };
    if rt.public_transcript_inputs != ro.public_transcript_inputs {
        d.push("full circuits: public_transcript_inputs differ".into());
    }
    if !rt
        .public_transcript_inputs
        .starts_with(&executed.preimage.public_transcript_inputs)
    {
        d.push("the state part's transcript is not a prefix of the full transcript".into());
    }
    if let Err(e) = exec::decode_program(&rt.public_transcript_inputs) {
        d.push(format!("the full transcript does not decode: {e}"));
    }
    let full = ProofPreimage {
        inputs: inputs.to_vec(),
        private_transcript: private.to_vec(),
        public_transcript_inputs: rt.public_transcript_inputs.clone(),
        public_transcript_outputs: pre.public_transcript_outputs.clone(),
        binding_input: call.binding_input,
        communications_commitment: Some((comm_commitment(inputs, &rt.outputs, rand), rand)),
        key_location: call.key_location.clone(),
    };
    d.extend(call_compatibility(ours, theirs, &full));
    let pis_len = minocrab_sim::v3::simulate(theirs, &full)
        .map(|r| r.pis.len())
        .unwrap_or(0);
    result(name, expect_accept, d, pis_len)
}

fn result(name: &str, expect_accept: bool, disagreements: Vec<String>, pis_len: usize) -> ProbeResult {
    let outcome = Outcome::Other("Accepted (split run: executor effects decode, Q6)".into());
    ProbeResult {
        name: name.to_string(),
        expect_accept,
        reference: outcome.clone(),
        port: outcome,
        disagreements,
        pis_len,
    }
}
