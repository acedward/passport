//! The differential probe: one call, one ledger state, run through BOTH artifacts by Midnight's
//! own transcript executor (`minocrab_sim::v3::exec`: the ZKIR walk plus the Impact VM over the
//! live `StateValue`), then compared.
//!
//! For a call the reference (compactc) ACCEPTS, agreement means all of:
//!   1. the same typed input schema and output schema;
//!   2. the same public-input vector (`pis`) and the same `pi_skips` when both artifacts are
//!      simulated on the reference's preimage;
//!   3. Midnight's `IrSource::check` accepts the reference preimage on both, with those
//!      `pi_skips`;
//!   4. the port's executor derives a byte-identical preimage (both transcript halves, the
//!      binding input and the communications commitment, which spans the OUTPUTS);
//!   5. reference-VM replay: both transcripts, re-run through `QueryContext::query` in verify mode,
//!      leave the SAME post-state.
//!
//! For a call the reference REFUSES, agreement means the port refuses it too, the same way
//! (a failed assert, a ledger refusal, or a malformed walk).
#![allow(dead_code)]

use midnight_onchain_state::state::StateValue;
use midnight_transient_crypto::proofs::Zkir;
use minocrab::Fr;
use minocrab_sim::v3::exec::{self, Call, ExecError, Executed};
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    /// A failed assert (the circuit refuses the call).
    Rejected,
    /// The circuit is satisfied but the ledger will not apply the transcript.
    NotApplied,
    /// The ZKIR walk itself failed (an unsatisfiable instruction, e.g. `inv(0)`).
    Walk,
    Other(String),
}

fn outcome_of(r: &Result<Executed, ExecError>) -> Outcome {
    match r {
        Ok(_) => Outcome::Accepted,
        Err(ExecError::Rejected { .. }) => Outcome::Rejected,
        Err(ExecError::NotApplied { .. }) => Outcome::NotApplied,
        Err(ExecError::Circuit(_)) => Outcome::Walk,
        Err(e) => Outcome::Other(format!("{e}")),
    }
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub name: String,
    pub expect_accept: bool,
    pub reference: Outcome,
    pub port: Outcome,
    /// Empty when the two agree on everything this probe checks.
    pub disagreements: Vec<String>,
    pub pis_len: usize,
}

impl ProbeResult {
    pub fn ok(&self) -> bool {
        self.disagreements.is_empty()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "probe": self.name,
            "expect": if self.expect_accept { "accept" } else { "refuse" },
            "compactc": format!("{:?}", self.reference),
            "minocrab": format!("{:?}", self.port),
            "pis": self.pis_len,
            "agree": self.ok(),
            "disagreements": self.disagreements,
        })
    }
}

/// Everything upstream's comparator asserts, as a list of findings instead of a panic
/// (`minocrab_sim::v3::assert_call_compatible`, same checks, same order).
pub fn call_compatibility(
    ours: &IrSource,
    theirs: &IrSource,
    pi: &midnight_transient_crypto::proofs::ProofPreimage,
) -> Vec<String> {
    let mut out = Vec::new();
    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    if types(ours) != types(theirs) {
        out.push("input schemas differ".into());
    }
    if ours.outputs != theirs.outputs {
        out.push("output schemas differ".into());
    }
    let our_run = match simulate(ours, pi) {
        Ok(r) => r,
        Err(e) => {
            out.push(format!("port refuses the reference preimage: {e}"));
            return out;
        }
    };
    let their_run = match simulate(theirs, pi) {
        Ok(r) => r,
        Err(e) => {
            out.push(format!("reference refuses its own preimage: {e}"));
            return out;
        }
    };
    if our_run.pi_skips != their_run.pi_skips {
        out.push("pi_skips differ".into());
    }
    if our_run.pis != their_run.pis {
        let at = our_run.pis.iter().zip(their_run.pis.iter()).position(|(a, b)| a != b);
        out.push(format!(
            "PI vectors differ (lengths {} vs {}, first difference at {:?})",
            our_run.pis.len(),
            their_run.pis.len(),
            at
        ));
    }
    if our_run.outputs != their_run.outputs {
        out.push("circuit outputs differ".into());
    }
    match ours.check(pi) {
        Ok(skips) if skips == our_run.pi_skips => {}
        Ok(_) => out.push("upstream check (port) reports different pi_skips".into()),
        Err(e) => out.push(format!("upstream check refuses the port: {e}")),
    }
    match theirs.check(pi) {
        Ok(skips) if skips == their_run.pi_skips => {}
        Ok(_) => out.push("upstream check (reference) reports different pi_skips".into()),
        Err(e) => out.push(format!("upstream check refuses the reference: {e}")),
    }
    out
}

/// Run one probe.
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
    let ctx = exec::context(state, self_addr);
    let mut call = Call::new(inputs, private).with_comm_rand(Fr::from(0x00c0_ffee_u64));
    call.binding_input = Fr::from(0x0b1d_u64);

    let reference = exec::execute(theirs, &call, &ctx);
    let port = exec::execute(ours, &call, &ctx);
    let (ro, po) = (outcome_of(&reference), outcome_of(&port));

    let mut disagreements = Vec::new();
    let mut pis_len = 0;
    if ro != po {
        disagreements.push(format!("outcome: compactc {ro:?}, minocrab {po:?}"));
    }
    if expect_accept != (ro == Outcome::Accepted) {
        // Not a port disagreement, but a probe that does not test what it says it tests.
        disagreements.push(format!(
            "probe mis-specified: expected the reference to {}, it returned {ro:?}{}",
            if expect_accept { "accept" } else { "refuse" },
            match &reference {
                Err(e) => format!(" ({e})"),
                Ok(_) => String::new(),
            }
        ));
    }
    if let (Ok(r), Ok(p)) = (&reference, &port) {
        pis_len = r.run.pis.len();
        disagreements.extend(call_compatibility(ours, theirs, &r.preimage));
        if p.preimage.public_transcript_inputs != r.preimage.public_transcript_inputs {
            disagreements.push("port-derived public_transcript_inputs differ".into());
        }
        if p.preimage.public_transcript_outputs != r.preimage.public_transcript_outputs {
            disagreements.push("port-derived public_transcript_outputs differ".into());
        }
        if p.preimage.communications_commitment != r.preimage.communications_commitment {
            disagreements.push("communications commitments differ".into());
        }
        if p.post != r.post {
            disagreements.push("reference-VM replay: post-states differ".into());
        }
        if p.ops != r.ops {
            disagreements.push("Impact op streams differ".into());
        }
    }
    ProbeResult {
        name: name.to_string(),
        expect_accept,
        reference: ro,
        port: po,
        disagreements,
        pis_len,
    }
}
