//! AA 00040 P2.3: verify the proofs that the pinned proof server (`midnightntwrk/proof-server`
//! 9.0.0-rc.6) produced for the ported circuits, with Midnight's own verifier (`transient-crypto`
//! at the `midnight-ledger` rev MinoCrab pins) and each arm's verifier key. Offline: files only.
//!
//! Inputs (`contract/scripts/minocrab/prove-bench.sh` writes them):
//!   `PROOF_DIR`    `<c>.preimage` (ledger-v9's serialisation of the call's proof preimage) and
//!                  `<c>.<arm>.proof`, `<c>.<arm>.run<N>.proof` (the server's `/prove` answers);
//!   `KEYSETS_DIR`  `compactc/account` and `mixed/account` (`contract/scripts/minocrab/keyset.ts`).
//!
//! Per circuit it checks that:
//!   1. both artifacts accept the shared preimage (`IrSource::check`) and derive the SAME public
//!      statement from it (binding input, communications commitment, every Impact input);
//!   2. every MinoCrab proof verifies against the MinoCrab verifier key, and every compactc proof
//!      against the compactc one;
//!   3. the negative controls fail: a MinoCrab proof against the compactc key, a compactc proof
//!      against the MinoCrab key, and a MinoCrab proof against a statement with one element changed.
//!
//! Without `PROOF_DIR` it prints why and passes, so `cargo test` stays offline.

use std::path::{Path, PathBuf};

use midnight_serialize::Deserializable;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{Proof, ProofPreimage, VerifierKey, Zkir, PARAMS_VERIFIER};
use midnight_zkir_v3::{Instruction, IrSource};
use sha2::{Digest, Sha256};

const CIRCUITS: [&str; 2] = ["append_inbox_with_evm", "withdraw_shielded_with_evm"];

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The body of a `midnight:<tag>:`-tagged serialisation.
fn untag<'a>(bytes: &'a [u8], tag: &str) -> &'a [u8] {
    let prefix = format!("midnight:{tag}:");
    assert!(
        bytes.starts_with(prefix.as_bytes()),
        "expected the tag {prefix:?}, found {:?}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(48)])
    );
    &bytes[prefix.len()..]
}

fn load_preimage(path: &Path) -> ProofPreimage {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut body = untag(&bytes, "proof-preimage");
    let pi = ProofPreimage::deserialize(&mut body, 0)
        .unwrap_or_else(|e| panic!("{}: not a ProofPreimage at this rev: {e}", path.display()));
    assert!(body.is_empty(), "{}: {} trailing bytes", path.display(), body.len());
    pi
}

/// A `/prove` answer: a tagged `ProofVersioned` (a one-byte version, then the proof).
fn load_proof(path: &Path) -> (u8, Proof) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut body = untag(&bytes, "proof-versioned");
    let version = body[0];
    body = &body[1..];
    let proof =
        Proof::deserialize(&mut body, 0).unwrap_or_else(|e| panic!("{}: not a Proof at this rev: {e}", path.display()));
    assert!(body.is_empty(), "{}: {} trailing bytes", path.display(), body.len());
    (version, proof)
}

fn load_ir(path: &Path) -> IrSource {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    IrSource::load(std::io::BufReader::new(f))
        .unwrap_or_else(|e| panic!("{}: not a ZKIR v3 source: {e}", path.display()))
}

fn load_vk(path: &Path) -> VerifierKey {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let vk: VerifierKey = midnight_serialize::tagged_deserialize(std::io::BufReader::new(f))
        .unwrap_or_else(|e| panic!("{}: not a verifier key at this rev: {e}", path.display()));
    vk.init()
        .unwrap_or_else(|e| panic!("{}: the verifier key does not initialise: {e}", path.display()));
    vk
}

/// The public statement a proof of `ir` on `pi` is verified against: the binding input, the
/// communications commitment when the artifact commits, then every Impact's inputs (zeros for an
/// Impact the run skipped). The layout `IrSource::prove` exposes at this rev (AA 00023's harness).
fn statement(ir: &IrSource, pi: &ProofPreimage) -> Vec<Fr> {
    let skips = ir.check(pi).expect("the artifact refuses the preimage");
    let impacts: Vec<_> = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Impact { .. }))
        .collect();
    assert_eq!(impacts.len(), skips.len(), "Impact/check lengths differ");
    let mut out = vec![pi.binding_input];
    if ir.do_communications_commitment {
        out.push(
            pi.communications_commitment
                .expect("the artifact needs a communications commitment")
                .0,
        );
    }
    let mut at = 0usize;
    for (instruction, skip) in impacts.into_iter().zip(skips) {
        let Instruction::Impact { inputs, .. } = instruction else {
            unreachable!()
        };
        match skip {
            Some(padded) => out.extend(std::iter::repeat_n(Fr::from(0u64), padded)),
            None => {
                out.extend_from_slice(&pi.public_transcript_inputs[at..at + inputs.len()]);
                at += inputs.len();
            }
        }
    }
    assert_eq!(at, pi.public_transcript_inputs.len(), "unused public transcript inputs");
    out
}

fn proofs_of(dir: &Path, circuit: &str, arm: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_string();
            n.starts_with(&format!("{circuit}.{arm}.")) && n.ends_with(".proof")
        })
        .collect();
    v.sort();
    v
}

#[test]
fn verify_proof_server_proofs() {
    let Ok(dir) = std::env::var("PROOF_DIR") else {
        println!("PROOF_DIR is not set: nothing to verify (run contract/scripts/minocrab/prove-bench.sh first)");
        return;
    };
    let dir = PathBuf::from(dir);
    let keysets = PathBuf::from(std::env::var("KEYSETS_DIR").expect("set KEYSETS_DIR"));
    let mut report = Vec::new();
    for circuit in CIRCUITS {
        let pi = load_preimage(&dir.join(format!("{circuit}.preimage")));
        let ir_c = load_ir(&keysets.join(format!("compactc/account/zkir/{circuit}.zkir")));
        let ir_m = load_ir(&keysets.join(format!("mixed/account/zkir/{circuit}.zkir")));
        let vk_c_path = keysets.join(format!("compactc/account/keys/{circuit}.verifier"));
        let vk_m_path = keysets.join(format!("mixed/account/keys/{circuit}.verifier"));
        let (vk_c, vk_m) = (load_vk(&vk_c_path), load_vk(&vk_m_path));
        let st_c = statement(&ir_c, &pi);
        let st_m = statement(&ir_m, &pi);
        assert_eq!(st_c, st_m, "{circuit}: the two artifacts derive different statements");

        let verify =
            |vk: &VerifierKey, proof: &Proof, st: &[Fr]| vk.verify(&PARAMS_VERIFIER, proof, st.iter().copied()).is_ok();
        let mut rows = Vec::new();
        for (arm, own, other) in [("minocrab", &vk_m, &vk_c), ("compactc", &vk_c, &vk_m)] {
            let files = proofs_of(&dir, circuit, arm);
            assert!(!files.is_empty(), "{circuit}: no {arm} proofs in {}", dir.display());
            for f in files {
                let (version, proof) = load_proof(&f);
                let ok_own = verify(own, &proof, &st_m);
                let ok_other = verify(other, &proof, &st_m);
                let mut tampered = st_m.clone();
                tampered[0] = tampered[0] + Fr::from(1u64);
                let ok_tampered = verify(own, &proof, &tampered);
                println!(
                    "{circuit} {arm} {}: {} B, own key {ok_own}, other key {ok_other}, tampered statement {ok_tampered}",
                    f.file_name().unwrap().to_string_lossy(),
                    proof.0.len()
                );
                assert!(ok_own, "{}: does NOT verify against its own verifier key", f.display());
                assert!(!ok_other, "{}: verifies against the OTHER arm's key", f.display());
                assert!(!ok_tampered, "{}: verifies against a tampered statement", f.display());
                rows.push(serde_json::json!({
                    "file": f.file_name().unwrap().to_string_lossy(),
                    "arm": arm,
                    "proof_versioned_tag": version,
                    "proof_bytes": proof.0.len(),
                    "proof_sha256": sha(&proof.0),
                    "verifies_own_key": ok_own,
                    "verifies_other_arm_key": ok_other,
                    "verifies_tampered_statement": ok_tampered,
                }));
            }
        }
        report.push(serde_json::json!({
            "circuit": circuit,
            "preimage_sha256": sha(&std::fs::read(dir.join(format!("{circuit}.preimage"))).unwrap()),
            "statement_len": st_m.len(),
            "statements_equal_compactc_minocrab": true,
            "minocrab_verifier_sha256": sha(&std::fs::read(&vk_m_path).unwrap()),
            "compactc_verifier_sha256": sha(&std::fs::read(&vk_c_path).unwrap()),
            "verifier_params": "transient-crypto PARAMS_VERIFIER (embedded bls_midnight_2p14)",
            "proofs": rows,
        }));
    }
    let out = serde_json::json!({
        "what": "AA 00040 P2.3: proof-server rc.6 proofs verified with transient-crypto @ midnight-ledger 04c9c5d9",
        "verdict": "PASS",
        "circuits": report,
    });
    std::fs::write(dir.join("verify.json"), serde_json::to_string_pretty(&out).unwrap()).unwrap();
}
