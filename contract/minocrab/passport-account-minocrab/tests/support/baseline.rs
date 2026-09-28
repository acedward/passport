//! The compactc 0.34.0 baseline: `account.compact` sha256 `44cff904…` compiled with
//! `--feature-zkir-v3`, read from `COMPACTC_BASELINE_DIR` (its `managed/account/zkir`). Every file
//! is checked against the pinned SHA-256 below BEFORE it is parsed, so a gate run against the
//! wrong baseline fails loudly instead of comparing against the wrong statement.
//!
//! k and rows are the 00034 G2 measurements (`g2-measure-k-merged.json`, compactc's bundled
//! `zkir-v3`); `p0_baseline` re-derives them with Midnight's own cost model.

use minocrab_zkir::v3::IrSource;
use sha2::{Digest, Sha256};

/// (circuit, zkir sha256, k, rows) — every k=18 `_with_evm` candidate of Q1's option B.
pub const PINS: &[(&str, &str, u8, usize)] = &[
    (
        "append_inbox_with_evm",
        "b2040ba1329cb7088a89510b5bf2d059df4df291ea58e0ff4a7e30b77a320fab",
        18,
        160_236,
    ),
    (
        "withdraw_shielded_with_evm",
        "d78eeb1cd977730664ec506e7ea3d0604a3edd536b1e56f39c4942f87bb96119",
        18,
        182_809,
    ),
    (
        "rotate_enc_key_with_evm",
        "4d1b79a210e041c812d5c8e306f01e9afb3fa59758a927dab01eade09002f87c",
        18,
        147_602,
    ),
    (
        "add_device_with_evm",
        "4f420a5c24abb80297e1eb9992e1593fa8bf5bd610e0d46bc2b43aa7e5a27367",
        18,
        147_648,
    ),
    (
        "remove_device_with_evm",
        "bb7685124c9484f1481d707b4cd4c5ad46d1438fd391525cff7258727d7902e1",
        18,
        151_466,
    ),
    (
        "withdraw_unshielded_with_evm",
        "cc35e5417d31e9898a83885324521517b75ea11f933b659a2c51ff9c8ced44e4",
        18,
        161_623,
    ),
    (
        "withdraw_shielded_to_contract_with_evm",
        "735965a1c5096492b56945f756d8a72891d4a52a6e3155e20f026bb1d673d0d0",
        18,
        188_532,
    ),
];

pub fn pin(name: &str) -> (&'static str, u8, usize) {
    let (_, sha, k, rows) = PINS
        .iter()
        .find(|p| p.0 == name)
        .unwrap_or_else(|| panic!("no pin for {name}"));
    (sha, *k, *rows)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Load a baseline circuit, refusing any file whose SHA-256 is not the pinned one.
pub fn load(name: &str) -> IrSource {
    let dir = std::env::var("COMPACTC_BASELINE_DIR")
        .expect("COMPACTC_BASELINE_DIR must point at compactc's managed/account/zkir directory");
    let path = format!("{dir}/{name}.zkir");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let got = hex(&Sha256::digest(&bytes));
    let (want, _, _) = pin(name);
    assert_eq!(
        got, want,
        "{path}: baseline SHA-256 is not the pinned compactc 0.34.0 artifact of account.compact 44cff904…"
    );
    minocrab_zkir::v3::parse_zkir(&bytes[..], &path).expect("baseline parses")
}
