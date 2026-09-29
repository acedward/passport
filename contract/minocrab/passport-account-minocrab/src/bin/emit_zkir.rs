//! Emit the ported circuits' ZKIR v3: `emit-zkir OUT_DIR` writes `OUT_DIR/<circuit>.zkir` for
//! every circuit in `passport_account_minocrab::ported()`, and prints each file's SHA-256.
//!
//! The files are what `zkir-v3 compile-many` keys (P2) and what the mixed key set replaces
//! compactc's `managed/account/zkir/<circuit>.zkir` with.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("usage: emit-zkir OUT_DIR"));
    std::fs::create_dir_all(&out).expect("create OUT_DIR");
    for (name, build) in passport_account_minocrab::ported() {
        let compiled = build();
        let text = minocrab_zkir::v3::to_zkir_string(&compiled.ir).expect("serialise zkir");
        let path = out.join(format!("{name}.zkir"));
        std::fs::write(&path, text.as_bytes()).expect("write zkir");
        let sha = Sha256::digest(text.as_bytes());
        let hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
        println!("{hex}  {name}.zkir");
    }
}
