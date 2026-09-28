//! The gate's machinery: the pinned compactc baseline, the off-circuit model of the account, and
//! the differential probe. Not a test target; `tests/gate.rs` declares `mod support;`.
#![allow(dead_code)]

pub mod baseline;
pub mod model;
pub mod prims;
pub mod probe;
