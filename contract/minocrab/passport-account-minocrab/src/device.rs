//! The enc-key and device-lifecycle custody chips of `account.compact` (MIP-0012 §6.7, MIP-0013 §6),
//! ported for the `_with_evm` exports of lane L-DEV (AA 00040 P4): `rotate_enc_key_with_evm`,
//! `add_device_with_evm` and `remove_device_with_evm`. The exports themselves live in
//! [`crate::account`]; this module holds their bodies after the seam.
//!
//! ```text
//! circuit do_rotate_enc_key(new_key: Bytes<32>): [] {
//!   enc_key = disclose(new_key);
//! }
//!
//! circuit do_add_device(new_entry: Bytes<32>): [] {
//!   const e = disclose(new_entry);
//!   assert(!devices.member(e), "device entry already present");
//!   devices.insert(e);
//!   device_count = ((device_count + (1 as Uint<8>)) as Uint<8>);
//! }
//!
//! circuit do_remove_device(entry: Bytes<32>, caller_entry: Bytes<32>): [] {
//!   const e = disclose(entry);
//!   assert(device_count > (1 as Uint<8>), "cannot remove last device");
//!   assert(e != disclose(caller_entry), "cannot remove the authorising device");
//!   assert(devices.member(e), "unknown device entry");
//!   devices.remove(e);
//!   device_count = ((device_count - (1 as Uint<8>)) as Uint<8>);
//! }
//! ```
//!
//! LEDGER-OP ORDER IS THE CONTRACT (see [`crate::seam`]): `device_count` is read twice in each of
//! the device chips, once for the check and once for the update, because compactc's artifact reads
//! it twice (the vm-code of the compiled `contract/index.js`), and each read is a `popeq` in the
//! public transcript.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_std::v3::{greater_than, is_true, label, Uint, B32};

use crate::account::ACCOUNT;

label! {
    pub NewEncKey = "new enc key";
    pub NewDeviceEntry = "new device entry";
    pub RemovedDeviceEntry = "removed device entry";
}

/// `do_rotate_enc_key(new_key)` — one cell write (`push 1; pushs new_key; ins 1`).
pub fn do_rotate_enc_key(c: &mut Circuit3, new_key: &B32<Public>) {
    c.region("device: rotate enc key", |c| {
        ACCOUNT.enc_key.write(c, new_key);
    })
}

/// `do_add_device(new_entry)`, `new_entry` already disclosed.
pub fn do_add_device(c: &mut Circuit3, entry: &B32<Public>) {
    c.region("device: add", |c| {
        // assert(!devices.member(e), "device entry already present");
        let present = ACCOUNT.devices.member(c, entry);
        let absent = c.not(present.field());
        c.assert_with(absent, Some("device entry already present"));

        // devices.insert(e);
        ACCOUNT.devices.insert(c, entry);

        // device_count = ((device_count + 1) as Uint<8>);  — the add, then the cast's range check
        // (a count at 255 makes the proof unsatisfiable, as in compactc).
        let count = ACCOUNT.device_count.read(c).stale(c);
        let one = c.constant(1u64);
        let sum = c.add(count.field(), one);
        let next = Uint::<8, Public>::from_field_checked(c, sum);
        ACCOUNT.device_count.write(c, &next);
    })
}

/// `do_remove_device(entry, caller_entry)`, `entry` already disclosed. `caller_entry` is the
/// authorising device's post-roll entry, recomputed by the caller from fresh `kernel.self()` and
/// `device_epoch` reads exactly as the Compact export does.
pub fn do_remove_device(c: &mut Circuit3, entry: &B32<Public>, caller_entry: &B32<Private>) {
    c.region("device: remove", |c| {
        // assert(device_count > (1 as Uint<8>), "cannot remove last device");
        let count = *ACCOUNT.device_count.read(c);
        c.assert(greater_than(count, 1u64).message("cannot remove last device"));

        // assert(e != disclose(caller_entry), "cannot remove the authorising device");
        let e = entry.private();
        let same_hi = c.test_eq(e.hi, caller_entry.hi);
        let same_lo = c.test_eq(e.lo, caller_entry.lo);
        let same = c.mul(same_hi, same_lo);
        let differ = c.not(same);
        c.assert_with(differ, Some("cannot remove the authorising device"));

        // assert(devices.member(e), "unknown device entry"); devices.remove(e);
        let known = ACCOUNT.devices.member(c, entry);
        c.assert(is_true(*known).message("unknown device entry"));
        ACCOUNT.devices.remove(c, entry);

        // device_count = ((device_count - (1 as Uint<8>)) as Uint<8>);  — Compact's checked
        // subtraction (the underflow guard), on a second read.
        let count2 = ACCOUNT.device_count.read(c).stale(c);
        let one = Uint::<8, Public>::constant(c, 1);
        let next = count2.sub(c, one);
        ACCOUNT.device_count.write(c, &next);
    })
}
