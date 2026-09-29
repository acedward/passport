//! The gate's off-circuit model against the ethers-generated fixture vectors
//! (`contract/src/tests/fixtures/passport-evm-v1.json`), and the port's frozen EIP-712 constants
//! and build-time challenge DSTs against their recomputation. Needs no baseline, so it runs in the
//! plain `cargo test` (scripts/gate.sh test).

mod support;

use support::baseline::hex;
use support::model::*;
use support::prims::*;

// ── the off-circuit model reproduces the ethers fixture vectors ─────────────────────────────────

fn h32(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn kat_eip712() {
    // The fixture's public point hashes to its owner address: the gate's off-circuit
    // `secp256k1EthereumAddress` agrees with ethers.
    let point = point_from_be(
        &h32("4e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e"),
        &h32("47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de"),
    );
    let owner = eth_address(&point);
    assert_eq!(
        hex(&owner),
        "2c7536e3605d9c16a7a3d7b1898e529396a65c23",
        "fixture owner address"
    );
    let account = [0xaa; 32];
    let salt = [0xdd; 32];
    let dom = Domain::default();
    assert_eq!(hex(&alias(&account)), "8fb9007a8537c8dfdb6a3f8c2cfd64db19d2ec90");
    let sep = domain_separator(&dom, &account, &salt);
    assert_eq!(
        sep,
        h32("4b0a5945027e516dc1ebf1bb3ff970216c32e7af8a7c825c83e907421ca09922")
    );
    let sh = struct_hash(APPEND_INBOX_STR, &account, &owner, 7, &[[0xcc; 32]], &[0x11; 32]);
    assert_eq!(
        sh,
        h32("eb8e6357657444a1f368d8c321f99436b1a94a10866f8685f21da4ffca45aa28")
    );
    assert_eq!(
        eip712_digest(&sep, &sh),
        h32("c302215423f8ae4a91c91d0880097f38efe47356d6b9d014ca930932bd80dd04")
    );
    let sh = struct_hash(
        WITHDRAW_SHIELDED_STR,
        &account,
        &owner,
        7,
        &[[0xcc; 32], uint_word(4_000_000), [0xcc; 32]],
        &[0x11; 32],
    );
    assert_eq!(
        sh,
        h32("b2d23b2dfdf2b452b5f3951f6da5dcdbb25181a174dfd17f7e81d765b2613213")
    );
    assert_eq!(
        eip712_digest(&sep, &sh),
        h32("787141ede00429e3b60f7c7e6d8675dc414a163fe40cfa958d773cf064359213")
    );
    // The port's frozen constants are the keccaks of their type strings.
    use passport_account_minocrab::eip712 as e;
    assert_eq!(e::DOMAIN_TYPE, keccak(DOMAIN_TYPE_STR.as_bytes()));
    assert_eq!(e::DOMAIN_NAME, keccak(b"Midnight Passport Account"));
    assert_eq!(e::DOMAIN_VERSION, keccak(b"1"));
    assert_eq!(e::TYPE_APPEND_INBOX, keccak(APPEND_INBOX_STR.as_bytes()));
    assert_eq!(e::TYPE_WITHDRAW_SHIELDED, keccak(WITHDRAW_SHIELDED_STR.as_bytes()));
    for (c, s) in [
        (e::TYPE_WITHDRAW_UNSHIELDED, "WithdrawUnshielded(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipient,bytes32 challenge)"),
        (e::TYPE_WITHDRAW_SHIELDED_TO_CONTRACT, "WithdrawShieldedToContract(bytes32 account,address owner,uint64 authNonce,bytes32 color,uint128 amount,bytes32 recipientContract,bytes32 challenge)"),
        (e::TYPE_ROTATE_ENC_KEY, "RotateEncKey(bytes32 account,address owner,uint64 authNonce,bytes32 newKey,bytes32 challenge)"),
        (e::TYPE_ADD_DEVICE, "AddDevice(bytes32 account,address owner,uint64 authNonce,bytes32 newEntry,bytes32 challenge)"),
        (e::TYPE_REMOVE_DEVICE, "RemoveDevice(bytes32 account,address owner,uint64 authNonce,bytes32 entry,bytes32 challenge)"),
    ] {
        assert_eq!(c, keccak(s.as_bytes()), "{s}");
    }
    // The port's build-time challenge DST is the FAB-route persistentHash.
    for circuit in [
        "append_inbox",
        "withdraw_shielded",
        "rotate_enc_key",
        "add_device",
        "remove_device",
        "withdraw_unshielded",
        "withdraw_shielded_to_contract",
    ] {
        assert_eq!(
            passport_account_minocrab::seam::challenge_dst_bytes(circuit),
            challenge_dst(circuit),
            "{circuit}"
        );
    }
}
