// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {TestTBill} from "../src/TestTBill.sol";

/// Mints more of one "Test T-Bill" series token (TB13W, TB26W or TB52W):
/// `mint(MINT_TO, MINT_AMOUNT)` on `TOKEN`, signed by the token's owner.
///
/// Everything comes from the process environment, the key included (`SK`, sourced inside
/// the container from the owner's `.sepolia` file), so the key never reaches a command line.
/// (`cast send … --private-key` would put it on one: cast has no environment variable for a raw key.)
///
///   TOKEN=0x… MINT_TO=0x… MINT_AMOUNT=1000000000 \
///     forge script script/MintTestTBill.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
///
/// MINT_AMOUNT is in base units (10^6 per token). MINT_TO defaults to the signer.
contract MintTestTBill is Script {
    function run() external {
        require(block.chainid == 11155111, "MintTestTBill: Sepolia only");
        uint256 pk = vm.envUint("SK");
        _mintAs(pk, TestTBill(vm.envAddress("TOKEN")), vm.envOr("MINT_TO", vm.addr(pk)), vm.envUint("MINT_AMOUNT"));
    }

    function _mintAs(uint256 pk, TestTBill t, address to, uint256 amount) internal {
        require(t.owner() == vm.addr(pk), "MintTestTBill: the key is not the token's owner");
        require(amount > 0, "MintTestTBill: zero amount");
        uint256 before = t.balanceOf(to);

        vm.startBroadcast(pk);
        t.mint(to, amount);
        vm.stopBroadcast();

        require(t.balanceOf(to) == before + amount, "MintTestTBill: balance did not move");
        console2.log("minted", amount, t.symbol(), to);
    }
}
