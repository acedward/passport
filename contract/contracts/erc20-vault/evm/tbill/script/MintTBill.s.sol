// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {TBill} from "../src/TBill.sol";

/// Mints more TBILL: `mint(MINT_TO, MINT_AMOUNT)` signed by the token's owner.
///
/// Everything comes from the process environment, the key included (`SK`, sourced inside
/// the container from the owner's `.sepolia` file), so the key never reaches a command line.
/// (`cast send … --private-key` would put it on one: cast has no environment variable for a raw key.)
///
///   TBILL=0x… MINT_TO=0x… MINT_AMOUNT=1000000000 \
///     forge script script/MintTBill.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
///
/// MINT_AMOUNT is in base units (10^6 per TBILL). MINT_TO defaults to the signer.
contract MintTBill is Script {
    function run() external {
        require(block.chainid == 11155111, "MintTBill: Sepolia only");
        uint256 pk = vm.envUint("SK");
        address signer = vm.addr(pk);
        TBill t = TBill(vm.envAddress("TBILL"));
        require(t.owner() == signer, "MintTBill: the key is not the token's owner");
        address to = vm.envOr("MINT_TO", signer);
        uint256 amount = vm.envUint("MINT_AMOUNT");
        require(amount > 0, "MintTBill: zero amount");
        uint256 before = t.balanceOf(to);

        vm.startBroadcast(pk);
        t.mint(to, amount);
        vm.stopBroadcast();

        require(t.balanceOf(to) == before + amount, "MintTBill: balance did not move");
        console2.log("minted", amount, "to", to);
    }
}
