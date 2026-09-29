// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {TBill} from "../src/TBill.sol";

/// Deploys TBILL ("T-Bill", 6 decimals) with owner = holder = the deployer, and mints
/// 1,000,000 TBILL to it.
///
/// The key is read from the process environment ONLY (`SK`, the owner's `.sepolia` file
/// sourced inside the container that runs this script) — never from the command line.
/// The script refuses anything but Sepolia and anything but the expected deployer, and
/// checks the deployed token before it returns.
///
///   forge script script/DeployTBill.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --slow
contract DeployTBill is Script {
    uint256 internal constant INITIAL_SUPPLY = 1_000_000 * 10 ** 6;
    address internal constant EXPECTED_DEPLOYER = 0x484738A67858305Edfc139B194Ed430Fe4D8e56b;

    function run() external returns (TBill t) {
        require(block.chainid == 11155111, "DeployTBill: Sepolia only");
        uint256 pk = vm.envUint("SK");
        address deployer = vm.addr(pk);
        require(deployer == EXPECTED_DEPLOYER, "DeployTBill: unexpected deployer");

        vm.startBroadcast(pk);
        t = new TBill(deployer, deployer, INITIAL_SUPPLY);
        vm.stopBroadcast();

        require(keccak256(bytes(t.name())) == keccak256("T-Bill"), "DeployTBill: name");
        require(keccak256(bytes(t.symbol())) == keccak256("TBILL"), "DeployTBill: symbol");
        require(t.decimals() == 6, "DeployTBill: decimals");
        require(t.totalSupply() == INITIAL_SUPPLY, "DeployTBill: supply");
        require(t.balanceOf(deployer) == INITIAL_SUPPLY, "DeployTBill: holder");
        require(t.owner() == deployer, "DeployTBill: owner");
        console2.log("TBILL", address(t));
    }
}
