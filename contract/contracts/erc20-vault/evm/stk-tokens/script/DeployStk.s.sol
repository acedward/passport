// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {StkToken} from "../src/StkToken.sol";

/// Deploys stkA, stkB and stkC (6 decimals, 1,000,000 each, all to the deployer).
///
/// The key is read from the process environment ONLY (`SK`, the owner's `.sepolia` file
/// sourced inside the container that runs this script) — never from the command line.
/// The script refuses anything but Sepolia and anything but the expected deployer.
///
///   forge script script/DeployStk.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
contract DeployStk is Script {
    uint256 internal constant SUPPLY = 1_000_000 * 10 ** 6;
    address internal constant EXPECTED_DEPLOYER = 0x484738A67858305Edfc139B194Ed430Fe4D8e56b;

    function run() external {
        require(block.chainid == 11155111, "DeployStk: Sepolia only");
        uint256 pk = vm.envUint("SK");
        address deployer = vm.addr(pk);
        require(deployer == EXPECTED_DEPLOYER, "DeployStk: unexpected deployer");

        string[3] memory syms = ["stkA", "stkB", "stkC"];
        vm.startBroadcast(pk);
        for (uint256 i = 0; i < 3; i++) {
            StkToken t = new StkToken(syms[i], deployer, SUPPLY);
            console2.log(syms[i], address(t));
        }
        vm.stopBroadcast();
    }
}
