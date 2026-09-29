// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {TestTBill} from "../src/TestTBill.sol";

/// Deploys the "Test T-Bill" series (AA project 00045): TB13W, TB26W and TB52W, each a
/// `TestTBill` with 6 decimals, owner = holder = the deployer, and 1,000,000 of each minted
/// to it. The three are created in this order, one transaction each.
///
/// The key is read from the process environment ONLY (`SK`, the owner's `.sepolia` file
/// sourced inside the container that runs this script) — never from the command line.
/// The script refuses anything but Sepolia and anything but the expected deployer, and
/// checks every deployed token before it returns.
///
///   forge script script/DeployTestTBills.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --slow
contract DeployTestTBills is Script {
    uint256 internal constant INITIAL_SUPPLY = 1_000_000 * 10 ** 6;
    address internal constant EXPECTED_DEPLOYER = 0x484738A67858305Edfc139B194Ed430Fe4D8e56b;

    struct Series {
        string name;
        string symbol;
    }

    /// The series, in deployment order. Name, symbol and decimals are immutable once deployed.
    function series() public pure returns (Series[3] memory s) {
        s[0] = Series({name: "Test T-Bill 13-week", symbol: "TB13W"});
        s[1] = Series({name: "Test T-Bill 26-week", symbol: "TB26W"});
        s[2] = Series({name: "Test T-Bill 52-week", symbol: "TB52W"});
    }

    function run() external returns (TestTBill[3] memory) {
        require(block.chainid == 11155111, "DeployTestTBills: Sepolia only");
        return _run(vm.envUint("SK"));
    }

    function _run(uint256 pk) internal returns (TestTBill[3] memory tokens) {
        address deployer = vm.addr(pk);
        require(deployer == EXPECTED_DEPLOYER, "DeployTestTBills: unexpected deployer");
        vm.startBroadcast(pk);
        tokens = _deploy(deployer);
        vm.stopBroadcast();
        _check(tokens, deployer);
    }

    function _deploy(address deployer) internal returns (TestTBill[3] memory tokens) {
        Series[3] memory s = series();
        for (uint256 i = 0; i < s.length; i++) {
            tokens[i] = new TestTBill(s[i].name, s[i].symbol, deployer, deployer, INITIAL_SUPPLY);
        }
    }

    function _check(TestTBill[3] memory tokens, address deployer) internal view {
        Series[3] memory s = series();
        for (uint256 i = 0; i < s.length; i++) {
            TestTBill t = tokens[i];
            require(keccak256(bytes(t.name())) == keccak256(bytes(s[i].name)), "DeployTestTBills: name");
            require(keccak256(bytes(t.symbol())) == keccak256(bytes(s[i].symbol)), "DeployTestTBills: symbol");
            require(t.decimals() == 6, "DeployTestTBills: decimals");
            require(t.totalSupply() == INITIAL_SUPPLY, "DeployTestTBills: supply");
            require(t.balanceOf(deployer) == INITIAL_SUPPLY, "DeployTestTBills: holder");
            require(t.owner() == deployer, "DeployTestTBills: owner");
            (, string memory domainName,,,,,) = t.eip712Domain();
            require(keccak256(bytes(domainName)) == keccak256(bytes(s[i].name)), "DeployTestTBills: EIP-712 name");
            console2.log(s[i].symbol, address(t));
        }
    }
}
