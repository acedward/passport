// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {StkToken} from "../src/StkToken.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract StkTokenTest is Test {
    uint256 internal constant SUPPLY = 1_000_000 * 10 ** 6;
    address internal holder = makeAddr("holder");
    address internal alice = makeAddr("alice");

    function _deploy(string memory sym) internal returns (StkToken t) {
        t = new StkToken(sym, holder, SUPPLY);
    }

    function test_metadata() public {
        string[3] memory syms = ["stkA", "stkB", "stkC"];
        for (uint256 i = 0; i < 3; i++) {
            StkToken t = _deploy(syms[i]);
            assertEq(t.name(), syms[i]);
            assertEq(t.symbol(), syms[i]);
            assertEq(t.decimals(), 6);
        }
    }

    function test_supplyMintedOnceToHolder() public {
        StkToken t = _deploy("stkA");
        assertEq(t.totalSupply(), 1e12);
        assertEq(t.balanceOf(holder), 1e12);
        assertEq(t.balanceOf(address(this)), 0);
    }

    function test_transfer() public {
        StkToken t = _deploy("stkB");
        vm.prank(holder);
        assertTrue(t.transfer(alice, 100 * 10 ** 6));
        assertEq(t.balanceOf(alice), 100e6);
        assertEq(t.balanceOf(holder), 1e12 - 100e6);
        assertEq(t.totalSupply(), 1e12);
    }

    function test_transferMoreThanBalanceReverts() public {
        StkToken t = _deploy("stkC");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 0, 1));
        t.transfer(holder, 1);
    }

    function test_noMintSurface() public {
        StkToken t = _deploy("stkA");
        (bool ok,) = address(t).call(abi.encodeWithSignature("mint(address,uint256)", alice, 1));
        assertFalse(ok);
        assertEq(t.totalSupply(), 1e12);
    }

    function test_constructorGuards() public {
        vm.expectRevert(bytes("StkToken: zero holder"));
        new StkToken("stkA", address(0), SUPPLY);
        vm.expectRevert(bytes("StkToken: zero supply"));
        new StkToken("stkA", holder, 0);
    }
}
