// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TBill} from "../src/TBill.sol";
import {DeployTBill} from "../script/DeployTBill.s.sol";
import {MintTBill} from "../script/MintTBill.s.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TBillTest is Test {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    uint256 internal constant SUPPLY = 1_000_000 * 10 ** 6;
    bytes32 internal constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    address internal owner = makeAddr("owner");
    address internal holder;
    uint256 internal holderPk;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    TBill internal t;

    function setUp() public {
        (holder, holderPk) = makeAddrAndKey("holder");
        t = new TBill(owner, holder, SUPPLY);
    }

    // ---- metadata and supply -------------------------------------------------------------

    function test_metadata() public view {
        assertEq(t.name(), "T-Bill");
        assertEq(t.symbol(), "TBILL");
        assertEq(t.decimals(), 6);
    }

    function test_initialSupplyToHolder_ownerSet() public view {
        assertEq(t.totalSupply(), 1e12);
        assertEq(t.balanceOf(holder), 1e12);
        assertEq(t.balanceOf(owner), 0);
        assertEq(t.owner(), owner);
    }

    function test_constructorEmitsMintAndOwnership() public {
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(address(0), owner);
        vm.expectEmit(true, true, false, true);
        emit Transfer(address(0), holder, SUPPLY);
        new TBill(owner, holder, SUPPLY);
    }

    function test_constructorGuards() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new TBill(address(0), holder, SUPPLY);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        new TBill(owner, address(0), SUPPLY);
    }

    // ---- transfer, approve, transferFrom, allowance --------------------------------------------

    function test_transfer() public {
        vm.expectEmit(true, true, false, true, address(t));
        emit Transfer(holder, alice, 100e6);
        vm.prank(holder);
        assertTrue(t.transfer(alice, 100e6));
        assertEq(t.balanceOf(alice), 100e6);
        assertEq(t.balanceOf(holder), 1e12 - 100e6);
        assertEq(t.totalSupply(), 1e12);
    }

    function test_transferReverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 0, 1));
        t.transfer(bob, 1);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        t.transfer(address(0), 1);
    }

    function testFuzz_transferConservesSupply(uint256 amount) public {
        amount = bound(amount, 0, SUPPLY);
        vm.prank(holder);
        t.transfer(alice, amount);
        assertEq(t.balanceOf(alice) + t.balanceOf(holder), SUPPLY);
        assertEq(t.totalSupply(), SUPPLY);
    }

    function test_approveAndTransferFrom() public {
        vm.expectEmit(true, true, false, true, address(t));
        emit Approval(holder, alice, 50e6);
        vm.prank(holder);
        assertTrue(t.approve(alice, 50e6));
        assertEq(t.allowance(holder, alice), 50e6);

        vm.expectEmit(true, true, false, true, address(t));
        emit Transfer(holder, bob, 20e6);
        vm.prank(alice);
        assertTrue(t.transferFrom(holder, bob, 20e6));
        assertEq(t.balanceOf(bob), 20e6);
        assertEq(t.allowance(holder, alice), 30e6);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, alice, 30e6, 31e6));
        t.transferFrom(holder, bob, 31e6);
    }

    function test_infiniteAllowanceIsNotSpent() public {
        vm.prank(holder);
        t.approve(alice, type(uint256).max);
        vm.prank(alice);
        t.transferFrom(holder, bob, 7e6);
        assertEq(t.allowance(holder, alice), type(uint256).max);
    }

    // ---- permit (EIP-2612) -----------------------------------------------------------------------

    function _permitDigest(address o, address spender, uint256 value, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, o, spender, value, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", t.DOMAIN_SEPARATOR(), structHash));
    }

    function test_domainSeparator() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("T-Bill"),
                keccak256("1"),
                block.chainid,
                address(t)
            )
        );
        assertEq(t.DOMAIN_SEPARATOR(), expected);
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = t.eip712Domain();
        assertEq(name, "T-Bill");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifying, address(t));
    }

    function test_permit() public {
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(holderPk, _permitDigest(holder, alice, 25e6, 0, deadline));

        vm.expectEmit(true, true, false, true, address(t));
        emit Approval(holder, alice, 25e6);
        vm.prank(bob); // anyone may submit the signed permit
        t.permit(holder, alice, 25e6, deadline, v, r, s);
        assertEq(t.allowance(holder, alice), 25e6);
        assertEq(t.nonces(holder), 1);

        vm.prank(alice);
        t.transferFrom(holder, alice, 25e6);
        assertEq(t.balanceOf(alice), 25e6);
        assertEq(t.allowance(holder, alice), 0);

        // The same signature cannot be replayed: the nonce moved on.
        vm.expectRevert();
        t.permit(holder, alice, 25e6, deadline, v, r, s);
    }

    function test_permitRejectsExpiredAndWrongSigner() public {
        uint256 deadline = block.timestamp + 10;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(holderPk, _permitDigest(holder, alice, 1e6, 0, deadline));
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, deadline));
        t.permit(holder, alice, 1e6, deadline, v, r, s);

        (address mallory, uint256 malloryPk) = makeAddrAndKey("mallory");
        uint256 d2 = block.timestamp + 1 hours;
        (v, r, s) = vm.sign(malloryPk, _permitDigest(holder, alice, 1e6, 0, d2));
        vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612InvalidSigner.selector, mallory, holder));
        t.permit(holder, alice, 1e6, d2, v, r, s);
        assertEq(t.allowance(holder, alice), 0);
        assertEq(t.nonces(holder), 0);
    }

    function testFuzz_permit(uint256 value, uint256 ttl) public {
        ttl = bound(ttl, 0, 365 days);
        uint256 deadline = block.timestamp + ttl;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(holderPk, _permitDigest(holder, bob, value, 0, deadline));
        t.permit(holder, bob, value, deadline, v, r, s);
        assertEq(t.allowance(holder, bob), value);
    }

    // ---- burn / burnFrom -------------------------------------------------------------------------

    function test_burn() public {
        vm.expectEmit(true, true, false, true, address(t));
        emit Transfer(holder, address(0), 10e6);
        vm.prank(holder);
        t.burn(10e6);
        assertEq(t.balanceOf(holder), 1e12 - 10e6);
        assertEq(t.totalSupply(), 1e12 - 10e6);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 0, 1));
        t.burn(1);
    }

    function test_burnFrom() public {
        vm.prank(holder);
        t.approve(alice, 5e6);
        vm.prank(alice);
        t.burnFrom(holder, 3e6);
        assertEq(t.allowance(holder, alice), 2e6);
        assertEq(t.totalSupply(), 1e12 - 3e6);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, alice, 2e6, 3e6));
        t.burnFrom(holder, 3e6);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, bob, 0, 1));
        t.burnFrom(holder, 1);
    }

    // ---- mint (owner only) -----------------------------------------------------------------------

    function test_ownerMints() public {
        vm.expectEmit(true, true, false, true, address(t));
        emit Transfer(address(0), alice, 500e6);
        vm.prank(owner);
        t.mint(alice, 500e6);
        assertEq(t.balanceOf(alice), 500e6);
        assertEq(t.totalSupply(), 1e12 + 500e6);
    }

    function test_nonOwnerCannotMint() public {
        for (uint256 i = 0; i < 3; i++) {
            address who = [holder, alice, address(this)][i];
            vm.prank(who);
            vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, who));
            t.mint(who, 1);
        }
        assertEq(t.totalSupply(), 1e12);
    }

    function test_mintToZeroReverts() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        t.mint(address(0), 1);
    }

    function testFuzz_nonOwnerCannotMint(address who, uint256 amount) public {
        vm.assume(who != owner);
        vm.prank(who);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, who));
        t.mint(alice, amount);
    }

    // ---- ownership ------------------------------------------------------------------------------

    function test_transferOwnership() public {
        vm.expectEmit(true, true, false, false, address(t));
        emit OwnershipTransferred(owner, alice);
        vm.prank(owner);
        t.transferOwnership(alice);
        assertEq(t.owner(), alice);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        t.mint(owner, 1);

        vm.prank(alice);
        t.mint(bob, 1e6);
        assertEq(t.balanceOf(bob), 1e6);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, bob));
        t.transferOwnership(bob);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        t.transferOwnership(address(0));
    }

    function test_renounceOwnershipEndsMinting() public {
        vm.prank(owner);
        t.renounceOwnership();
        assertEq(t.owner(), address(0));
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        t.mint(owner, 1);
    }

    // ---- the deploy script's guards (no secret: a throwaway key) --------------------------------

    function test_deployScriptRefusesOtherChains() public {
        DeployTBill script = new DeployTBill();
        vm.chainId(1);
        vm.expectRevert(bytes("DeployTBill: Sepolia only"));
        script.run();
    }

    function test_deployScriptRefusesOtherDeployers() public {
        DeployTBill script = new DeployTBill();
        vm.chainId(11155111);
        (, uint256 throwaway) = makeAddrAndKey("not-the-owner");
        vm.setEnv("SK", vm.toString(bytes32(throwaway)));
        vm.expectRevert(bytes("DeployTBill: unexpected deployer"));
        script.run();
    }

    // ---- the mint script (owner key from the environment; a throwaway key here) -------------------

    function test_mintScriptMintsAsOwner() public {
        (address tmpOwner, uint256 tmpPk) = makeAddrAndKey("script-owner");
        TBill token = new TBill(tmpOwner, holder, SUPPLY);
        vm.chainId(11155111);
        vm.setEnv("SK", vm.toString(bytes32(tmpPk)));
        vm.setEnv("TBILL", vm.toString(address(token)));
        vm.setEnv("MINT_TO", vm.toString(alice));
        vm.setEnv("MINT_AMOUNT", "5000000");
        new MintTBill().run();
        assertEq(token.balanceOf(alice), 5e6);
        assertEq(token.totalSupply(), SUPPLY + 5e6);
    }

    function test_mintScriptRefusesNonOwnerAndOtherChains() public {
        (, uint256 notOwnerPk) = makeAddrAndKey("not-the-owner");
        vm.setEnv("SK", vm.toString(bytes32(notOwnerPk)));
        vm.setEnv("TBILL", vm.toString(address(t)));
        vm.setEnv("MINT_TO", vm.toString(alice));
        vm.setEnv("MINT_AMOUNT", "1");
        MintTBill script = new MintTBill();
        vm.chainId(11155111);
        vm.expectRevert(bytes("MintTBill: the key is not the token's owner"));
        script.run();
        vm.chainId(1);
        vm.expectRevert(bytes("MintTBill: Sepolia only"));
        script.run();
    }
}
