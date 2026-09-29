// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TestTBill} from "../src/TestTBill.sol";
import {DeployTestTBills} from "../script/DeployTestTBills.s.sol";
import {MintTestTBill} from "../script/MintTestTBill.s.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// The scripts' internals, exposed with the key as an argument. The tests never call
/// `vm.setEnv`: forge runs tests in parallel and the process environment is shared (TBILL's
/// own script tests set `SK` and `TBILL`), so env-driven script tests could race.
contract DeployTestTBillsHarness is DeployTestTBills {
    function runWithKey(uint256 pk) external returns (TestTBill[3] memory) {
        return _run(pk);
    }

    function deployAndCheck(address deployer) external returns (TestTBill[3] memory tokens) {
        tokens = _deploy(deployer);
        _check(tokens, deployer);
    }
}

contract MintTestTBillHarness is MintTestTBill {
    function mintAs(uint256 pk, TestTBill t, address to, uint256 amount) external {
        _mintAs(pk, t, to, amount);
    }
}

/// Every token test, run once per series token (TB13W, TB26W, TB52W): the concrete contracts
/// below only choose the constructor's name and symbol.
abstract contract TestTBillCases is Test {
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

    TestTBill internal t;

    function _name() internal pure virtual returns (string memory);
    function _symbol() internal pure virtual returns (string memory);

    function setUp() public {
        (holder, holderPk) = makeAddrAndKey("holder");
        t = new TestTBill(_name(), _symbol(), owner, holder, SUPPLY);
    }

    // ---- metadata and supply -------------------------------------------------------------

    function test_metadata() public view {
        assertEq(t.name(), _name());
        assertEq(t.symbol(), _symbol());
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
        new TestTBill(_name(), _symbol(), owner, holder, SUPPLY);
    }

    function test_constructorGuards() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        new TestTBill(_name(), _symbol(), address(0), holder, SUPPLY);
        vm.expectRevert(abi.encodeWithSelector(IERC20Errors.ERC20InvalidReceiver.selector, address(0)));
        new TestTBill(_name(), _symbol(), owner, address(0), SUPPLY);
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

    // ---- permit (EIP-2612), with the token's own EIP-712 domain ----------------------------------

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
                keccak256(bytes(_name())),
                keccak256("1"),
                block.chainid,
                address(t)
            )
        );
        assertEq(t.DOMAIN_SEPARATOR(), expected);
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = t.eip712Domain();
        assertEq(name, _name());
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

    // ---- the mint script on this token (a throwaway owner key, passed directly, not via the env) --

    function test_mintScriptMintsAsOwner() public {
        (address tmpOwner, uint256 tmpPk) = makeAddrAndKey("script-owner");
        TestTBill token = new TestTBill(_name(), _symbol(), tmpOwner, holder, SUPPLY);
        new MintTestTBillHarness().mintAs(tmpPk, token, alice, 5e6);
        assertEq(token.balanceOf(alice), 5e6);
        assertEq(token.totalSupply(), SUPPLY + 5e6);
    }
}

contract TB13WTest is TestTBillCases {
    function _name() internal pure override returns (string memory) {
        return "Test T-Bill 13-week";
    }

    function _symbol() internal pure override returns (string memory) {
        return "TB13W";
    }
}

contract TB26WTest is TestTBillCases {
    function _name() internal pure override returns (string memory) {
        return "Test T-Bill 26-week";
    }

    function _symbol() internal pure override returns (string memory) {
        return "TB26W";
    }
}

contract TB52WTest is TestTBillCases {
    function _name() internal pure override returns (string memory) {
        return "Test T-Bill 52-week";
    }

    function _symbol() internal pure override returns (string memory) {
        return "TB52W";
    }
}

/// Series-level checks: the tokens are independent, the deploy script deploys exactly the
/// spec's table, and the scripts refuse the wrong chain or key.
contract TestTBillSeriesTest is Test {
    uint256 internal constant SUPPLY = 1_000_000 * 10 ** 6;
    bytes32 internal constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    function test_seriesMatchesTheSpec() public {
        DeployTestTBills script = new DeployTestTBills();
        DeployTestTBills.Series[3] memory s = script.series();
        assertEq(s[0].name, "Test T-Bill 13-week");
        assertEq(s[0].symbol, "TB13W");
        assertEq(s[1].name, "Test T-Bill 26-week");
        assertEq(s[1].symbol, "TB26W");
        assertEq(s[2].name, "Test T-Bill 52-week");
        assertEq(s[2].symbol, "TB52W");
        for (uint256 i = 0; i < 3; i++) {
            // MIP-0018 metadata fields are at most 32 bytes.
            assertLe(bytes(s[i].name).length, 32);
            assertLe(bytes(s[i].symbol).length, 32);
        }
    }

    function test_eachTokenHasItsOwnPermitDomain() public {
        (address holder, uint256 holderPk) = makeAddrAndKey("holder");
        DeployTestTBills.Series[3] memory s = new DeployTestTBills().series();
        TestTBill[3] memory tok;
        for (uint256 i = 0; i < 3; i++) {
            tok[i] = new TestTBill(s[i].name, s[i].symbol, owner, holder, SUPPLY);
        }
        assertTrue(tok[0].DOMAIN_SEPARATOR() != tok[1].DOMAIN_SEPARATOR());
        assertTrue(tok[1].DOMAIN_SEPARATOR() != tok[2].DOMAIN_SEPARATOR());
        assertTrue(tok[0].DOMAIN_SEPARATOR() != tok[2].DOMAIN_SEPARATOR());

        // A permit signed for TB13W's domain is useless on TB26W (same holder, same nonce 0).
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, holder, alice, 1e6, 0, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", tok[0].DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(holderPk, digest);
        vm.expectRevert();
        tok[1].permit(holder, alice, 1e6, deadline, v, r, sg);
        tok[0].permit(holder, alice, 1e6, deadline, v, r, sg);
        assertEq(tok[0].allowance(holder, alice), 1e6);
        assertEq(tok[1].allowance(holder, alice), 0);
    }

    function testFuzz_anyNameAndSymbol(string memory name, string memory symbol) public {
        TestTBill t = new TestTBill(name, symbol, owner, alice, SUPPLY);
        assertEq(t.name(), name);
        assertEq(t.symbol(), symbol);
        assertEq(t.decimals(), 6);
        (, string memory domainName,,,,,) = t.eip712Domain();
        assertEq(domainName, name);
        assertEq(t.balanceOf(alice), SUPPLY);
    }

    // ---- the deploy script (no secret: a throwaway key, or no key at all) ----------------------------

    function test_deployScriptDeploysTheSeries() public {
        address deployer = 0x484738A67858305Edfc139B194Ed430Fe4D8e56b;
        DeployTestTBillsHarness h = new DeployTestTBillsHarness();
        TestTBill[3] memory tok = h.deployAndCheck(deployer);
        DeployTestTBills.Series[3] memory s = h.series();
        for (uint256 i = 0; i < 3; i++) {
            assertEq(tok[i].name(), s[i].name);
            assertEq(tok[i].symbol(), s[i].symbol);
            assertEq(tok[i].decimals(), 6);
            assertEq(tok[i].totalSupply(), SUPPLY);
            assertEq(tok[i].balanceOf(deployer), SUPPLY);
            assertEq(tok[i].owner(), deployer);
        }
    }

    function test_deployScriptRefusesOtherChains() public {
        DeployTestTBills script = new DeployTestTBills();
        vm.chainId(1);
        vm.expectRevert(bytes("DeployTestTBills: Sepolia only"));
        script.run();
    }

    function test_deployScriptRefusesOtherDeployers() public {
        DeployTestTBillsHarness h = new DeployTestTBillsHarness();
        (, uint256 throwaway) = makeAddrAndKey("not-the-owner");
        vm.expectRevert(bytes("DeployTestTBills: unexpected deployer"));
        h.runWithKey(throwaway);
    }

    // ---- the mint script's guards ---------------------------------------------------------------

    function test_mintScriptRefusesNonOwnerZeroAndOtherChains() public {
        TestTBill t = new TestTBill("Test T-Bill 13-week", "TB13W", owner, alice, SUPPLY);
        (, uint256 notOwnerPk) = makeAddrAndKey("not-the-owner");
        MintTestTBillHarness h = new MintTestTBillHarness();
        vm.expectRevert(bytes("MintTestTBill: the key is not the token's owner"));
        h.mintAs(notOwnerPk, t, alice, 1);

        (address o2, uint256 o2Pk) = makeAddrAndKey("owner-2");
        TestTBill t2 = new TestTBill("Test T-Bill 13-week", "TB13W", o2, alice, SUPPLY);
        vm.expectRevert(bytes("MintTestTBill: zero amount"));
        h.mintAs(o2Pk, t2, alice, 0);

        MintTestTBill script = new MintTestTBill();
        vm.chainId(1);
        vm.expectRevert(bytes("MintTestTBill: Sepolia only"));
        script.run();
    }
}
