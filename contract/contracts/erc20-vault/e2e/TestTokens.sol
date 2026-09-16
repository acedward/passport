// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// The ERC20 the F4 end-to-end run bridges. Deliberately minimal and openly mintable: the
/// vault only ever asks the MPC to sign `transfer(address,uint256)` and settles on the
/// attested `bool`, so nothing else of the standard is exercised. Real balance accounting
/// IS kept, because the strongest assertion the run makes is that the vault's own EVM
/// account gains exactly the deposited amount and loses exactly the withdrawn one.
contract TestUsd {
    string public constant name = "Test USD";
    string public constant symbol = "TUSD";
    uint8 public constant decimals = 6;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /// Unrestricted on purpose: the harness deals balances to MPC-derived addresses whose
    /// keys nobody holds, on a throwaway chain.
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}

/// A token whose `transfer` EXECUTES and returns `false` without moving anything — the
/// legacy-ERC20 failure mode the vault's settle circuits route on. The MPC attests the
/// `false`, `completeDeposit` closes the request with no mint, and `completeWithdraw`
/// re-mints to the pinned refund recipient. Without a token like this that branch can only
/// ever be tested in the simulator.
contract FalseReturnToken {
    string public constant name = "Always False";
    string public constant symbol = "NOPE";
    uint8 public constant decimals = 6;

    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}
