// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title TestTBill — the "Test T-Bill" series, full ERC20s on Sepolia (AA project 00045).
/// @notice Testnet assets with no value. The same token as `TBill` (AA 00043), with the name
///         and symbol given to the constructor, so one source serves the whole series:
///         - TB13W "Test T-Bill 13-week";
///         - TB26W "Test T-Bill 26-week";
///         - TB52W "Test T-Bill 52-week".
///         6 decimals (like USDC, TBILL and the stk tokens). A complete standard token:
///         - ERC-20 (`transfer`, `approve`, `transferFrom`, `allowance`);
///         - EIP-2612 `permit` (gasless approvals; EIP-712 domain name = the token's name,
///           version "1", so every token of the series has its own domain);
///         - `burn` / `burnFrom`;
///         - `Ownable`, with an owner-only `mint(to, amount)` so the owner can add supply for
///           demos without redeploying.
///         The initial supply is minted to `holder` in the constructor. There is no pause
///         function: a paused token would strand in-flight bridge deposits and withdrawals.
/// @dev `TBill.sol` stays as deployed (TBILL's verified source); this contract is its
///      parameterised twin. Each token is bridged to Midnight stagenet by the witness-free Sig
///      Network ERC20 vault, which only calls `transfer`. The bridged colour is listed under
///      the token's own symbol (no "w" prefix, owner 2026-09-28), with on-chain MIP-0018
///      metadata name = `name()`, symbol = `symbol()`, decimals 6.
contract TestTBill is ERC20, ERC20Burnable, ERC20Permit, Ownable {
    /// @param name_ ERC-20 name, also the EIP-712 domain name (e.g. "Test T-Bill 13-week").
    /// @param symbol_ ERC-20 symbol (e.g. "TB13W").
    /// @param initialOwner The only account that may `mint`; transferable with `transferOwnership`.
    /// @param holder Receives `initialSupply`.
    /// @param initialSupply Base units (10^6 per token).
    constructor(string memory name_, string memory symbol_, address initialOwner, address holder, uint256 initialSupply)
        ERC20(name_, symbol_)
        ERC20Permit(name_)
        Ownable(initialOwner)
    {
        _mint(holder, initialSupply);
    }

    /// @notice Creates `amount` base units and assigns them to `to`. Owner only.
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @inheritdoc ERC20
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}
