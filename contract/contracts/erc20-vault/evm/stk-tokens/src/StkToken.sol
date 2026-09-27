// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title StkToken — the Sepolia test ERC20s stkA / stkB / stkC (AA project 00037).
/// @notice Testnet asset with no value. `name` equals `symbol`, 6 decimals, and the whole
///         supply is minted ONCE, to `holder`, in the constructor. There is no mint, burn,
///         owner or pause function: the supply is fixed forever.
/// @dev Bridged to Midnight stagenet by the witness-free Sig Network ERC20 vault; the
///      bridged colours are listed as wStkA / wStkB / wStkC.
contract StkToken is ERC20 {
    /// @param symbol_ Both the name and the symbol, e.g. "stkA".
    /// @param holder Receives the entire fixed supply.
    /// @param supply Base units (10^6 per token).
    constructor(string memory symbol_, address holder, uint256 supply) ERC20(symbol_, symbol_) {
        require(holder != address(0), "StkToken: zero holder");
        require(supply > 0, "StkToken: zero supply");
        _mint(holder, supply);
    }

    /// @inheritdoc ERC20
    function decimals() public pure override returns (uint8) {
        return 6;
    }
}
