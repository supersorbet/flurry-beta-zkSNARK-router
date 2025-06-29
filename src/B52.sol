// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "solady/src/tokens/ERC20.sol";

/// @title B52 Token
/// @notice ERC20 token for the B52 privacy system
contract B52Token is ERC20 {
    constructor() {
        _mint(msg.sender, 100_000_000 * 10**18);
    }

    /// @notice Returns the name of the token
    function name() public pure override returns (string memory) {
        return "B-52-Z Token";
    }

    /// @notice Returns the symbol of the token
    function symbol() public pure override returns (string memory) {
        return "B52Z";
    }

    /// @notice Returns the number of decimals the token uses
    function decimals() public pure override returns (uint8) {
        return 18;
    }
}