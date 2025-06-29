// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {ReentrancyGuard} from "solady/src/utils/ReentrancyGuard.sol";
import {B52zFactory} from "./B52zFactory.sol";
import {IB52zInstance} from "./interfaces/IB52zInstance.sol";

/// @title B52z Router
/// @notice Routes transactions to appropriate blender instances
contract B52zRouter is ReentrancyGuard {
    /// @notice Error thrown when an instance is not found for a denomination
    /// @param denomination The requested denomination
    error InstanceNotFound(uint256 denomination);
    
    /// @notice Error thrown when a token transfer fails
    error TransferFailed();

    /// @notice The factory contract
    B52zFactory public immutable factory;

    /// @param _factory The factory contract address
    constructor(address _factory) {
        factory = B52zFactory(_factory);
    }

    /// @notice Make a deposit into the blender
    /// @param denomination The denomination amount
    /// @param commitment The commitment hash
    function deposit(uint256 denomination, bytes32 commitment)
        external
        nonReentrant
    {
        address instance = factory.instances(factory.b52Token(), denomination);
        if (instance == address(0)) revert InstanceNotFound(denomination);

        SafeTransferLib.safeTransferFrom(
            factory.b52Token(),
            msg.sender,
            instance,
            denomination
        );
        IB52zInstance(instance).deposit(commitment);
    }

    /// @notice Withdraw from the blender
    /// @param denomination The denomination amount
    /// @param _pA First part of the proof
    /// @param _pB Second part of the proof
    /// @param _pC Third part of the proof
    /// @param _pubSignals Public inputs to the proof
    /// @param recipient The recipient address
    /// @param relayer The relayer address (optional)
    /// @param fee The relayer fee (optional)
    function withdraw(
        uint256 denomination,
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals,
        address recipient,
        address relayer,
        uint256 fee
    ) external nonReentrant {
        address instance = factory.instances(factory.b52Token(), denomination);
        if (instance == address(0)) revert InstanceNotFound(denomination);
        IB52zInstance(instance).withdraw(
            _pA,
            _pB,
            _pC,
            _pubSignals,
            recipient,
            relayer,
            fee
        );
    }
}
