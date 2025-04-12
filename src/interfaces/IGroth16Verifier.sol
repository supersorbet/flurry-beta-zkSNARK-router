// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title Groth16 Verifier Interface
/// @notice Interface for verifying zk-SNARK proofs
interface IGroth16Verifier {
    /// @notice Verify a zk-SNARK proof
    /// @param _pA First part of the proof (G1 point)
    /// @param _pB Second part of the proof (G2 point)
    /// @param _pC Third part of the proof (G1 point)
    /// @param _pubSignals Public inputs to the proof
    /// @return Whether the proof is valid
    function verifyProof(
        uint256[2] memory _pA,
        uint256[2][2] memory _pB,
        uint256[2] memory _pC,
        uint256[4] memory _pubSignals
    ) external view returns (bool);
} 