
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
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}

/// @title Groth16 Verifier
/// @notice Implementation of a zk-SNARK verifier using the Groth16 protocol
contract Groth16Verifier is IGroth16Verifier {
    /// @notice Custom errors
    error G1AdditionFailed();
    error G1ScalarMultiplicationFailed();
    error PairingCheckFailed();
    error InvalidNumberOfPublicInputs(uint256 provided, uint256 expected);
    error InputNotInScalarField(uint256 input);

    /// @notice Error selectors as hex constants
    /// @dev These are the first 4 bytes of the keccak256 hash of the signature
    uint256 private constant ERROR_G1_ADDITION_FAILED = 0x4e4339db;        
    uint256 private constant ERROR_G1_SCALAR_MUL_FAILED = 0x06d3835f;         
    uint256 private constant ERROR_PAIRING_CHECK_FAILED = 0x09008461;  
    /// @notice The scalar field size for BN254
    uint256 constant scalarField = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    /// @notice The base field size for BN254
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    /// @notice Verification key structure
    struct VerificationKey {
        uint256[2] alpha1;
        uint256[2][2] beta2;
        uint256[2][2] gamma2;
        uint256[2][2] delta2;
        uint256[2][] IC; // Dynamic array for IC elements
    }
    
    /// @notice Point in G1 (Elliptic curve point)
    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    
    /// @notice Point in G2 (Elliptic curve point in extension field)
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }
    
    /// @notice Returns the generator of G1
    /// @return G1 generator point
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }
    
    /// @notice Returns the generator of G2
    /// @return G2 generator point
    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }
    
    /// @notice Negates a G1 point
    /// @param p The point to negate
    /// @return The negated point
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.X, q - (p.Y % q));
    }
    
    /// @notice Returns the sum of two G1 points
    /// @param p1 First point
    /// @param p2 Second point
    /// @return result Sum of the points
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory result) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, result, 0x60)
            if iszero(success) {
                mstore(0, ERROR_G1_ADDITION_FAILED)
                revert(0, 4)
            }
        }
    }
    
    /// @notice Returns the product of a G1 point and a scalar
    /// @param p The point
    /// @param s The scalar
    /// @return result The scalar multiplication result
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory result) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, result, 0x60)
            if iszero(success) {
                mstore(0, ERROR_G1_SCALAR_MUL_FAILED)
                revert(0, 4)
            }
        }
    }

    /// @notice Returns the verification key
    /// @return vk The verification key
    function verificationKey() internal pure returns (VerificationKey memory vk) {
        vk.alpha1 = [
            0x1b9d9bcce2dca3fa14e4b20ff6250aecc0eea30eb1e43386ec83b3d4c28dbc10,
            0x10c7e38b637a9bc98e328a39eb25997e8cc20fb6657b5b3dcca1f7fbff4552f7
        ];
        vk.beta2 = [
            [
                0x2cd874e1ccefc0eef6fda66379c1ba4bc4ba402563bef2a6b7eafb95c81f3d82,
                0x153e48887fb21e76ca4b386aaa9d1e1387ad12692bd286c0e4e01c3194e1dfc5
            ],
            [
                0x15a01d3c96cb23e22dfe4bfda53b47c66142570b1e77f05e7b4a66eec10fde40,
                0x201d3a5881ffde30c45b09bf33dd5bc8f1cb677b3a9f35f9bb92abb00cb4cc57
            ]
        ];
        vk.gamma2 = [
            [
                0x12746a6387a01dc19890dcbb9968bd9a2e20dcd49b11e0e8a4e7fc1f0d72cb57,
                0x146d35a0b7cda8bef5d32aacb2b7e7b32d80b69a28ae1550a7f27a35e797598f
            ],
            [
                0x11df3311fa0e617c8ec6875acd3fdcaa9cc368ef8e5de5e11e781806d208cd31,
                0x2f0e79d3d0c64ae6dc97aba4ddf7fea6f2f3bfbd0bfa1c7f01be4e5d2784bbb8
            ]
        ];
        vk.delta2 = [
            [
                0x17f8b5f2e77cc570da7e17755b87bb0a473ce92e64972da24dad9d9ee6ea6176,
                0x27e5005aeb43fb24aedc8e107ded4e3ebbd16c3c799e86e96412cbb0fd97e4c8
            ],
            [
                0x2acd3d03ef6c86e7acb8e31acf6c9b15f176b1c8fa7faaffda7d92cd732dee5b,
                0x292e0e4fa36acdac9d72edef590aa441ba73f5baa24cc41ec986acf53d38a5ff
            ]
        ];
        vk.IC = new uint256[2][](4);
        vk.IC[0] = [
            0x00c4df9c9df29a0da4a6c0586881ddf2aadfed64f213b52eb423ec0732f6be78,
            0x1c0ba5c40d0c01c95be2beb3d33b29ed24ab389b8a47dbadc4341f41adee3fa0
        ];
        vk.IC[1] = [
            0x2f4152ac396b80f9d859f70a37e7a7f0ca07d200dad3ade8fb52168e7a4d0b69,
            0x111fda91a8f8e4db3a66d05eddae6d030cf87e02e8a8a69cc3b13697ef86f659
        ];
        vk.IC[2] = [
            0x14680f8cec8e32af5c801616f0c48a11d5b4c0128cf6a31da73a639a269f3e2b,
            0x12e64e5a875b9c656285a2dce01ccecca9acf3d89cfd548b33685277a5cac1de
        ];
        vk.IC[3] = [
            0x293aab6c77f69c8bd9ae470fd0fbe85e23682ec3b5d10b92c5bc8aee0ec08d9c,
            0x1c59fdcc66a4c2bc1baad7d455ed09dae9955da98d89a9199c66b1593cc1ccde
        ];
        
        return vk;
    }
    
    /// @notice Performs a pairing check
    /// @param a1 First G1 point of first pair
    /// @param a2 First G2 point of first pair
    /// @param b1 Second G1 point of first pair
    /// @param b2 Second G2 point of first pair
    /// @param c1 First G1 point of second pair
    /// @param c2 First G2 point of second pair
    /// @param d1 Second G1 point of second pair
    /// @param d2 Second G2 point of second pair
    /// @return Result of the pairing check
    function pairing(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        uint256[24] memory input;
        input[0] = a1.X;
        input[1] = a1.Y;
        input[2] = a2.X[0];
        input[3] = a2.X[1];
        input[4] = a2.Y[0];
        input[5] = a2.Y[1];
        
        input[6] = b1.X;
        input[7] = b1.Y;
        input[8] = b2.X[0];
        input[9] = b2.X[1];
        input[10] = b2.Y[0];
        input[11] = b2.Y[1];
        
        input[12] = c1.X;
        input[13] = c1.Y;
        input[14] = c2.X[0];
        input[15] = c2.X[1];
        input[16] = c2.Y[0];
        input[17] = c2.Y[1];
        
        input[18] = d1.X;
        input[19] = d1.Y;
        input[20] = d2.X[0];
        input[21] = d2.X[1];
        input[22] = d2.Y[0];
        input[23] = d2.Y[1];
        uint256[1] memory out;
        bool success;
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, input, 0x300, out, 0x20)
            if iszero(success) {
                mstore(0, ERROR_PAIRING_CHECK_FAILED)
                revert(0, 4)
            }
        }
        
        return out[0] != 0;
    }
    
    /// @notice Convenience function that checks if a pairing product equals one
    /// @param a1 First G1 point
    /// @param a2 First G2 point
    /// @param b1 Second G1 point
    /// @param b2 Second G2 point
    /// @return Result of the pairing check
    function pairingProd2(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2
    ) internal view returns (bool) {
        G1Point memory p1 = negate(a1);
        return pairing(p1, a2, b1, b2, P1(), P2(), P1(), P2());
    }
    
    /// @notice Verifies a Groth16 proof
    /// @param _pA First part of the proof (G1 point)
    /// @param _pB Second part of the proof (G2 point)
    /// @param _pC Third part of the proof (G1 point)
    /// @param _pubSignals Public inputs to verify against
    /// @return True if the proof is valid
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view override returns (bool) {
        VerificationKey memory vk = verificationKey();
        if (_pubSignals.length != 4) {
            revert InvalidNumberOfPublicInputs(_pubSignals.length, 4);
        }
        //// ALL inputs -> scalar field
        for (uint256 i = 0; i < 4; i++) {
            if (_pubSignals[i] >= scalarField) {
                revert InputNotInScalarField(_pubSignals[i]);
            }
        }
        G1Point memory vk_x = G1Point(0, 0);
        vk_x.X = vk.IC[0][0];
        vk_x.Y = vk.IC[0][1];
        for (uint256 i = 0; i < _pubSignals.length; i++) {
            if (_pubSignals[i] != 0) {
                G1Point memory term = G1Point(vk.IC[i+1][0], vk.IC[i+1][1]);
                term = scalar_mul(term, _pubSignals[i]);
                vk_x = addition(vk_x, term);
            }
        }
        G1Point memory a = G1Point(_pA[0], _pA[1]);
        G2Point memory b = G2Point([_pB[0][1], _pB[0][0]], [_pB[1][1], _pB[1][0]]);
        G1Point memory c = G1Point(_pC[0], _pC[1]);
        
        G1Point memory alpha = G1Point(vk.alpha1[0], vk.alpha1[1]);
        G2Point memory beta = G2Point(vk.beta2[0], vk.beta2[1]);
        G2Point memory gamma = G2Point(vk.gamma2[0], vk.gamma2[1]);
        G2Point memory delta = G2Point(vk.delta2[0], vk.delta2[1]);
        
        return pairingProd2(
            addition(a, negate(alpha)),
            b,
            addition(vk_x, negate(c)),
            delta
        );
    }
}
