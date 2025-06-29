// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {LibBitmap} from "solady/src/utils/LibBitmap.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {LibClone} from "solady/src/utils/LibClone.sol";
import {ReentrancyGuard} from "solady/src/utils/ReentrancyGuard.sol";
import {IGroth16Verifier} from "./interfaces/IGroth16Verifier.sol";
import {IB52zInstance} from "./interfaces/IB52zInstance.sol";

/// @title B52z Instance
/// @notice Individual blender instance for a specific denomination
/// @dev Implements a privacy blender using zk-SNARKs and merkle trees
contract B52zInstance is IB52zInstance, ReentrancyGuard {
    using LibBitmap for LibBitmap.Bitmap;


    /// @notice Error thrown when an invalid root is provided
    /// @param root The invalid root
    error InvalidRoot(bytes32 root);
    
    /// @notice Error thrown when a nullifier has already been used
    /// @param nullifierHash The nullifier hash
    error NullifierAlreadyUsed(bytes32 nullifierHash);
    
    /// @notice Error thrown when a root is not yet valid (time delay for front-running protection)
    /// @param root The root
    /// @param validFrom The timestamp when the root becomes valid
    /// @param currentTime The current timestamp
    error RootNotYetValid(bytes32 root, uint256 validFrom, uint256 currentTime);
    
    /// @notice Error thrown when an invalid proof is provided
    error InvalidProof();
    
    /// @notice Error thrown when a fee is too high
    /// @param fee The fee
    /// @param maxFee The maximum allowed fee
    error FeeTooHigh(uint256 fee, uint256 maxFee);
    
    /// @notice Error thrown when the merkle tree is full
    error TreeFull();
    
    /// @notice Error thrown when trying to initialize an already initialized instance
    error AlreadyInitialized();
    
    /// @notice Error thrown when a transfer fails
    error TransferFailed();
    
    /// @notice Error thrown when called by an invalid caller
    error InvalidCaller();

    /// @notice The token address
    address public immutable token;
    
    /// @notice The verifier contract
    IGroth16Verifier public immutable verifier;
    
    /// @notice The merkle tree height
    uint8 public immutable merkleTreeHeight;
    
    /// @notice The token denomination for this instance
    uint256 private _denomination;
    
    /// @notice The current merkle root
    bytes32 public override currentRoot;

    /// @notice Bitmap of used nullifiers
    LibBitmap.Bitmap private _nullifiers;
    
    /// @notice Bitmap of historical roots
    LibBitmap.Bitmap private _historicalRoots;
    
    /// @notice Array of historical roots
    bytes32[] private _roots;

    /// @notice Mapping of merkle tree nodes at each level
    /// @dev level -> index -> node
    mapping(uint8 => mapping(uint256 => bytes32)) public nodes;
    
    /// @notice Current index in the merkle tree
    uint256 public currentIndex;
    
    /// @notice Zero values for each level of the merkle tree
    bytes32[] public zeros;

    /// @notice Salt used for hashing
    bytes32 private constant HASH_MIX_SALT = keccak256("B_52_Z_HASH_SALT");
    
    /// @notice Confirmation blocks required to prevent front-running
    uint256 private constant CONFIRMATION_BLOCKS = 10;
    
    /// @notice Mapping of when each root becomes valid
    mapping(bytes32 => uint256) public rootValidFrom;

    /// @notice Constructor
    /// @param _token The token address
    /// @param _initialDenomination The initial denomination amount
    /// @param _verifier The verifier contract address
    /// @param _merkleTreeHeight The height of the merkle tree
    constructor(
        address _token,
        uint256 _initialDenomination,
        address _verifier,
        uint8 _merkleTreeHeight
    ) {
        token = _token;
        _denomination = _initialDenomination;
        verifier = IGroth16Verifier(_verifier);
        merkleTreeHeight = _merkleTreeHeight;

        bytes32[] memory _zeros = new bytes32[](_merkleTreeHeight + 1);
        bytes32 currentZero = keccak256(abi.encodePacked("B_52_Z_INIT_ZERO"));
        _zeros[0] = currentZero;

        for (uint8 i = 1; i <= _merkleTreeHeight; i++) {
            currentZero = _hashLeftRight(currentZero, currentZero);
            _zeros[i] = currentZero;
        }
        
        zeros = _zeros;
        currentRoot = _zeros[_merkleTreeHeight];
        _historicalRoots.set(uint256(uint160(currentRoot)));
        _roots.push(currentRoot);
        rootValidFrom[currentRoot] = block.timestamp;
    }

    /// @notice Initialize the instance
    /// @param _denom The denomination amount
    function initialize(uint256 _denom) external {
        if (_denomination != 0) revert AlreadyInitialized();
            if (msg.sender != address(B52zFactory(address(0)))) {
            address expectedCaller = LibClone.predictDeterministicAddress(
                address(this),
                keccak256(abi.encodePacked(token, _denom)),
                address(0)
            );
            if (msg.sender != expectedCaller) revert InvalidCaller();
        }

        _denomination = _denom;
    }

    /// @notice Get the denomination of this blender
    /// @return The token denomination
    function denomination() external view override returns (uint256) {
        return _denomination;
    }

    /// @notice Make a deposit into the blender
    /// @param _commitment The commitment hash
    function deposit(bytes32 _commitment) external override nonReentrant {
        if (currentIndex >= (1 << merkleTreeHeight)) revert TreeFull();
        
        uint256 index = currentIndex;
        _insertLeaf(_commitment);
        
        uint256 nextValidTimestamp = block.timestamp + CONFIRMATION_BLOCKS * 15; // ~15s per block
        rootValidFrom[currentRoot] = nextValidTimestamp;

        emit Deposit(_commitment, index, currentRoot);
    }

    /// @notice Withdraw from the blender
    /// @param _pA First part of the proof
    /// @param _pB Second part of the proof
    /// @param _pC Third part of the proof
    /// @param _pubSignals Public inputs to the proof
    /// @param _recipient The recipient address
    /// @param _relayer The relayer address (optional)
    /// @param _fee The relayer fee (optional)
    function withdraw(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals,
        address _recipient,
        address _relayer,
        uint256 _fee
    ) external override nonReentrant {
        bytes32 nullifierHash = bytes32(_pubSignals[0]);
        bytes32 root = bytes32(_pubSignals[1]);
        if (_nullifiers.get(uint256(uint160(nullifierHash))))
            revert NullifierAlreadyUsed(nullifierHash);
            
        if (!_historicalRoots.get(uint256(uint160(root)))) 
            revert InvalidRoot(root);
            
        uint256 _rootValidFrom = rootValidFrom[root];
        if (block.timestamp < _rootValidFrom) {
            revert RootNotYetValid(root, _rootValidFrom, block.timestamp);
        }
        
        if (!verifier.verifyProof(_pA, _pB, _pC, _pubSignals))
            revert InvalidProof();
            
        uint256 maxFee = _denomination / 10;
        if (_fee > maxFee) revert FeeTooHigh(_fee, maxFee);
        
        _nullifiers.set(uint256(uint160(nullifierHash)));
        
        uint256 amount = _denomination - _fee;
        SafeTransferLib.safeTransfer(token, _recipient, amount);
        
        if (_fee > 0) {
            SafeTransferLib.safeTransfer(token, _relayer, _fee);
        }

        emit Withdrawal(nullifierHash, _recipient, _relayer, _fee);
    }

    /// @notice Check if a nullifier has been used
    /// @param _nullifierHash The nullifier hash
    /// @return Whether the nullifier has been used
    function isNullifierUsed(bytes32 _nullifierHash)
        external
        view
        override
        returns (bool)
    {
        return _nullifiers.get(uint256(uint160(_nullifierHash)));
    }

    /// @notice Insert a leaf into the merkle tree
    /// @param _leaf The leaf to insert
    function _insertLeaf(bytes32 _leaf) internal {
        uint256 index = currentIndex;
        nodes[0][index] = _leaf;
        bytes32 currentHash = _leaf;
        bytes32 left;
        bytes32 right;
        
        unchecked {
            currentIndex += 1;
            uint256 currentLevelIndex = index;

            for (uint8 i = 0; i < merkleTreeHeight; i++) {
                if ((currentLevelIndex & 1) == 0) {
                    left = currentHash;
                    right = zeros[i];
                } else {
                    left = nodes[i][currentLevelIndex - 1];
                    right = currentHash;
                }
                
                currentHash = _hashLeftRight(left, right);
                currentLevelIndex >>= 1;
                nodes[i + 1][currentLevelIndex] = currentHash;
            }
        }
        
        currentRoot = currentHash;
        _historicalRoots.set(uint256(uint160(currentHash)));
        _roots.push(currentHash);
    }

    /// @notice Hash two values as a merkle node
    /// @param _left The left value
    /// @param _right The right value
    /// @return hash The resulting hash
    /// @dev Optimized hash function using assembly
    function _hashLeftRight(bytes32 _left, bytes32 _right)
        internal
        pure
        returns (bytes32 hash)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, _left)
            mstore(add(memPtr, 32), _right)
            hash := keccak256(memPtr, 64)
        }
    }

    /// @notice Event emitted when a deposit is made
    /// @param commitment The commitment hash
    /// @param index The index in the merkle tree
    /// @param root The new merkle root
    event Deposit(bytes32 indexed commitment, uint256 index, bytes32 root);
    
    /// @notice Event emitted when a withdrawal is made
    /// @param nullifierHash The nullifier hash
    /// @param recipient The recipient address
    /// @param relayer The relayer address (optional)
    /// @param fee The relayer fee (optional)
    event Withdrawal(
        bytes32 indexed nullifierHash,
        address indexed recipient,
        address indexed relayer,
        uint256 fee
    );
}