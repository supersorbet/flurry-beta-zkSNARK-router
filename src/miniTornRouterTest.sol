// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {LibBitmap} from "solady/src/utils/LibBitmap.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {LibClone} from "solady/src/utils/LibClone.sol";
import {ReentrancyGuard} from "solady/src/utils/ReentrancyGuard.sol";
import {OwnableRoles} from "solady/src/auth/OwnableRoles.sol";
import {ERC20} from "solady/src/tokens/ERC20.sol";
import {LibString} from "solady/src/utils/LibString.sol";
import {ECDSA} from "solady/src/utils/ECDSA.sol";

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

/// @title B52z Instance Interface
/// @notice Interface for interacting with mixer instances
interface IB52zInstance {
    /// @notice Make a deposit into the mixer
    /// @param commitment The commitment hash
    function deposit(bytes32 commitment) external;
    
    /// @notice Withdraw from the mixer
    /// @param _pA First part of the proof
    /// @param _pB Second part of the proof
    /// @param _pC Third part of the proof
    /// @param _pubSignals Public inputs to the proof
    /// @param recipient The recipient address
    /// @param relayer The relayer address (optional)
    /// @param fee The relayer fee (optional)
    function withdraw(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals,
        address recipient,
        address relayer,
        uint256 fee
    ) external;
    
    /// @notice Get the denomination of this mixer
    /// @return The token denomination
    function denomination() external view returns (uint256);
    
    /// @notice Get the merkle root of this mixer
    /// @return The current merkle root
    function currentRoot() external view returns (bytes32);
    
    /// @notice Check if a nullifier has been used
    /// @param nullifierHash The nullifier hash
    /// @return Whether the nullifier has been used
    function isNullifierUsed(bytes32 nullifierHash) external view returns (bool);
}

/// @title B52z Factory
/// @notice Creates and manages mixer instances for different denominations
contract B52zFactory is OwnableRoles {
    /// @notice Error thrown when trying to create an instance that already exists
    /// @param token The token address
    /// @param denomination The denomination amount
    error InstanceAlreadyExists(address token, uint256 denomination);
    
    /// @notice Error thrown when a caller doesn't have the required role
    error NotAuthorized();
    
    /// @notice Error thrown when a zero address is provided
    error ZeroAddress();
    
    /// @notice Error thrown when initialization of a cloned instance fails
    error InitializationFailed();

    /// @notice Role constant for governance operations
    uint256 constant GOVERNANCE_ROLE = 1;
    
    /// @notice Role constant for instance management
    uint256 constant INSTANCE_MANAGER_ROLE = 2;

    /// @notice Mapping of token address and denomination to instance address
    /// @dev token -> denomination -> instance
    mapping(address => mapping(uint256 => address)) public instances;
    
    /// @notice Array of all created instances
    address[] public allInstances;
    
    /// @notice The verifier contract address
    address public verifier;
    
    /// @notice The B52 token address
    address public immutable b52Token;
    
    /// @notice The implementation contract for instances
    address public instanceImplementation;

    /// @notice Event emitted when a new instance is created
    /// @param token The token address
    /// @param denomination The denomination amount
    /// @param instance The created instance address
    event InstanceCreated(
        address indexed token,
        uint256 indexed denomination,
        address instance
    );
    
    /// @notice Event emitted when the verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event VerifierUpdated(address oldVerifier, address newVerifier);
    
    /// @notice Event emitted when the implementation is updated
    /// @param oldImplementation The previous implementation address
    /// @param newImplementation The new implementation address
    event ImplementationUpdated(
        address oldImplementation,
        address newImplementation
    );

    /// @notice Constructor
    /// @param _b52Token The B52 token address
    /// @param _verifier The verifier contract address
    constructor(address _b52Token, address _verifier) {
        if (_b52Token == address(0) || _verifier == address(0))
            revert ZeroAddress();
            
        b52Token = _b52Token;
        verifier = _verifier;
        
        // Deploy the implementation contract that will be cloned
        instanceImplementation = address(
            new B52zInstance(_b52Token, 0, _verifier, 20)
        );
        
        _initializeOwner(msg.sender);
        _grantRoles(msg.sender, GOVERNANCE_ROLE | INSTANCE_MANAGER_ROLE);
    }

    /// @notice Create a new mixer instance
    /// @param denomination The denomination amount
    /// @return instance The created instance address
    function createIII(uint256 denomination)
        external
        returns (address instance)
    {
        if (!hasAnyRole(msg.sender, GOVERNANCE_ROLE | INSTANCE_MANAGER_ROLE)) {
            revert NotAuthorized();
        }
        
        if (instances[b52Token][denomination] != address(0)) {
            revert InstanceAlreadyExists(b52Token, denomination);
        }
        
        // Create initialization data
        bytes memory initData = abi.encodeWithSelector(
            B52zInstance.initialize.selector,
            denomination
        );
        
        // Create deterministic clone
        instance = LibClone.cloneDeterministic(
            instanceImplementation,
            keccak256(abi.encodePacked(b52Token, denomination))
        );
        
        // Initialize the clone
        (bool success, ) = instance.call(initData);
        if (!success) revert InitializationFailed();

        // Register the instance
        instances[b52Token][denomination] = instance;
        allInstances.push(instance);

        emit InstanceCreated(b52Token, denomination, instance);
        return instance;
    }

    /// @notice Get all instances
    /// @return Array of all created instances
    function getAllInstances() external view returns (address[] memory) {
        return allInstances;
    }

    /// @notice Update the verifier address
    /// @param _verifier The new verifier address
    function updateVerifier(address _verifier)
        external
        onlyRolesOrOwner(GOVERNANCE_ROLE)
    {
        if (_verifier == address(0)) revert ZeroAddress();
        
        address oldVerifier = verifier;
        verifier = _verifier;
        
        emit VerifierUpdated(oldVerifier, _verifier);
    }

    /// @notice Update the implementation address
    /// @param _implementation The new implementation address
    function updateImplementation(address _implementation)
        external
        onlyRolesOrOwner(GOVERNANCE_ROLE)
    {
        if (_implementation == address(0)) revert ZeroAddress();
        
        address oldImplementation = instanceImplementation;
        instanceImplementation = _implementation;
        
        emit ImplementationUpdated(oldImplementation, _implementation);
    }
}

/// @title B52z Router
/// @notice Routes transactions to appropriate mixer instances
contract B52zRouter is ReentrancyGuard {
    /// @notice Error thrown when an instance is not found for a denomination
    /// @param denomination The requested denomination
    error InstanceNotFound(uint256 denomination);
    
    /// @notice Error thrown when a token transfer fails
    error TransferFailed();

    /// @notice The factory contract
    B52zFactory public immutable factory;

    /// @notice Constructor
    /// @param _factory The factory contract address
    constructor(address _factory) {
        factory = B52zFactory(_factory);
    }

    /// @notice Make a deposit into the mixer
    /// @param denomination The denomination amount
    /// @param commitment The commitment hash
    function deposit(uint256 denomination, bytes32 commitment)
        external
        nonReentrant
    {
        // Get instance for this denomination
        address instance = factory.instances(factory.b52Token(), denomination);
        if (instance == address(0)) revert InstanceNotFound(denomination);

        // Transfer tokens to the instance
        SafeTransferLib.safeTransferFrom(
            factory.b52Token(),
            msg.sender,
            instance,
            denomination
        );

        // Call deposit on the instance
        IB52zInstance(instance).deposit(commitment);
    }

    /// @notice Withdraw from the mixer
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
        // Get instance for this denomination
        address instance = factory.instances(factory.b52Token(), denomination);
        if (instance == address(0)) revert InstanceNotFound(denomination);

        // Call withdraw on the instance
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

/// @title B52z Instance
/// @notice Individual mixer instance for a specific denomination
/// @dev Implements a privacy mixer using zk-SNARKs and merkle trees
contract B52zInstance is IB52zInstance, ReentrancyGuard {
    using LibBitmap for LibBitmap.Bitmap;
    using LibString for uint256;

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

        // Initialize the Merkle tree with default values
        bytes32[] memory _zeros = new bytes32[](_merkleTreeHeight + 1);
        bytes32 currentZero = keccak256(abi.encodePacked("B_52_Z_INIT_ZERO"));
        _zeros[0] = currentZero;

        // Calculate zero values for each level
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
        
        // Security check to ensure only the factory or a deterministic deployment can call initialize
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

    /// @notice Get the denomination of this mixer
    /// @return The token denomination
    function denomination() external view override returns (uint256) {
        return _denomination;
    }

    /// @notice Make a deposit into the mixer
    /// @param _commitment The commitment hash
    function deposit(bytes32 _commitment) external override nonReentrant {
        // Ensure the tree isn't full
        if (currentIndex >= (1 << merkleTreeHeight)) revert TreeFull();
        
        uint256 index = currentIndex;
        _insertLeaf(_commitment);
        
        // Set time delay for front-running protection
        uint256 nextValidTimestamp = block.timestamp + CONFIRMATION_BLOCKS * 15; // ~15s per block
        rootValidFrom[currentRoot] = nextValidTimestamp;

        emit Deposit(_commitment, index, currentRoot);
    }

    /// @notice Withdraw from the mixer
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
        // Extract proof components
        bytes32 nullifierHash = bytes32(_pubSignals[0]);
        bytes32 root = bytes32(_pubSignals[1]);
        
        // Verify the proof is valid
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
            
        // Check fee is reasonable
        uint256 maxFee = _denomination / 10;
        if (_fee > maxFee) revert FeeTooHigh(_fee, maxFee);
        
        // Mark nullifier as used to prevent double-spending
        _nullifiers.set(uint256(uint160(nullifierHash)));
        
        // Calculate and transfer amounts
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
                // Determine if this is a left or right node
                if ((currentLevelIndex & 1) == 0) {
                    // Even index = left node
                    left = currentHash;
                    right = zeros[i];
                } else {
                    // Odd index = right node
                    left = nodes[i][currentLevelIndex - 1];
                    right = currentHash;
                }
                
                // Calculate parent hash
                currentHash = _hashLeftRight(left, right);
                currentLevelIndex >>= 1;
                nodes[i + 1][currentLevelIndex] = currentHash;
            }
        }
        
        // Update root tracking
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
}

/// @title B52 Token
/// @notice ERC20 token for the B52 privacy system
contract B52Token is ERC20 {
    /// @notice Constructor - mints initial supply to deployer
    constructor() {
        // Mint 100 million tokens with 18 decimals
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

/// @title Groth16 Verifier
/// @notice Implementation of a zk-SNARK verifier using the Groth16 protocol
contract Groth16Verifier is IGroth16Verifier {
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
            switch success case 0 { invalid() }
        }
        
        require(success, "G1 addition failed");
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
            switch success case 0 { invalid() }
        }
        
        require(success, "G1 scalar multiplication failed");
    }

    /// @notice Returns the verification key
    /// @return vk The verification key
    function verificationKey() internal pure returns (VerificationKey memory vk) {
        // Alpha
        vk.alpha1 = [
            0x1b9d9bcce2dca3fa14e4b20ff6250aecc0eea30eb1e43386ec83b3d4c28dbc10,
            0x10c7e38b637a9bc98e328a39eb25997e8cc20fb6657b5b3dcca1f7fbff4552f7
        ];
        // Beta
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
        // Gamma
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
        // Delta
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
            switch success case 0 { invalid() }
        }
        
        require(success, "Pairing check failed");
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
        
        require(_pubSignals.length == 4, "Invalid number of public inputs");
        for (uint256 i = 0; i < _pubSignals.length; i++) {
            require(_pubSignals[i] < scalarField, "Input not in scalar field");
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

/// @title B52z Deployer
/// @notice Creates and initializes the full B52z privacy system
contract B52zDeployer {
    /// @notice The B52 token
    B52Token public token;
    
    /// @notice The zk-SNARK verifier
    Groth16Verifier public verifier;
    
    /// @notice The factory that creates mixer instances
    B52zFactory public factory;
    
    /// @notice The router that routes transactions to instances
    B52zRouter public router;
    
    /// @notice Constructor - creates and initializes the system
    constructor() {
        token = new B52Token();
        verifier = new Groth16Verifier();
        factory = new B52zFactory(address(token), address(verifier));
        router = new B52zRouter(address(factory));
        
        factory.createIII(1 * 10**18);      // 1 token
        factory.createIII(10 * 10**18);     // 10 tokens
        factory.createIII(100 * 10**18);    // 100 tokens
    }
}
