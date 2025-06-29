// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {LibClone} from "solady/src/utils/LibClone.sol";
import {OwnableRoles} from "solady/src/auth/OwnableRoles.sol";
import {IGroth16Verifier} from "./interfaces/IGroth16Verifier.sol";
import {B52zInstance} from "./B52zInstance.sol";

/// @title B52z Factory
/// @notice Creates and manages blender instances for different denominations
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

    /// @notice Constructor
    /// @param _b52Token The B52 token address
    /// @param _verifier The verifier contract address
    constructor(address _b52Token, address _verifier) {
        if (_b52Token == address(0) || _verifier == address(0))
            revert ZeroAddress();
            
        b52Token = _b52Token;
        verifier = _verifier;
        
        instanceImplementation = address(
            new B52zInstance(_b52Token, 0, _verifier, 20)
        );
        
        _initializeOwner(msg.sender);
        _grantRoles(msg.sender, GOVERNANCE_ROLE | INSTANCE_MANAGER_ROLE);
    }

    /// @notice Create a new blender instance
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
        
        bytes memory initData = abi.encodeWithSelector(
            B52zInstance.initialize.selector,
            denomination
        );
        
        instance = LibClone.cloneDeterministic(
            instanceImplementation,
            keccak256(abi.encodePacked(b52Token, denomination))
        );
        
        (bool success, ) = instance.call(initData);
        if (!success) revert InitializationFailed();

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
}