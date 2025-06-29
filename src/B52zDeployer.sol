// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {LibClone} from "solady/src/utils/LibClone.sol";
import {OwnableRoles} from "solady/src/auth/OwnableRoles.sol";
import {IGroth16Verifier} from "./interfaces/IGroth16Verifier.sol";
import {B52zInstance} from "./B52zInstance.sol";

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

        factory.createIII(1 * 10**18);  
        factory.createIII(10 * 10**18);   
        factory.createIII(100 * 10**18); 
    }
}
