// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {B52zDeployer} from "../src/B52z.sol";

contract DeployB52z is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the entire B52z system
        B52zDeployer deployer = new B52zDeployer();

        // Log the deployed addresses
        console2.log("B52z Deployment Addresses:");
        console2.log("---------------------------------------------------");
        console2.log("B52Token: %s", address(deployer.token()));
        console2.log("Groth16Verifier: %s", address(deployer.verifier()));
        console2.log("B52zFactory: %s", address(deployer.factory()));
        console2.log("B52zRouter: %s", address(deployer.router()));
        
        vm.stopBroadcast();
    }
} 