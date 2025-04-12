// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {B52zDeployer} from "../src/B52z.sol";

contract DeployB52z is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the entire B52z system
        B52zDeployer deployer = new B52zDeployer();

        // Log the deployed addresses
        console.log("B52z Deployment Addresses:");
        console.log("---------------------------------------------------");
        console.log("B52Token:", address(deployer.token()));
        console.log("Groth16Verifier:", address(deployer.verifier()));
        console.log("B52zFactory:", address(deployer.factory()));
        console.log("B52zRouter:", address(deployer.router()));
        
        vm.stopBroadcast();
    }
} 