// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console2} from "forge-std/Test.sol";
import {B52Token, B52zDeployer, B52zFactory, B52zRouter, Groth16Verifier} from "../src/B52z.sol";

contract B52zTest is Test {
    B52Token public token;
    Groth16Verifier public verifier;
    B52zFactory public factory;
    B52zRouter public router;
    B52zDeployer public deployer;

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address relayer = makeAddr("relayer");

    function setUp() public {
        // Deploy the full system
        deployer = new B52zDeployer();
        
        // Get contract references
        token = deployer.token();
        verifier = deployer.verifier();
        factory = deployer.factory();
        router = deployer.router();
        
        // Provide tokens to test accounts
        deal(address(token), alice, 1000 ether);
        deal(address(token), bob, 1000 ether);
    }

    function testTokenBasics() public {
        assertEq(token.name(), "B-52-Z Token");
        assertEq(token.symbol(), "B52Z");
        assertEq(token.decimals(), 18);
        assertEq(token.balanceOf(alice), 1000 ether);
    }

    function testFactoryInstances() public {
        address[] memory instances = factory.getAllInstances();
        assertEq(instances.length, 3); // 3 instances created by default
        
        // Verify denominations
        assertEq(instances.length, 3);
        
        // Test instance creation
        vm.startPrank(factory.owner());
        address newInstance = factory.createInstance(1000 ether);
        vm.stopPrank();
        
        instances = factory.getAllInstances();
        assertEq(instances.length, 4);
        assertEq(instances[3], newInstance);
    }

    //just aamock test - in reality we'd need proper zk proofs for withdrawal
    function testDeposit() public {
        // Choose one of the pre-created denominations that we know exists (1 ether)
        uint256 denomination = 1 ether;
        bytes32 mockCommitment = keccak256(abi.encodePacked("test commitment"));
        
        // Get the instance
        address instance = factory.instances(address(token), denomination);
        require(instance != address(0), "Instance not found");
        
        // Approve tokens
        vm.startPrank(alice);
        token.approve(address(router), denomination);
        
        // Deposit
        router.deposit(denomination, mockCommitment);
        vm.stopPrank();
        
        // Check balance
        assertEq(token.balanceOf(instance), denomination);
    }
} 