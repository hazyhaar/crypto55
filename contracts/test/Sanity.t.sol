// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "../OneStepEVM.sol";

contract SanityTest {
    OneStepEVM evm;

    function setUp() public {
        evm = new OneStepEVM();
    }

    function test_Deployment() public view {
        require(address(evm) != address(0), "Deployment failed");
    }
}
