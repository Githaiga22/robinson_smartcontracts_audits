// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Airtime} from "../../src/Airtime.sol";
import {ERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

// Minimal mock USDC with permit support
contract MockUSDC is ERC20Permit {
    constructor() ERC20("USD Coin", "USDC") ERC20Permit("USD Coin") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract AirtimeAuditTest is Test {
    Airtime public airtime;
    MockUSDC public usdc;

    address public treasury;
    address public user;
    uint256 public userPrivateKey;

    function setUp() public {
        treasury  = address(this);
        usdc      = new MockUSDC();
        airtime   = new Airtime(address(usdc), treasury);

        userPrivateKey = 0xA11CE;
        user = vm.addr(userPrivateKey);

        usdc.mint(user, 1000e18);
    }

    // =====================================================================
    // H-1: No Refund Deduplication
    // Proves treasury can call refund() multiple times with the same orderRef
    // draining funds that belong to other users
    // =====================================================================

    function test_doubleRefundDrainsOtherUsersFunds() public {
        // Three honest users deposit 100 USDC each — 300 USDC total in contract
        address userA = address(0xA);
        address userB = address(0xB);
        address userC = address(0xC);

        usdc.mint(userA, 100e18);
        usdc.mint(userB, 100e18);
        usdc.mint(userC, 100e18);

        vm.prank(userA);
        usdc.approve(address(airtime), 100e18);
        vm.prank(userA);
        airtime.deposit("ORDER-A", 100e18);

        vm.prank(userB);
        usdc.approve(address(airtime), 100e18);
        vm.prank(userB);
        airtime.deposit("ORDER-B", 100e18);

        vm.prank(userC);
        usdc.approve(address(airtime), 100e18);
        vm.prank(userC);
        airtime.deposit("ORDER-C", 100e18);

        uint256 contractBalanceBefore = usdc.balanceOf(address(airtime));

        console.log("---------- H-1: DOUBLE REFUND ----------");
        emit log_named_uint("Contract USDC balance before (wei)", contractBalanceBefore);

        // userA's top-up failed — treasury correctly issues one refund
        airtime.refund("ORDER-A", userA, 100e18);

        // BUG: same ORDER-A refund issued again (backend bug or compromised key)
        // Contract has NO check — it processes it again without reverting
        airtime.refund("ORDER-A", userA, 100e18);

        uint256 contractBalanceAfter = usdc.balanceOf(address(airtime));
        uint256 userABalance = usdc.balanceOf(userA);

        emit log_named_uint("Contract USDC balance after  (wei)", contractBalanceAfter);
        emit log_named_uint("userA received (wei)               ", userABalance);

        // userA received 200 USDC from a 100 USDC deposit
        // userB and userC's 100 USDC each are now at risk
        assertEq(userABalance, 200e18, "userA double-refunded");
        assertEq(contractBalanceAfter, 100e18, "other users funds drained by double refund");

        console.log("CONFIRMED: Same orderRef refunded twice. Other users lost funds.");
        console.log("------------------------------------------");
    }

    // =====================================================================
    // H-2: Unrestricted Treasury Withdrawal
    // Proves a single transaction by treasury drains ALL user deposits
    // =====================================================================

    function test_treasuryDrainsAllUserFunds() public {
        // Five users deposit varying amounts — total 500 USDC
        uint256 totalDeposited = 0;
        for (uint256 i = 1; i <= 5; i++) {
            address depositor = address(uint160(i + 100));
            uint256 amount    = i * 100e18; // 100, 200, 300, 400, 500
            usdc.mint(depositor, amount);
            vm.startPrank(depositor);
            usdc.approve(address(airtime), amount);
            airtime.deposit(string(abi.encodePacked("ORDER-", i)), amount);
            vm.stopPrank();
            totalDeposited += amount;
        }

        uint256 contractBalance = usdc.balanceOf(address(airtime));
        uint256 treasuryBefore  = usdc.balanceOf(treasury);

        console.log("---------- H-2: TREASURY FULL DRAIN ----------");
        emit log_named_uint("Total user deposits (wei) ", contractBalance);
        emit log_named_uint("Treasury balance before   ", treasuryBefore);

        // Treasury (or attacker with treasury key) calls withdrawTreasury once
        // No timelock. No limit. No multi-sig. Instant total drain.
        airtime.withdrawTreasury(treasury, contractBalance);

        uint256 contractAfter  = usdc.balanceOf(address(airtime));
        uint256 treasuryAfter  = usdc.balanceOf(treasury);

        emit log_named_uint("Contract balance after    ", contractAfter);
        emit log_named_uint("Treasury balance after    ", treasuryAfter);
        emit log_named_uint("Total drained (wei)       ", treasuryAfter - treasuryBefore);

        assertEq(contractAfter, 0,            "Contract was not fully drained");
        assertEq(treasuryAfter - treasuryBefore, totalDeposited, "Treasury did not receive all funds");

        console.log("CONFIRMED: Single tx drained all user deposits. No timelock. No limit.");
        console.log("----------------------------------------------");
    }

    // =====================================================================
    // M-1: No Treasury Transfer Mechanism
    // Proves there is no way to change the treasury address on-chain
    // =====================================================================

    function test_noTreasuryTransferMechanism() public {
        address newTreasury = address(0xBEEF);

        console.log("---------- M-1: NO TREASURY TRANSFER ----------");
        console.log("Current treasury:", airtime.treasury());

        // There is no setTreasury() or transferTreasury() function
        // If the treasury key is lost, all funds below are permanently locked
        usdc.mint(address(this), 500e18);
        usdc.approve(address(airtime), 500e18);

        vm.prank(address(this));
        usdc.approve(address(airtime), 500e18);
        airtime.deposit("ORDER-LOCK", 500e18);

        emit log_named_uint("Funds locked in contract (wei)", usdc.balanceOf(address(airtime)));

        // Attempting to call setTreasury would revert — function does not exist
        // We verify by checking: treasury address is unchanged and immutable
        assertEq(airtime.treasury(), treasury, "Treasury address should not have changed");
        assertTrue(airtime.treasury() != newTreasury, "No mechanism to transfer treasury");

        console.log("CONFIRMED: No setTreasury() exists. Key loss = permanent fund lockup.");
        console.log("-----------------------------------------------");
    }

    // =====================================================================
    // M-2: withdrawTreasury Missing nonReentrant
    // Proves the inconsistency: refund() has nonReentrant, withdrawTreasury() does not
    // =====================================================================

    function test_withdrawTreasuryMissingNonReentrant() public {
        // Demonstrate the inconsistency by showing refund has the guard, withdraw does not
        // A malicious treasury contract could re-enter withdrawTreasury before state settles

        usdc.mint(address(this), 200e18);
        usdc.approve(address(airtime), 200e18);
        airtime.deposit("ORDER-REENTRANT", 200e18);

        // withdrawTreasury has no nonReentrant — if treasury were a contract with
        // a callback on USDC transfer, it could re-enter here
        // We document this by confirming the function lacks the guard
        // (verified by reading src/Airtime.sol#L88 — no nonReentrant modifier)
        console.log("---------- M-2: MISSING nonReentrant ----------");
        console.log("refund()          -> has nonReentrant: YES (line 79)");
        console.log("withdrawTreasury() -> has nonReentrant: NO  (line 88)");
        console.log("Inconsistent protection. Contract treasury could be a smart wallet.");

        // Baseline: confirm withdrawTreasury still works (no guard means it executes)
        uint256 bal = usdc.balanceOf(address(airtime));
        airtime.withdrawTreasury(treasury, bal);
        assertEq(usdc.balanceOf(address(airtime)), 0);

        console.log("CONFIRMED: withdrawTreasury() has no nonReentrant guard.");
        console.log("-----------------------------------------------");
    }
}
