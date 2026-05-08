// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Airtime} from "../src/Airtime.sol";
import {ERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MockUSDC2 is ERC20Permit {
    constructor() ERC20("USD Coin", "USDC") ERC20Permit("USD Coin") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

/// @notice H-2 Treasury Full Drain Demo on Anvil.
/// Deploys MockUSDC + Airtime, simulates 5 honest users depositing USDC,
/// then proves the treasury can drain EVERYTHING in a single transaction —
/// no timelock, no spending limit, no multi-sig required.
contract AttackTreasuryDrain is Script {

    // Anvil default accounts (accounts 0-3, all pre-funded with 10000 ETH)
    uint256 constant TREASURY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant USER1_KEY    = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant USER2_KEY    = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant USER3_KEY    = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;

    function run() external {
        address treasury = vm.addr(TREASURY_KEY);
        address user1    = vm.addr(USER1_KEY);
        address user2    = vm.addr(USER2_KEY);
        address user3    = vm.addr(USER3_KEY);

        // ── Step 1: Deploy contracts ────────────────────────────────────
        vm.startBroadcast(TREASURY_KEY);
        MockUSDC2 usdc    = new MockUSDC2();
        Airtime   airtime = new Airtime(address(usdc), treasury);

        // Mint different amounts to 3 users -- simulating real deposits
        usdc.mint(user1, 500e18);   // user1: $500
        usdc.mint(user2, 1000e18);  // user2: $1,000
        usdc.mint(user3, 750e18);   // user3: $750
        vm.stopBroadcast();

        console.log("=== H-2: TREASURY FULL DRAIN SETUP ===");
        console.log("Airtime contract :", address(airtime));
        console.log("MockUSDC         :", address(usdc));
        console.log("Treasury         :", treasury);
        console.log("");
        console.log("Users and deposits:");
        console.log("  User1:", user1, "-> $500 USDC");
        console.log("  User2:", user2, "-> $1000 USDC");
        console.log("  User3:", user3, "-> $750 USDC");

        // ── Step 2: All 3 users deposit ─────────────────────────────────
        vm.startBroadcast(USER1_KEY);
        usdc.approve(address(airtime), 500e18);
        airtime.deposit("ORDER-U1", 500e18);
        vm.stopBroadcast();

        vm.startBroadcast(USER2_KEY);
        usdc.approve(address(airtime), 1000e18);
        airtime.deposit("ORDER-U2", 1000e18);
        vm.stopBroadcast();

        vm.startBroadcast(USER3_KEY);
        usdc.approve(address(airtime), 750e18);
        airtime.deposit("ORDER-U3", 750e18);
        vm.stopBroadcast();

        console.log("");
        console.log("---------- BEFORE ATTACK ----------");
        console.log("Total deposited : $2,250 USDC");
        console.log("Treasury USDC   : $0");
        console.log("No timelock. No spending cap. No multi-sig.");

        // ── Step 3: Treasury drains everything in ONE transaction ────────
        // Single EOA key controls all funds -- leaked .env = instant total loss.
        vm.startBroadcast(TREASURY_KEY);
        uint256 contractBalance = usdc.balanceOf(address(airtime));
        airtime.withdrawTreasury(treasury, contractBalance);
        vm.stopBroadcast();

        console.log("");
        console.log("---------- AFTER ATTACK (1 transaction) ----------");
        console.log("Contract USDC   : $0  (completely drained)");
        console.log("Treasury USDC   : $2,250 (all user deposits stolen)");
        console.log("");
        console.log("CONFIRMED: withdrawTreasury() drained all 3 users funds.");
        console.log("One private key. One transaction. Zero recourse.");
        console.log("==================================================");
    }
}
