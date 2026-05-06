# Smart Contract Security Audits

> Independent Web3 security research by **Allan Robinson** — finding vulnerabilities before attackers do.

---

## About Me

I am an independent smart contract security auditor focused on protecting Web3 protocols and their users. My work involves deep manual code review, automated static analysis, and live proof-of-concept exploit development on local testnets — so every finding I report comes with verified, reproducible evidence.

**Connect with me:**
- Email: [allangithaiga5@gmail.com](mailto:allangithaiga5@gmail.com)
- Join the journey: follow along as I audit real protocols and document every vulnerability I find

If your protocol needs an audit — reach out. I review DeFi, NFT, and general-purpose smart contracts on EVM-compatible chains.

---

## How I Audit Smart Contracts

### Step 1 — Reconnaissance

Before touching any code I understand the protocol's purpose, architecture, and trust model.

- Read the README, docs, and any available spec
- Identify all external interfaces, privileged roles, and fund flows
- Map every state variable and which functions can modify them
- Note the Solidity version and compiler settings (`foundry.toml` / `hardhat.config`)

### Step 2 — Toolchain Setup

I set up a reproducible local environment for every audit:

| Tool | Purpose |
|------|---------|
| **Foundry** (`forge`, `cast`, `anvil`) | Build, test, and simulate on a local chain |
| **Slither** | Automated static analysis — catches common patterns fast |
| **solc** | Direct compiler checks for version-specific issues |
| **Anvil** | Local Ethereum node for live on-chain PoC testing |

```bash
# Run the test suite
forge test -vvvv

# Run static analysis
slither src/

# Start local chain for manual interaction
anvil
```

### Step 3 — Manual Code Review

I read every line of in-scope code at least twice — once top-down for context, once following individual execution paths.

**What I look for:**

- **Reentrancy** — ETH/token transfers before state updates (CEI violations)
- **Integer overflow/underflow** — especially in pre-0.8 Solidity with `uint64` or explicit casts
- **Weak PRNG** — randomness derived from `block.timestamp`, `block.difficulty`, or `msg.sender`
- **Access control gaps** — missing `onlyOwner`, zero-address checks, or unprotected initializers
- **Denial of Service** — unbounded loops, strict equality checks on balances, pull-vs-push patterns
- **Oracle manipulation** — spot price reads, TWAP window sizing, price feed staleness
- **Flash loan attack surfaces** — single-block balance manipulations
- **Logic errors** — off-by-one errors, incorrect fee math, wrong ordering of operations

### Step 4 — Proof of Concept Development

Every High and Medium finding gets a working PoC — either a Foundry unit test or a live Anvil demo.

```
audited-protocol/
├── src/
│   └── AttackerContract.sol    # malicious contract that exploits the bug
├── script/
│   └── AttackScript.sol        # forge script to run the exploit on Anvil
├── test/
│   └── ProtocolTest.t.sol      # forge unit test proving the vulnerability
└── findings.md                 # full audit report
```

I use `forge test -vvvv` to show exact call traces and `cast` commands to verify on-chain state after each step.

### Step 5 — Report Writing

Each finding in my reports follows a consistent structure:

```
[SEVERITY-ID] Short, descriptive title

Severity:    High / Medium / Low / Informational
Likelihood:  High / Medium / Low
Impact:      High / Medium / Low

Description
  What the bug is and where it lives in the code (file + line number).

Impact
  What an attacker can do with it and what users/protocol lose.

Proof of Concept
  Exact steps to reproduce + verified test output.

Recommended Mitigation
  Concrete fix with before/after code snippets.
```

Severity is determined by combining **likelihood** (how easy is it to trigger?) and **impact** (what is the worst-case outcome?).

---

## Vulnerability Severity Guide

| Severity | Definition |
|----------|-----------|
| **Critical** | Direct loss of all funds or complete protocol takeover |
| **High** | Significant fund loss, broken core invariant, or manipulation of critical outcomes |
| **Medium** | Partial fund loss, DoS, or privilege escalation under specific conditions |
| **Low** | Edge-case issues, bad UX, or incorrect behavior with limited financial impact |
| **Informational** | Gas optimizations, dead code, outdated dependencies, style issues |

---

## Audits

| Protocol | Type | Findings | Report |
|---------|------|---------|--------|
| [PuppyRaffle](./puppy-raffle-audit/) | NFT Raffle / ERC-721 | 3 High, 3 Medium, 2 Low, 4 Info | [findings.md](./puppy-raffle-audit/findings.md) |

---

## Tools & Skills

```
Languages  : Solidity, Python, Bash
Frameworks : Foundry, Hardhat, OpenZeppelin
Analysis   : Slither, Mythril, manual review
Chains     : Ethereum, Polygon, Arbitrum, Base
```

---

## Want Your Protocol Audited?

Smart contract bugs cost the Web3 ecosystem billions of dollars every year — most of them preventable.

If you are building a DeFi protocol, NFT project, or any smart contract system and want an independent security review before launch, get in touch:

**Email: [allangithaiga5@gmail.com](mailto:allangithaiga5@gmail.com)**

I review code, write detailed reports, and help teams ship safer protocols.

---

*"Move fast and break things" is fine for web apps. In Web3, bugs are permanent and funds are irreversible. Audit first.*
