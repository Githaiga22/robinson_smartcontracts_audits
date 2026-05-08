# Smart Contracts

This folder contains the smart contracts for the Airtime project.

## Contracts

### **Airtime.sol**

This contract allows users to deposit USDC using a permit signature (EIP-2612) for gasless approvals and implements refund and treasury withdraw logic.

**Key Features:**
- Gasless USDC deposits using EIP-2612 permit signatures
- Automatic refund mechanism for failed airtime transactions
- Treasury-controlled withdrawals
- Event emission for payment tracking

**Functions:**
- `depositWithPermit()` - Deposit USDC with permit signature
- `refund()` - Refund USDC to users (treasury only)
- `withdrawTreasury()` - Withdraw funds to treasury (treasury only)

## Prerequisites

Before deploying, ensure you have:
- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed
- A funded wallet with ETH for gas fees
- RPC URL for your target network
- Private key of the deployer wallet (becomes treasury)

## Deployment

### Base Sepolia (Testnet)

```bash
forge script script/Deploy.s.sol \
  --rpc-url https://sepolia.base.org \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $BASESCAN_API_KEY \
  -vvvv
```

### Base Mainnet (Production)

```bash
forge script script/Deploy.s.sol \
  --rpc-url https://mainnet.base.org \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $BASESCAN_API_KEY \
  -vvvv
```

### Using Environment Variables

Create a `.env` file in the `smart_contracts` directory:

```bash
# Network RPC URLs
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
BASE_MAINNET_RPC_URL=https://mainnet.base.org

# Deployer private key
PRIVATE_KEY=0x...

# USDC Token Addresses
# Base Mainnet USDC: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
# Base Sepolia USDC: 0x036CbD53842c5426634e7929541eC2318f3dCF7e
USDC_TOKEN_ADDRESS=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

# Treasury wallet address (can perform refunds and withdrawals)
TREASURY_ADDRESS=0x...

# Basescan API key for contract verification
BASESCAN_API_KEY=your_basescan_api_key
```

Then deploy using:

```bash
# Load environment variables
source .env

# Deploy to Base Sepolia
forge script script/Deploy.s.sol \
  --rpc-url $BASE_SEPOLIA_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $BASESCAN_API_KEY \
  -vvvv

# Or deploy to Base Mainnet
forge script script/Deploy.s.sol \
  --rpc-url $BASE_MAINNET_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $BASESCAN_API_KEY \
  -vvvv
```

## Post-Deployment

After deployment:

1. **Save the contract address** - You'll see output like:
   ```
   Airtime contract deployed at: 0x...
   Treasury address: 0x...
   ```

2. **Update frontend environment variables** - Add to `frontend/.env`:
   ```
   NEXT_PUBLIC_AIRTIME_CONTRACT_ADDRESS=0x...
   TREASURY_PRIVATE_KEY=0x...  # Same as deployer (for refunds)
   ```

3. **Verify on Basescan**:
   - Base Sepolia: https://sepolia.basescan.org/address/YOUR_CONTRACT_ADDRESS
   - Base Mainnet: https://basescan.org/address/YOUR_CONTRACT_ADDRESS

4. **Test the deployment**:
   ```bash
   # Check treasury address
   cast call YOUR_CONTRACT_ADDRESS "treasury()(address)" --rpc-url $RPC_URL
   
   # Check deposit counter
   cast call YOUR_CONTRACT_ADDRESS "depositCounter()(uint256)" --rpc-url $RPC_URL
   ```

## Testing

Run the test suite:

```bash
forge test -vvv
```

Run specific test:

```bash
forge test --match-test testDepositWithPermit -vvvv
```

## Contract Addresses

### Base Sepolia (Testnet)
- Airtime Contract: `TBD`
- USDC Token: `0x036CbD53842c5426634e7929541eC2318f3dCF7e`

### Base Mainnet (Production)
- Airtime Contract: `0x...` (Update after deployment)
- USDC Token: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`

## Security Notes

⚠️ **Important Security Considerations:**

1. **Private Key Security**: Never commit private keys to version control
2. **Treasury Control**: The deployer address becomes the treasury with special privileges
3. **Mainnet Deployment**: Always test thoroughly on testnet before mainnet deployment
4. **Contract Verification**: Always verify contracts on Basescan for transparency
5. **Audit**: Consider a professional audit before handling significant funds

## Troubleshooting

**Error: "Invalid nonce"**
- Your wallet nonce might be out of sync. Try resetting it or checking pending transactions.

**Error: "Insufficient funds"**
- Ensure your deployer wallet has enough ETH for gas fees.

**Verification Failed**
- Check that your Basescan API key is correct
- Try manual verification on Basescan if automatic verification fails

**Transaction Failed**
- Increase gas limit: Add `--gas-limit 3000000` to the deployment command
- Check RPC URL is accessible and correct
