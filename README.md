# DO NOT RUN IN PRODUCTION, BETA EXPERIMENTAL SYSTEM.

B52z is a privacy-focused token mixing system built using zero-knowledge proofs. It allows users to make private transfers of B52Z tokens through deposit and withdrawal operations with ZK-SNARK proofs.

## Features

- 🛡️ **Privacy Protection**: Deposit and withdraw tokens without linking your identity
- 🔐 **ZK-SNARK Proofs**: Uses zero-knowledge proofs for cryptographic privacy
- 🌲 **Merkle Trees**: Efficient storage and verification of deposits
- 🔄 **Multiple Denominations**: Supports various token amounts for different use cases
- 🔌 **Modular Design**: Factory pattern for deploying new mixer instances

## Development Setup

### Requirements

- [Foundry](https://book.getfoundry.sh/getting-started/installation.html)
- [Solidity](https://docs.soliditylang.org/en/v0.8.25/)

### Installation

1. Clone the repository:
```bash
git clone <repo-url>
cd b52z-foundry
```

2. Install dependencies:
```bash
forge install
```

3. Copy the environment file and configure your settings:
```bash
cp .env.example .env
```

4. Build the project:
```bash
forge build
```

### Testing

Run the test suite:
```bash
forge test
```

Generate a gas report:
```bash
forge test --gas-report
```

Run coverage:
```bash
forge coverage
```

### Deployment

Deploy to a local Anvil network:
```bash
# Start a local node
make anvil

# In a separate terminal
make deploy-anvil
```

Deploy to a public network:
```bash
# Set environment variables in .env
make deploy
```

## Contract Architecture

- **B52Token**: ERC20 token used for the mixer
- **Groth16Verifier**: Verifies ZK-SNARK proofs for withdrawals
- **B52zFactory**: Creates and manages mixer instances
- **B52zInstance**: Individual mixer for a specific denomination
- **B52zRouter**: Routes transactions to appropriate instances
- **B52zDeployer**: Deploys and initializes the full system

## License

This project is licensed under the MIT License. 