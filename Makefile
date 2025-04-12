-include .env

.PHONY: all test clean deploy-anvil deploy

all: clean install build

# Clean build artifacts
clean:
	forge clean

# Install dependencies
install:
	forge install

# Build contracts
build:
	forge build

# Run tests
test:
	forge test

# Run coverage
coverage:
	forge coverage

# Generate gas report
gas-report:
	forge test --gas-report

# Run slither static analysis
slither:
	slither .

# Run local node
anvil:
	anvil -m "test test test test test test test test test test test junk"

# Deploy to local network
deploy-anvil:
	@forge script script/Deploy.s.sol:DeployB52z --fork-url http://localhost:8545 --broadcast

# Deploy to specific network
deploy:
	@forge script script/Deploy.s.sol:DeployB52z --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --verify -vvvv

# Format code
format:
	forge fmt 