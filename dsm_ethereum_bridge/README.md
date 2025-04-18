# DSM Ethereum Bridge

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/dsm-project/decentralized-state-machine/)

The DSM Ethereum Bridge provides interoperability between the Decentralized State Machine (DSM) system and Ethereum (or any EVM-compatible blockchain). This bridge enables secure state synchronization, cross-chain verification, and asset transfers between DSM and EVM chains.

## Documentation

For comprehensive documentation on the DSM Protocol, please visit:
- [DSM Developer Documentation](https://decentralizedstatemachine.com/devdocs/index.html)
- [Integration Patterns](https://decentralizedstatemachine.com/devdocs/dsm_integration_patterns.html)

## Features

- **Bidirectional State Anchoring**: Anchor DSM states to Ethereum and vice versa
- **Cross-Chain Verification**: Verify DSM states from Ethereum smart contracts
- **Asset Bridging**: Transfer assets between DSM and Ethereum networks
- **Quantum-Resistant Security**: Implements post-quantum secure verification methods
- **Configurable Finality**: Adjustable confirmation thresholds for chain finality
- **Multi-Chain Support**: Compatible with any EVM-based chain (Ethereum, Polygon, Avalanche, etc.)
- **Event Monitoring**: Listens for relevant events on both networks

## Getting Started

### Prerequisites

- Rust 1.66.0 or later
- Ethereum RPC endpoint (Infura, Alchemy, local node, etc.)
- Deployed DSM network

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dsm-project/decentralized-state-machine.git
   cd decentralized-state-machine
   ```

2. Build the Ethereum bridge:
   ```bash
   cargo build --release -p dsm-ethereum-bridge
   ```

3. Run the bridge:
   ```bash
   ./target/release/dsm-ethereum-bridge --config config.toml
   ```

## Configuration

The bridge is configured via environment variables or a configuration file:

```toml
[ethereum]
# Ethereum RPC URL (required)
rpc_url = "https://network.example.com/v2/YOUR_API_KEY"

# Chain ID
chain_id = 1

# Required confirmations for Ethereum finality
confirmations = 6

# Contract addresses
anchor_contract = "0x1234..."
token_bridge_contract = "0x5678..."

[dsm]
# DSM node endpoint
endpoint = "http://dsm-core:7545"

# Polling interval in seconds
poll_interval = 10

[bridge]
# Bridge operator private key (DO NOT SHARE!)
operator_key = "${BRIDGE_OPERATOR_KEY}"

# Log level (debug, info, warn, error)
log_level = "info"

# Maximum gas price (in gwei)
max_gas_price = 100
```

## Smart Contracts

The bridge interacts with several Ethereum smart contracts:

1. **DSMAnchor.sol**: Anchors DSM state roots to Ethereum for verification
2. **DSMTokenBridge.sol**: Handles token bridging between chains
3. **DSMVerifier.sol**: Verifies DSM state transitions on Ethereum

The Solidity contracts are located in the `solidity/` directory.

## Architecture

The Ethereum bridge consists of several components:

- **State Manager**: Monitors and synchronizes state between chains
- **Anchor Handler**: Manages the anchoring of state roots
- **Event Processor**: Listens for and processes relevant events
- **Relayer**: Submits transactions to both networks

The bridge operates as a daemon that continuously monitors both networks for relevant events and state changes.

## Deployment

### Docker

A Dockerfile is provided for containerized deployment:

```bash
docker build -t dsm/ethereum-bridge -f dsm-ethereum-bridge/Dockerfile .
docker run -p 8768:8768 -v $(pwd)/config.toml:/etc/dsm/config.toml dsm/ethereum-bridge
```

For a complete deployment with DSM and the bridge, see the Docker Compose configuration in the root directory.

## Security Considerations

- The bridge operator key should be stored securely
- Configure appropriate confirmation thresholds based on your security requirements
- For production environments, consider running multiple bridge instances
- Implement monitoring and alerting for bridge operations

## Development and Testing

To run tests:

```bash
cargo test -p dsm-ethereum-bridge
```

To deploy contracts to a local test network:

```bash
cd solidity
npx hardhat deploy --network localhost
```

## License

This project is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](../CONTRIBUTING.md) file for guidelines.

## Contact

For more information:
- Visit [decentralizedstatemachine.com](https://decentralizedstatemachine.com)
- Follow us on [X/Twitter](https://x.com/state_machine_)
- For help or commercial inquiries, email [info@decentralizedstatemachine.com](mailto:info@decentralizedstatemachine.com)
- Join our [Developer Telegram](https://t.me/+agb3_DHBcCI5MTkx) for development support and questions
