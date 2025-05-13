# DSM SDK (Software Development Kit)

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/dsm-project/decentralized-state-machine/)

The DSM Software Development Kit (SDK) provides a high-level interface for building applications on top of the Decentralized State Machine system. It abstracts the complexity of cryptographic operations, state transitions, and network communication to enable easy integration with the DSM infrastructure.

## Documentation

For comprehensive documentation on the DSM SDK, please visit:
- [DSM Developer Documentation](https://decentralizedstatemachine.com/devdocs/index.html)
- [SDK Module Setup Guide](https://decentralizedstatemachine.com/devdocs/dsm_sdk_module_setup.html)
- [API Reference](https://decentralizedstatemachine.com/devdocs/dsm_dev_reference.html)

## Features

- **Identity Management**: Create, manage, and recover cryptographic identities
- **State Machine Integration**: Interact with the DSM state machine for secure state transitions
- **Smart Commitments**: Create and verify cryptographic commitments for state validation
- **Token Operations**: Manage tokens and transactions within the DSM ecosystem
- **Wallet Functionality**: Secure key storage and transaction signing
- **Contact Management**: Manage peer relationships and secure communications
- **Cross-Platform**: Works on desktop, mobile, and server environments
- **Bluetooth Support**: Optional Bluetooth transport for device-to-device communication
- **Quantum Resistance**: All cryptographic operations use quantum-resistant algorithms

## Getting Started

### Prerequisites

- Rust 1.66.0 or later
- Connection to a DSM node (local or remote)

### Installation

#### As a Dependency

Add the SDK to your Cargo.toml:

```toml
[dependencies]
dsm-sdk = { git = "https://github.com/dsm-project/decentralized-state-machine.git" }
```

#### Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/dsm-project/decentralized-state-machine.git
   cd decentralized-state-machine
   ```

2. Build the SDK:
   ```bash
   cargo build --release -p dsm_sdk
   ```

## Usage Examples

### Identity Creation

```rust
use dsm_sdk::identity_sdk::IdentitySDK;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the identity SDK
    let identity_sdk = IdentitySDK::new("my_device_id")?;
    
    // Create a new identity
    let identity = identity_sdk.create_identity("My Identity")?;
    
    // Generate a mnemonic for recovery
    let mnemonic = identity_sdk.generate_recovery_mnemonic()?;
    println!("Save this mnemonic: {}", mnemonic);
    
    Ok(())
}
```

### State Transitions

```rust
use dsm_sdk::core_sdk::CoreSDK;
use dsm_sdk::hashchain_sdk::HashchainSDK;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the core SDK
    let core_sdk = CoreSDK::new()?;
    
    // Get the hashchain SDK
    let hashchain_sdk = HashchainSDK::new(core_sdk.clone())?;
    
    // Create an operation
    let operation = hashchain_sdk.create_operation(
        "example_operation",
        "Example operation description",
        vec![1, 2, 3, 4]
    )?;
    
    // Apply the operation to create a new state
    let new_state = hashchain_sdk.apply_operation(operation)?;
    println!("New state created: {:?}", new_state);
    
    Ok(())
}
```

### Token Operations

```rust
use dsm_sdk::token_sdk::TokenSDK;
use dsm_sdk::core_sdk::CoreSDK;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the core SDK
    let core_sdk = CoreSDK::new()?;
    
    // Get the token SDK
    let token_sdk = TokenSDK::new(core_sdk.clone())?;
    
    // Create a token
    let token_id = token_sdk.create_token(
        "MyToken",
        "A demonstration token",
        1_000_000
    )?;
    
    // Transfer tokens
    token_sdk.transfer(
        token_id,
        "recipient_identity_id",
        1000,
        Some("Transfer memo")
    )?;
    
    Ok(())
}
```

### Bluetooth Communication

```rust
use dsm_sdk::bluetooth_transport::BluetoothTransport;
use dsm_sdk::bluetooth_transport::BluetoothMode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a Bluetooth transport in central mode
    let transport = BluetoothTransport::new(
        BluetoothMode::Central,
        "my_device_id",
        "My Device"
    );
    
    // Start scanning for devices
    transport.start_scanning().await?;
    
    // Wait for discovered devices
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    
    // Get discovered devices
    let devices = transport.get_discovered_devices();
    for device in devices {
        println!("Found device: {} ({})", device.name, device.id);
    }
    
    // Connect to a device
    if !devices.is_empty() {
        transport.connect_to_device(&devices[0].id).await?;
        println!("Connected to {}", devices[0].name);
    }
    
    Ok(())
}
```

## Architecture

The SDK is organized into several modules:

- **Core SDK**: Foundation for all other modules
- **Identity SDK**: Identity management and verification
- **Hashchain SDK**: Interaction with the DSM state machine
- **Token SDK**: Token management and transactions
- **Smart Commitment SDK**: Cryptographic commitments
- **Wallet SDK**: Key management and secure storage
- **Contact SDK**: Peer relationship management
- **Bluetooth Transport**: Device-to-device communication

## Example Applications

The SDK includes several example implementations:

- **Pokemon Trading**: A demonstration of secure digital asset trading using the DSM system
- **Bluetooth Device Communication**: Example of device pairing and communication

## Advanced Features

### Cross-Platform Support

The SDK is designed to work on multiple platforms:

- **Desktop**: Linux, macOS, Windows
- **Mobile**: Android (via JNI), iOS (future support)
- **Web**: WebAssembly (future support)

### Quantum Resistance

All cryptographic operations use quantum-resistant algorithms:

- SPHINCS+ for signatures
- Kyber for key exchange
- BLAKE3 and SHA3 for hashing

## Use Cases

Explore detailed use cases of the DSM SDK in real-world applications:

- [Gaming & Interactive Worlds](https://decentralizedstatemachine.com/usecasedocs/gaming.html)
- [IoT & Sensor Networks](https://decentralizedstatemachine.com/usecasedocs/iot_and_sensor_networks.html)
- [P2P Decentralized Exchange](https://decentralizedstatemachine.com/usecasedocs/p2p_dex.html)
- [Offline Credentialing & Identity](https://decentralizedstatemachine.com/usecasedocs/offline_credentialing_and_identity.html)

See the [DSM Use Cases](https://decentralizedstatemachine.com/usecasedocs/index.html) for more examples.

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
