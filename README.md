# Decentralized State Machine (DSM) v0.1.0-alpha.1

> **ALPHA RELEASE**: This is an alpha release intended for developer preview and testing. Not for production use.

A quantum-resistant decentralized state machine implementation with cryptographic verification and bilateral state isolation.

This guide will help you set up and run the Decentralized State Machine (DSM) project. For more comprehensive documentation, visit the [DSM Developer Documentation](https://decentralizedstatemachine.com/devdocs/index.html).

## Prerequisites

- **Rust** (1.76 or later) - Install from [https://rustup.rs/](https://rustup.rs/)
- **RocksDB**:
  - **Linux**: `sudo apt install librocksdb-dev` (Ubuntu/Debian)
  - **macOS**: `brew install rocksdb`
  - **Windows**: See [Windows Setup](#windows-setup) section
- **Docker** and **Docker Compose** (optional, for containerized deployment)
- **Git** for cloning the repository

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/dsm-project/dsm.git
   cd dsm
   ```

2. Copy the environment template:
   ```bash
   cp .env.template .env
   ```

3. Edit the `.env` file to configure your environment.

4. Build the project:
   - **Linux/macOS**:
     ```bash
     ./scripts/build.sh all
     ```
   - **Windows**:
     ```powershell
     .\scripts\build.ps1 -Target all
     ```

5. Run the core DSM node:
   - **Linux/macOS**:
     ```bash
     cd dsm
     cargo run --bin server
     ```
   - **Windows**:
     ```powershell
     cd dsm
     cargo run --bin server
     ```

## Windows Setup

Setting up RocksDB on Windows requires additional steps:

1. Install LLVM and Clang from [https://releases.llvm.org/download.html](https://releases.llvm.org/download.html)

2. Install Visual Studio 2019 or later with C++ support

3. Install CMake from [https://cmake.org/download/](https://cmake.org/download/)

4. Build RocksDB from source:
   ```powershell
   git clone https://github.com/facebook/rocksdb.git
   cd rocksdb
   mkdir build
   cd build
   cmake -G "Visual Studio 16 2019" -A x64 -DOPTDBG=1 -DPORTABLE=1 ..
   cmake --build . --config Release
   ```

5. Set environment variables:
   ```powershell
   $env:ROCKSDB_LIB_DIR="C:\Path\to\rocksdb\build\Release"
   ```

## Docker Deployment

For a containerized deployment:

1. Ensure Docker and Docker Compose are installed.

2. Build and run all services:
   ```bash
   docker-compose up -d
   ```

3. Access the services:
   - DSM API: http://localhost:7545
   - Grafana Dashboard: http://localhost:3000 (login with credentials from .env)

## Project Structure

- **dsm**: Core library and node implementation
  - `src/`: Source code
  - `bin/`: Binary entry points
  - `tests/`: Integration tests

- **dsm-storage-node**: Decentralized storage node implementation

- **dsm-ethereum-bridge**: Ethereum blockchain bridge

- **dsm-sdk**: Client SDK for applications

## Basic Usage Examples

### Creating an Identity

```rust
use dsm::initialize;
use dsm::identity::IdentityBuilder;

fn main() {
    // Initialize DSM
    initialize().unwrap();
    
    // Create a new identity
    let identity = IdentityBuilder::new()
        .with_name("Alice")
        .with_device_id("device-1")
        .build()
        .unwrap();
    
    println!("Created identity: {}", identity.id());
}
```

### Performing State Transitions

```rust
use dsm::initialize;
use dsm::core::state_machine::StateMachine;
use dsm::types::operations::Operation;

fn main() {
    // Initialize DSM
    initialize().unwrap();
    
    // Create a state machine
    let state_machine = StateMachine::new().unwrap();
    
    // Create a sample operation
    let operation = Operation::Generic {
        operation_type: "example".to_string(),
        message: "Hello, DSM!".to_string(),
        data: vec![1, 2, 3, 4],
    };
    
    // Apply the operation
    let genesis_state = state_machine.current_state().unwrap();
    let next_state = state_machine
        .apply_operation(
            genesis_state.clone(),
            operation,
            vec![0, 1, 2, 3], // Example entropy
        )
        .unwrap();
    
    println!("Created new state: {}", hex::encode(&next_state.hash));
}
```

## Configuration

The DSM system can be configured through environment variables or a configuration file.
See the `.env.template` file for available options.

## Next Steps

- Explore the [online documentation](https://decentralizedstatemachine.com/devdocs/index.html)
- Follow the [Developer Walkthrough](https://decentralizedstatemachine.com/devdocs/dsm_dev_walkthrough.html)
- Check out the [SDK Module Setup Guide](https://decentralizedstatemachine.com/devdocs/dsm_sdk_module_setup.html)
- Review [Use Cases](https://decentralizedstatemachine.com/usecasedocs/index.html) for practical application ideas
- Explore the [examples](examples/) directory
- Run the [test suite](tests/) to verify your setup

## Release Information

### Alpha Status

This v0.1.0-alpha.1 release includes the following limitations:

- **API Stability**: The API is not yet stable and may change in future releases
- **Security**: The implementation has undergone internal review but not external audit
- **Performance**: Not yet optimized for production workloads
- **Documentation**: Some components lack comprehensive documentation

### Release Goals

This alpha release is intended to:

1. Gather feedback from the developer community
2. Validate the core architecture and API design
3. Identify integration challenges in real-world scenarios
4. Build a community of early adopters and contributors

### What's Working

- Core state machine with deterministic transitions
- Quantum-resistant cryptographic primitives
- Bilateral state isolation
- Basic token operations
- Storage node replication
- SDK for application development

### Known Issues

- Some tests are marked as `#[ignore]` due to implementation details
- Error handling could be more consistent in some modules
- Performance optimization is still in progress
- Limited platform testing (primarily Linux and macOS)

## Troubleshooting

### Common Issues

1. **RocksDB not found**: Ensure RocksDB is properly installed for your platform.

2. **Compile errors**: Make sure you have the latest Rust toolchain installed.

3. **Port conflicts**: If services fail to start due to port conflicts, modify the ports in your `.env` file.

### Getting Help

- Open an issue on GitHub
- Check the [online documentation](https://decentralizedstatemachine.com/devdocs/index.html)
- Visit the [DSM website](https://decentralizedstatemachine.com) for more resources
- For help or commercial inquiries, email [info@decentralizedstatemachine.com](mailto:info@decentralizedstatemachine.com)
- Join our [Developer Telegram](https://t.me/+agb3_DHBcCI5MTkx) for development support and questions
- Follow us on [X/Twitter](https://x.com/state_machine_)

## Security

See [SECURITY.md](SECURITY.md) for information about the security model and vulnerability reporting process.

## License

This project is licensed under either of
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
