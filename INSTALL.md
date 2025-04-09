# DSM Installation Guide

This document provides detailed instructions for installing the Decentralized State Machine (DSM) v0.1.0-alpha.1.

## Prerequisites

### Required Software

- **Rust** (1.76.0 or later) - Install via [rustup](https://rustup.rs/)
- **Git** (2.0 or later)
- **RocksDB** (6.29.3 or later) - See platform-specific instructions below

### System Requirements

- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 1GB minimum for core components, plus storage for state data
- **Network**: Internet connectivity for initial setup and peer-to-peer communication

## Platform-Specific Setup

### Linux (Debian/Ubuntu)

1. Install system dependencies:
   ```bash
   sudo apt update
   sudo apt install -y build-essential pkg-config libssl-dev librocksdb-dev clang cmake
   ```

2. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

### macOS

1. Install Homebrew if not already installed:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. Install dependencies:
   ```bash
   brew install openssl rocksdb cmake
   ```

3. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

### Windows

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with C++ support

2. Install [LLVM](https://releases.llvm.org/download.html)

3. Install [CMake](https://cmake.org/download/)

4. Install [Git for Windows](https://gitforwindows.org/)

5. Install Rust:
   ```powershell
   curl -sSf https://sh.rustup.rs | sh
   ```

6. Build RocksDB from source (see Windows-specific instructions in README.md)

## Installation Methods

### Method 1: From Source (Recommended for Alpha)

1. Clone the repository:
   ```bash
   git clone https://github.com/dsm-project/dsm.git
   cd dsm
   ```

2. Checkout the release version:
   ```bash
   git checkout v0.1.0-alpha.1
   ```

3. Build the project:
   ```bash
   cargo build --release
   ```

4. Install to your system (optional):
   ```bash
   cargo install --path dsm
   ```

### Method 2: From Release Package

1. Download the release package from the releases page:
   ```bash
   curl -LO https://github.com/dsm-project/dsm/releases/download/v0.1.0-alpha.1/dsm-0.1.0-alpha.1.tar.gz
   ```

2. Verify the checksum:
   ```bash
   curl -LO https://github.com/dsm-project/dsm/releases/download/v0.1.0-alpha.1/dsm-0.1.0-alpha.1.sha256
   shasum -a 256 -c dsm-0.1.0-alpha.1.sha256
   ```

3. Extract the package:
   ```bash
   tar -xzf dsm-0.1.0-alpha.1.tar.gz
   cd dsm-0.1.0-alpha.1
   ```

4. Run the installation script:
   ```bash
   ./install.sh
   ```

### Method 3: Using Cargo

*Note: This method will be available in future releases.*

```bash
cargo install dsm --version 0.1.0-alpha.1
```

## Configuration

1. Create a configuration file:
   ```bash
   cp config/dsm.env.template ~/.dsm.env
   ```

2. Edit the configuration file to match your environment:
   ```bash
   nano ~/.dsm.env
   ```

## Verification

Verify your installation by running:

```bash
dsm-cli --version
```

Should output: `DSM CLI v0.1.0-alpha.1`

## Running DSM

### Start the DSM Server

```bash
dsm-server --config ~/.dsm.env
```

### Using the CLI

```bash
dsm-cli status
```

## Docker Deployment

1. Customize the docker-compose file:
   ```bash
   cp config/docker-compose.yml ./
   ```

2. Start the containers:
   ```bash
   docker-compose up -d
   ```

## Common Issues

### RocksDB Compilation Errors

If you encounter errors related to RocksDB:

1. Ensure you have the latest version installed
2. Try setting environment variables:
   ```bash
   export ROCKSDB_LIB_DIR=/usr/local/lib
   export ROCKSDB_INCLUDE_DIR=/usr/local/include
   ```

### Permission Denied Errors

If you see "permission denied" errors:

```bash
sudo chown -R $(whoami) ~/.dsm
chmod +x bin/dsm-server bin/dsm-cli
```

## Next Steps

- Explore the examples in the `examples/` directory
- Read the documentation in the `docs/` directory
- Join the developer community at [https://t.me/+agb3_DHBcCI5MTkx](https://t.me/+agb3_DHBcCI5MTkx)

## Getting Help

For troubleshooting and support:

- File issues on GitHub
- Join the developer community Telegram
- Email support@decentralizedstatemachine.com
