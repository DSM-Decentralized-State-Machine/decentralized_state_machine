# DSM v0.1.0-alpha.1 Release

This is the initial alpha release of the Decentralized State Machine (DSM), a quantum-resistant decentralized state machine implementation with cryptographic verification and bilateral state isolation.

## Alpha Status Notice

This is an **alpha release** intended for developer preview and testing. Please do not use in production environments.

## What's Included

- Core state machine with deterministic transitions
- Quantum-resistant cryptographic primitives (SPHINCS+, Kyber)
- Bilateral state isolation
- Hash chain verification
- Basic token operations
- Storage node replication
- SDK for application development

## Getting Started

Download and extract the release archive, then follow the instructions in the `INSTALL.md` file.

```bash
# Clone the repository
git clone https://github.com/dsm-project/dsm.git
cd dsm

# Check out the release tag
git checkout v0.1.0-alpha.1

# Install dependencies (on Debian/Ubuntu)
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev librocksdb-dev clang cmake

# Build the project
cargo build --release
```

For more detailed instructions, see the [INSTALL.md](INSTALL.md) file included in the release package.

## Known Issues

- Some tests are marked as `#[ignore]` due to implementation details
- Error handling could be more consistent in some modules
- Performance optimization is still in progress
- Limited platform testing (primarily Linux and macOS)

## Checksums

SHA-256:
```
209100ed18868574cbfff8626c55fe6dffe063b846806a2bfbed30e496bcf907  dsm-0.1.0-alpha.1.tar.gz
```

## Feedback and Support

We welcome your feedback on this alpha release! Please report any issues or suggestions through:

- GitHub Issues: https://github.com/dsm-project/dsm/issues
- Developer Telegram: https://t.me/+agb3_DHBcCI5MTkx
- Email: info@decentralizedstatemachine.com

## License

This project is licensed under either of:
- Apache License, Version 2.0
- MIT License

at your option.
