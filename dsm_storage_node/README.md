# DSM Storage Node

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/dsm-project/decentralized-state-machine/)

This module provides the storage node implementation for the Decentralized State Machine (DSM) system. It is responsible for securely storing and retrieving state data, providing resilient distributed storage capabilities with quantum-resistant encryption.

## Documentation

For comprehensive documentation on the DSM Protocol, please visit:
- [DSM Developer Documentation](https://decentralizedstatemachine.com/devdocs/index.html)
- [Protocol Specifications](https://decentralizedstatemachine.com/devdocs/dsm_protocol_specs.html)

## Features

- **Secure Storage**: All data is encrypted with quantum-resistant cryptography before storage
- **Distributed Architecture**: Multiple storage nodes can be deployed for redundancy and availability
- **Pruning Capabilities**: Intelligent data pruning to manage storage requirements
- **Blind Encryption**: Support for privacy-preserving data storage
- **Replication**: Automatic data replication across nodes
- **REST API**: Simple HTTP API for data access
- **Access Control**: Fine-grained permissions for data access

## Getting Started

### Prerequisites

- Rust 1.66.0 or later
- SQLite3 development libraries
- OpenSSL development libraries

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dsm-project/decentralized-state-machine.git
   cd decentralized-state-machine
   ```

2. Build the storage node:
   ```bash
   cargo build --release -p dsm-storage-node
   ```

3. Run the storage node:
   ```bash
   ./target/release/dsm-storage-node --config config.toml
   ```

## Configuration

The storage node is configured via a TOML file. An example configuration is provided in `config.toml`:

```toml
[storage]
# Storage backend ("memory", "sql")
backend = "sql"

# Database path (for SQL backend)
db_path = "storage.db"

# Maximum storage size in MB
max_size_mb = 1024

# Enable pruning of old data
enable_pruning = true

[network]
# Node identifier
node_id = "primary"

# Listen address
address = "0.0.0.0"

# Listen port
port = 8765

# Replication factor
replication_factor = 2

# Peer nodes (comma-separated)
peers = ""

[encryption]
# Enable quantum-resistant encryption
quantum_resistant = true

# Enable blind encryption
blind_encryption = false
```

## API Reference

The storage node exposes a REST API for data access. Here are the main endpoints:

- `GET /api/v1/data/:key` - Retrieve data by key
- `PUT /api/v1/data/:key` - Store data
- `DELETE /api/v1/data/:key` - Delete data
- `GET /api/v1/status` - Get node status
- `GET /api/v1/peers` - List connected peers

## Docker Deployment

A Dockerfile is provided for containerized deployment:

```bash
docker build -t dsm/storage-node -f dsm-storage-node/Dockerfile .
docker run -p 8765:8765 -v $(pwd)/config.toml:/etc/dsm/config.toml dsm/storage-node
```

For a complete deployment with multiple nodes, see the Docker Compose configuration in the root directory.

## Architecture

The storage node consists of several components:

- **API Layer**: Handles HTTP requests and authentication
- **Storage Engine**: Manages data persistence
- **Encryption Layer**: Handles data encryption/decryption
- **Distribution Layer**: Manages data replication across nodes
- **Pruning Service**: Manages data lifecycle and cleanup

## Developing and Extending

The storage node is designed to be extensible. You can:

- Implement new storage backends by implementing the `StorageBackend` trait
- Add new encryption schemes by extending the encryption module
- Implement custom access control policies

## License

This project is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](../CONTRIBUTING.md) file for guidelines.

## Related Use Cases

Explore use cases that leverage the DSM storage node:

- [IoT & Sensor Networks](https://decentralizedstatemachine.com/usecasedocs/iot_and_sensor_networks.html)
- [Mesh Grid Micropayments](https://decentralizedstatemachine.com/usecasedocs/mesh_grid_micropayments.html)

## Contact

For more information:
- Visit [decentralizedstatemachine.com](https://decentralizedstatemachine.com)
- Follow us on [X/Twitter](https://x.com/state_machine_)
- For help or commercial inquiries, email [info@decentralizedstatemachine.com](mailto:info@decentralizedstatemachine.com)
- Join our [Developer Telegram](https://t.me/+agb3_DHBcCI5MTkx) for development support and questions
