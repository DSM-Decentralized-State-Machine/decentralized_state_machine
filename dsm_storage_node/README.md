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
- **Replication**: Automatic data replication across nodes with configurable consistency levels
- **REST API**: Comprehensive HTTP API for data access and node management
- **Access Control**: Fine-grained permissions for data access with identity verification
- **Storage Strategies**: Multiple storage backends including SQLite, memory, and epidemic protocols
- **Data Sharding**: Support for distributing data across multiple nodes based on customizable sharding strategies
- **Metrics and Monitoring**: Built-in monitoring capabilities with Prometheus integration
- **Horizontal Scaling**: Designed to scale horizontally with zero downtime
- **Data Validation**: Pre-storage validation hooks for domain-specific validation logic

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
   cargo build --release -p dsm_storage_node
   ```

3. Run the storage node:
   ```bash
   ./target/release/dsm_storage_node --config config.toml
   ```

### Quick Start Example

To quickly set up a storage node with default settings:

```bash
# Start a storage node with default in-memory configuration
./target/release/dsm_storage_node --config config-memory.toml

# For an epidemic protocol storage node (distributed)
./target/release/dsm_storage_node --config config-epidemic.toml

# Run storage node with custom data directory
./target/release/dsm_storage_node --config config.toml --data-dir /path/to/data
```

## Configuration

The storage node is configured via a TOML file. An example configuration is provided in `config.toml`:

```toml
[storage]
# Storage backend ("memory", "sql", "epidemic")
backend = "sql"

# Database path (for SQL backend)
db_path = "storage.db"

# Maximum storage size in MB
max_size_mb = 1024

# Enable pruning of old data
enable_pruning = true

# Pruning interval in seconds
pruning_interval = 3600

# Sharding strategy ("hash", "range", "consistent", "none")
sharding_strategy = "consistent"

[network]
# Node identifier
node_id = "primary"

# Listen address
address = "0.0.0.0"

# Listen port
port = 8765

# Replication factor
replication_factor = 2

# Replication consistency level ("eventual", "quorum", "all")
consistency_level = "quorum"

# Peer nodes (comma-separated)
peers = ""

# Node discovery mechanism ("static", "multicast", "dns")
discovery = "static"

# Gossip protocol interval in seconds
gossip_interval = 30

[encryption]
# Enable quantum-resistant encryption
quantum_resistant = true

# Enable blind encryption
blind_encryption = false

# Encryption algorithm options ("aes256", "chacha20", "lattice")
algorithm = "lattice"

# Key rotation interval in hours (0 = disabled)
key_rotation_interval = 24

[api]
# Enable or disable API
enabled = true

# API authentication ("none", "token", "certificate")
auth_method = "token"

# Rate limiting (requests per minute)
rate_limit = 100

# CORS settings
cors_allowed_origins = "*"

[staking]
# Enable staking functionality
enabled = false

# Minimum stake amount
min_stake = 1000

# Reward rate (annual percentage)
reward_rate = 5.0
```

## API Reference

The storage node exposes a comprehensive REST API for data access and node management. Here's a detailed overview:

### Data Operations

- `GET /api/v1/data/:key` - Retrieve data by key
  - Query Parameters:
    - `consistency` - Consistency level for read (default: as configured)
  - Response: `200 OK` with data or `404 Not Found`

- `PUT /api/v1/data/:key` - Store data
  - Query Parameters:
    - `ttl` - Time-to-live in seconds (optional)
    - `replication` - Replication factor override (optional)
  - Request Body: Raw data or JSON object
  - Response: `201 Created` or `400 Bad Request`

- `DELETE /api/v1/data/:key` - Delete data
  - Response: `204 No Content` or `404 Not Found`

- `GET /api/v1/data/batch` - Batch retrieve multiple keys
  - Request Body: JSON array of keys
  - Response: `200 OK` with data mapping

- `POST /api/v1/data/batch` - Batch store multiple key-value pairs
  - Request Body: JSON mapping of keys to values
  - Response: `201 Created` or partial success details

### Node Management

- `GET /api/v1/status` - Get node status
  - Response: Detailed node status including:
    - Storage utilization
    - Network connectivity
    - Node uptime
    - Version information

- `GET /api/v1/peers` - List connected peers
  - Response: Array of peer information

- `POST /api/v1/peers` - Add new peer
  - Request Body: Peer connection details
  - Response: `201 Created` or `400 Bad Request`

- `GET /api/v1/metrics` - Prometheus-compatible metrics endpoint
  - Response: Plain text metrics in Prometheus format

### Administration

- `POST /api/v1/admin/prune` - Trigger manual data pruning
  - Request Parameters:
    - `older_than` - Prune data older than specified timestamp
  - Response: Pruning operation details

- `POST /api/v1/admin/keys/rotate` - Trigger encryption key rotation
  - Response: Key rotation operation status

- `GET /api/v1/admin/health` - Detailed health check for monitoring
  - Response: Component-level health status

## Client Library

The storage node includes a Rust client library for easy integration:

```rust
use dsm_storage_node::client::StorageClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
    let client = StorageClient::new("http://localhost:8765")?;
    
    // Store data
    client.put("my_key", b"Hello, DSM!").await?;
    
    // Retrieve data
    let data = client.get("my_key").await?;
    println!("Retrieved: {}", String::from_utf8_lossy(&data));
    
    // Delete data
    client.delete("my_key").await?;
    
    Ok(())
}
```

## Docker Deployment

A Dockerfile is provided for containerized deployment:

```bash
docker build -t dsm/storage-node -f dsm_storage_node/Dockerfile .
docker run -p 8765:8765 -v $(pwd)/config.toml:/etc/dsm/config.toml dsm/storage-node
```

For a complete deployment with multiple nodes, see the Docker Compose configuration in the root directory.

### Multi-Node Docker Deployment

To deploy a cluster of storage nodes using Docker Compose:

```bash
# From the project root directory
docker-compose -f docker-compose.yml up -d
```

This will spin up multiple storage nodes configured for replication and high availability.

## Architecture

The storage node consists of several components:

### Core Components

- **API Layer**: Handles HTTP requests and authentication
  - RESTful interface for data operations
  - Node management endpoints
  - Rate limiting and access control

- **Storage Engine**: Manages data persistence
  - Pluggable backend implementations (SQLite, Memory, Epidemic)
  - Indexing for fast key-based lookups
  - Optimized for different workload patterns

- **Encryption Layer**: Handles data encryption/decryption
  - Post-quantum cryptographic algorithms
  - Key management and rotation
  - Blind encryption for zero-knowledge storage

- **Distribution Layer**: Manages data across nodes
  - Consistent hashing for distributed storage
  - Replication and fault tolerance
  - Epidemic protocols for eventual consistency

- **Pruning Service**: Manages data lifecycle
  - TTL-based expiration
  - Space reclamation strategies
  - Historical data archiving options

### Advanced Features

- **Sharding Manager**: Handles data partitioning across nodes
  - Hash-based partitioning
  - Range-based partitioning
  - Consistent hashing with virtual nodes

- **Consensus Module**: Ensures data consistency
  - Configurable consistency levels
  - Quorum-based writes and reads
  - Conflict resolution strategies

- **Monitoring System**: Tracks node health and performance
  - Prometheus metrics export
  - Storage utilization tracking
  - Network performance monitoring

## Developing and Extending

The storage node is designed to be extensible. You can:

### Implementing Custom Components

#### Custom Storage Backend

```rust
use dsm_storage_node::storage::{StorageBackend, StorageResult};

pub struct MyCustomStorage {
    // Your storage implementation details
}

impl StorageBackend for MyCustomStorage {
    fn get(&self, key: &[u8]) -> StorageResult<Vec<u8>> {
        // Your implementation
    }
    
    fn put(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        // Your implementation
    }
    
    fn delete(&mut self, key: &[u8]) -> StorageResult<()> {
        // Your implementation
    }
    
    // Implement other required methods...
}
```

#### Custom Sharding Strategy

```rust
use dsm_storage_node::distribution::{ShardingStrategy, NodeAssignment};

pub struct MyShardingStrategy {
    // Your strategy details
}

impl ShardingStrategy for MyShardingStrategy {
    fn assign_node(&self, key: &[u8], nodes: &[NodeInfo]) -> NodeAssignment {
        // Your implementation
    }
    
    // Implement other required methods...
}
```

## Performance Considerations

The DSM Storage Node is optimized for:

- **High Throughput**: Can handle thousands of operations per second
- **Low Latency**: Fast response times for data operations
- **Horizontal Scalability**: Add more nodes to increase capacity
- **Resilience**: Continues operating despite node failures

Typical performance metrics (on reference hardware):
- Read operations: ~10,000 ops/sec
- Write operations: ~5,000 ops/sec
- P99 latency: <20ms for reads, <50ms for writes
- Storage efficiency: ~20% overhead for replication and indexing

## Benchmarking

The storage node includes benchmarking tools for performance testing:

```bash
# Run basic benchmark
cargo bench -p dsm-storage-node

# Run specific benchmark scenario
cargo bench -p dsm-storage-node -- throughput
```

## Troubleshooting

Common issues and their solutions:

- **Connection Refused**: Verify the node is running and accessible from your network
- **Authentication Failures**: Check API token or certificate configuration
- **Slow Performance**: Consider adjusting shard count or consistency level
- **High Memory Usage**: Review storage backend configuration and tune GC parameters
- **Replication Failures**: Ensure peer nodes are accessible and properly configured

## License

This project is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](../CONTRIBUTING.md) file for guidelines.

### Testing

```bash
# Run unit tests
cargo test -p dsm-storage-node

# Run integration tests
cargo test -p dsm-storage-node -- --test integration
```

## Related Use Cases

Explore use cases that leverage the DSM storage node:

- [IoT & Sensor Networks](https://decentralizedstatemachine.com/usecasedocs/iot_and_sensor_networks.html)
- [Mesh Grid Micropayments](https://decentralizedstatemachine.com/usecasedocs/mesh_grid_micropayments.html)
- [Distributed Gaming State](https://decentralizedstatemachine.com/usecasedocs/gaming_state.html)
- [Supply Chain Tracking](https://decentralizedstatemachine.com/usecasedocs/supply_chain.html)
- [Decentralized Identity Management](https://decentralizedstatemachine.com/usecasedocs/identity_management.html)

## Contact

For more information:
- Visit [decentralizedstatemachine.com](https://decentralizedstatemachine.com)
- Follow us on [X/Twitter](https://x.com/state_machine_)
- For help or commercial inquiries, email [info@decentralizedstatemachine.com](mailto:info@decentralizedstatemachine.com)
- Join our [Developer Telegram](https://t.me/+agb3_DHBcCI5MTkx) for development support and questions
