# DSM Storage Node Setup Guide

This guide will walk you through the process of setting up and running a Decentralized State Machine (DSM) storage node from scratch.

## Overview

The DSM storage node is a core component of the Decentralized State Machine network, providing secure, distributed storage for state data, policies, and unilateral transactions.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (1.66.0 or later)
- SQLite3 development libraries
- OpenSSL development libraries

## Directory Structure

Before starting, ensure you have the following directory structure:

```
DSM_Decentralized_State_Machine/
├── data/               # For storing the database and other data
├── keys/               # For security keys
│   ├── node.key        # Private key for the node
│   ├── node.pub        # Public key for the node
│   └── authorized_keys.json # Keys authorized to access the node
└── logs/               # For log files
```

## Step 1: Create Required Directories

Create the necessary directories for your storage node:

```bash
mkdir -p data logs keys
```

## Step 2: Generate Security Keys

The storage node requires security keys for secure communication. Create them with:

```bash
# Generate private key
openssl genrsa -out keys/node.key 2048

# Extract public key
openssl rsa -in keys/node.key -pubout -out keys/node.pub

# Create empty authorized keys file
echo "[]" > keys/authorized_keys.json
```

## Step 3: Configure Your Storage Node

Create a configuration file (config.toml) to define your storage node's behavior. You can use the template below:

```toml
# DSM Storage Node Configuration

# API configuration
[api]
bind_address = "127.0.0.1"
port = 8080
enable_cors = false
enable_rate_limits = true
max_body_size = 10485760  # 10 MB

# Node information
[node]
id = "node1"
name = "DSM Storage Node 1"
region = "us-west"
operator = "DSM Dev Team"
version = "0.1.0"
description = "Development storage node for DSM"
public_key = ""
endpoint = "http://127.0.0.1:8080"

# Storage configuration
[storage]
engine = "sqlite"  # Options: "sqlite", "memory", "epidemic"
capacity = 10737418240  # 10 GB
data_dir = "./data"
database_path = "./data/storage.db"
assignment_strategy = "DeterministicHashing"
replication_strategy = "FixedReplicas"
replica_count = 3
min_regions = 2
default_ttl = 0  # No expiration by default
enable_pruning = true
pruning_interval = 3600  # 1 hour
# Epidemic storage specific settings (only needed when engine = "epidemic")
gossip_interval_ms = 5000  # 5 seconds between gossip rounds
anti_entropy_interval_ms = 30000  # 30 seconds for full synchronization
max_entries_per_gossip = 100  # Maximum entries per gossip message
gossip_fanout = 3  # Number of peers to gossip with each round
enable_small_world = true  # Use small-world topology
max_immediate_neighbors = 16  # Maximum close neighbors
max_long_links = 15  # Maximum long-distance links

# Network configuration
[network]
listen_addr = "0.0.0.0"
public_endpoint = "http://localhost:8080"
port = 8080
max_connections = 1000
connection_timeout = 30
bootstrap_nodes = [
    "http://bootstrap1.dsm.network:8080",
    "http://bootstrap2.dsm.network:8080"
]
enable_discovery = true
discovery_interval = 300
max_peers = 100

# Security configuration
[security]
private_key_path = "./keys/node.key"
public_key_path = "./keys/node.pub"
enable_tls = false
tls_cert_path = "./keys/node.crt"
tls_key_path = "./keys/node.key"
require_auth = false
authorized_keys_path = "./keys/authorized_keys.json"
enable_rate_limits = true
rate_limit = 100

# Staking configuration
[staking]
enable_staking = false
dsm_endpoint = "http://dsm.network:8080"
staking_address = ""
validator_id = ""
min_stake = 1000
auto_compound = true

# Logging configuration
[logging]
level = "info"
file_path = "./logs/node.log"
format = "text"
console_logging = true
```

## Step 4: Configure and Use Different Storage Engines

The DSM storage node supports multiple storage engines to meet different needs. Here's how to configure and use each one:

### SQLite Storage (Default)

SQLite storage is persistent and ideal for production environments where data durability is important.

```toml
# In your config.toml
[storage]
engine = "sqlite"
database_path = "./data/storage.db"
# Other storage settings...
```

Run the node with:
```bash
./target/release/dsm-storage-node --config config.toml run
```

### In-Memory Storage

In-memory storage is fast but volatile (data is lost when the node restarts). It's ideal for testing and development.

```toml
# In your config.toml or create a new config-memory.toml
[storage]
engine = "memory"
# Other storage settings...
```

Run the node with:
```bash
./target/release/dsm-storage-node --config config-memory.toml run
```

### Epidemic Storage (Distributed)

Epidemic storage provides a distributed storage solution using gossip protocols with a small-world topology. It's ideal for large-scale deployments requiring high availability and fault tolerance.

Create a specific configuration file for epidemic storage (e.g., config-epidemic.toml):

```toml
# In config-epidemic.toml
[storage]
engine = "epidemic"
data_dir = "./data"
database_path = "./data/epidemic-storage.db"
# Epidemic-specific settings
gossip_interval_ms = 5000  # 5 seconds between gossip rounds
anti_entropy_interval_ms = 30000  # 30 seconds for synchronization
max_entries_per_gossip = 100  # Maximum entries per gossip message
gossip_fanout = 3  # Number of peers to gossip with each round
enable_small_world = true  # Use small-world topology
max_immediate_neighbors = 16  # Maximum close neighbors
max_long_links = 15  # Maximum long-distance links

[network]
# Network settings are especially important for epidemic storage
listen_addr = "0.0.0.0"
public_endpoint = "http://localhost:8080"  # Change to your public IP in production
bootstrap_nodes = [
    "http://bootstrap1.dsm.network:8080",
    "http://bootstrap2.dsm.network:8080"
]
enable_discovery = true
```

Run the node with:
```bash
./target/release/dsm-storage-node --config config-epidemic.toml run
```

#### Testing Multi-Node Epidemic Storage

To properly test epidemic storage, you should run multiple nodes that can communicate with each other:

1. Create multiple configuration files with different ports and node IDs:
   - config-epidemic-node1.toml (port 8080)
   - config-epidemic-node2.toml (port 8081)
   - config-epidemic-node3.toml (port 8082)

2. Ensure each node lists the others as bootstrap nodes.

3. Run each node in a separate terminal:
   ```bash
   # Terminal 1
   ./target/release/dsm-storage-node --config config-epidemic-node1.toml run
   
   # Terminal 2
   ./target/release/dsm-storage-node --config config-epidemic-node2.toml run
   
   # Terminal 3
   ./target/release/dsm-storage-node --config config-epidemic-node3.toml run
   ```

4. Test data propagation by storing data in one node and verifying it propagates to the others:
   ```bash
   # Store data in node 1
   curl -X PUT http://localhost:8080/api/v1/data/test-key -d '{"value":"test data"}'
   
   # After a brief delay for gossip propagation (5-10 seconds)...
   
   # Verify data exists in node 2
   curl http://localhost:8081/api/v1/data/test-key
   
   # Verify data exists in node 3
   curl http://localhost:8082/api/v1/data/test-key
   ```

You can use the included test script for automated testing:
```bash
./test_epidemic_storage.sh
```

## Step 5: Build the Storage Node

To build the DSM storage node from source, follow these steps:

```bash
# Clone the repository if you haven't already
git clone https://github.com/dsm-project/decentralized-state-machine.git
cd DSM_Decentralized_State_Machine

# Update dependencies
rustup update

# Build the storage node in release mode
cargo build --release -p dsm-storage-node

# Verify the build
ls -la target/release/dsm-storage-node
```

This will compile the storage node with optimizations for production use. The executable will be located at `target/release/dsm-storage-node`.

For macOS users, you can use the provided script to create an optimized build:
```bash
./scripts/macos_release.sh
```

For Linux users:
```bash
./scripts/build.sh --release
```

## Step 6: Run the Storage Node

After building, you can run the DSM storage node with your configuration:

```bash
./target/release/dsm-storage-node --config dsm-storage-node/config.toml run
```

If successful, you should see output like this:

```
INFO dsm_storage_node: Loading configuration from "dsm-storage-node/config.toml"
INFO dsm_storage_node: Configuration loaded successfully
INFO dsm_storage_node: Running without explicit stake
INFO dsm_storage_node: Initializing SQLite storage engine at ./data/storage.db
INFO dsm_storage_node: Initializing networking on 0.0.0.0:8080
INFO dsm_storage_node: Connecting to bootstrap nodes: ["http://bootstrap1.dsm.network:8080", "http://bootstrap2.dsm.network:8080"]
INFO dsm_storage_node: Starting API server on 127.0.0.1:8080
INFO dsm_storage_node: DSM Storage Node running. Press Ctrl+C to stop.
```

## Step 6: Running with Staking (Optional)

If you want to run the node with staking (which may provide rewards):

```bash
./target/release/dsm-storage-node --config dsm-storage-node/config.toml stake --amount 1000
```

Note: Staking requires a minimum of 1000 tokens.

## Understanding the Configuration Options

### API Configuration

- `bind_address`: The IP address the API server binds to
- `port`: The port the API server listens on
- `enable_cors`: Whether to enable Cross-Origin Resource Sharing
- `enable_rate_limits`: Whether to enable rate limiting for API requests
- `max_body_size`: Maximum size of request bodies in bytes

### Node Information

- `id`: Unique identifier for the node
- `name`: Human-readable name for the node
- `region`: Geographic region of the node
- `operator`: Entity operating the node
- `description`: Additional information about the node
- `endpoint`: Public endpoint for other nodes to connect to

### Storage Configuration

- `engine`: Storage backend ("sqlite", "memory", "epidemic", "distributed")
- `capacity`: Maximum storage capacity in bytes
- `data_dir`: Directory for storing data
- `database_path`: Path to the database file
- `assignment_strategy`: Strategy for assigning data to nodes
- `replication_strategy`: Strategy for replicating data
- `replica_count`: Number of replicas to maintain
- `min_regions`: Minimum number of regions to replicate data to
- `default_ttl`: Default time-to-live for data entries
- `enable_pruning`: Whether to automatically prune expired data
- `pruning_interval`: Interval for pruning in seconds

### Network Configuration

- `listen_addr`: IP address to listen on for network connections
- `public_endpoint`: Public endpoint for other nodes to connect to
- `port`: Port to listen on for network connections
- `max_connections`: Maximum number of concurrent connections
- `connection_timeout`: Connection timeout in seconds
- `bootstrap_nodes`: List of nodes to connect to for bootstrapping
- `enable_discovery`: Whether to enable automatic peer discovery
- `discovery_interval`: Interval for peer discovery in seconds
- `max_peers`: Maximum number of peers to maintain

### Security Configuration

- `private_key_path`: Path to the private key file
- `public_key_path`: Path to the public key file
- `enable_tls`: Whether to enable TLS encryption
- `tls_cert_path`: Path to the TLS certificate
- `tls_key_path`: Path to the TLS key
- `require_auth`: Whether to require authentication
- `authorized_keys_path`: Path to the authorized keys file
- `enable_rate_limits`: Whether to enable rate limiting
- `rate_limit`: Rate limit in requests per minute

### Staking Configuration

- `enable_staking`: Whether to enable staking
- `dsm_endpoint`: Endpoint for the DSM network
- `staking_address`: Address for staking
- `validator_id`: Validator ID
- `min_stake`: Minimum stake amount
- `auto_compound`: Whether to automatically compound rewards

### Logging Configuration

- `level`: Log level ("debug", "info", "warn", "error")
- `file_path`: Path to the log file
- `format`: Log format ("text", "json")
- `console_logging`: Whether to log to the console

## API Endpoints

Once running, the storage node exposes these REST API endpoints:

- `GET /api/v1/data/:key` - Retrieve data by key
- `PUT /api/v1/data/:key` - Store data
- `DELETE /api/v1/data/:key` - Delete data
- `GET /api/v1/status` - Get node status
- `GET /api/v1/peers` - List connected peers

## Troubleshooting

### Cannot Connect to Bootstrap Nodes

If you see errors connecting to bootstrap nodes, it may be because:
- The bootstrap nodes are not running
- Your network has firewalls blocking the connections
- The bootstrap node addresses are incorrect

Solution: Edit your config.toml to update bootstrap_nodes or set up your own bootstrap nodes.

### Database Errors

If you see database-related errors:
- Check that the data directory exists and is writable
- Ensure the SQLite database is not corrupted
- Verify that you have sufficient disk space

Solution: Delete the database file and restart the node to create a fresh database.

### Security Key Issues

If you encounter issues with security keys:
- Verify that the key files exist and have correct permissions
- Ensure the paths in the configuration file are correct
- Check that the keys are valid and properly formatted

Solution: Regenerate the keys using the commands in Step 2.

## Additional Resources

- [DSM Developer Documentation](https://decentralizedstatemachine.com/devdocs/index.html)
- [Protocol Specifications](https://decentralizedstatemachine.com/devdocs/dsm_protocol_specs.html)
- [DSM GitHub Repository](https://github.com/dsm-project/decentralized-state-machine)

## License

This project is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

## Interacting with Your Running Storage Node

Once your storage node is running, you'll need to open a new terminal to interact with it. The original terminal will be occupied with the running node process and its logs.

> **IMPORTANT**: All of the following commands must be run in a new terminal window, NOT in the same terminal where the node is running. The node process occupies the original terminal with its logs and won't accept any commands.

### Checking Node Status

Open a new terminal and use the following command to check if your node is running correctly:

```bash
curl http://127.0.0.1:8080/api/v1/status
```

You should receive a JSON response with information about your node's status, including its ID, uptime, and connection information.

### Storing Data

To store data in your node, use a PUT request:

```bash
curl -X PUT http://127.0.0.1:8080/api/v1/data/my-test-key -d '{"value": "This is my test data"}'
```

### Retrieving Data

To retrieve previously stored data:

```bash
curl http://127.0.0.1:8080/api/v1/data/my-test-key
```

### Listing Connected Peers

To see which peers your node is connected to:

```bash
curl http://127.0.0.1:8080/api/v1/peers
```

### Monitoring Node Activity

While interacting with your node from the new terminal, you can observe the logs in the original terminal to see how the node is processing your requests. This is particularly useful for debugging and understanding the node's behavior.

### Remote Monitoring

If you've configured your node with a public endpoint and appropriate network settings, you can also access the API from other machines. Just replace `127.0.0.1` with your server's public IP address or domain name.
