# DSM Docker Deployment Architecture

This document describes the containerized deployment architecture for the Decentralized State Machine (DSM) system, which implements quantum-resistant hash chain verification and Content-Addressed Token Policy Anchors (CTPA).

## System Architecture

The DSM containerized architecture consists of the following components:

1. **DSM Core Node**: Implements the state machine, CTPA verification, and token policy enforcement
2. **DSM Storage Nodes**: Provides decentralized storage for policies and state
3. **Ethereum Bridge**: Connects DSM to EVM-compatible chains for interoperability
4. **Monitoring Stack**: Prometheus and Grafana for system observability

![DSM Architecture](/docs/images/dsm-docker-architecture.png)

## Security Considerations

The Docker implementation includes advanced security hardening:

- **Multi-stage builds**: Minimizes attack surface by excluding build toolchains
- **Least privilege principles**: Non-root users for all containers
- **Capability restrictions**: Minimal Linux capabilities for each service
- **Read-only filesystems**: Immutable runtime for core components
- **Resource limits**: Prevent DoS through resource exhaustion
- **Network isolation**: Service-specific network exposure

## Getting Started

### Prerequisites

- Docker Engine 20.10.0+
- Docker Compose 2.10.0+
- At least 8GB RAM and 4 CPU cores
- 20GB available disk space

### Deployment

1. Clone the repository:
   ```bash
   git clone https://github.com/cryptskii/self_evolving_cryptographic_identification.git
   cd self_evolving_cryptographic_identification/dsm_project
   ```

2. Configure environment variables (optional):
   ```bash
   cp .env.example .env
   # Edit .env with your specific configuration
   ```

3. Build and start the services:
   ```bash
   docker compose build
   docker compose up -d
   ```

4. Verify the deployment:
   ```bash
   docker compose ps
   ```

### Default Ports

- DSM Core API: `7545`
- DSM Core P2P: `8765`
- DSM Storage Primary P2P: `8766`
- DSM Storage Replica P2P: `8767`
- Ethereum Bridge API: `8768`
- Prometheus: `9090`
- Grafana: `3000`

## Component Descriptions

### DSM Core Node (`dsm-core`)

The core component implementing the decentralized state machine, quantum-resistant cryptography, and token policy verification.

- **Image**: Multi-stage build with security hardening
- **Volumes**: 
  - `dsm-core-data`: Persistent state storage
  - `dsm-core-config`: Configuration files
  - `dsm-core-policies`: CTPA policy storage
- **Key Features**:
  - Token policy enforcement
  - Quantum-resistant signatures
  - State transitions with cryptographic verification

### DSM Storage Node (`dsm-storage-primary` and `dsm-storage-replica`)

Provides decentralized, redundant storage for token policies and state data.

- **Primary Node**: Handles initial policy storage and verification
- **Replica Node**: Provides redundancy and high availability
- **Replication**: Automatic synchronization between nodes
- **Volumes**: Separate data and configuration for each node

### Ethereum Bridge (`dsm-ethereum-bridge`)

Facilitates interoperability between DSM and Ethereum/EVM-compatible chains.

- **Supports**: 
  - Token wrapping between ecosystems
  - State proof verification
  - Cross-chain transactions
- **Security**: Cryptographic verification of bridged assets

### Monitoring Stack

Comprehensive monitoring solution using Prometheus and Grafana.

- **Prometheus**: Time-series database for metrics
- **Grafana**: Visualization and alerting dashboard
- **Metrics Collected**:
  - System resource usage
  - Token operations and performance
  - Policy verification statistics
  - State transition metrics

## Advanced Configuration

### Customizing CTPA Settings

Edit the CTPA configuration:

```bash
docker compose exec dsm-core /usr/local/bin/cli config set --policy-cache-size=2000 --policy-ttl=7200
```

### Storage Node Scaling

Add additional storage nodes for horizontal scaling:

1. Add the service to `docker-compose.yml`:
   ```yaml
   dsm-storage-extra:
     build:
       context: .
       dockerfile: dsm-storage-node/Dockerfile
     # Rest of configuration
   ```

2. Update synchronization configuration:
   ```bash
   docker compose exec dsm-core /usr/local/bin/cli topology add-peer dsm-storage-extra:8765
   ```

### Using External Ethereum Node

To connect the bridge to an external Ethereum node:

1. Update the environment variable in `docker-compose.yml`:
   ```yaml
   dsm-ethereum-bridge:
     environment:
       - DSM_BRIDGE_ETHEREUM_RPC=https://your-custom-rpc-endpoint
   ```

## Troubleshooting

### Container Fails to Start

Check logs for detailed error information:

```bash
docker compose logs dsm-core
```

### State Synchronization Issues

Verify network connectivity between components:

```bash
docker compose exec dsm-core ping dsm-storage-primary
```

### Performance Tuning

1. **CPU Optimization**:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '4'  # Increase for better performance
   ```

2. **Memory Optimization**:
   ```yaml
   environment:
     RUST_BACKTRACE: 0  # Disable in production
     DSM_CACHE_SIZE: 2048  # Increase for performance
   ```

## Production Deployment Recommendations

For production deployments, consider the following enhancements:

1. **External Volume Storage**: Use docker volume drivers for cloud or networked storage
2. **Secrets Management**: Use Docker secrets instead of environment variables
3. **Load Balancing**: Deploy multiple DSM core instances behind a load balancer
4. **Backup Strategy**: Implement regular volume backups
5. **High Availability**: Run components across multiple hosts

## License and Acknowledgements

The DSM Docker implementation is licensed under MIT and Apache 2.0 dual license.

Contributions and bug reports are welcome via GitHub issues and pull requests.
