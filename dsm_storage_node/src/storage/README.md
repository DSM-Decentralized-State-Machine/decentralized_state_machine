# DSM Storage Node - Epidemic Storage Module

This module provides a distributed storage implementation using an epidemic coordination protocol with a small-world topology for efficient scalability.

## Overview

The epidemic storage module implements a distributed storage system based on epidemic (gossip) protocols where nodes periodically exchange information with a small subset of neighbors. The implementation is optimized using a small-world topology where each node maintains both close neighbors and long-range connections to enable efficient routing and data propagation.

## Key Features

- **Small-World Topology**: Logarithmic diameter network for efficient routing and data propagation
- **Vector Clock Synchronization**: Causal ordering of updates across distributed nodes
- **Anti-Entropy Protocol**: Reliable synchronization mechanism to ensure eventual consistency
- **Bounded Neighborhood**: Scale-efficient node connections with O(log n) complexity
- **Adaptive Gossip Frequency**: Self-tuning mechanisms based on network conditions
- **Regional Consistency Options**: Configurable consistency models for different geographic regions
- **Conflict Resolution**: Automatic resolution of concurrent updates
- **Read Repair**: On-demand synchronization during read operations

## Usage

The epidemic storage engine can be configured and used as follows:

```rust
// Create a storage factory
let storage_factory = StorageFactory::new(config);

// Create epidemic storage with SQL backing
let backing_storage = storage_factory.create_sql_storage()?;

// Create and start epidemic storage
let storage = storage_factory.create_epidemic_storage(
    node_id,
    node_info,
    bootstrap_nodes,
    Some(backing_storage),
).await?;
```

## Configuration Options

The epidemic storage can be configured through several parameters:

- `node_id`: Unique identifier for the node
- `region`: Geographic region identifier for regional consistency
- `gossip_interval_ms`: Interval between gossip rounds (default: 5000ms)
- `anti_entropy_interval_ms`: Interval between anti-entropy sessions (default: 60000ms)
- `gossip_fanout`: Number of peers to propagate updates to (default: 3)
- `max_immediate_neighbors`: Maximum number of close neighbors (default: 16)
- `max_long_links`: Maximum number of long-range connections (default: 16)

## Implementation Details

### Small-World Topology

The small-world topology creates a network where the average path length between any two nodes scales logarithmically with the number of nodes, enabling efficient routing and data propagation. Each node maintains:

1. A set of immediate neighbors (closest in the ID space)
2. Long-range connections ("fingers") that provide shortcuts across the ID space

This structure provides O(log n) routing complexity, dramatically improving scalability compared to traditional approaches.

### Epidemic Protocol

The epidemic protocol consists of:

1. **Gossip**: Periodic exchange of digests with neighbors
2. **Anti-Entropy**: Scheduled reconciliation sessions to ensure consistency
3. **Direct Updates**: Immediate propagation of critical updates
4. **Read Repair**: On-demand synchronization during read operations

### Vector Clocks

Vector clocks track causal relationships between updates, enabling:

1. Detection of concurrent updates
2. Correct ordering of causally related updates
3. Automatic resolution of conflicts based on deterministic rules

## Performance Characteristics

- **Message Complexity**: O(n log n) compared to O(n²) for naive flooding
- **Convergence Time**: O(log n) rounds to reach all nodes
- **Storage Overhead**: O(m) where m is the number of data items
- **Topology Maintenance**: O(log² n) operations per node join/leave
