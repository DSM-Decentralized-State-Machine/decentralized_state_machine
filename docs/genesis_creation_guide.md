# Genesis Creation Guide for DSM

This guide explains how to start storage nodes and create a genesis state for a new user in the Decentralized State Machine (DSM) system.

## Overview

Genesis creation is a critical process in DSM that establishes the initial state for a user's device. Unlike traditional systems that rely on a single trusted authority, DSM uses a threshold multiparty computation approach where multiple independent storage nodes contribute to the creation process, ensuring no single party can compromise the genesis state.

## Prerequisites

Before you begin, make sure you have:

1. Rust toolchain installed (rustc, cargo)
2. DSM library and dependencies installed
3. Network connectivity (for real deployments)

## Starting Storage Nodes

In a production environment, storage nodes would run on separate physical or virtual machines across the network. For development and testing, we can simulate multiple nodes within a single application.

### Using the Storage Node Simulator

The `start_storage_nodes.rs` example demonstrates how to start multiple storage nodes and perform the genesis creation ceremony:

```bash
# Navigate to the DSM directory
cd /path/to/DSM_Decentralized_State_Machine

# Run the storage nodes example
cargo run --example start_storage_nodes
```

This example:
1. Creates 10 simulated storage nodes with varying reputation scores
2. Selects 5 nodes for the genesis ceremony using the reputation-weighted algorithm
3. Collects contributions from at least 3 nodes (the threshold)
4. Creates a genesis state using the combined entropy from these contributions

### How It Works

1. **Node Selection**: Nodes are selected using a deterministic algorithm based on a seed, ensuring the selection cannot be manipulated while still being unpredictable.
2. **Contribution Collection**: Each selected node provides a contribution containing entropy that will be used in the genesis state.
3. **Threshold Security**: A minimum number of contributions (the threshold) is required to create the genesis state, ensuring no small group can control the process.
4. **State Creation**: Once enough contributions are collected, they are combined to create the genesis state with cryptographic binding to the user's device.

## Creating Genesis for a New User

The user-side process for requesting and processing a genesis state is demonstrated in the `user_genesis_creation.rs` example:

```bash
# Run the user genesis creation example
cargo run --example user_genesis_creation
```

This example shows:
1. Creating a new user device with cryptographic keys
2. Connecting to a network of storage nodes
3. Requesting genesis creation with user-specific parameters
4. Receiving and validating the created genesis state
5. Setting up the device with the new genesis state

### Step-by-Step Process for Users

1. **Device Setup**:
   ```rust
   let mut user_device = UserDevice::new("user_device_id")?;
   ```

2. **Network Connection**:
   ```rust
   let mut network_provider = NetworkProvider::new();
   network_provider.discover_nodes()?;
   ```

3. **Prepare Genesis Request**:
   ```rust
   let app_id = "com.example.app";
   let genesis_params = user_device.prepare_genesis_request(app_id);
   ```

4. **Request Genesis Creation**:
   ```rust
   let (genesis_creator, genesis_state) = 
       network_provider.request_genesis_creation(genesis_params)?;
   ```

5. **Set Genesis State**:
   ```rust
   user_device.set_genesis_state(genesis_state)?;
   ```

6. **Process Secure Wrapper**:
   ```rust
   let genesis_wrapper = genesis_creator.create_genesis_state_wrapper(signing_key)?;
   user_device.process_genesis_wrapper(genesis_wrapper)?;
   ```

## Advanced Configuration

### Customizing Genesis Parameters

You can customize various aspects of the genesis creation process:

```rust
let params = GenesisParams {
    ceremony_id: "unique_ceremony_id",
    app_id: "your.app.id",
    node_count: 7,              // Use 7 nodes instead of default 5
    threshold: 4,               // Require 4 contributions instead of default 3
    selection_seed: Some(seed), // Provide a specific seed for node selection
    initial_entropy: None,      // Let the system generate entropy
    device_info: Some(device),  // Provide device information
    metadata: custom_metadata,  // Add application-specific metadata
};
```

### Security Recommendations

1. **Node Count and Threshold**: Follow the n >= 2t - 1 rule, where n is the node count and t is the threshold. This ensures security against a malicious minority.

2. **Entropy Sources**: Use high-quality entropy sources for all random values, including node selection seeds and contribution blinding factors.

3. **Verification**: Always verify the created genesis state before using it, including checking participant signatures and the integrity of the state hash.

4. **Key Storage**: Securely store the signing key associated with the genesis state, preferably in hardware-backed secure storage.

## Troubleshooting

### Common Issues

1. **Not Enough Nodes**: If the system cannot find enough nodes to meet the requested count, the genesis creation will fail. Try reducing the `node_count` parameter.

2. **Threshold Not Met**: If too many selected nodes are unavailable or fail to provide valid contributions, the threshold may not be met. Check node connectivity and increase the timeout.

3. **Verification Failure**: If the genesis state fails verification, it may indicate a network attack or implementation error. Examine the logs for more details.

## Next Steps

After creating a genesis state, you can:

1. Create state transitions using the `StateMachine` interface
2. Establish relationships with other users through bilateral state transitions
3. Synchronize state across multiple devices

For more information, refer to the DSM API documentation and examples.
