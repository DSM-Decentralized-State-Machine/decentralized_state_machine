// DSM Storage Node
//
// This crate implements a quantum-resistant decentralized storage node for the Decentralized State Machine (DSM) system.
// Storage nodes form the backbone of the DSM network, providing secure, distributed, and resilient storage
// capabilities with post-quantum cryptography as described in Section 16 of the DSM whitepaper.
//
// # Architecture
//
// The storage node is built around several modular components:
//
// * **API Layer**: RESTful interface for data operations and node management
// * **Storage Engine**: Pluggable storage backends with various consistency guarantees
// * **Distribution Layer**: Manages data replication and sharding across the network
// * **Encryption Layer**: Handles quantum-resistant cryptography and key management
// * **Network Layer**: Facilitates communication between nodes using various protocols
//
// # Usage
//
// The storage node can be run as a standalone service or integrated into other applications:
//
// ```rust,no_run
// use dsm_storage_node::storage::{StorageEngine, StorageConfig};
// use dsm_storage_node::api::ApiServer;
// use std::sync::Arc;
//
// async fn example() -> Result<(), Box<dyn std::error::Error>> {
//     // Initialize storage engine
//     let config = StorageConfig::from_file("config.toml")?;
//     let storage = StorageEngine::new(config)?;
//
//     // Start API server
//     let api_server = ApiServer::new(Arc::new(storage), "0.0.0.0:8765");
//     api_server.start().await?;
//
//     Ok(())
// }
// ```
//
// # Modules Overview

/// API implementation for the DSM Storage Node.
///
/// This module provides the HTTP REST API endpoints for interacting with the storage node,
/// including data operations, node management, and administrative functions.
///
/// # Features
///
/// * RESTful API for data operations (get, put, delete)
/// * Batch operations for efficient multi-key access
/// * Node management endpoints for configuration and peer management
/// * Health monitoring and metrics endpoints
/// * Admin operations for maintenance tasks
pub mod api;

/// Client library for interacting with DSM Storage Nodes.
///
/// This module provides a high-level client API for applications to interact with
/// DSM Storage Nodes, handling connection management, request formatting, and response parsing.
///
/// # Examples
///
/// ```rust,no_run
/// use dsm_storage_node::client::StorageClient;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let client = StorageClient::new("http://localhost:8765")?;
///
///     // Store data
///     client.put("my_key", b"Hello, DSM!").await?;
///
///     // Retrieve data
///     let data = client.get("my_key").await?;
///     println!("Retrieved: {}", String::from_utf8_lossy(&data));
///
///     Ok(())
/// }
/// ```
pub mod client;

/// Cryptographic primitives for the DSM Storage Node.
///
/// This module provides cryptographic operations specifically tailored for
/// storage node operations, including hashing, signatures, and key derivation.
///
/// # Features
///
/// * Quantum-resistant cryptographic algorithms
/// * Key derivation functions for secure key management
/// * Content addressing through cryptographic hashing
/// * Privacy-preserving operations through random walks & blind encryption
pub mod crypto;

/// Distributed storage management for the DSM Storage Node.
///
/// This module handles how data is distributed across multiple storage nodes,
/// including sharding strategies, replica placement, and consistency guarantees.
///
/// # Features
///
/// * Various sharding strategies (hash-based, range-based, consistent hashing)
/// * Configurable replica placement for availability and locality
/// * Data partitioning and load balancing
/// * Epidemic protocols for eventual consistency
pub mod distribution;

/// Encryption services for the DSM Storage Node.
///
/// This module handles encryption of data stored in the node, key management,
/// and related security features to ensure confidentiality and integrity.
///
/// # Features
///
/// * Post-quantum encryption algorithms
/// * Transparent encryption/decryption of stored data
/// * Key rotation and management
/// * Blind encryption for zero-knowledge storage
pub mod encryption;

/// Error types for the DSM Storage Node.
///
/// This module defines the error types and error handling mechanisms used
/// throughout the storage node implementation.
///
/// # Error Categories
///
/// * Storage errors (I/O, corruption, capacity)
/// * Network errors (connection, timeout, protocol)
/// * Encryption errors (key management, algorithm)
/// * API errors (invalid requests, authentication)
/// * Distribution errors (replication, consensus)
pub mod error;

/// Network communication for the DSM Storage Node.
///
/// This module handles network communication between storage nodes,
/// implementing discovery, gossip protocols, and data transfer.
///
/// # Features
///
/// * Node discovery mechanisms
/// * Gossip protocol for metadata propagation
/// * Direct node-to-node communication
/// * Connection pooling and management
pub mod network;

/// Node management for the DSM Storage Node.
///
/// This module provides functionality for managing the storage node's
/// lifecycle, configuration, and runtime behavior.
///
/// # Features
///
/// * Node configuration management
/// * Resource monitoring and management
/// * Runtime reconfiguration capabilities
/// * Node lifecycle management (startup, shutdown, maintenance)
pub mod node_management;

/// Staking and incentive mechanisms for DSM Storage Nodes.
///
/// This module implements the staking and reward mechanisms that incentivize
/// storage node operators to provide reliable and honest service.
///
/// # Features
///
/// * Staking and unstaking operations
/// * Reward calculation and distribution
/// * Slashing for malicious or unreliable behavior
/// * Validator selection based on stake
pub mod staking;

/// Storage backends for the DSM Storage Node.
///
/// This module provides the core storage functionality, implementing various
/// backends for persisting and retrieving data.
///
/// # Features
///
/// * Multiple storage backends (SQLite, Memory, Epidemic)
/// * Common interface for all backends
/// * Transaction support
/// * Indexing for efficient lookups
/// * Data pruning and lifecycle management
pub mod storage;

/// Common types used throughout the DSM Storage Node.
///
/// This module defines the core data structures, traits, and type definitions
/// that are used across multiple components of the storage node.
///
/// # Key Types
///
/// * `StorageKey` and `StorageValue` for data representation
/// * `NodeInfo` for peer information
/// * `StorageStats` for performance and utilization metrics
/// * `ConsistencyLevel` for configuring replication guarantees
pub mod types;
