//! # Storage Module for DSM Storage Node
//!
//! This module provides the core storage functionality for the DSM Storage Node,
//! implementing various storage backends and distributed storage strategies.
//!
//! ## Key Features
//!
//! * Multiple storage backend implementations (Memory, SQL, Epidemic)
//! * Distributed storage with customizable replication strategies
//! * Data partitioning and routing across multiple nodes
//! * Epidemic protocols for eventual consistency
//! * Vector clocks for conflict resolution
//! * Metrics collection and health monitoring
//!
//! ## Architecture
//!
//! The storage module is built around the `StorageEngine` trait, which defines
//! the core interface for all storage backends. Various implementations provide
//! different trade-offs in terms of persistence, performance, and distribution:
//!
//! * `MemoryStorage`: In-memory storage with optional persistence
//! * `SqlStorage`: SQLite-based persistent storage
//! * `DistributedStorage`: Distributes data across multiple nodes
//! * `EpidemicStorageEngine`: Eventually consistent distributed storage
//!
//! ## Usage
//!
//! Storage engines are typically created through the `StorageFactory`, which
//! handles configuration and initialization details:
//!
//! ```rust,no_run
//! use dsm_storage_node::storage::{StorageConfig, StorageFactory};
//!
//! // Create configuration
//! let config = StorageConfig {
//!     database_path: "data/storage.db".to_string(),
//!     default_ttl: 0, // No expiration
//!     enable_pruning: true,
//!     pruning_interval: 3600,
//! };
//!
//! // Create factory and storage engine
//! let factory = StorageFactory::new(config);
//! let storage = factory.create_sql_storage().unwrap();
//!
//! // Use the storage engine
//! // storage.store(...).await?;
//! ```

use crate::error::Result;
use crate::types::storage_types::StorageStats;
use crate::types::BlindedStateEntry;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
// Explicitly import NodeId for use in this module
use crate::storage::topology::NodeId;

// Module declarations
/// Data digest generation for content addressing
pub mod digest;
/// Distributed storage across multiple nodes
pub mod distributed_storage;
/// Epidemic protocol-based eventually consistent storage
pub mod epidemic_storage;
/// Health checking and monitoring
pub mod health;
/// In-memory storage implementation
pub mod memory_storage;
/// Storage metrics collection
pub mod metrics;
/// Data partitioning strategies
pub mod partition;
/// Data reconciliation between nodes
pub mod reconciliation;
/// Request routing algorithms
pub mod routing;
/// SQLite-based persistent storage
pub mod sql_storage;
/// Background maintenance tasks
pub mod tasks;
/// Network topology management
pub mod topology;
/// Vector clocks for causality tracking
pub mod vector_clock;

// Re-exports for convenience
pub use digest::DigestGenerator;
pub use distributed_storage::DistributedStorage;
pub use epidemic_storage::{EpidemicStorageEngine, EpidemicConfig, TopologyType};
pub use memory_storage::{EvictionPolicy, MemoryStorage, MemoryStorageConfig};
pub use sql_storage::SqlStorage;

/// Core interface for all storage engines in the DSM Storage Node.
///
/// This trait defines the essential operations that any storage implementation
/// must provide, regardless of whether it's a local or distributed storage.
/// All methods are asynchronous to allow for efficient I/O operations and
/// network communication.
///
/// # Examples
///
/// ```rust,no_run
/// use dsm_storage_node::storage::{StorageEngine, MemoryStorage, MemoryStorageConfig};
/// use dsm_storage_node::types::BlindedStateEntry;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a storage engine
/// let config = MemoryStorageConfig::default();
/// let storage: Arc<dyn StorageEngine + Send + Sync> = Arc::new(MemoryStorage::new(config));
///
/// // Store a blinded state entry
/// let entry = BlindedStateEntry {
///     blinded_id: "test_id".to_string(),
///     data: serde_json::json!({"value": "test_data"}),
///     timestamp: chrono::Utc::now(),
///     // ... other fields ...
/// };
/// storage.store(entry.clone()).await?;
///
/// // Retrieve the entry
/// let retrieved = storage.retrieve(&entry.blinded_id).await?;
/// # Ok(())
/// # }
/// ```
#[async_trait]
pub trait StorageEngine: Send + Sync {
    /// Store a blinded state entry in the storage engine.
    ///
    /// This operation adds or updates a state entry in the storage.
    /// If an entry with the same blinded_id already exists, it will be overwritten.
    ///
    /// # Arguments
    ///
    /// * `entry` - The blinded state entry to store
    ///
    /// # Returns
    ///
    /// A `Result` containing a `StorageResponse` with details about the storage operation
    /// or an error if the operation failed.
    async fn store(
        &self,
        entry: BlindedStateEntry,
    ) -> Result<crate::types::storage_types::StorageResponse>;

    /// Retrieve a blinded state entry by its ID.
    ///
    /// # Arguments
    ///
    /// * `blinded_id` - The unique identifier for the blinded state entry
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<BlindedStateEntry>`. Returns `None` if
    /// the entry doesn't exist, or an error if the operation failed.
    async fn retrieve(&self, blinded_id: &str) -> Result<Option<BlindedStateEntry>>;

    /// Delete a blinded state entry by its ID.
    ///
    /// # Arguments
    ///
    /// * `blinded_id` - The unique identifier for the blinded state entry to delete
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean: `true` if the entry was deleted,
    /// `false` if it didn't exist, or an error if the operation failed.
    async fn delete(&self, blinded_id: &str) -> Result<bool>;

    /// Check if a blinded state entry exists in the storage.
    ///
    /// This is more efficient than `retrieve` when you only need to check existence.
    ///
    /// # Arguments
    ///
    /// * `blinded_id` - The unique identifier for the blinded state entry
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean: `true` if the entry exists,
    /// `false` otherwise, or an error if the operation failed.
    async fn exists(&self, blinded_id: &str) -> Result<bool>;

    /// List all blinded state entries in the storage.
    ///
    /// # Arguments
    ///
    /// * `limit` - Optional maximum number of entries to return
    /// * `offset` - Optional offset for pagination
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of blinded IDs, or an error
    /// if the operation failed.
    async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>>;

    /// Get statistics about the storage engine.
    ///
    /// # Returns
    ///
    /// A `Result` containing storage statistics including capacity, usage,
    /// entry count, etc., or an error if the operation failed.
    async fn get_stats(&self) -> Result<StorageStats>;
}

/// Configuration for storage engines.
///
/// This struct provides common configuration parameters used by
/// various storage engine implementations.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Path to the database file (for SQL storage)
    pub database_path: String,

    /// Default time-to-live for entries in seconds
    /// A value of 0 means no expiration (entries live forever)
    pub default_ttl: u64,

    /// Whether to enable automatic pruning of expired entries
    pub enable_pruning: bool,

    /// Interval for pruning expired entries in seconds
    pub pruning_interval: u64,
}

/// Factory for creating different storage engine implementations.
///
/// This factory simplifies the creation of storage engines by handling
/// the complexity of configuration and initialization. It supports creating
/// various types of storage engines with appropriate default settings.
///
/// # Examples
///
/// ```rust,no_run
/// use dsm_storage_node::storage::{StorageConfig, StorageFactory};
/// use dsm_storage_node::types::StorageNode;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create configuration
/// let config = StorageConfig {
///     database_path: "data/storage.db".to_string(),
///     default_ttl: 0,
///     enable_pruning: true,
///     pruning_interval: 3600,
/// };
///
/// // Create factory
/// let factory = StorageFactory::new(config);
///
/// // Create memory storage
/// let memory_storage = factory.create_memory_storage()?;
///
/// // Create SQL storage
/// let sql_storage = factory.create_sql_storage()?;
///
/// // Create distributed storage
/// let distributed = factory.create_distributed_storage(
///     memory_storage.clone(),
///     "node1".to_string(),
///     vec![],
///     3,
///     2
/// )?;
/// # Ok(())
/// # }
/// ```
pub struct StorageFactory {
    /// Storage configuration
    config: StorageConfig,
}

impl StorageFactory {
    /// Create a new storage factory with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The storage configuration to use
    ///
    /// # Returns
    ///
    /// A new `StorageFactory` instance
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// Create an in-memory storage engine.
    ///
    /// This creates a memory-based storage engine with optional persistence.
    /// The memory storage engine provides fast access but doesn't persist
    /// data across restarts unless persistence is enabled.
    ///
    /// # Returns
    ///
    /// A `Result` containing an Arc-wrapped `StorageEngine` implementation
    /// or an error if creation failed.
    pub fn create_memory_storage(&self) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let config = MemoryStorageConfig {
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
            max_entries: 1_000_000,
            persistence_path: Some(PathBuf::from(format!(
                "{}.memdb",
                self.config.database_path
            ))),
            eviction_policy: EvictionPolicy::LRU,
            db_path: self.config.database_path.clone(),
            compression: Some("lz4".to_string()),
        };

        Ok(Arc::new(MemoryStorage::new(config)))
    }

    /// Create a SQL-based persistent storage engine.
    ///
    /// This creates a SQLite-based storage engine that provides
    /// durable persistence of data with ACID guarantees.
    ///
    /// # Returns
    ///
    /// A `Result` containing an Arc-wrapped `StorageEngine` implementation
    /// or an error if creation failed.
    pub fn create_sql_storage(&self) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let storage = SqlStorage::new(&self.config.database_path)?;
        Ok(Arc::new(storage))
    }

    /// Create a distributed storage engine.
    ///
    /// This creates a storage engine that distributes data across multiple
    /// nodes according to a replication strategy. It provides higher
    /// availability and fault tolerance at the cost of complexity.
    ///
    /// # Arguments
    ///
    /// * `local_storage` - Local storage engine for this node
    /// * `node_id` - Unique identifier for this node
    /// * `peers` - List of peer nodes in the network
    /// * `replication_factor` - Number of replicas to maintain for each entry
    /// * `max_hops` - Maximum number of forwarding hops for routing
    ///
    /// # Returns
    ///
    /// A `Result` containing an Arc-wrapped `StorageEngine` implementation
    /// or an error if creation failed.
    pub fn create_distributed_storage(
        &self,
        local_storage: Arc<dyn StorageEngine + Send + Sync>,
        node_id: String,
        peers: Vec<crate::types::StorageNode>,
        replication_factor: usize,
        max_hops: usize,
    ) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let storage = distributed_storage::DistributedStorage::new(
            local_storage.clone(),
            node_id.clone(),
            peers.clone(),
            replication_factor,
            max_hops,
        )?;
        Ok(Arc::new(storage))
    }

    /// Create an epidemic storage engine with small-world topology.
    ///
    /// This creates an eventually consistent storage engine based on
    /// epidemic protocols and small-world network topology. It provides
    /// high availability and partition tolerance with eventual consistency.
    ///
    /// # Arguments
    ///
    /// * `node_id` - Unique identifier for this node
    /// * `node` - Node information for this storage node
    /// * `_bootstrap_nodes` - List of bootstrap nodes to connect to initially
    /// * `_backing_storage` - Optional underlying storage engine
    ///
    /// # Returns
    ///
    /// A `Result` containing an Arc-wrapped `StorageEngine` implementation
    /// or an error if creation failed.
    pub async fn create_epidemic_storage(
        &self,
        node_id: String,
        node: crate::types::StorageNode,
        _bootstrap_nodes: Vec<crate::types::StorageNode>,
        _backing_storage: Option<Arc<dyn StorageEngine + Send + Sync>>,
    ) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let storage = epidemic_storage::EpidemicStorageEngine::new(
            epidemic_storage::EpidemicConfig {
                node_id: NodeId::from_string(&node_id).unwrap(),
                gossip_interval_ms: 5000,
                reconciliation_interval_ms: 30000,
                topology_maintenance_interval_ms: 60000,
                gossip_fanout: 3,
                max_reconciliation_diff: 100,
                conflict_resolution_strategy:
                    epidemic_storage::ConflictResolutionStrategy::LastWriteWins,
                partition_count: 16,
                replication_factor: 3,
                partition_strategy: crate::storage::partition::PartitionStrategy::ConsistentHash,
                min_nodes_for_rebalance: 2,
                max_partitions_per_node: 8,
                k_neighbors: 4,
                alpha: 0.5,
                max_long_links: 15, // Added this missing field
                max_topology_connections: 10,
                topology_connection_timeout_ms: 1000,
                rebalance_check_interval_ms: Some(60000),
                placement_stability: Some(0.8),
                rebalance_throttle: Some(5),
                min_transfer_interval_ms: Some(1000),
            },
            crate::network::NetworkClientFactory::create_client(node.clone())?,
            std::sync::Arc::new(crate::storage::metrics::MetricsCollector::new(
                crate::storage::metrics::MetricsCollectorConfig::default(),
            )),
        )?;

        // Direct return without trying to call start_background_tasks
        Ok(std::sync::Arc::new(storage))
    }
}

/// High-level storage provider that manages multiple storage engines.
///
/// This provider simplifies working with multiple storage engines
/// by providing a unified interface and managing primary and backup
/// storage engines. It also handles node metadata and default settings.
///
/// # Examples
///
/// ```rust,no_run
/// use dsm_storage_node::storage::{StorageProvider, StorageConfig, StorageFactory};
/// use dsm_storage_node::types::StorageNode;
/// use std::sync::Arc;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create storage engines
/// let config = StorageConfig {
///     database_path: "data/storage.db".to_string(),
///     default_ttl: 0,
///     enable_pruning: true,
///     pruning_interval: 3600,
/// };
/// let factory = StorageFactory::new(config);
/// let primary = factory.create_sql_storage()?;
/// let backup = factory.create_memory_storage().ok();
///
/// // Create node info
/// let node = StorageNode {
///     id: "node1".to_string(),
///     endpoint: "http://localhost:8080".to_string(),
///     region: "us-west".to_string(),
///     // ... other fields ...
/// };
///
/// // Create provider
/// let provider = StorageProvider::new(
///     primary,
///     backup,
///     node,
///     3600, // 1 hour TTL
///     "us-west".to_string(),
/// );
///
/// // Access storage
/// let storage = provider.get_primary();
/// # Ok(())
/// # }
/// ```
pub struct StorageProvider {
    /// Primary storage engine
    primary: Arc<dyn StorageEngine + Send + Sync>,

    /// Optional backup storage engine for redundancy
    backup: Option<Arc<dyn StorageEngine + Send + Sync>>,

    /// Node information for this storage node
    node: crate::types::StorageNode,

    /// Default time-to-live for entries in seconds
    default_ttl: u64,

    /// Default region for this storage node
    default_region: String,
}

impl StorageProvider {
    /// Create a new storage provider.
    ///
    /// # Arguments
    ///
    /// * `primary` - Primary storage engine
    /// * `backup` - Optional backup storage engine
    /// * `node` - Node information for this storage node
    /// * `default_ttl` - Default time-to-live for entries in seconds
    /// * `default_region` - Default region for this storage node
    ///
    /// # Returns
    ///
    /// A new `StorageProvider` instance
    pub fn new(
        primary: Arc<dyn StorageEngine + Send + Sync>,
        backup: Option<Arc<dyn StorageEngine + Send + Sync>>,
        node: crate::types::StorageNode,
        default_ttl: u64,
        default_region: String,
    ) -> Self {
        Self {
            primary,
            backup,
            node,
            default_ttl,
            default_region,
        }
    }

    /// Get the primary storage engine.
    ///
    /// # Returns
    ///
    /// An Arc-wrapped reference to the primary storage engine
    pub fn get_primary(&self) -> Arc<dyn StorageEngine + Send + Sync> {
        self.primary.clone()
    }

    /// Get the backup storage engine if available.
    ///
    /// # Returns
    ///
    /// An optional Arc-wrapped reference to the backup storage engine
    pub fn get_backup(&self) -> Option<Arc<dyn StorageEngine + Send + Sync>> {
        self.backup.clone()
    }

    /// Get the node information.
    ///
    /// # Returns
    ///
    /// A reference to the node information
    pub fn get_node(&self) -> &crate::types::StorageNode {
        &self.node
    }

    /// Get the default time-to-live.
    ///
    /// # Returns
    ///
    /// The default time-to-live in seconds
    pub fn get_default_ttl(&self) -> u64 {
        self.default_ttl
    }

    /// Get the default region.
    ///
    /// # Returns
    ///
    /// The default region as a string slice
    pub fn get_default_region(&self) -> &str {
        &self.default_region
    }
}
