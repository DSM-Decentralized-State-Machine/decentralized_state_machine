// Storage module for DSM Storage Node
//
// This module provides various storage implementations for the DSM storage node.

use crate::error::Result;
use crate::types::storage_types::StorageStats;
use crate::types::BlindedStateEntry;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
// Explicitly import NodeId for use in this module
use crate::storage::topology::NodeId;

pub mod digest;
pub mod distributed_storage;
pub mod epidemic_storage;
pub mod health;
pub mod memory_storage;
pub mod metrics;
pub mod partition;
pub mod reconciliation;
pub mod routing;
pub mod topology;
pub mod sql_storage;
pub mod tasks;
pub mod vector_clock;

// Re-export storage types
pub use digest::DigestGenerator;
pub use distributed_storage::DistributedStorage;
pub use epidemic_storage::{EpidemicStorageEngine, EpidemicConfig, TopologyType};
pub use memory_storage::{EvictionPolicy, MemoryStorage, MemoryStorageConfig};
pub use sql_storage::SqlStorage;


/// Storage engine interface
#[async_trait]
pub trait StorageEngine: Send + Sync {
    /// Store a blinded state entry
    async fn store(&self, entry: BlindedStateEntry) -> Result<crate::types::storage_types::StorageResponse>;

    /// Retrieve a blinded state entry
    async fn retrieve(&self, blinded_id: &str) -> Result<Option<BlindedStateEntry>>;

    /// Delete a blinded state entry
    async fn delete(&self, blinded_id: &str) -> Result<bool>;

    /// Check if a blinded state entry exists
    async fn exists(&self, blinded_id: &str) -> Result<bool>;

    /// List all blinded state entries
    async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>>;

    /// Get storage statistics
    async fn get_stats(&self) -> Result<StorageStats>;
}

/// Storage configuration
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Path to the database file (for SQL storage)
    pub database_path: String,
    /// Default time-to-live for entries (in seconds)
    pub default_ttl: u64,
    /// Whether to enable automatic pruning of expired entries
    pub enable_pruning: bool,
    /// Interval for pruning expired entries (in seconds)
    pub pruning_interval: u64,
}

/// Storage factory to create different storage implementations
pub struct StorageFactory {
    /// Storage configuration
    config: StorageConfig,
}

impl StorageFactory {
    /// Create a new storage factory
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }

    /// Create an in-memory storage engine
    pub fn create_memory_storage(&self) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let config = MemoryStorageConfig {
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
            max_entries: 1_000_000,
            persistence_path: Some(PathBuf::from(format!("{}.memdb", self.config.database_path))),
            eviction_policy: EvictionPolicy::LRU,
            db_path: self.config.database_path.clone(),
            compression: Some("lz4".to_string()),
        };

        Ok(Arc::new(MemoryStorage::new(config)))
    }

    /// Create a SQL storage engine
    pub fn create_sql_storage(&self) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let storage = SqlStorage::new(&self.config.database_path)?;
        Ok(Arc::new(storage))
    }

    /// Create a distributed storage engine
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

    /// Create an epidemic storage engine with small-world topology
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
                conflict_resolution_strategy: epidemic_storage::ConflictResolutionStrategy::LastWriteWins,
                partition_count: 16,
                replication_factor: 3,
                partition_strategy: crate::storage::partition::PartitionStrategy::ConsistentHash,
                min_nodes_for_rebalance: 2,
                max_partitions_per_node: 8,
                k_neighbors: 4,
                alpha: 0.5,
                max_long_links: 15,  // Added this missing field
                max_topology_connections: 10,
                topology_connection_timeout_ms: 1000,
                rebalance_check_interval_ms: Some(60000),
                placement_stability: Some(0.8),
                rebalance_throttle: Some(5),
                min_transfer_interval_ms: Some(1000),
            },
            crate::network::NetworkClientFactory::create_client(node.clone())?,
            std::sync::Arc::new(crate::storage::metrics::MetricsCollector::new(
                crate::storage::metrics::MetricsCollectorConfig::default()
            ))
        )?;

        // Direct return without trying to call start_background_tasks
        Ok(std::sync::Arc::new(storage))
    }
}

/// Storage provider that manages multiple storage engines
pub struct StorageProvider {
    /// Primary storage engine
    primary: Arc<dyn StorageEngine + Send + Sync>,
    /// Optional backup storage engine
    backup: Option<Arc<dyn StorageEngine + Send + Sync>>,
    /// Node information
    node: crate::types::StorageNode,
    /// Default time-to-live for entries (in seconds)
    default_ttl: u64,
    /// Default region for entries
    default_region: String,
}

impl StorageProvider {
    /// Create a new storage provider
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

    /// Get the primary storage engine
    pub fn get_primary(&self) -> Arc<dyn StorageEngine + Send + Sync> {
        self.primary.clone()
    }

    /// Get the backup storage engine if available
    pub fn get_backup(&self) -> Option<Arc<dyn StorageEngine + Send + Sync>> {
        self.backup.clone()
    }

    /// Get the node information
    pub fn get_node(&self) -> &crate::types::StorageNode {
        &self.node
    }

    /// Get the default time-to-live
    pub fn get_default_ttl(&self) -> u64 {
        self.default_ttl
    }

    /// Get the default region
    pub fn get_default_region(&self) -> &str {
        &self.default_region
    }
}
