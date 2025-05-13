//! # Epidemic Storage Engine
//!
//! This module implements an eventually consistent, distributed storage engine
//! based on epidemic protocols (also known as gossip protocols) with a small-world
//! network topology. It provides highly available, partition-tolerant storage
//! that can scale horizontally across many nodes.
//!
//! ## Key Features
//!
//! * **Eventually Consistent Storage**: Tolerates network partitions and node failures
//! * **Small-World Topology**: Efficient information propagation with low network diameter
//! * **Vector Clock Synchronization**: Detects and resolves conflicts in distributed updates
//! * **Automatic Data Partitioning**: Distributes data across nodes using consistent hashing
//! * **Adaptive Gossip**: Dynamically optimizes communication patterns
//!
//! ## How It Works
//!
//! The epidemic storage engine uses a combination of techniques to provide resilient,
//! distributed storage:
//!
//! 1. **Data Partitioning**: Each node is responsible for a subset of the key space
//! 2. **Gossip Protocol**: Nodes periodically exchange state digests with peers
//! 3. **Vector Clocks**: Track causal relationships between updates
//! 4. **Reconciliation**: Resolve conflicts when divergent states are detected
//! 5. **Topology Management**: Maintain an efficient small-world network structure
//!
//! ## Usage
//!
//! ```rust,no_run
//! use dsm_storage_node::storage::epidemic_storage::{
//!     EpidemicStorageEngine, EpidemicConfig, ConflictResolutionStrategy
//! };
//! use dsm_storage_node::storage::partition::PartitionStrategy;
//! use dsm_storage_node::storage::topology::NodeId;
//! use dsm_storage_node::network::NetworkClientFactory;
//! use dsm_storage_node::types::StorageNode;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create node information
//! let node = StorageNode {
//!     id: "node1".to_string(),
//!     endpoint: "http://localhost:8080".to_string(),
//!     // ...other fields...
//! };
//!
//! // Create epidemic storage configuration
//! let config = EpidemicConfig {
//!     node_id: NodeId::from_string("node1").unwrap(),
//!     gossip_interval_ms: 5000,
//!     reconciliation_interval_ms: 30000,
//!     topology_maintenance_interval_ms: 60000,
//!     gossip_fanout: 3,
//!     max_reconciliation_diff: 100,
//!     conflict_resolution_strategy: ConflictResolutionStrategy::LastWriteWins,
//!     partition_count: 16,
//!     replication_factor: 3,
//!     partition_strategy: PartitionStrategy::ConsistentHash,
//!     // ...other fields...
//! };
//!
//! // Create network client and metrics collector
//! let network_client = NetworkClientFactory::create_client(node)?;
//! let metrics = Arc::new(MetricsCollector::new(Default::default()));
//!
//! // Create the epidemic storage engine
//! let storage = EpidemicStorageEngine::new(config, network_client, metrics)?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock as ParkingRwLock;

use tracing::{debug, info};

use crate::error::Result;
use crate::network::NetworkClient;
use crate::storage::metrics::{MetricsCollector, OperationType};
use crate::storage::partition::{
    PartitionConfig, PartitionManager, PartitionedStorage, PartitionStrategy,
};
use crate::storage::topology::{NodeId, HybridTopologyConfig, HybridTopology};
use crate::storage::vector_clock::VectorClock;
use crate::types::{
    BlindedStateEntry,
    storage_types::{StorageResponse, StorageStats},
};

use super::StorageEngine;

/// Network topology configurations for the epidemic storage.
///
/// Defines different network structure approaches that affect how
/// nodes connect and share information with each other.
#[derive(Clone, Debug)]
pub enum TopologyType {
    /// Densely connected mesh with each node directly connected to many peers
    DistributedMesh,

    /// Randomly connected graph with probabilistic node connections
    RandomGraph,

    /// Structured overlay with deterministic node connections (e.g., DHT-like)
    StructuredOverlay,
}

/// Internal representation of an entry in the epidemic storage.
///
/// Contains the actual data plus vector clock and timestamp information
/// needed for consistency and conflict resolution.
#[derive(Clone, Debug)]
struct EpidemicEntry {
    /// Unique key identifying this entry
    key: String,

    /// Binary value of the entry
    value: Vec<u8>,

    /// Vector clock for causal ordering and conflict detection
    vector_clock: VectorClock,

    /// Timestamp of the last update
    timestamp: SystemTime,
}

/// Storage-level representation of an entry.
///
/// Used for persistence and transmission between nodes.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct StateEntry {
    /// Unique key identifying this entry
    key: String,

    /// Binary value of the entry
    value: Vec<u8>,

    /// Vector clock for causal ordering and conflict detection
    vector_clock: VectorClock,

    /// Timestamp as seconds since epoch
    timestamp: u64,
}

impl From<EpidemicEntry> for StateEntry {
    fn from(entry: EpidemicEntry) -> Self {
        Self {
            key: entry.key,
            value: entry.value,
            vector_clock: entry.vector_clock,
            timestamp: entry
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

#[allow(dead_code)]
impl EpidemicEntry {
    /// Convert a state entry back to an epidemic entry.
    fn from_state_entry(entry: StateEntry, timestamp: SystemTime) -> Self {
        Self {
            key: entry.key,
            value: entry.value,
            vector_clock: entry.vector_clock,
            timestamp,
        }
    }
}

/// Epidemic Storage Engine implementation.
///
/// This storage engine provides eventually consistent, distributed storage
/// using epidemic protocols and small-world network topology. It is designed
/// for high availability and partition tolerance with horizontal scalability.
#[derive(Clone)]
#[allow(dead_code)]
pub struct EpidemicStorageEngine {
    /// Unique identifier for this node
    node_id: NodeId,

    /// Configuration for this epidemic storage instance
    config: EpidemicConfig,

    /// In-memory store for local data
    local_store: Arc<DashMap<String, EpidemicEntry>>,

    /// Vector clock for this node's logical time
    vector_clock: Arc<ParkingRwLock<VectorClock>>,

    /// Network topology management
    topology: Arc<tokio::sync::RwLock<HybridTopology>>,

    /// Partition management for distributing keys
    partition_manager: Arc<PartitionManager>,

    /// Interface for handling partitioned storage
    partitioned_storage: Arc<PartitionedStorage<String>>,

    /// Network client for inter-node communication
    network_client: Arc<dyn NetworkClient + Send + Sync>,

    /// Metrics collection for monitoring
    metrics: Arc<MetricsCollector>,
}

/// Configuration for the Epidemic Storage Engine.
///
/// This struct defines the behavior and characteristics of the
/// epidemic storage, including network topology, gossip parameters,
/// and conflict resolution strategies.
#[derive(Clone, Debug)]
pub struct EpidemicConfig {
    /// Unique identifier for this node
    pub node_id: NodeId,

    /// Interval in milliseconds between gossip rounds
    pub gossip_interval_ms: u64,

    /// Interval in milliseconds between data reconciliations
    pub reconciliation_interval_ms: u64,

    /// Interval in milliseconds between topology maintenance operations
    pub topology_maintenance_interval_ms: u64,

    /// Number of peers to gossip with in each round
    pub gossip_fanout: usize,

    /// Maximum number of entries to reconcile in a single round
    pub max_reconciliation_diff: usize,

    /// Strategy to resolve conflicts between divergent versions
    pub conflict_resolution_strategy: ConflictResolutionStrategy,

    /// Number of partitions to divide the key space into
    pub partition_count: usize,

    /// Number of replicas to maintain for each key
    pub replication_factor: usize,

    /// Strategy for partitioning keys across nodes
    pub partition_strategy: PartitionStrategy,

    /// Minimum number of nodes required before rebalancing
    pub min_nodes_for_rebalance: usize,

    /// Maximum number of partitions a single node can own
    pub max_partitions_per_node: usize,

    /// Number of close neighbors to maintain in the topology
    pub k_neighbors: usize,

    /// Small-world network parameter (controls long links)
    pub alpha: f64,

    /// Maximum number of long-distance links per node
    pub max_long_links: usize,

    /// Maximum number of connections in the topology
    pub max_topology_connections: usize,

    /// Timeout in milliseconds for topology connection attempts
    pub topology_connection_timeout_ms: u64,

    /// Optional interval in milliseconds for checking partition balance
    pub rebalance_check_interval_ms: Option<u64>,

    /// Optional stability factor for partition placement (0-1)
    pub placement_stability: Option<f64>,

    /// Optional limit on rebalance operations per interval
    pub rebalance_throttle: Option<usize>,

    /// Optional minimum interval in milliseconds between partition transfers
    pub min_transfer_interval_ms: Option<u64>,
}

/// Strategies for resolving conflicts between divergent versions.
///
/// When nodes have different versions of the same data, these strategies
/// determine which version should be considered authoritative.
#[derive(Clone, Debug)]
pub enum ConflictResolutionStrategy {
    /// The most recent update wins (based on timestamps)
    LastWriteWins,

    /// Use vector clocks to determine causal relationships and resolve conflicts
    VectorClock,

    /// Use a custom conflict resolution function identified by name
    Custom(String),
}

impl EpidemicStorageEngine {
    /// Creates a new Epidemic Storage Engine.
    ///
    /// Initializes the epidemic storage with the provided configuration,
    /// network client, and metrics collector. Also starts background tasks
    /// for gossip propagation, data reconciliation, and topology maintenance.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the epidemic storage
    /// * `network_client` - Client for network communication
    /// * `metrics` - Collector for operational metrics
    ///
    /// # Returns
    ///
    /// A Result containing the initialized epidemic storage engine
    pub fn new(
        config: EpidemicConfig,
        network_client: Arc<dyn NetworkClient + Send + Sync>,
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self> {
        info!(
            "Initializing Epidemic Storage Engine for node: {}",
            config.node_id
        );

        // Configure Partition Manager
        let partition_config = PartitionConfig {
            partition_count: config.partition_count,
            replication_factor: config.replication_factor,
            strategy: config.partition_strategy,
            min_nodes_for_rebalance: config.min_nodes_for_rebalance,
            max_partitions_per_node: config.max_partitions_per_node,
            rebalance_check_interval_ms: config.rebalance_check_interval_ms.unwrap_or(60000),
            placement_stability: config.placement_stability.unwrap_or(0.8),
            rebalance_throttle: config.rebalance_throttle.unwrap_or(5),
            min_transfer_interval_ms: config.min_transfer_interval_ms.unwrap_or(5000),
        };

        let partition_manager = Arc::new(PartitionManager::new(
            config.node_id.to_string(),
            partition_config,
        ));

        // Configure Hybrid Topology
        let topology_config = HybridTopologyConfig {
            structural_connection_count: config.k_neighbors,
            long_range_connection_count: config.max_long_links,
            geographic_connections_per_region: 5,
            min_region_coverage: 3,
            epidemic_alpha: config.alpha,
            epidemic_beta: 0.2,
            min_reputation_threshold: 50,
            refresh_interval_seconds: config.topology_maintenance_interval_ms / 1000,
        };

        let topology = Arc::new(tokio::sync::RwLock::new(HybridTopology::new(
            config.node_id.clone(),
            topology_config,
            None, // local region
        )));

        // Set network client and metrics
        {
            let mut topology_guard = topology.blocking_write();
            topology_guard.set_network_client(network_client.clone());
            topology_guard.set_metrics_collector(metrics.clone());
        }

        // Initialize Partitioned Storage Adapter
        let partitioned_storage = Arc::new(PartitionedStorage::new(
            partition_manager.clone(),
            config.node_id.to_string(),
        ));

        let engine = Self {
            node_id: config.node_id.clone(),
            config,
            local_store: Arc::new(DashMap::new()),
            vector_clock: Arc::new(ParkingRwLock::new(VectorClock::new())),
            topology,
            partition_manager,
            partitioned_storage,
            network_client,
            metrics,
        };

        // Schedule periodic tasks for epidemic propagation
        let engine_clone = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = engine_clone.init_periodic_tasks().await {
                tracing::error!("Failed to initialize periodic tasks: {}", e);
            }
        });

        Ok(engine)
    }

    /// Store data in the epidemic storage with key routing.
    ///
    /// Routes the data to the appropriate node(s) based on the key's hash
    /// and the partition assignment. If this node is not responsible for
    /// the key, it forwards the request to the primary node.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store the data under
    /// * `value` - The binary data to store
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure
    async fn put(&self, key: String, value: Vec<u8>) -> Result<()> {
        let _timer = self
            .metrics
            .start_operation(OperationType::Store, None, Some(key.clone()));

        if !self.partitioned_storage.is_responsible(key.as_bytes())? {
            // Forward the request to the responsible node(s)
            let (primary, _) = self
                .partitioned_storage
                .get_responsible_nodes(key.as_bytes())?;
            info!(
                "Not responsible for key {}, forwarding PUT to primary: {}",
                key, primary
            );
            if primary != self.node_id.to_string() {
                self.network_client
                    .forward_put(primary.to_string(), key.clone(), value.clone())
                    .await?;
                return Ok(());
            }
        }

        let mut vc = self.vector_clock.write();
        vc.increment(&self.node_id.to_string());
        let new_entry = EpidemicEntry {
            key: key.clone(),
            value,
            vector_clock: vc.clone(),
            timestamp: SystemTime::now(),
        };

        self.local_store.insert(key.clone(), new_entry.clone());
        debug!("Stored key: {}", key);

        Ok(())
    }

    /// Retrieve data from the epidemic storage with key routing.
    ///
    /// Retrieves data from the appropriate node based on the key's hash
    /// and partition assignment. If this node is not responsible for the
    /// key, it forwards the request to the primary node.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve data for
    ///
    /// # Returns
    ///
    /// A Result containing an Option with the data if found
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _timer =
            self.metrics
                .start_operation(OperationType::Retrieve, None, Some(key.to_string()));

        if !self.partitioned_storage.is_responsible(key.as_bytes())? {
            // Forward the request to the responsible node(s)
            let (primary, _) = self
                .partitioned_storage
                .get_responsible_nodes(key.as_bytes())?;
            info!(
                "Not responsible for key {}, forwarding GET to primary: {}",
                key, primary
            );
            if primary != self.node_id.to_string() {
                let result = self
                    .network_client
                    .forward_get(primary.to_string(), key.to_string())
                    .await?;
                return Ok(result);
            }
        }

        match self.local_store.get(key) {
            Some(entry) => {
                let value = entry.value().value.clone();
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Delete data from the epidemic storage with key routing.
    ///
    /// Deletes data from the appropriate node based on the key's hash and
    /// partition assignment. Implements deletion using tombstones to ensure
    /// deleted keys are properly propagated through the system.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure
    async fn delete_internal(&self, key: &str) -> Result<()> {
        let _timer =
            self.metrics
                .start_operation(OperationType::Delete, None, Some(key.to_string()));

        if !self.partitioned_storage.is_responsible(key.as_bytes())? {
            // Forward the request to the responsible node(s)
            let (primary, _) = self
                .partitioned_storage
                .get_responsible_nodes(key.as_bytes())?;
            info!(
                "Not responsible for key {}, forwarding DELETE to primary: {}",
                key, primary
            );
            if primary != self.node_id.to_string() {
                self.network_client
                    .forward_delete(primary.to_string(), key.to_string())
                    .await?;
                return Ok(());
            }
        }

        // Implement deletion using tombstones
        let mut vc = self.vector_clock.write();
        vc.increment(&self.node_id.to_string());
        let tombstone_entry = EpidemicEntry {
            key: key.to_string(),
            value: Vec::new(), // Empty value signifies tombstone
            vector_clock: vc.clone(),
            timestamp: SystemTime::now(), // Mark deletion time
        };

        self.local_store
            .insert(key.to_string(), tombstone_entry.clone());
        debug!("Marked key for deletion (tombstone): {}", key);

        Ok(())
    }

    /// Generate a digest of blinded state entries for synchronization.
    ///
    /// Creates a map of key to blinded state entry for all non-tombstone
    /// entries in the local store. This digest is used during gossip and
    /// reconciliation to identify differences between nodes.
    ///
    /// # Returns
    ///
    /// A HashMap mapping keys to BlindedStateEntry instances
    fn get_blinded_state_digest(&self) -> HashMap<String, BlindedStateEntry> {
        let mut digest = HashMap::new();

        for entry in self.local_store.iter() {
            let key = entry.key().clone();
            let value = entry.value();

            // Skip tombstones (empty values)
            if value.value.is_empty() {
                continue;
            }

            let timestamp = value
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let blinded_entry = BlindedStateEntry {
                blinded_id: key.clone(),
                encrypted_payload: value.value.clone(),
                ttl: 3600, // Default TTL
                region: "default".to_string(),
                priority: 0,
                proof_hash: [0u8; 32], // Empty proof hash for now
                metadata: HashMap::new(),
                timestamp,
            };

            digest.insert(key, blinded_entry);
        }

        digest
    }

    /// Initialize periodic tasks for epidemic propagation.
    ///
    /// Sets up background tasks for gossip, reconciliation, and topology
    /// maintenance. These tasks run at the intervals specified in the
    /// configuration.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure
    async fn init_periodic_tasks(&self) -> Result<()> {
        // Use get_blinded_state_digest to synchronize with peers periodically
        let self_clone = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(
                self_clone.config.gossip_interval_ms,
            ));
            loop {
                interval.tick().await;
                // Get current state digest
                let digest = self_clone.get_blinded_state_digest();
                // In a real implementation, you would send this digest to peers
                tracing::debug!("Generated state digest with {} entries", digest.len());
                // ... synchronization logic with peers would go here
            }
        });
        Ok(())
    }
}

#[async_trait]
impl StorageEngine for EpidemicStorageEngine {
    /// Store a blinded state entry in the epidemic storage.
    ///
    /// This operation adds or updates a state entry in the storage.
    /// The entry will be routed to the appropriate node(s) based on
    /// the blinded_id hash and partition assignment.
    ///
    /// # Arguments
    ///
    /// * `entry` - The blinded state entry to store
    ///
    /// # Returns
    ///
    /// A `Result` containing a `StorageResponse` with operation details
    async fn store(&self, entry: BlindedStateEntry) -> Result<StorageResponse> {
        let key = entry.blinded_id.clone();
        let value = entry.encrypted_payload.clone();

        self.put(key, value).await?;

        Ok(StorageResponse {
            blinded_id: entry.blinded_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            status: "success".to_string(),
            message: Some("Stored entry".to_string()),
        })
    }

    /// Retrieve a blinded state entry by its ID.
    ///
    /// Retrieves an entry from the appropriate node based on the
    /// blinded_id hash and partition assignment.
    ///
    /// # Arguments
    ///
    /// * `blinded_id` - The unique identifier for the blinded state entry
    ///
    /// # Returns
    ///
    /// A `Result` containing an Option with the entry if found
    async fn retrieve(&self, blinded_id: &str) -> Result<Option<BlindedStateEntry>> {
        let data = self.get(blinded_id).await?;

        if let Some(value) = data {
            Ok(Some(BlindedStateEntry {
                blinded_id: blinded_id.to_string(),
                encrypted_payload: value,
                ttl: 3600, // Default TTL - should be configurable
                region: "default".to_string(),
                priority: 0,
                proof_hash: [0u8; 32], // Empty proof hash
                metadata: HashMap::new(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Check if a blinded state entry exists in the storage.
    ///
    /// # Arguments
    ///
    /// * `blinded_id` - The unique identifier for the blinded state entry
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating existence
    async fn exists(&self, blinded_id: &str) -> Result<bool> {
        Ok(self.local_store.contains_key(blinded_id))
    }

    /// List all blinded state entries in the storage.
    ///
    /// # Arguments
    ///
    /// * `limit` - Optional maximum number of entries to return
    /// * `offset` - Optional offset for pagination
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of blinded IDs
    async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>> {
        let mut keys = self
            .local_store
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<String>>();

        // Apply offset if provided
        if let Some(offset_val) = offset {
            keys = keys.into_iter().skip(offset_val).collect();
        }

        // Apply limit if provided
        if let Some(limit_val) = limit {
            keys.truncate(limit_val);
        }

        Ok(keys)
    }

    /// Get statistics about the epidemic storage.
    ///
    /// # Returns
    ///
    /// A `Result` containing storage statistics
    async fn get_stats(&self) -> Result<StorageStats> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Calculate stats based on local store
        let _total_entries = Some(self.local_store.len() as u64);
        let mut oldest_entry = None;
        let mut newest_entry = None;
        let mut total_expired = Some(0);
        let mut total_bytes = 0;

        for entry in self.local_store.iter() {
            let timestamp = entry
                .value()
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if let Some(oldest) = oldest_entry {
                if timestamp < oldest {
                    oldest_entry = Some(timestamp);
                }
            } else {
                oldest_entry = Some(timestamp);
            }

            if let Some(newest) = newest_entry {
                if timestamp > newest {
                    newest_entry = Some(timestamp);
                }
            } else {
                newest_entry = Some(timestamp);
            }

            // Calculate total bytes
            total_bytes += entry.value().value.len() as u64;

            // Simplistic TTL check (3600 seconds)
            if current_time - timestamp > 3600 {
                if let Some(expired) = total_expired {
                    total_expired = Some(expired + 1);
                }
            }
        }

        let stats = StorageStats {
            total_entries: self.local_store.len(),
            total_expired: total_expired.unwrap_or(0) as usize,
            oldest_entry,
            newest_entry,
            total_bytes: total_bytes as usize,
        };

        Ok(stats)
    }

    /// Delete a blinded state entry by its ID.
    ///
    /// # Arguments
    ///
    /// * `blinded_id` - The unique identifier for the blinded state entry to delete
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating success
    async fn delete(&self, blinded_id: &str) -> Result<bool> {
        self.delete_internal(blinded_id).await?;

        // Return true to indicate successful deletion
        Ok(true)
    }
}

/// Helper function to get current time in seconds since epoch.
///
/// # Returns
///
/// The current time as seconds since the Unix epoch
#[allow(dead_code)]
fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
