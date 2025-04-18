// Epidemic Storage implementation for DSM Storage Node
//
// This module implements the epidemic storage engine for the DSM storage node
// with small-world topology and vector clock synchronized storage.

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

// Define the topology type enum for config
#[derive(Clone, Debug)]
pub enum TopologyType {
    DistributedMesh,
    RandomGraph,
    StructuredOverlay,
}

// Define EpidemicEntry and StateEntry types
#[derive(Clone, Debug)]
struct EpidemicEntry {
    key: String,
    value: Vec<u8>,
    vector_clock: VectorClock,
    timestamp: SystemTime,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct StateEntry {
    key: String,
    value: Vec<u8>,
    vector_clock: VectorClock,
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
    fn from_state_entry(entry: StateEntry, timestamp: SystemTime) -> Self {
        Self {
            key: entry.key,
            value: entry.value,
            vector_clock: entry.vector_clock,
            timestamp,
        }
    }
}

// Public types for epidemic storage
#[derive(Clone)]
#[allow(dead_code)]
pub struct EpidemicStorageEngine {
    node_id: NodeId,
    config: EpidemicConfig,
    local_store: Arc<DashMap<String, EpidemicEntry>>,
    vector_clock: Arc<ParkingRwLock<VectorClock>>,
    topology: Arc<tokio::sync::RwLock<HybridTopology>>,
    partition_manager: Arc<PartitionManager>,
    partitioned_storage: Arc<PartitionedStorage<String>>,
    network_client: Arc<dyn NetworkClient + Send + Sync>,
    metrics: Arc<MetricsCollector>,
}

// Define config structure for epidemic storage
#[derive(Clone, Debug)]
pub struct EpidemicConfig {
    pub node_id: NodeId,
    pub gossip_interval_ms: u64,
    pub reconciliation_interval_ms: u64,
    pub topology_maintenance_interval_ms: u64,
    pub gossip_fanout: usize,
    pub max_reconciliation_diff: usize,
    pub conflict_resolution_strategy: ConflictResolutionStrategy,
    pub partition_count: usize,
    pub replication_factor: usize,
    pub partition_strategy: PartitionStrategy,
    pub min_nodes_for_rebalance: usize,
    pub max_partitions_per_node: usize,
    pub k_neighbors: usize,
    pub alpha: f64,
    pub max_long_links: usize,
    pub max_topology_connections: usize,
    pub topology_connection_timeout_ms: u64,
    pub rebalance_check_interval_ms: Option<u64>,
    pub placement_stability: Option<f64>,
    pub rebalance_throttle: Option<usize>,
    pub min_transfer_interval_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum ConflictResolutionStrategy {
    LastWriteWins,
    VectorClock,
    Custom(String),
}

impl EpidemicStorageEngine {
    /// Creates a new Epidemic Storage Engine.
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

    // Internal methods that implement the core functionality but aren't exposed via the StorageEngine trait
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

    // Initialize periodic tasks for epidemic propagation
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

    async fn exists(&self, blinded_id: &str) -> Result<bool> {
        Ok(self.local_store.contains_key(blinded_id))
    }

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

    async fn delete(&self, blinded_id: &str) -> Result<bool> {
        self.delete_internal(blinded_id).await?;

        // Return true to indicate successful deletion
        Ok(true)
    }
}

// Helper function to get current time in seconds since epoch
#[allow(dead_code)]
fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
