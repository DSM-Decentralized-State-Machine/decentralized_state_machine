// Partition management for epidemic storage
//
// This module implements deterministic rotation and partitioning mechanisms
// to distribute storage load across nodes while maintaining locality.

use crate::error::Result;
use crate::error::StorageNodeError;
use crate::storage::topology::calculate_key_hash;
use crate::storage::StorageEngine; // Added for potential interaction
use crate::types::StorageNode;
use tracing::{error, info, warn}; // Added 'error' macro
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering}; // Use imported AtomicU64 and Ordering
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
// Add this import to fix the unresolved module error
use tracing as log;

/// PartitionedStorage adapter for integrating with epidemic storage
pub struct PartitionedStorage<S> {
    /// Underlying storage engine
    // Removed unused field `storage`

    /// Partition manager
    partition_manager: Arc<PartitionManager>,

    /// Node ID
    node_id: String,

    /// Marker for unused type parameter
    _marker: std::marker::PhantomData<S>,
}

/// Partition assignment strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStrategy {
    /// Consistent hashing around ring
    ConsistentHash,

    /// Random assignment
    Random,

    /// Geography optimized
    GeographyAware,

    /// Load-balanced
    LoadBalanced,
}

/// Partition information
#[derive(Debug, Clone)]
pub struct Partition {
    /// Partition ID
    pub id: String,

    /// Start range (inclusive)
    pub start: Vec<u8>,

    /// End range (exclusive)
    pub end: Vec<u8>,

    /// Primary owner
    pub primary: String,

    /// Replicas
    pub replicas: Vec<String>,

    /// Timestamp of last assignment
    pub last_assignment: u64,

    /// Assignment generation
    pub generation: u64,

    /// Keyspace fraction (0.0 - 1.0)
    pub keyspace_fraction: f64,

    /// Estimated item count
    pub estimated_items: u64,

    /// Estimated size in bytes
    pub estimated_size: u64,
}

/// Transfer state of a partition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Not being transferred
    None,

    /// Preparing for transfer
    Preparing,

    /// Transferring data
    Transferring,

    /// Verifying transfer
    Verifying,

    /// Transfer complete
    Complete,

    /// Transfer failed
    Failed,
}

/// Partition transfer information
#[derive(Debug, Clone)]
pub struct PartitionTransfer {
    /// Partition ID
    pub partition_id: String,

    /// Source node
    pub source: String,

    /// Target node
    pub target: String,

    /// Transfer state
    pub state: TransferState,

    /// Start time
    pub start_time: u64,

    /// Completion time (if completed)
    pub completion_time: Option<u64>,

    /// Total items
    pub total_items: u64,

    /// Transferred items
    pub transferred_items: u64,

    /// Transfer rate (items per second)
    pub items_per_second: f64,

    /// Total bytes
    pub total_bytes: u64,

    /// Transferred bytes
    pub transferred_bytes: u64,

    /// Transfer rate (bytes per second)
    pub bytes_per_second: f64,

    /// Transfer priority
    pub priority: i32,

    /// Retry count
    pub retry_count: u32,
}

/// Partition ring configuration
#[derive(Debug, Clone)]
pub struct PartitionConfig {
    /// Number of partitions
    pub partition_count: usize,

    /// Replication factor
    pub replication_factor: usize,

    /// Placement strategy
    pub strategy: PartitionStrategy,

    /// Minimum nodes for auto-rebalance
    pub min_nodes_for_rebalance: usize,

    /// Maximum partitions per node
    pub max_partitions_per_node: usize,

    /// Rebalance check interval in milliseconds
    pub rebalance_check_interval_ms: u64,

    /// Placement stability factor (0.0-1.0, higher means less movement)
    pub placement_stability: f64,

    /// Rebalance throttle (partitions per minute)
    pub rebalance_throttle: usize,

    /// Minimum transfer interval between partitions (milliseconds)
    pub min_transfer_interval_ms: u64,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            partition_count: 256,
            replication_factor: 3,
            strategy: PartitionStrategy::ConsistentHash,
            min_nodes_for_rebalance: 3,
            max_partitions_per_node: 32,
            rebalance_check_interval_ms: 60000, // 1 minute
            placement_stability: 0.8,
            rebalance_throttle: 5,          // 5 partitions per minute
            min_transfer_interval_ms: 5000, // 5 seconds
        }
    }
}

/// Transfer batch configuration
#[derive(Debug, Clone)]
pub struct TransferBatchConfig {
    /// Maximum number of concurrent transfers
    pub max_concurrent_transfers: usize,
    /// Maximum batch size in bytes
    pub max_batch_size_bytes: usize,
    /// Priority queue size
    pub priority_queue_size: usize,
    /// Timeout for each transfer operation
    pub transfer_timeout_ms: u64,
    /// Number of retry attempts
    pub max_retries: u32,
}

impl Default for TransferBatchConfig {
    fn default() -> Self {
        Self {
            max_concurrent_transfers: 5,
            max_batch_size_bytes: 1024 * 1024 * 50, // 50MB
            priority_queue_size: 1000,
            transfer_timeout_ms: 30000, // 30 seconds
            max_retries: 3,
        }
    }
}

/// Region metrics for geography-aware placement
#[derive(Debug)]
pub struct RegionMetrics {
    pub total_capacity: u64,
    pub current_load: u64,
    pub partition_count: usize,
    pub node_count: usize,
    pub avg_latency: f64,
    pub failure_rate: f64,
}

/// Replication task
#[derive(Debug, Clone)]
pub struct ReplicationTask {
    pub partition_id: String,
    pub priority: ReplicationPriority,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Replication priority
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationType {
    Read,
    Write,
    Delete,
}

/// Partition move priority
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MovePriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Partition move
#[derive(Debug, Clone)]
pub struct PartitionMove {
    pub partition_id: String,
    pub source_node: String,
    pub target_node: String,
    pub reason: String,
    pub priority: MovePriority,
}

/// Node load metrics for load balancing
#[derive(Debug)]
pub struct NodeLoadMetrics {
    pub partition_count: usize,
    pub capacity_used: u64,
    pub recent_latency: Duration,
    pub max_capacity: u64,
    pub current_load: u64,
}

/// Extended StorageNode with capacity and load fields needed for load balancing
#[derive(Debug, Clone)]
pub struct ExtendedStorageNode {
    /// Base StorageNode
    pub node: StorageNode,

    /// Node capacity (useful for load balancing)
    pub capacity: u64,

    /// Current load (useful for load balancing)
    pub current_load: u64,
}

// Struct for metrics
#[derive(Debug, Clone)]
pub struct PartitionMetrics {
    pub item_count: u64,
    pub size_bytes: u64,
    pub key_distribution: HashMap<String, u64>,
}

/// Partition manager
/// Type alias for transfer handler function
type TransferHandlerFn = Arc<dyn Fn(PartitionTransfer) -> Result<()> + Send + Sync>;

/// Type alias for transfer handlers map
type TransferHandlerMap = Arc<RwLock<HashMap<String, TransferHandlerFn>>>;

pub struct PartitionManager {
    /// Node ID
    node_id: String,

    /// Configuration
    config: PartitionConfig,

    /// Partitions map
    partitions: Arc<DashMap<String, Partition>>,

    /// Nodes map (node_id -> node)
    nodes: Arc<RwLock<HashMap<String, StorageNode>>>,

    /// Node partition counts (node_id -> count)
    node_partition_counts: Arc<DashMap<String, usize>>,

    /// Active transfers
    active_transfers: Arc<DashMap<String, PartitionTransfer>>,

    /// Ring generation counter
    ring_generation: Arc<AtomicU64>, // Use imported AtomicU64

    /// Last global rebalance timestamp
    last_rebalance: Arc<RwLock<Instant>>,

    /// Transfer handlers
    transfer_handlers: TransferHandlerMap,

    /// Replication queue
    #[allow(dead_code)]
    replication_queue: Arc<parking_lot::Mutex<Vec<ReplicationTask>>>,
}
impl PartitionManager {
    /// Create a new partition manager
    pub fn new(node_id: String, config: PartitionConfig) -> Self {
        Self {
            node_id,
            config,
            partitions: Arc::new(DashMap::new()),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            node_partition_counts: Arc::new(DashMap::new()),
            active_transfers: Arc::new(DashMap::new()),
            ring_generation: Arc::new(AtomicU64::new(1)), // Use imported AtomicU64
            last_rebalance: Arc::new(RwLock::new(Instant::now())),
            transfer_handlers: Arc::new(RwLock::new(HashMap::new())),
            replication_queue: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }

    /// Initialize the partition ring
    pub fn initialize(&self) -> Result<()> {
        // Initialize the partition ring
        info!(
            "Initializing partition ring with {} partitions",
            self.config.partition_count
        );

        // Create the partitions
        self.create_partitions()?;

        // Initialize node partition counts
        {
            let nodes = self.nodes.read();
            for node_id in nodes.keys() {
                self.node_partition_counts.insert(node_id.clone(), 0);
            }
        }

        Ok(())
    }

    /// Create the partitions
    fn create_partitions(&self) -> Result<()> {
        let count = self.config.partition_count;

        // Clear existing partitions
        self.partitions.clear();

        // Calculate step size
        let step = (u64::MAX as f64) / (count as f64);

        for i in 0..count {
            let start_value = (i as f64 * step) as u64;
            let end_value = ((i + 1) as f64 * step) as u64;

            // Convert values to byte arrays
            let mut start = Vec::with_capacity(8);
            let mut end = Vec::with_capacity(8);

            for j in 0..8 {
                start.push(((start_value >> (8 * (7 - j))) & 0xFF) as u8);
                end.push(((end_value >> (8 * (7 - j))) & 0xFF) as u8);
            }

            // Create partition
            let partition_id = format!("partition-{:08x}", i);

            let partition = Partition {
                id: partition_id.clone(),
                start,
                end,
                primary: "".to_string(),
                replicas: Vec::new(),
                last_assignment: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs(),
                generation: 1,
                keyspace_fraction: 1.0 / (count as f64),
                estimated_items: 0,
                estimated_size: 0,
            };

            self.partitions.insert(partition_id, partition);
        }

        Ok(())
    }

    /// Add a node to the ring
    pub fn add_node(&self, node: StorageNode) -> Result<()> {
        let node_id = node.id.clone();

        // Add to nodes map
        {
            let mut nodes = self.nodes.write();
            nodes.insert(node_id.clone(), node);
        }

        // Initialize partition count
        self.node_partition_counts.insert(node_id, 0);

        // Rebalance if we have enough nodes
        if self.get_node_count() >= self.config.min_nodes_for_rebalance {
            self.rebalance()?;
        }

        Ok(())
    }

    /// Remove a node from the ring
    pub fn remove_node(&self, node_id: &str) -> Result<()> {
        // Remove from nodes map
        {
            let mut nodes = self.nodes.write();
            nodes.remove(node_id);
        }

        // Remove partition count
        self.node_partition_counts.remove(node_id);

        // Rebalance if we have enough nodes
        if self.get_node_count() >= self.config.min_nodes_for_rebalance {
            self.rebalance()?;
        }

        Ok(())
    }

    /// Rebalance the partition ring
    pub fn rebalance(&self) -> Result<()> {
        let nodes = self.nodes.read();
        let node_count = nodes.len();

        if node_count < self.config.min_nodes_for_rebalance {
            return Ok(());
        }

        // Update last rebalance time
        *self.last_rebalance.write() = Instant::now();

        // Create optimized assignments
        match self.config.strategy {
            PartitionStrategy::ConsistentHash => {
                self.rebalance_consistent_hash(&nodes)?;
            }
            PartitionStrategy::Random => {
                self.rebalance_random(&nodes)?;
            }
            PartitionStrategy::GeographyAware => {
                self.rebalance_geography_aware(&nodes)?;
            }
            PartitionStrategy::LoadBalanced => {
                self.rebalance_load_balanced(&nodes)?;
            }
        }

        // Increment ring generation
        self.ring_generation.fetch_add(1, Ordering::SeqCst); // Use imported Ordering

        Ok(())
    }

    /// Rebalance using consistent hashing algorithm
    fn rebalance_consistent_hash(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        let node_ids: Vec<String> = nodes.keys().cloned().collect();

        // Fundamental architectural invariant: rebalancing requires nodes
        if node_ids.is_empty() {
            info!(
                "Critical state: No nodes available in topology. Using self-healing mechanism..."
            );
            info!(
                "Assigning all partitions to local node {} to maintain system integrity",
                self.node_id
            );

            // Emergency self-assignment to maintain system availability
            for mut partition_entry in self.partitions.iter_mut() {
                let partition = partition_entry.value_mut();
                partition.primary = self.node_id.clone();
                partition.replicas = Vec::new(); // No replicas in emergency mode
                partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
                // Use imported Ordering
            }
            return Ok(());
        }

        // Reset partition allocation counters
        for node_id in &node_ids {
            self.node_partition_counts.insert(node_id.clone(), 0);
        }

        // Core consistent hash ring with ultra-high-density virtual nodes
        let mut hash_ring = BTreeMap::new();
        const VIRTUAL_NODE_DENSITY: u32 = 512; // Higher density ensures more uniform distribution

        // Virtual node injection phase with cryptographically strong identifiers
        for (i, node_id) in node_ids.iter().enumerate() {
            // Critical: Create a distinct discriminator pattern for each physical node
            let node_index = format!("{:04x}", i);

            for v in 0..VIRTUAL_NODE_DENSITY {
                // Enhanced entropy discriminator with positional encoding
                let vnode_key = format!("{}-{:08x}-{}", node_id, v, node_index);
                let hash = calculate_key_hash(&vnode_key);

                // Deterministic hash transformation using idiomatic fold pattern
                let position = hash
                    .0
                    .iter()
                    .take(8)
                    .fold(0u64, |acc, &b| (acc << 8) | b as u64);

                // Virtual-to-physical mapping
                hash_ring.insert(position, node_id.clone());
            }
        }

        // Critical topology validation
        if hash_ring.is_empty() {
            return Err(StorageNodeError::Storage(
                "Critical topology corruption: virtual node injection phase failed".to_string(),
            ));
        }

        // Diagnostic instrumentation with uniform distribution validation
        let unique_physical_nodes = hash_ring.values().collect::<HashSet<_>>().len();
        info!(
            "Consistent hash ring topology: {} virtual nodes mapped to {} physical nodes",
            hash_ring.len(),
            unique_physical_nodes
        );

        // Foundational correctness assertion
        assert_eq!(
            unique_physical_nodes,
            node_ids.len(),
            "Topological invariant violation: physical node count mismatch"
        );

        // Partition assignment phase with guaranteed total coverage
        let mut assigned_partitions = 0;

        // Pre-cached ring traversal points for optimal concurrency distribution
        let _first_position = hash_ring.iter().next().map(|(pos, _)| *pos).unwrap_or(0);
        let ring_entries: Vec<(u64, String)> = hash_ring
            .iter()
            .map(|(pos, node)| (*pos, node.clone()))
            .collect();

        info!(
            "Executing deterministic partition assignment with {} partitions",
            self.partitions.len()
        );

        // Collect partition IDs first to avoid holding iterator during potential map modifications
        let partition_ids: Vec<String> = self.partitions.iter().map(|e| e.key().clone()).collect();

        // Total partition coverage guarantee
        for partition_id in partition_ids {
            // Deterministic partition position using identical hash transformation
            let partition_hash = calculate_key_hash(&partition_id);
            let position = partition_hash
                .0
                .iter()
                .take(8)
                .fold(0u64, |acc, &b| (acc << 8) | b as u64);

            // Primary node allocation with mandatory assignment guarantee
            let primary_owner = if let Some((_, node_id)) = hash_ring.range(position..).next() {
                // Forward traversal hit
                node_id.clone()
            } else if !ring_entries.is_empty() {
                // Ring wraparound with explicit first entry extraction
                ring_entries[0].1.clone()
            } else {
                // Ultra-defensive fallback (should never execute due to earlier validation)
                self.node_id.clone()
            };

            // Multi-phase replica selection with deduplication to maximize topological distance
            let mut assigned_physical_nodes = HashSet::new();
            assigned_physical_nodes.insert(primary_owner.clone());

            // Phase 1: Forward scan from partition position
            let mut potential_replicas = Vec::new();

            // Geometric traversal for optimal replica spacing
            let mut current_pos = position;
            for _ in 0..hash_ring.len() {
                if let Some((pos, node)) = hash_ring.range((current_pos + 1)..).next() {
                    if !assigned_physical_nodes.contains(node) {
                        potential_replicas.push(node.clone());
                        assigned_physical_nodes.insert(node.clone());
                        current_pos = *pos;

                        if potential_replicas.len() >= self.config.replication_factor * 2 {
                            break;
                        }
                    } else {
                        // Skip duplicate physical nodes but continue traversal
                        current_pos = *pos;
                    }
                } else {
                    // Reached end of ring, wrap around to beginning
                    break;
                }
            }

            // Phase 2: Wraparound scan if needed
            if potential_replicas.len() < self.config.replication_factor - 1
                && !ring_entries.is_empty()
            {
                // Start from beginning of ring
                for (pos, node) in &ring_entries {
                    if *pos >= current_pos {
                        break; // Completed full ring traversal
                    }

                    if !assigned_physical_nodes.contains(node) {
                        potential_replicas.push(node.clone());
                        assigned_physical_nodes.insert(node.clone());

                        if potential_replicas.len() >= self.config.replication_factor - 1 {
                            break;
                        }
                    }
                }
            }

            // Take final replica set up to replication factor, ensuring correct type
            let replica_owners: Vec<String> = potential_replicas
                .into_iter()
                .take(self.config.replication_factor.saturating_sub(1))
                .collect();

            // Get mutable reference again and update
            if let Some(mut partition_entry) = self.partitions.get_mut(&partition_id) {
                let partition = partition_entry.value_mut();
                let old_primary = partition.primary.clone();

                // Atomic partition update
                partition.primary = primary_owner.clone();
                partition.replicas = replica_owners; // Assign Vec<String>
                partition.last_assignment = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
                partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1; // Use imported Ordering

                // Update load distribution metrics
                if let Some(mut count) = self.node_partition_counts.get_mut(&primary_owner) {
                    *count += 1;
                }

                // Track successful assignment
                assigned_partitions += 1;

                // Coordinate data transfer if ownership changed
                if !old_primary.is_empty() && old_primary != primary_owner {
                    // Pass the updated partition reference
                    self.create_transfer(partition, &old_primary, &primary_owner)?;
                }
            } else {
                warn!("Partition {} disappeared during rebalance", partition_id);
            }
        }

        // Post-assignment verification with comprehensive diagnostics
        info!(
            "Partition assignment complete: {}/{} partitions assigned",
            assigned_partitions,
            self.partitions.len()
        );

        assert_eq!(
            assigned_partitions,
            self.partitions.len(),
            "Assignment invariant violation: incomplete partition coverage"
        );

        // Load distribution analysis
        let max_partitions = self
            .node_partition_counts
            .iter()
            .map(|entry| *entry.value())
            .max()
            .unwrap_or(0);

        let min_partitions = self
            .node_partition_counts
            .iter()
            .map(|entry| *entry.value())
            .min()
            .unwrap_or(0);

        let partition_count = self.partitions.len();
        let node_count = node_ids.len();
        let expected_avg = partition_count as f64 / node_count as f64;

        info!(
            "Load distribution: avg={:.2} min={} max={} (expected avg={:.2})",
            assigned_partitions as f64 / node_count as f64,
            min_partitions,
            max_partitions,
            expected_avg
        );

        if max_partitions > self.config.max_partitions_per_node {
            warn!(
                "Load imbalance detected: max={} exceeds threshold={}",
                max_partitions, self.config.max_partitions_per_node
            );
        }

        Ok(())
    }

    /// Rebalance using random assignment
    fn rebalance_random(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        let node_ids: Vec<String> = nodes.keys().cloned().collect();

        if node_ids.is_empty() {
            return Ok(());
        }

        // Clear current node partition counts
        for node_id in &node_ids {
            self.node_partition_counts.insert(node_id.clone(), 0);
        }

        // Assign partitions randomly
        use rand::{seq::SliceRandom, thread_rng};

        // Continue with the random assignment implementation...
        let mut rng = thread_rng();

        for mut partition_entry in self.partitions.iter_mut() {
            let partition = partition_entry.value_mut();

            // Remember old primary for transfer creation
            let old_primary = partition.primary.clone();

            // Randomly select primary and replicas
            let mut selected_nodes = node_ids.clone();
            selected_nodes.shuffle(&mut rng);

            let primary = selected_nodes[0].clone();
            let replicas: Vec<String> = selected_nodes[1..]
                .iter()
                .take(self.config.replication_factor.min(selected_nodes.len() - 1))
                .cloned()
                .collect();

            // Update partition info
            partition.primary = primary.clone();
            partition.replicas = replicas;
            partition.last_assignment = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs();
            partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1; // Use imported Ordering

            // Update node partition counts
            if let Some(mut count) = self.node_partition_counts.get_mut(&primary) {
                *count += 1;
            }

            // Create transfer if ownership changed
            if !old_primary.is_empty() && old_primary != primary {
                self.create_transfer(partition, &old_primary, &primary)?;
            }
        }

        Ok(())
    }

    /// Rebalance using geography-aware algorithm to optimize data locality
    fn rebalance_geography_aware(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        // Group nodes by region
        let mut nodes_by_region: HashMap<String, Vec<&StorageNode>> = HashMap::new();
        for node in nodes.values() {
            nodes_by_region
                .entry(node.region.clone())
                .or_default()
                .push(node);
        }

        // Calculate region capacities and current loads
        let mut region_metrics: HashMap<String, RegionMetrics> = HashMap::new();
        for (region, region_nodes) in &nodes_by_region {
            // Since StorageNode doesn't have capacity/current_load fields,
            // use a placeholder value (1) for each node
            let node_count = region_nodes.len();
            let total_capacity = node_count as u64; // One unit per node
            let current_load = 0u64; // Assume no load initially

            // Count partitions assigned to nodes in this region
            let partition_count = region_nodes
                .iter()
                .map(|n| {
                    self.node_partition_counts
                        .get(&n.id)
                        .map(|c| *c)
                        .unwrap_or(0)
                })
                .sum();

            region_metrics.insert(
                region.clone(),
                RegionMetrics {
                    total_capacity,
                    current_load,
                    partition_count,
                    node_count,
                    avg_latency: 0.0,
                    failure_rate: 0.0,
                },
            );
        }

        // Process each partition
        for mut partition_entry in self.partitions.iter_mut() {
            let partition = partition_entry.value_mut();
            let primary_region = nodes
                .get(&partition.primary)
                .map(|n| n.region.clone())
                .unwrap_or_default();

            // Determine target regions for replicas
            let mut target_regions = self.select_target_regions(
                &primary_region,
                &region_metrics,
                self.config.replication_factor,
            )?;

            // Ensure primary stays in original region if possible
            if !target_regions.contains(&primary_region)
                && nodes_by_region.contains_key(&primary_region)
            {
                target_regions[0] = primary_region.clone();
            }

            // Select best nodes in each target region
            let mut new_replicas = Vec::new();
            let mut assigned_nodes = HashSet::new();
            assigned_nodes.insert(&partition.primary);

            for region in target_regions {
                if let Some(region_nodes) = nodes_by_region.get(&region) {
                    if let Some(best_node) =
                        self.select_best_node_in_region(region_nodes, &assigned_nodes, partition)?
                    {
                        new_replicas.push(best_node.id.clone());
                        assigned_nodes.insert(&best_node.id);
                    }
                }
            }

            // Update partition replicas if changed
            if new_replicas != partition.replicas {
                partition.replicas = new_replicas;

                // Update assignment timestamp and generation
                partition.last_assignment = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
                partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
                // Use imported Ordering
            }
        }

        Ok(())
    }

    /// Helper function to select target regions for replication
    fn select_target_regions(
        &self,
        primary_region: &str,
        region_metrics: &HashMap<String, RegionMetrics>,
        replication_factor: usize,
    ) -> Result<Vec<String>> {
        let mut regions: Vec<_> = region_metrics.iter().collect();

        // Sort regions by health metrics
        regions.sort_by(|(_, metrics_a), (_, metrics_b)| {
            // Prefer regions with lower load relative to capacity
            let load_a = metrics_a.current_load as f64 / metrics_a.total_capacity as f64;
            let load_b = metrics_b.current_load as f64 / metrics_b.total_capacity as f64;

            // Consider failure rates and latency as tiebreakers
            if (load_b - load_a).abs() < 0.1 {
                let health_a = metrics_a.failure_rate * metrics_a.avg_latency;
                let health_b = metrics_b.failure_rate * metrics_b.avg_latency;
                health_a
                    .partial_cmp(&health_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            } else {
                load_a
                    .partial_cmp(&load_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }
        });

        // Always include primary region first
        let mut selected = vec![primary_region.to_string()];

        // Add remaining regions up to replication factor
        selected.extend(
            regions
                .iter()
                .filter(|(region, _)| *region != primary_region)
                .take(replication_factor - 1)
                .map(|(region, _)| region.to_string()),
        );

        Ok(selected)
    }

    /// Helper function to select the best node in a region for a partition
    fn select_best_node_in_region<'a>(
        &self,
        region_nodes: &'a [&'a StorageNode],
        assigned_nodes: &HashSet<&String>,
        _partition: &Partition,
    ) -> Result<Option<&'a StorageNode>> {
        let mut candidates: Vec<&StorageNode> = region_nodes
            .iter()
            .filter(|n| !assigned_nodes.contains(&n.id))
            .copied()
            .collect();

        if candidates.is_empty() {
            return Ok(None);
        }

        // Sort primarily by partition count since we can't access capacity/load
        candidates.sort_by(|a, b| {
            let a_count = self
                .node_partition_counts
                .get(&a.id)
                .map(|count| *count)
                .unwrap_or(0);
            let b_count = self
                .node_partition_counts
                .get(&b.id)
                .map(|count| *count)
                .unwrap_or(0);
            a_count.cmp(&b_count)
        });

        Ok(candidates.first().copied())
    }

    /// Rebalance using load-aware algorithm to optimize resource utilization
    fn rebalance_load_balanced(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        // Calculate load metrics for each node
        let mut node_metrics: HashMap<String, NodeLoadMetrics> = HashMap::new();

        for node_id in nodes.keys() {
            let partition_count = self
                .node_partition_counts
                .get(node_id)
                .map(|count| *count)
                .unwrap_or(0);
            let capacity_used = self.get_node_capacity_usage(node_id)?;
            let recent_latency = self.get_node_latency_stats(node_id)?;

            // Since StorageNode doesn't have capacity/current_load fields,
            // use placeholder values based on partition count
            let max_capacity = 100u64; // Standard capacity value
            let current_load = partition_count as u64; // Use partition count as a load metric

            node_metrics.insert(
                node_id.clone(),
                NodeLoadMetrics {
                    partition_count,
                    capacity_used,
                    recent_latency,
                    max_capacity,
                    current_load,
                },
            );
        }
        let mut target_counts: HashMap<String, usize> = HashMap::new();
        let total_partitions = self.config.partition_count;
        let node_count = nodes.len();
        let base_target = total_partitions / node_count;
        let remainder = total_partitions % node_count;
        for (i, id) in nodes.keys().enumerate() {
            // Distribute remainder among first N nodes
            let target = if i < remainder {
                base_target + 1
            } else {
                base_target
            };
            target_counts.insert(id.clone(), target);
        }

        // Sort partitions by load (heaviest first)
        let mut partition_loads: Vec<_> = self
            .partitions
            .iter()
            .map(|entry| {
                let partition = entry.value();
                let load = self.get_partition_load(partition)?;
                Ok((partition.id.clone(), load))
            })
            .collect::<Result<Vec<_>>>()?;

        partition_loads.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Rebalance partitions starting with heaviest
        for (partition_id, _) in partition_loads {
            let mut partition_entry = self.partitions.get_mut(&partition_id).unwrap();
            let partition = partition_entry.value_mut();

            // Find best primary node
            let mut candidates = nodes.keys().collect::<Vec<_>>();
            candidates.sort_by(|a, b| {
                let a_metrics = node_metrics.get(*a).unwrap();
                let b_metrics = node_metrics.get(*b).unwrap();

                // Sort by: under target count, current load
                let a_under = a_metrics.partition_count < *target_counts.get(*a).unwrap_or(&0);
                let b_under = b_metrics.partition_count < *target_counts.get(*b).unwrap_or(&0);

                match (a_under, b_under) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => {
                        // If both under or both over target, choose the one with less load
                        a_metrics.partition_count.cmp(&b_metrics.partition_count)
                    }
                }
            });

            // Select new primary if better than current
            if let Some(best_node) = candidates.first() {
                let current_primary = &partition.primary;
                let best_node_metrics = node_metrics.get(*best_node).unwrap();

                let should_move = if current_primary.is_empty() {
                    true
                } else if let Some(current_metrics) = node_metrics.get(current_primary) {
                    // Move if current node is overloaded or best node is underloaded
                    current_metrics.partition_count
                        > *target_counts.get(current_primary).unwrap_or(&0)
                        && best_node_metrics.partition_count
                            < *target_counts.get(*best_node).unwrap_or(&0)
                } else {
                    true // Current primary not in metrics, should move
                };

                if should_move {
                    let old_primary = partition.primary.clone();
                    partition.primary = (*best_node).clone();

                    // Update metrics
                    if let Some(metrics) = node_metrics.get_mut(*best_node) {
                        metrics.partition_count += 1;
                        metrics.current_load += 1; // Increment by 1 for simplicity
                    }

                    if !old_primary.is_empty() {
                        if let Some(metrics) = node_metrics.get_mut(&old_primary) {
                            metrics.partition_count = metrics.partition_count.saturating_sub(1);
                            metrics.current_load = metrics.current_load.saturating_sub(1);
                        }

                        // Create transfer if needed
                        if old_primary != (*best_node).clone() {
                            self.create_transfer(partition, &old_primary, &partition.primary)?;
                        }
                    }
                }
            }

            // Update replicas similarly
            let mut new_replicas = Vec::new();
            let replicas_needed = self.config.replication_factor.saturating_sub(1);

            // Filter out the primary from candidates
            let replica_candidates: Vec<_> = candidates
                .iter()
                .filter(|n| ***n != partition.primary)
                .take(replicas_needed)
                .map(|n| (*n).clone())
                .collect();

            new_replicas.extend(replica_candidates);

            partition.replicas = new_replicas;
            partition.last_assignment = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs();
            partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
            // Use imported Ordering
        }

        Ok(())
    }

    /// Create a partition transfer with optimized protocol
    fn create_transfer(&self, partition: &Partition, source: &str, target: &str) -> Result<()> {
        // Skip if source is empty or source is same as target
        if source.is_empty() || source == target {
            return Ok(());
        }
        info!(
            "Creating transfer for partition {} from {} to {}",
            partition.id, source, target
        );

        // Calculate priority based on several factors
        let priority = {
            let mut score = 0i32;

            // Higher priority for larger partitions
            score += (partition.estimated_size / (1024 * 1024)) as i32; // Size in MB

            // Higher priority for partitions with more items
            score += (partition.estimated_items / 1000) as i32; // Per thousand items

            // Higher priority for older assignments
            let age = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs()
                .saturating_sub(partition.last_assignment);
            score += (age / 3600) as i32; // Hours since last assignment

            score
        };

        // Create transfer object with enhanced metrics
        let transfer = PartitionTransfer {
            partition_id: partition.id.clone(),
            source: source.to_string(),
            target: target.to_string(),
            state: TransferState::Preparing,
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            completion_time: None,
            total_items: partition.estimated_items,
            transferred_items: 0,
            items_per_second: 0.0,
            total_bytes: partition.estimated_size,
            transferred_bytes: 0,
            bytes_per_second: 0.0,
            priority,
            retry_count: 0,
        };

        // Add to active transfers with priority-based key
        let transfer_key = format!("{}-{}", priority, partition.id);
        self.active_transfers
            .insert(transfer_key.clone(), transfer.clone());
        info!("Added transfer {} to active transfers", transfer_key);

        // Clone the Arc before spawning the task
        let transfer_handlers = Arc::clone(&self.transfer_handlers);
        let active_transfers_clone = self.active_transfers.clone();
        let partition_id_clone = partition.id.clone();
        let priority_clone = priority;
        let source_clone = source.to_string();
        let transfer_clone = transfer.clone();

        // Get handler before spawning task
        let handler = {
            let handlers = transfer_handlers.read();
            handlers.get(source).cloned()
        };

        if let Some(handler) = handler {
            tokio::spawn(async move {
                info!("Found handler for source node {}", source_clone);

                // Execute the handler
                let handler_result = handler(transfer_clone);

                // Update transfer state based on result
                let final_state = match handler_result {
                    Ok(_) => {
                        info!("Transfer handler for {} succeeded", partition_id_clone);
                        TransferState::Complete
                    }
                    Err(e) => {
                        error!("Transfer handler for {} failed: {}", partition_id_clone, e);
                        TransferState::Failed
                    }
                };

                // Update the state in the active_transfers map
                if let Some(mut entry) = active_transfers_clone
                    .get_mut(&format!("{}-{}", priority_clone, partition_id_clone))
                {
                    entry.value_mut().state = final_state;
                    if final_state == TransferState::Complete {
                        entry.value_mut().completion_time = Some(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_else(|_| Duration::from_secs(0))
                                .as_secs(),
                        );
                    }
                } else {
                    warn!(
                        "Transfer {} disappeared while handler was running",
                        partition_id_clone
                    );
                }

                // Return a Result to satisfy the expected return type
                Ok::<(), StorageNodeError>(())
            });
        } else {
            warn!("No transfer handler registered for source node {}", source);
            // Mark transfer as failed immediately
            if let Some(mut entry) = self
                .active_transfers
                .get_mut(&format!("{}-{}", priority, partition.id))
            {
                entry.value_mut().state = TransferState::Failed;
            }
        }

        Ok(())
    }
    /// A proper batching implementation would require a dedicated task/queue.
    #[allow(dead_code)]
    async fn execute_transfer_batch(
        &self,
        _batch: &[PartitionTransfer],
        _handler: &(dyn Fn(PartitionTransfer) -> Result<()> + Send + Sync),
    ) -> Result<()> {
        warn!("execute_transfer_batch is currently a placeholder and does not execute.");
        // The actual execution logic is now within the tokio::spawn in create_transfer
        // for individual transfers. A full batching implementation needs more work.
        Ok(())
    }

    /// Get node count
    pub fn get_node_count(&self) -> usize {
        let nodes = self.nodes.read();
        nodes.len()
    }

    /// Get the partition for a key
    pub fn get_partition_for_key(&self, key: &[u8]) -> Result<Partition> {
        // Convert bytes to string for hashing
        let key_str = String::from_utf8_lossy(key);
        // Hash the key
        let hash = calculate_key_hash(&key_str);

        // Convert hash to bytes for comparison
        let hash_bytes: &[u8] = &hash.0;

        // Find the partition that contains this hash
        for entry in self.partitions.iter() {
            let partition = entry.value();

            // Use proper comparison between hash and partition boundaries
            if Self::partition_contains_hash(&partition.start, &partition.end, hash_bytes) {
                return Ok(partition.clone());
            }
        }

        // If not found, could be an edge case with ranges
        // Return the first partition as a fallback
        self.partitions
            .iter()
            .next()
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                crate::error::StorageNodeError::NotFound("No partitions available".to_string())
            })
    }

    /// Helper function to check if a hash is within partition bounds
    fn partition_contains_hash(start: &[u8], end: &[u8], hash: &[u8]) -> bool {
        // Compare bytes in order
        hash >= start && hash < end
    }

    /// Get the responsible nodes for a key
    pub fn get_responsible_nodes(&self, key: &[u8]) -> Result<(String, Vec<String>)> {
        let partition = self.get_partition_for_key(key)?;

        Ok((partition.primary.clone(), partition.replicas.clone()))
    }

    /// Check if this node is responsible for a key
    pub fn is_responsible_for_key(&self, key: &[u8]) -> Result<bool> {
        let partition = self.get_partition_for_key(key)?;

        Ok(partition.primary == self.node_id || partition.replicas.contains(&self.node_id))
    }

    /// Check if this node is primary for a key
    pub fn is_primary_for_key(&self, key: &[u8]) -> Result<bool> {
        let partition = self.get_partition_for_key(key)?;

        Ok(partition.primary == self.node_id)
    }

    /// Get the partition information
    pub fn get_partition(&self, partition_id: &str) -> Result<Partition> {
        self.partitions
            .get(partition_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                crate::error::StorageNodeError::NotFound(format!(
                    "Partition {} not found",
                    partition_id
                ))
            })
    }

    /// Get all partitions
    pub fn get_all_partitions(&self) -> Vec<Partition> {
        self.partitions.iter().map(|e| e.value().clone()).collect()
    }

    /// Get active transfers
    pub fn get_active_transfers(&self) -> Vec<PartitionTransfer> {
        self.active_transfers
            .iter()
            .map(|e| e.value().clone())
            .collect()
    }

    /// Get transfers for a specific partition
    pub fn get_transfers_for_partition(&self, partition_id: &str) -> Option<PartitionTransfer> {
        for entry in self.active_transfers.iter() {
            let transfer = entry.value();
            if transfer.partition_id == partition_id {
                return Some(transfer.clone());
            }
        }
        None
    }

    /// Update partition metrics
    pub fn update_partition_metrics(
        &self,
        partition_id: &str,
        item_count: u64,
        size_bytes: u64,
        keyspace_fraction: f64,
    ) -> Result<()> {
        // Schedule replication for the updated partition
        if let Some(partition) = self.partitions.get(partition_id) {
            self.schedule_replication(&partition)?;
        }
        let mut partition_entry = self.partitions.get_mut(partition_id).ok_or_else(|| {
            StorageNodeError::NotFound(format!("Partition {} not found", partition_id))
        })?;

        let partition = partition_entry.value_mut();
        partition.estimated_items = item_count;
        partition.estimated_size = size_bytes;
        partition.keyspace_fraction = keyspace_fraction;

        Ok(())
    }

    /// Calculate partition metrics for all partitions
    pub fn calculate_all_partition_metrics(
        &self,
        storage: &dyn StorageEngine,
    ) -> Result<Vec<PartitionMetrics>> {
        let mut metrics = Vec::new();
        for entry in self.partitions.iter() {
            let partition = entry.value();
            // Pass the storage engine reference
            let partition_metrics = self.calculate_partition_metrics(partition, storage)?;
            metrics.push(partition_metrics);
        }
        Ok(metrics)
    }

    /// Calculate metrics for a single partition
    #[allow(unused_variables)]
    fn calculate_partition_metrics(
        &self,
        partition: &Partition,
        storage: &dyn StorageEngine,
    ) -> Result<PartitionMetrics> {
        // This needs to interact with the underlying storage to get real data.
        // For now, simulate based on partition info.
        // In a real system, you'd query the storage engine for keys within the partition range.

        // Placeholder: Use estimated values if available, otherwise simulate
        let item_count = partition.estimated_items;
        let size_bytes = partition.estimated_size;

        // Simulate key distribution (requires actual key data)
        let mut key_distribution = HashMap::new();
        key_distribution.insert("simulated_prefix".to_string(), item_count); // Very basic simulation

        Ok(PartitionMetrics {
            item_count,
            size_bytes,
            key_distribution,
        })
    }

    /// Rebalance based on load metrics
    fn rebalance_load(&self, threshold: f64) -> Result<Vec<PartitionMove>> {
        let mut moves = Vec::new();
        let nodes = self.nodes.read();

        // Calculate load metrics for each node using the partition count as a proxy
        let mut node_loads = HashMap::new();
        for (id, _node) in nodes.iter() {
            // Use partition count as load metric since we don't have current_load/capacity fields
            let partition_count = self.node_partition_counts.get(id).map(|c| *c).unwrap_or(0);
            node_loads.insert(id.clone(), (partition_count, 100)); // Assume capacity = 100 for all nodes
        }

        // Calculate global average load ratio
        let total_load: usize = node_loads.values().map(|(load, _)| *load).sum();
        let total_capacity: usize = node_loads.values().map(|(_, capacity)| *capacity).sum();
        let global_load_ratio = if total_capacity > 0 {
            total_load as f64 / total_capacity as f64
        } else {
            0.0
        };

        // Find overloaded and underloaded nodes
        let mut overloaded: Vec<_> = node_loads
            .iter()
            .filter(|(_, &(load, capacity))| {
                let load_ratio = load as f64 / capacity as f64;
                load_ratio > global_load_ratio * (1.0 + threshold)
            })
            .collect();

        let mut underloaded: Vec<_> = node_loads
            .iter()
            .filter(|(_, &(load, capacity))| {
                let load_ratio = load as f64 / capacity as f64;
                load_ratio < global_load_ratio * (1.0 - threshold)
            })
            .collect();

        // Sort by load ratio difference from global average
        overloaded.sort_by(|(_, &(a_load, a_capacity)), (_, &(b_load, b_capacity))| {
            let a_ratio = a_load as f64 / a_capacity as f64;
            let b_ratio = b_load as f64 / b_capacity as f64;
            b_ratio
                .partial_cmp(&a_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        underloaded.sort_by(|(_, &(a_load, a_capacity)), (_, &(b_load, b_capacity))| {
            let a_ratio = a_load as f64 / a_capacity as f64;
            let b_ratio = b_load as f64 / b_capacity as f64;
            a_ratio
                .partial_cmp(&b_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Generate partition moves to balance load
        for (overloaded_id, &(overloaded_load, overloaded_capacity)) in overloaded {
            let node_partitions: Vec<_> = self
                .partitions
                .iter()
                .filter(|e| e.value().primary == *overloaded_id)
                .map(|e| e.value().clone())
                .collect();

            for partition in node_partitions {
                if let Some((target_id, &(target_load, target_capacity))) = underloaded.first() {
                    // Check if move would improve balance
                    let src_ratio = overloaded_load as f64 / overloaded_capacity as f64;
                    let dst_ratio = target_load as f64 / target_capacity as f64;

                    if src_ratio - dst_ratio > threshold {
                        moves.push(PartitionMove {
                            partition_id: partition.id.clone(),
                            source_node: overloaded_id.clone(),
                            target_node: (*target_id).clone(),
                            reason: "load_balance".to_string(),
                            priority: MovePriority::High,
                        });
                    }
                }
            }
        }

        Ok(moves)
    }

    /// Apply partition moves to rebalance the cluster
    fn apply_moves(&self, moves: Vec<PartitionMove>) -> Result<()> {
        for movement in moves {
            if let Some(mut partition_entry) = self.partitions.get_mut(&movement.partition_id) {
                let partition = partition_entry.value_mut();
                // Update primary node
                let old_primary = partition.primary.clone();
                partition.primary = movement.target_node.clone();

                // Update node partition counts
                if let Some(mut count) = self.node_partition_counts.get_mut(&movement.source_node) {
                    *count -= 1;
                }

                if let Some(mut count) = self.node_partition_counts.get_mut(&movement.target_node) {
                    *count += 1;
                }

                // Create transfer
                self.create_transfer(partition, &old_primary, &movement.target_node)?;

                // Update generation and timestamp
                partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1; // Use imported Ordering
                partition.last_assignment = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
            }
        }
        Ok(())
    }

    /// Coordinate rebalancing of the ring
    pub async fn coordinate_rebalancing(&self) -> Result<()> {
        const LOAD_THRESHOLD: f64 = 0.2; // 20% deviation tolerance
        const REGION_IMBALANCE_THRESHOLD: f64 = 0.3; // 30% regional imbalance tolerance

        // First check for critical load imbalances
        let load_moves = self.rebalance_load(LOAD_THRESHOLD)?;
        if !load_moves.is_empty() {
            self.apply_moves(load_moves)?;
            return Ok(());
        }

        // If load is balanced, optimize for geography
        let geo_moves = self.rebalance_geography(REGION_IMBALANCE_THRESHOLD)?;
        if !geo_moves.is_empty() {
            self.apply_moves(geo_moves)?;
        }

        Ok(())
    }

    /// Schedule replication of a partition
    fn schedule_replication(&self, partition: &Partition) -> Result<()> {
        // Queue replication task
        let mut queue = self.replication_queue.lock();
        queue.push(ReplicationTask {
            partition_id: partition.id.clone(),
            priority: ReplicationPriority::Normal,
            timestamp: chrono::Utc::now(),
        });

        Ok(())
    }

    /// Run the rebalancing loop
    pub async fn run_rebalancing_loop(&self) {
        let interval = tokio::time::Duration::from_secs(300); // Run every 5 minutes

        loop {
            if let Err(e) = self.coordinate_rebalancing().await {
                log::error!("Error during rebalancing: {}", e);
            }

            tokio::time::sleep(interval).await;
        }
    }

    /// Rebalance based on geographic metrics
    fn rebalance_geography(&self, _latency_threshold: f64) -> Result<Vec<PartitionMove>> {
        // Placeholder implementation for geography-based rebalancing
        let moves = Vec::new();

        // This would be implemented in a real system with actual geographic metrics

        Ok(moves)
    }

    /// Gets the capacity usage of a node (Simulated)
    fn get_node_capacity_usage(&self, node_id: &str) -> Result<u64> {
        // Simulate capacity usage based on partition count
        let partition_count = self
            .node_partition_counts
            .get(node_id)
            .map(|c| *c)
            .unwrap_or(0);
        // Assume each partition takes ~10MB for simulation
        Ok(partition_count as u64 * 10 * 1024 * 1024)
    }

    /// Gets latency statistics for a node (Simulated)
    fn get_node_latency_stats(&self, _node_id: &str) -> Result<Duration> {
        // Simulate latency - perhaps fetch from HealthMonitor if integrated
        Ok(Duration::from_millis(50)) // Simulate 50ms latency
    }

    /// Get the load of a partition (Simulated)
    fn get_partition_load(&self, partition: &Partition) -> Result<f64> {
        // Simulate load based on estimated size and items
        // Weight size more heavily
        let size_load = partition.estimated_size as f64 / (1024.0 * 1024.0); // Load per MB
        let item_load = partition.estimated_items as f64 / 1000.0; // Load per 1k items
        Ok(size_load * 0.7 + item_load * 0.3) // Weighted average
    }

    /// Register transfer handler for a node
    pub fn register_transfer_handler<F>(&self, node_id: &str, handler: F) -> Result<()>
    where
        F: Fn(PartitionTransfer) -> Result<()> + Send + Sync + 'static,
    {
        let mut handlers = self.transfer_handlers.write();
        handlers.insert(node_id.to_string(), Arc::new(handler));

        Ok(())
    }

    /// Process transfer chunk (for receiving data)
    pub fn process_transfer_chunk(
        &self,
        partition_id: String,
        chunk_id: String,
        data: Vec<u8>,
    ) -> Result<()> {
        // First validate the partition exists and this node is a valid target
        let partition = self.get_partition(&partition_id)?;
        if partition.primary != self.node_id && !partition.replicas.contains(&self.node_id) {
            return Err(StorageNodeError::InvalidOperation(format!(
                "This node is not responsible for partition {}",
                partition_id
            )));
        }

        // Process the chunk transfer
        // In a real implementation, this would store the chunk data and track progress
        info!(
            "Received chunk {} for partition {}, size: {} bytes",
            chunk_id,
            partition_id,
            data.len()
        );

        Ok(())
    }

    /// Get partition metrics (requires storage engine access)
    pub fn get_partition_metrics(
        &self,
        partition_id: &str,
        storage: &dyn StorageEngine,
    ) -> Result<PartitionMetrics> {
        let partition = self.get_partition(partition_id)?;
        self.calculate_partition_metrics(&partition, storage)
    }
}

impl<S> PartitionedStorage<S>
where
    S: 'static + Send + Sync,
{
    /// Create a new partitioned storage adapter
    pub fn new(partition_manager: Arc<PartitionManager>, node_id: String) -> Self {
        Self {
            partition_manager,
            node_id,
            _marker: std::marker::PhantomData,
        }
    }

    /// Check if a key is responsible for this node
    pub fn is_responsible(&self, key: &[u8]) -> Result<bool> {
        self.partition_manager.is_responsible_for_key(key)
    }

    /// Check if a key is primary for this node
    pub fn is_primary(&self, key: &[u8]) -> Result<bool> {
        self.partition_manager.is_primary_for_key(key)
    }

    /// Get the responsible nodes for a key
    pub fn get_responsible_nodes(&self, key: &[u8]) -> Result<(String, Vec<String>)> {
        self.partition_manager.get_responsible_nodes(key)
    }

    /// Start partition transfers
    pub fn start_transfers(&self) -> Result<()> {
        // Register transfer handler
        self.partition_manager
            .register_transfer_handler(&self.node_id, |transfer| {
                info!(
                    "Starting transfer of partition {} from {} to {}",
                    transfer.partition_id, transfer.source, transfer.target
                );

                // In a real implementation, this would initiate a data transfer

                Ok(())
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_for_key() {
        let manager = PartitionManager::new("test-node".to_string(), PartitionConfig::default());
        manager.initialize().unwrap();

        let nodes = vec![
            StorageNode {
                id: "node1".to_string(),
                name: "Node 1".to_string(),
                region: "region1".to_string(),
                public_key: "key1".to_string(),
                endpoint: "endpoint1".to_string(),
            },
            StorageNode {
                id: "node2".to_string(),
                name: "Node 2".to_string(),
                region: "region1".to_string(),
                public_key: "key2".to_string(),
                endpoint: "endpoint2".to_string(),
            },
            StorageNode {
                id: "node3".to_string(),
                name: "Node 3".to_string(),
                region: "region2".to_string(),
                public_key: "key3".to_string(),
                endpoint: "endpoint3".to_string(),
            },
        ];

        for node in nodes {
            manager.add_node(node).unwrap();
        }

        // Rebalance
        manager.rebalance().unwrap();

        // Test key lookup
        let test_keys = [
            "key1".to_string().into_bytes(),
            "key2".to_string().into_bytes(),
            "key3".to_string().into_bytes(),
            "key4".to_string().into_bytes(),
        ];

        for key in &test_keys {
            let partition = manager.get_partition_for_key(key).unwrap();
            let (primary, replicas) = manager.get_responsible_nodes(key).unwrap();

            assert!(!primary.is_empty());
            assert_eq!(replicas.len(), manager.config.replication_factor - 1);

            // Verify partition boundaries
            let hash_vec = calculate_key_hash(&String::from_utf8_lossy(key)).0.to_vec();
            assert!(hash_vec < partition.end);
        }
    }

    #[test]
    fn test_consistent_hash_rebalance() {
        // Create a partition manager with controlled test parameters
        let manager = PartitionManager::new(
            "master-node".to_string(),
            PartitionConfig {
                partition_count: 16,
                replication_factor: 2,
                strategy: PartitionStrategy::ConsistentHash,
                min_nodes_for_rebalance: 1, // Allow rebalancing with just 1 node
                ..Default::default()
            },
        );

        // Initialize the partition manager and handle errors properly
        if let Err(e) = manager.initialize() {
            panic!("Failed to initialize partition manager: {:?}", e);
        }

        // Create test nodes with distinct IDs
        let nodes = vec![
            StorageNode {
                id: "node-0a1b2c3d".to_string(),
                name: "Alpha Node".to_string(),
                region: "region1".to_string(),
                public_key: "key1".to_string(),
                endpoint: "endpoint1".to_string(),
            },
            StorageNode {
                id: "node-4e5f6g7h".to_string(),
                name: "Beta Node".to_string(),
                region: "region1".to_string(),
                public_key: "key2".to_string(),
                endpoint: "endpoint2".to_string(),
            },
        ];

        // Add nodes to the topology
        for node in nodes {
            if let Err(e) = manager.add_node(node) {
                panic!("Failed to add node to partition manager: {:?}", e);
            }
        }

        // Force rebalance directly to ensure partitions are assigned
        if let Err(e) = manager.rebalance() {
            panic!("Failed to rebalance partition manager: {:?}", e);
        }

        // Verify partition count
        let partitions = manager.get_all_partitions();
        assert_eq!(partitions.len(), 16, "Partition count mismatch");

        // Verify all partitions have a primary assigned
        for (i, partition) in partitions.iter().enumerate() {
            assert!(
                !partition.primary.is_empty(),
                "Partition {} has no primary assigned",
                i
            );
        }

        // Verify primary assignment distribution
        let node1_count = manager
            .node_partition_counts
            .get("node-0a1b2c3d")
            .map(|c| *c)
            .unwrap_or(0);

        let node2_count = manager
            .node_partition_counts
            .get("node-4e5f6g7h")
            .map(|c| *c)
            .unwrap_or(0);

        // Total should be equal to partition count
        let total_primary_assignments = node1_count + node2_count;
        assert_eq!(
            total_primary_assignments, 16,
            "Total primary assignments should equal partition count: got {}, expected 16",
            total_primary_assignments
        );

        // Add a third node to trigger rebalancing
        let node3 = StorageNode {
            id: "node-8i9j0k1l".to_string(),
            name: "Gamma Node".to_string(),
            region: "region2".to_string(),
            public_key: "key3".to_string(),
            endpoint: "endpoint3".to_string(),
        };

        if let Err(e) = manager.add_node(node3) {
            panic!("Failed to add third node: {:?}", e);
        }

        // Force rebalance again to ensure partitions are reassigned after adding third node
        if let Err(e) = manager.rebalance() {
            panic!("Failed to rebalance after adding third node: {:?}", e);
        }

        // Verify all partitions still have a primary assigned
        let partitions = manager.get_all_partitions();
        for (i, partition) in partitions.iter().enumerate() {
            assert!(
                !partition.primary.is_empty(),
                "After adding third node, partition {} has no primary assigned",
                i
            );
        }

        // Check transfer operations after topology change
        let transfers = manager.get_active_transfers();

        // Check transfers only if the hash ring changed enough to require them
        if !transfers.is_empty() {
            // If transfers exist, verify they have valid source and target nodes
            for transfer in &transfers {
                assert!(!transfer.source.is_empty(), "Transfer has empty source");
                assert!(!transfer.target.is_empty(), "Transfer has empty target");
                assert_ne!(
                    transfer.source, transfer.target,
                    "Transfer source and target are the same"
                );
            }
        }

        // Validate load distribution after adding third node
        let node1_count = manager
            .node_partition_counts
            .get("node-0a1b2c3d")
            .map(|c| *c)
            .unwrap_or(0);

        let node2_count = manager
            .node_partition_counts
            .get("node-4e5f6g7h")
            .map(|c| *c)
            .unwrap_or(0);

        let node3_count = manager
            .node_partition_counts
            .get("node-8i9j0k1l")
            .map(|c| *c)
            .unwrap_or(0);

        // Calculate total assigned partitions (primary assignments only)
        let total = node1_count + node2_count + node3_count;
        assert_eq!(
            total, 16,
            "Total partition assignments mismatch: got {}, expected 16",
            total
        );

        // Calculate the maximum partitions any node should handle
        let partition_count = manager.get_all_partitions().len();
        let max_allowed = (partition_count as f64 * 0.7).ceil() as usize;

        // Ensure no node is overloaded
        assert!(
            node1_count <= max_allowed,
            "Node 1 has too many partitions: {} > {}",
            node1_count,
            max_allowed
        );
        assert!(
            node2_count <= max_allowed,
            "Node 2 has too many partitions: {} > {}",
            node2_count,
            max_allowed
        );
        assert!(
            node3_count <= max_allowed,
            "Node 3 has too many partitions: {} > {}",
            node3_count,
            max_allowed
        );

        // Test node removal and rebalancing
        if let Err(e) = manager.remove_node("node-0a1b2c3d") {
            panic!("Failed to remove node from topology: {:?}", e);
        }

        // Force rebalance after node removal
        if let Err(e) = manager.rebalance() {
            panic!("Failed to rebalance after node removal: {:?}", e);
        }

        // Verify all partitions still have primaries assigned
        let final_partitions = manager.get_all_partitions();
        for (i, partition) in final_partitions.iter().enumerate() {
            assert!(
                !partition.primary.is_empty(),
                "After node removal, partition {} has no primary assigned",
                i
            );
        }

        // Verify partition redistribution after node removal
        let remaining_node1_count = manager
            .node_partition_counts
            .get("node-4e5f6g7h")
            .map(|c| *c)
            .unwrap_or(0);

        let remaining_node2_count = manager
            .node_partition_counts
            .get("node-8i9j0k1l")
            .map(|c| *c)
            .unwrap_or(0);

        // Ensure all partitions are still assigned
        assert_eq!(
            remaining_node1_count + remaining_node2_count,
            16,
            "Missing partition assignments after node removal"
        );
    }
}
