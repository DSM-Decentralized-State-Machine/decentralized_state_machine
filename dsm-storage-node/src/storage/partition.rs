// Partition management for epidemic storage
//
// This module implements deterministic rotation and partitioning mechanisms
// to distribute storage load across nodes while maintaining locality.

use crate::error::Result;
use crate::storage::small_world::calculate_key_hash;
use crate::types::StorageNode;
use tracing::{info, warn};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
// Add this import to fix the unresolved module error
use tracing as log;

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
            rebalance_throttle: 5, // 5 partitions per minute
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
    Critical
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

/// Partition manager
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
    ring_generation: Arc<AtomicU64>,
    
    /// Last global rebalance timestamp
    last_rebalance: Arc<RwLock<Instant>>,
    
    /// Transfer handlers
    transfer_handlers: Arc<RwLock<HashMap<String, Box<dyn Fn(PartitionTransfer) -> Result<()> + Send + Sync>>>>,

    /// Replication queue
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
            ring_generation: Arc::new(AtomicU64::new(1)),
            last_rebalance: Arc::new(RwLock::new(Instant::now())),
            transfer_handlers: Arc::new(RwLock::new(HashMap::new())),
            replication_queue: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }
    
    /// Initialize the partition ring
    pub fn initialize(&self) -> Result<()> {
        // Initialize the partition ring
        info!("Initializing partition ring with {} partitions", self.config.partition_count);
        
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
        self.ring_generation.fetch_add(1, Ordering::SeqCst);
        
        Ok(())
    }
    
    /// Rebalance using consistent hashing algorithm
    fn rebalance_consistent_hash(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        let node_ids: Vec<String> = nodes.keys().cloned().collect();
        
        // Clear current node partition counts
        for node_id in &node_ids {
            self.node_partition_counts.insert(node_id.clone(), 0);
        }
        
        // Create consistent hash ring
        let mut hash_ring = BTreeMap::new();
        
        // Add nodes to the ring
        for node_id in &node_ids {
            // Add multiple points for each node
            for i in 0..100 { // Use 100 points per node
                let key = format!("{}-{}", node_id, i);
                let hash = calculate_key_hash(key.as_bytes());
                
                // Only use first 8 bytes for the ring
                let mut position = 0u64;
                for i in 0..8 {
                    position = (position << 8) | (hash[i] as u64);
                }
                
                hash_ring.insert(position, node_id.clone());
            }
        }
        
        // Assign partitions
        for mut partition_entry in self.partitions.iter_mut() {
            let partition = partition_entry.value_mut();
            
            // Calculate partition position
            let partition_hash = calculate_key_hash(partition.id.as_bytes());
            let mut position = 0u64;
            for i in 0..8 {
                position = (position << 8) | (partition_hash[i] as u64);
            }
            
            // Find primary owner
            let mut primary_owner = None;
            
            // Find nearest node clockwise
            let higher_nodes = hash_ring.range(position..);
            if let Some((_, node_id)) = higher_nodes.take(1).next() {
                primary_owner = Some(node_id.clone());
            } else {
                // Wrap around to the first node
                if let Some((_, node_id)) = hash_ring.iter().take(1).next() {
                    primary_owner = Some(node_id.clone());
                }
            }
            
            // Find replicas (next nodes clockwise)
            let mut replica_owners = Vec::new();
            
            if let Some(primary) = &primary_owner {
                // Continue from the primary, wrapping around if needed
                let mut remaining = self.config.replication_factor - 1;
                let mut seen = HashSet::new();
                seen.insert(primary.clone());
                
                // Start from after the primary's position
                let mut current_pos = position;
                
                while remaining > 0 {
                    // Find next node after current_pos
                    let mut found = false;
                    
                    // Try higher positions
                    for (pos, node_id) in hash_ring.range((current_pos + 1)..) {
                        if !seen.contains(node_id) {
                            replica_owners.push(node_id.clone());
                            seen.insert(node_id.clone());
                            current_pos = *pos;
                            found = true;
                            remaining -= 1;
                            break;
                        }
                    }
                    
                    // If didn't find or reached end, wrap around
                    if !found || remaining > 0 {
                        for (pos, node_id) in hash_ring.iter() {
                            if !seen.contains(node_id) {
                                replica_owners.push(node_id.clone());
                                seen.insert(node_id.clone());
                                current_pos = *pos;
                                found = true;
                                remaining -= 1;
                                break;
                            }
                        }
                    }
                    
                    // If still didn't find or no more nodes, break
                    if !found || seen.len() >= node_ids.len() {
                        break;
                    }
                }
            }
            
            // If we got a primary and enough replicas, update the partition
            if let Some(primary) = primary_owner {
                // Check if this is a change in ownership
                let old_primary = partition.primary.clone();
                
                // Update partition info
                partition.primary = primary.clone();
                partition.replicas = replica_owners;
                partition.last_assignment = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
                partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
                
                // Update node partition counts
                if let Some(mut count) = self.node_partition_counts.get_mut(&primary) {
                    *count += 1;
                }
                
                // Create transfer if ownership changed
                if !old_primary.is_empty() && old_primary != primary {
                    self.create_transfer(partition, &old_primary, &primary)?;
                }
            }
        }
        
        // Validate assignments - ensure no node exceeds max_partitions_per_node
        let max_partitions = self.node_partition_counts
            .iter()
            .map(|entry| *entry.value())
            .max()
            .unwrap_or(0);
            
        if max_partitions > self.config.max_partitions_per_node {
            warn!("Rebalance resulted in {} partitions for some nodes, exceeding max of {}",
                max_partitions, self.config.max_partitions_per_node);
                
            // In a real system, you'd implement more sophisticated balancing here
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
            partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
            
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
            let total_capacity = node_count as u64;  // One unit per node
            let current_load = 0u64;  // Assume no load initially
            
            // Count partitions assigned to nodes in this region
            let partition_count = region_nodes
                .iter()
                .map(|n| self.node_partition_counts.get(&n.id).map(|c| *c).unwrap_or(0))
                .sum();

            region_metrics.insert(region.clone(), RegionMetrics {
                total_capacity,
                current_load,
                partition_count,
                node_count,
                avg_latency: 0.0,
                failure_rate: 0.0,
            });
        }

        // Process each partition
        for mut partition_entry in self.partitions.iter_mut() {
            let partition = partition_entry.value_mut();
            let primary_region = nodes.get(&partition.primary)
                .map(|n| n.region.clone())
                .unwrap_or_default();

            // Determine target regions for replicas
            let mut target_regions = self.select_target_regions(
                &primary_region,
                &region_metrics,
                self.config.replication_factor,
            )?;

            // Ensure primary stays in original region if possible
            if !target_regions.contains(&primary_region) && 
               nodes_by_region.contains_key(&primary_region) {
                target_regions[0] = primary_region.clone();
            }

            // Select best nodes in each target region
            let mut new_replicas = Vec::new();
            let mut assigned_nodes = HashSet::new();
            assigned_nodes.insert(&partition.primary);

            for region in target_regions {
                if let Some(region_nodes) = nodes_by_region.get(&region) {
                    if let Some(best_node) = self.select_best_node_in_region(
                        region_nodes,
                        &assigned_nodes,
                        partition,
                    )? {
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
        regions.sort_by(|(region_a, metrics_a), (region_b, metrics_b)| {
            // Prefer regions with lower load relative to capacity
            let load_a = metrics_a.current_load as f64 / metrics_a.total_capacity as f64;
            let load_b = metrics_b.current_load as f64 / metrics_b.total_capacity as f64;
            
            // Consider failure rates and latency as tiebreakers
            if (load_b - load_a).abs() < 0.1 {
                let health_a = metrics_a.failure_rate * metrics_a.avg_latency;
                let health_b = metrics_b.failure_rate * metrics_b.avg_latency;
                health_a.partial_cmp(&health_b).unwrap_or(std::cmp::Ordering::Equal)
            } else {
                load_a.partial_cmp(&load_b).unwrap_or(std::cmp::Ordering::Equal)
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
                .map(|(region, _)| region.to_string())
        );

        Ok(selected)
    }

    /// Helper function to select the best node in a region for a partition
    fn select_best_node_in_region(
        &self,
        region_nodes: &[&StorageNode],
        assigned_nodes: &HashSet<&String>,
        _partition: &Partition,
    ) -> Result<Option<&StorageNode>> {
        let mut candidates: Vec<_> = region_nodes
            .iter()
            .filter(|n| !assigned_nodes.contains(&n.id))
            .collect();

        if candidates.is_empty() {
            return Ok(None);
        }

        // Sort primarily by partition count since we can't access capacity/load
        candidates.sort_by(|a, b| {
            let a_count = self.node_partition_counts.get(&a.id).map(|count| **count).unwrap_or(0);
            let b_count = self.node_partition_counts.get(&b.id).map(|count| **count).unwrap_or(0);
            a_count.cmp(&b_count)
        });

        Ok(Some(*candidates.first().unwrap()))
    }
    
    /// Rebalance using load-aware algorithm to optimize resource utilization
    fn rebalance_load_balanced(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        // Calculate load metrics for each node
        let mut node_metrics: HashMap<String, NodeLoadMetrics> = HashMap::new();
        
        for (node_id, _) in nodes {
            let partition_count = self.node_partition_counts.get(node_id).map(|count| *count).unwrap_or(0);
            let capacity_used = self.get_node_capacity_usage(node_id)?;
            let recent_latency = self.get_node_latency_stats(node_id)?;
            
            // Since StorageNode doesn't have capacity/current_load fields,
            // use placeholder values based on partition count
            let max_capacity = 100u64; // Standard capacity value
            let current_load = partition_count as u64; // Use partition count as a load metric
            
            node_metrics.insert(node_id.clone(), NodeLoadMetrics {
                partition_count,
                capacity_used,
                recent_latency,
                max_capacity,
                current_load,
            });
        }

        // Calculate ideal partition count per node
        let total_partitions = self.partitions.len();
        let node_count = nodes.len();
        if node_count == 0 {
            return Ok(());
        }
        
        let base_target = total_partitions / node_count;
        let remainder = total_partitions % node_count;
        
        let mut target_counts: HashMap<String, usize> = HashMap::new();
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
        let mut partition_loads: Vec<_> = self.partitions
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
            let partition = self.partitions.get_mut(&partition_id).unwrap();
            
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
                    current_metrics.partition_count > *target_counts.get(current_primary).unwrap_or(&0) &&
                    best_node_metrics.partition_count < *target_counts.get(*best_node).unwrap_or(&0)
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
                        if old_primary != partition.primary {
                            self.create_transfer(&partition, &old_primary, &partition.primary)?;
                        }
                    }
                }
            }

            // Update replicas similarly
            let mut new_replicas = Vec::new();
            let replicas_needed = self.config.replication_factor.saturating_sub(1);
            
            // Filter out the primary from candidates
            let replica_candidates: Vec<_> = candidates.iter()
                .filter(|n| **n != partition.primary)
                .collect();
            
            for (i, candidate) in replica_candidates.iter().take(replicas_needed).enumerate() {
                if i < replicas_needed {
                    new_replicas.push((*candidate).clone());
                    
                    // Update metrics
                    if let Some(metrics) = node_metrics.get_mut(*candidate) {
                        metrics.partition_count += 1;
                    }
                }
            }

            partition.replicas = new_replicas;
            partition.last_assignment = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs();
            partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
        }

        Ok(())
    }

    // Using the NodeLoadMetrics struct defined at module level
    
    /// Create a partition transfer with optimized protocol
    fn create_transfer(&self, partition: &Partition, source: &str, target: &str) -> Result<()> {
        // Skip if source is empty
        if source.is_empty() {
            return Ok(());
        }

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
            priority: priority,
            retry_count: 0,
        };

        // Add to active transfers with priority
        self.active_transfers.insert(
            format!("{}-{}", priority, partition.id), 
            transfer.clone()
        );

        // Get batch configuration
        let batch_config = TransferBatchConfig::default();

        // Call handler with batching logic
        let handlers = self.transfer_handlers.read();
        if let Some(handler) = handlers.get(source) {
            // Group transfers into batches
            let mut current_batch_size = 0;
            let mut current_batch = Vec::new();
            
            // Get all pending transfers sorted by priority
            let mut pending: Vec<_> = self.active_transfers
                .iter()
                .filter(|e| {
                    let t = e.value();
                    t.state == TransferState::Preparing && 
                    t.source == source &&
                    t.retry_count < batch_config.max_retries
                })
                .map(|e| e.value().clone())
                .collect();
            
            pending.sort_by(|a, b| b.priority.cmp(&a.priority));

            for transfer in pending {
                // Check if adding this transfer exceeds batch size
                if current_batch_size + transfer.total_bytes > batch_config.max_batch_size_bytes as u64 ||
                   current_batch.len() >= batch_config.max_concurrent_transfers {
                    // Execute current batch - use block_on since we're in a sync function
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(self.execute_transfer_batch(&current_batch, handler))?;
                    
                    // Reset batch
                    current_batch.clear();
                    current_batch_size = 0;
                }

                // Add to current batch
                current_batch.push(transfer.clone());
                current_batch_size += transfer.total_bytes;
            }
            // Execute any remaining transfers
            if !current_batch.is_empty() {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(self.execute_transfer_batch(&current_batch, handler))?;
            }
        }
        
        Ok(())
    }

    /// Execute a batch of transfers
    async fn execute_transfer_batch(
        &self,
        batch: &[PartitionTransfer],
        handler: &Box<dyn Fn(PartitionTransfer) -> Result<()> + Send + Sync>
    ) -> Result<()> {
        use tokio::time::timeout;
        use std::time::Duration;
        
        // Process each transfer in the batch
        for transfer in batch {
            // Use a timeout to avoid hanging
            let result = timeout(
                Duration::from_millis(TransferBatchConfig::default().transfer_timeout_ms),
                async {
                    // Execute the handler
                    handler(transfer.clone())
                }
            ).await;
            
            // Update transfer state based on result
            if let Ok(handler_result) = result {
                match handler_result {
                    Ok(_) => {
                        // Update transfer state to complete
                        if let Some(mut entry) = self.active_transfers.get_mut(&format!("{}-{}", transfer.priority, transfer.partition_id)) {
                            entry.state = TransferState::Complete;
                            entry.completion_time = Some(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_else(|_| Duration::from_secs(0))
                                    .as_secs()
                            );
                        }
                    },
                    Err(_) => {
                        // Update transfer state to failed and increment retry count
                        if let Some(mut entry) = self.active_transfers.get_mut(&format!("{}-{}", transfer.priority, transfer.partition_id)) {
                            entry.state = TransferState::Failed;
                            entry.retry_count += 1;
                        }
                    }
                }
            } else {
                // Timeout occurred
                if let Some(mut entry) = self.active_transfers.get_mut(&format!("{}-{}", transfer.priority, transfer.partition_id)) {
                    entry.state = TransferState::Failed;
                    entry.retry_count += 1;
                }
            }
        }
        
        Ok(())
    }
    
    /// Get node count
    pub fn get_node_count(&self) -> usize {
        let nodes = self.nodes.read();
        nodes.len()
    }
    
    /// Get the partition for a key
    pub fn get_partition_for_key(&self, key: &[u8]) -> Result<Partition> {
        // Hash the key
        let hash = calculate_key_hash(key);
        
        // Find the partition that contains this hash
        for entry in self.partitions.iter() {
            let partition = entry.value();
            
            // Ensure hash is converted to a compatible type for comparison
            if partition_contains_hash(&partition.start, &partition.end, &hash) {
                return Ok(partition.clone());
            }
        }
        
        // If not found, could be an edge case with ranges
        // Return the first partition as a fallback
        self.partitions.iter()
            .next()
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                crate::error::StorageNodeError::NotFound(
                    "No partitions available".to_string()
                )
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
        
        Ok((partition.primary, partition.replicas))
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
        self.partitions.get(partition_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                crate::error::StorageNodeError::NotFound(
                    format!("Partition {} not found", partition_id)
                )
            })
    }
    
    /// Get all partitions
    pub fn get_all_partitions(&self) -> Vec<Partition> {
        self.partitions.iter()
            .map(|e| e.value().clone())
            .collect()
    }
    
    /// Get active transfers
    pub fn get_active_transfers(&self) -> Vec<PartitionTransfer> {
        self.active_transfers.iter()
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

    /// Rebalance based on load metrics
    fn rebalance_load(&self, threshold: f64) -> Result<Vec<PartitionMove>> {
        let mut moves = Vec::new();
        let nodes = self.nodes.read();
        
        // Calculate global average load
        let total_load: u64 = nodes.values().map(|n| n.current_load).sum();
        let total_capacity: u64 = nodes.values().map(|n| n.capacity).sum();
        let global_load_ratio = total_load as f64 / total_capacity as f64;

        // Find overloaded and underloaded nodes
        let mut overloaded: Vec<_> = nodes
            .iter()
            .filter(|(_, n)| {
                let load_ratio = n.current_load as f64 / n.capacity as f64;
                load_ratio > global_load_ratio * (1.0 + threshold)
            })
            .collect();

        let mut underloaded: Vec<_> = nodes
            .iter()
            .filter(|(_, n)| {
                let load_ratio = n.current_load as f64 / n.capacity as f64;
                load_ratio < global_load_ratio * (1.0 - threshold)
            })
            .collect();

        // Sort by load ratio difference from global average
        overloaded.sort_by(|(_, a), (_, b)| {
            let a_ratio = a.current_load as f64 / a.capacity as f64;
            let b_ratio = b.current_load as f64 / b.capacity as f64;
            b_ratio.partial_cmp(&a_ratio).unwrap_or(std::cmp::Ordering::Equal)
        });

        underloaded.sort_by(|(_, a), (_, b)| {
            let a_ratio = a.current_load as f64 / a.capacity as f64;
            let b_ratio = b.current_load as f64 / b.capacity as f64;
            a_ratio.partial_cmp(&b_ratio).unwrap_or(std::cmp::Ordering::Equal)
        });

        // Generate partition moves to balance load
        for (overloaded_id, overloaded_node) in overloaded {
            let node_partitions: Vec<_> = self.partitions
                .iter()
                .filter(|e| e.value().primary == *overloaded_id)
                .map(|e| e.value().clone())
                .collect();

            for partition in node_partitions {
                if let Some((target_id, target_node)) = underloaded.first() {
                    // Check if move would improve balance
                    let src_ratio = overloaded_node.current_load as f64 / overloaded_node.capacity as f64;
                    let dst_ratio = target_node.current_load as f64 / target_node.capacity as f64;
                    
                    if src_ratio - dst_ratio > threshold {
                        moves.push(PartitionMove {
                            partition_id: partition.id.clone(),
                            source_node: overloaded_id.clone(),
                            target_node: target_id.clone(),
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
            if let Some(mut partition) = self.partitions.get_mut(&movement.partition_id) {
                let partition = partition.value_mut();
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
                partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
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
        let mut moves = Vec::new();
        
        // This would be implemented in a real system with actual geographic metrics
        
        Ok(moves)
    }
    
    /// Gets the capacity usage of a node
    fn get_node_capacity_usage(&self, _node_id: &str) -> Result<u64> {
        // Placeholder implementation - would query actual node metrics
        Ok(0)
    }
    
    /// Gets latency statistics for a node
    fn get_node_latency_stats(&self, _node_id: &str) -> Result<Duration> {
        // Placeholder implementation - would query actual node metrics
        Ok(Duration::from_millis(0))
    }
    
    /// Get the load of a partition
    fn get_partition_load(&self, _partition: &Partition) -> Result<f64> {
        // Placeholder implementation - would calculate actual partition load
        Ok(1.0)
    }
    
    /// Register transfer handler for a node
    pub fn register_transfer_handler<F>(&self, node_id: &str, handler: F) -> Result<()>
    where
        F: Fn(PartitionTransfer) -> Result<()> + Send + Sync + 'static
    {
        let mut handlers = self.transfer_handlers.write();
        handlers.insert(node_id.to_string(), Box::new(handler));
        Ok(())
    }
}

/// PartitionedStorage adapter for integrating with epidemic storage
pub struct PartitionedStorage<S> {
    /// Underlying storage engine
    storage: Arc<S>,
    
    /// Partition manager
    partition_manager: Arc<PartitionManager>,
    
    /// Node ID
    node_id: String,
}

impl<S> PartitionedStorage<S>
where
    S: 'static + Send + Sync,
{
    /// Create a new partitioned storage adapter
    pub fn new(storage: Arc<S>, partition_manager: Arc<PartitionManager>, node_id: String) -> Self {
        Self {
            storage,
            partition_manager,
            node_id,
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
        self.partition_manager.register_transfer_handler(&self.node_id, |transfer| {
            info!("Starting transfer of partition {} from {} to {}",
                transfer.partition_id, transfer.source, transfer.target);
                
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
        
        // Add some test nodes
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
            "key1".as_bytes(),
            "key2".as_bytes(),
            "key3".as_bytes(),
            "key4".as_bytes(),
        ];
        
        for key in &test_keys {
            let partition = manager.get_partition_for_key(key).unwrap();
            let (primary, replicas) = manager.get_responsible_nodes(key).unwrap();
            
            assert!(!primary.is_empty());
            assert_eq!(replicas.len(), manager.config.replication_factor - 1);
            
            // Verify partition boundaries
            assert!(calculate_key_hash(key) >= partition.start);
            assert!(calculate_key_hash(key) < partition.end);
        }
    }
    
    #[test]
    fn test_consistent_hash_rebalance() {
        let manager = PartitionManager::new(
            "test-node".to_string(), 
            PartitionConfig {
                partition_count: 16, // Small count for testing
                replication_factor: 2,
                strategy: PartitionStrategy::ConsistentHash,
                ..Default::default()
            }
        );
        manager.initialize().unwrap();
        
        // Add some test nodes
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
        ];
        
        for node in nodes {
            manager.add_node(node).unwrap();
        }
        
        // Rebalance
        manager.rebalance().unwrap();
        
        // Check partition assignment
        let partitions = manager.get_all_partitions();
        assert_eq!(partitions.len(), 16);
        
        // Verify all partitions have valid assignments
        for partition in &partitions {
            assert!(!partition.primary.is_empty());
            assert_eq!(partition.replicas.len(), 1); // Replication factor 2 (1 primary + 1 replica)
        }
        
        // Add another node and rebalance
        manager.add_node(StorageNode {
            id: "node3".to_string(),
            name: "Node 3".to_string(),
            region: "region2".to_string(),
            public_key: "key3".to_string(),
            endpoint: "endpoint3".to_string(),
        }).unwrap();
        
        // Rebalance
        manager.rebalance().unwrap();
        
        // Check transfer creation
        let transfers = manager.get_active_transfers();
        assert!(!transfers.is_empty()); // Should have created some transfers
        
        // Verify partition counts are somewhat balanced
        let node1_count = manager.node_partition_counts.get("node1").map(|c| *c).unwrap_or(0);
        let node2_count = manager.node_partition_counts.get("node2").map(|c| *c).unwrap_or(0);
        let node3_count = manager.node_partition_counts.get("node3").map(|c| *c).unwrap_or(0);
        
        // In a consistent hash with 3 nodes and 16 partitions, rough distribution expected
        assert!(node1_count > 0);
        assert!(node2_count > 0);
        assert!(node3_count > 0);
        
        // Check total adds up
        assert_eq!(node1_count + node2_count + node3_count, 16);
    }
}
