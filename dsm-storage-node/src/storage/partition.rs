// Partition management for epidemic storage
//
// This module implements deterministic rotation and partitioning mechanisms
// to distribute storage load across nodes while maintaining locality.

use crate::error::Result;
use crate::storage::small_world::{NodeId, calculate_key_hash};
use crate::types::StorageNode;

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

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
        let node_count = node_ids.len();
        
        // Calculate optimal partitions per node
        let optimal_per_node = self.config.partition_count / node_count;
        
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
        for partition_entry in self.partitions.iter_mut() {
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
        let node_count = node_ids.len();
        
        if node_count == 0 {
            return Ok(());
        }
        
        // Clear current node partition counts
        for node_id in &node_ids {
            self.node_partition_counts.insert(node_id.clone(), 0);
        }
        
        // Assign partitions randomly
        use rand::{seq::SliceRandom, thread_rng};
        let mut rng = thread_rng();
        
        for partition_entry in self.partitions.iter_mut() {
            let partition = partition_entry.value_mut();
            
            // Select a random primary
            let primary = node_ids.choose(&mut rng).unwrap().clone();
            
            // Select random replicas
            let mut replicas = Vec::new();
            let mut available: Vec<&String> = node_ids.iter()
                .filter(|id| **id != primary)
                .collect();
                
            available.shuffle(&mut rng);
            
            for node_id in available.iter().take(self.config.replication_factor - 1) {
                replicas.push((*node_id).clone());
            }
            
            // Check if this is a change in ownership
            let old_primary = partition.primary.clone();
            
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
    
    /// Rebalance using geography-aware algorithm
    fn rebalance_geography_aware(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        let node_ids: Vec<String> = nodes.keys().cloned().collect();
        
        // Group nodes by region
        let mut regions: HashMap<String, Vec<String>> = HashMap::new();
        
        for (node_id, node) in nodes {
            regions
                .entry(node.region.clone())
                .or_insert_with(Vec::new)
                .push(node_id.clone());
        }
        
        // Clear current node partition counts
        for node_id in &node_ids {
            self.node_partition_counts.insert(node_id.clone(), 0);
        }
        
        // Assign partitions, trying to keep regions together
        let region_names: Vec<String> = regions.keys().cloned().collect();
        
        for partition_entry in self.partitions.iter_mut() {
            let partition = partition_entry.value_mut();
            
            // Choose a random region for this partition
            let region = {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                region_names.choose(&mut rng).unwrap().clone()
            };
            
            // Choose a primary from this region
            let primary = {
                let region_nodes = regions.get(&region).unwrap();
                
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                region_nodes.choose(&mut rng).unwrap().clone()
            };
            
            // Choose replicas, preferring the same region but ensuring diversity
            let mut replicas = Vec::new();
            
            // First, try to pick from same region
            let same_region_nodes: Vec<String> = regions.get(&region).unwrap()
                .iter()
                .filter(|id| **id != primary)
                .cloned()
                .collect();
                
            for node_id in same_region_nodes.iter().take(self.config.replication_factor / 2) {
                replicas.push(node_id.clone());
            }
            
            // If we need more, pick from other regions
            if replicas.len() < self.config.replication_factor - 1 {
                // Get nodes from other regions
                let mut other_region_nodes = Vec::new();
                
                for (region_name, region_nodes) in &regions {
                    if region_name != &region {
                        other_region_nodes.extend(region_nodes.iter().cloned());
                    }
                }
                
                // Shuffle and pick needed count
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                other_region_nodes.shuffle(&mut rng);
                
                for node_id in other_region_nodes.iter().take(
                    self.config.replication_factor - 1 - replicas.len()
                ) {
                    replicas.push(node_id.clone());
                }
            }
            
            // Check if this is a change in ownership
            let old_primary = partition.primary.clone();
            
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
    
    /// Rebalance using load-balanced algorithm
    fn rebalance_load_balanced(&self, nodes: &HashMap<String, StorageNode>) -> Result<()> {
        let node_ids: Vec<String> = nodes.keys().cloned().collect();
        let node_count = node_ids.len();
        
        if node_count == 0 {
            return Ok(());
        }
        
        // Calculate optimal partitions per node
        let optimal_per_node = self.config.partition_count / node_count;
        
        // Clear current node partition counts
        for node_id in &node_ids {
            self.node_partition_counts.insert(node_id.clone(), 0);
        }
        
        // Group partitions by current primary
        let mut partition_groups: HashMap<String, Vec<String>> = HashMap::new();
        
        for partition_entry in self.partitions.iter() {
            let partition = partition_entry.value();
            let primary = partition.primary.clone();
            
            if !primary.is_empty() {
                partition_groups
                    .entry(primary)
                    .or_insert_with(Vec::new)
                    .push(partition.id.clone());
            }
        }
        
        // Initialize new assignment map
        let mut new_assignments: HashMap<String, String> = HashMap::new();
        
        // Identify overloaded and underloaded nodes
        let mut overloaded: Vec<(String, usize)> = Vec::new();
        let mut underloaded: Vec<(String, usize)> = Vec::new();
        
        for node_id in node_ids.iter() {
            let current_count = partition_groups
                .get(node_id)
                .map(|partitions| partitions.len())
                .unwrap_or(0);
                
            if current_count > optimal_per_node {
                overloaded.push((node_id.clone(), current_count - optimal_per_node));
            } else if current_count < optimal_per_node {
                underloaded.push((node_id.clone(), optimal_per_node - current_count));
            }
        }
        
        // Sort for deterministic behavior
        overloaded.sort_by(|a, b| b.1.cmp(&a.1)); // Most overloaded first
        underloaded.sort_by(|a, b| b.1.cmp(&a.1)); // Most underloaded first
        
        // Migrate partitions from overloaded to underloaded nodes
        for (overloaded_node, excess) in overloaded {
            // Get partitions owned by this node
            let owned_partitions = partition_groups
                .get(&overloaded_node)
                .cloned()
                .unwrap_or_default();
                
            if owned_partitions.is_empty() {
                continue;
            }
            
            // Calculate how many to migrate
            let to_migrate = std::cmp::min(excess, owned_partitions.len());
            
            // Select partitions to migrate
            let mut selected_partitions = owned_partitions.clone();
            selected_partitions.sort(); // Sort for determinism
            selected_partitions.truncate(to_migrate);
            
            // Find underloaded nodes to migrate to
            for partition_id in selected_partitions {
                if let Some((underloaded_node, _)) = underloaded.first() {
                    // Assign to this node
                    new_assignments.insert(partition_id, underloaded_node.clone());
                    
                    // Update underloaded count
                    if let Some((_, count)) = underloaded.first_mut() {
                        *count -= 1;
                    }
                    
                    // If no more capacity, remove this node
                    if underloaded[0].1 == 0 {
                        underloaded.remove(0);
                    }
                }
                
                // If no more underloaded nodes, stop
                if underloaded.is_empty() {
                    break;
                }
            }
            
            // If no more underloaded nodes, stop
            if underloaded.is_empty() {
                break;
            }
        }
        
        // Apply new assignments
        for (partition_id, new_owner) in new_assignments {
            if let Some(mut partition) = self.partitions.get_mut(&partition_id) {
                let old_primary = partition.primary.clone();
                
                // Only change if different
                if old_primary != new_owner {
                    // Select replicas (prefer to keep existing if possible)
                    let mut new_replicas = Vec::new();
                    
                    // Try to keep existing replicas, but avoid the old primary
                    for replica in partition.replicas.iter() {
                        if replica != &old_primary && replica != &new_owner {
                            new_replicas.push(replica.clone());
                        }
                    }
                    
                    // Add old primary as replica if space
                    if !old_primary.is_empty() && new_replicas.len() < self.config.replication_factor - 1 {
                        new_replicas.push(old_primary.clone());
                    }
                    
                    // Add random nodes if still need more
                    if new_replicas.len() < self.config.replication_factor - 1 {
                        let mut candidates: Vec<String> = node_ids.iter()
                            .filter(|id| **id != new_owner && !new_replicas.contains(id))
                            .cloned()
                            .collect();
                            
                        use rand::seq::SliceRandom;
                        let mut rng = rand::thread_rng();
                        candidates.shuffle(&mut rng);
                        
                        for node_id in candidates.iter().take(
                            self.config.replication_factor - 1 - new_replicas.len()
                        ) {
                            new_replicas.push(node_id.clone());
                        }
                    }
                    
                    // Update partition info
                    partition.primary = new_owner.clone();
                    partition.replicas = new_replicas;
                    partition.last_assignment = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_secs();
                    partition.generation = self.ring_generation.load(Ordering::SeqCst) + 1;
                    
                    // Create transfer
                    self.create_transfer(&partition, &old_primary, &new_owner)?;
                }
            }
        }
        
        // Update node partition counts
        for entry in self.partitions.iter() {
            let partition = entry.value();
            let primary = partition.primary.clone();
            
            if !primary.is_empty() {
                if let Some(mut count) = self.node_partition_counts.get_mut(&primary) {
                    *count += 1;
                }
            }
        }
        
        Ok(())
    }
    
    /// Create a partition transfer
    fn create_transfer(&self, partition: &Partition, source: &str, target: &str) -> Result<()> {
        // Skip if source is empty
        if source.is_empty() {
            return Ok(());
        }
        
        // Create transfer object
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
        };
        
        // Add to active transfers
        self.active_transfers.insert(partition.id.clone(), transfer.clone());
        
        // Call handler if registered
        let handlers = self.transfer_handlers.read();
        if let Some(handler) = handlers.get(source) {
            handler(transfer)?;
        }
        
        Ok(())
    }
    
    /// Register a transfer handler
    pub fn register_transfer_handler<F>(&self, node_id: &str, handler: F) -> Result<()>
    where
        F: Fn(PartitionTransfer) -> Result<()> + Send + Sync + 'static,
    {
        let mut handlers = self.transfer_handlers.write();
        handlers.insert(node_id.to_string(), Box::new(handler));
        Ok(())
    }
    
    /// Update transfer status
    pub fn update_transfer_status(
        &self,
        partition_id: &str,
        state: TransferState,
        transferred_items: u64,
        transferred_bytes: u64,
    ) -> Result<()> {
        if let Some(mut transfer) = self.active_transfers.get_mut(partition_id) {
            transfer.state = state;
            transfer.transferred_items = transferred_items;
            transfer.transferred_bytes = transferred_bytes;
            
            // Calculate rates
            let elapsed_secs = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs() - transfer.start_time) as f64;
                
            if elapsed_secs > 0.0 {
                transfer.items_per_second = transferred_items as f64 / elapsed_secs;
                transfer.bytes_per_second = transferred_bytes as f64 / elapsed_secs;
            }
            
            // If complete, set completion time
            if state == TransferState::Complete {
                transfer.completion_time = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_secs()
                );
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
            
            if (hash >= partition.start) && (hash < partition.end) {
                return Ok(partition.clone());
            }
        }
        
        // If not found, could be an edge case with ranges
        // Return the first partition as a fallback
        self.partitions.iter()
            .next()
            .map(|e| e.value().clone())
            .ok_or_else(|| {
                crate::error::StorageNodeError::NotFound {
                    context: "No partitions available".to_string()
                }
            })
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
                crate::error::StorageNodeError::NotFound {
                    context: format!("Partition {} not found", partition_id)
                }
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
        self.active_transfers.get(partition_id)
            .map(|e| e.value().clone())
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
