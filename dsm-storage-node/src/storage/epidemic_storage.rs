// Epidemic storage implementation using small-world topology
//
// This module implements a distributed storage engine using the
// epidemic propagation protocol with a small-world topology for efficient
// coordination and scalability.

use crate::error::Result;
use crate::storage::small_world::{SmallWorldTopology, SmallWorldConfig, calculate_key_hash};
use crate::storage::vector_clock::{VectorClock, VectorClockRelation};
use crate::types::storage_types::{StorageResponse, StorageStats};
use crate::types::{BlindedStateEntry, StorageNode, EntrySelector};

use async_trait::async_trait;
use dashmap::DashMap;
use futures::future::join_all;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Semaphore;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Entry wrapper with metadata for epidemic coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpidemicEntry {
    /// The blinded state entry
    pub entry: BlindedStateEntry,
    
    /// Vector clock for this entry
    pub vector_clock: VectorClock,
    
    /// Last modified timestamp
    pub last_modified: u64,
    
    /// Last sync timestamp
    pub last_sync: u64,
    
    /// Received from node
    pub received_from: Option<String>,
    
    /// Propagation count
    pub propagation_count: u32,
    
    /// Verification count
    pub verification_count: u32,
    
    /// Origin region
    pub origin_region: String,
}

impl EpidemicEntry {
    /// Create a new epidemic entry
    pub fn new(entry: BlindedStateEntry, node_id: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
            
        // Create a vector clock with a single entry for the originating node
        let mut vector_clock = VectorClock::new();
        vector_clock.increment(node_id);
        
        Self {
            entry,
            vector_clock,
            last_modified: now,
            last_sync: now,
            received_from: None,
            propagation_count: 0,
            verification_count: 1, // Self-verified
            origin_region: "unknown".to_string(),
        }
    }
    
    /// Create an epidemic entry from an existing entry with a specific node
    pub fn from_entry(
        entry: BlindedStateEntry, 
        vector_clock: VectorClock, 
        received_from: Option<String>,
        origin_region: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
            
        Self {
            entry,
            vector_clock,
            last_modified: now,
            last_sync: now,
            received_from,
            propagation_count: 0,
            verification_count: 1,
            origin_region,
        }
    }
    
    /// Check if the entry has expired
    pub fn is_expired(&self) -> bool {
        if self.entry.ttl == 0 {
            return false;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
            
        self.entry.timestamp + self.entry.ttl < now
    }
    
    /// Get the age of the entry in seconds
    pub fn age(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
            
        now - self.entry.timestamp
    }
    
    /// Update the entry from another
    pub fn update_from(&mut self, other: &EpidemicEntry) -> bool {
        match self.vector_clock.compare(&other.vector_clock) {
            VectorClockRelation::Before => {
                // Other is newer, update our entry
                self.entry = other.entry.clone();
                self.vector_clock = other.vector_clock.clone();
                self.last_modified = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
                self.propagation_count = 0;
                self.verification_count = 
                    std::cmp::max(self.verification_count, other.verification_count) + 1;
                true
            },
            VectorClockRelation::Concurrent => {
                // Conflict resolution
                // In this case, we deterministically choose one based on the blinded_id
                if other.entry.blinded_id > self.entry.blinded_id {
                    self.entry = other.entry.clone();
                    
                    // Merge the vector clocks
                    let mut merged_clock = self.vector_clock.clone();
                    merged_clock.merge(&other.vector_clock);
                    self.vector_clock = merged_clock;
                    
                    self.last_modified = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_secs();
                    self.propagation_count = 0;
                    self.verification_count = 
                        std::cmp::max(self.verification_count, other.verification_count) + 1;
                    true
                } else {
                    // Just merge the vector clocks but keep our data
                    self.vector_clock.merge(&other.vector_clock);
                    self.verification_count = 
                        std::cmp::max(self.verification_count, other.verification_count) + 1;
                    false
                }
            },
            _ => {
                // We are equal or newer, just update verification count
                self.verification_count = 
                    std::cmp::max(self.verification_count, other.verification_count) + 1;
                false
            }
        }
    }
}

/// Gossip event for the epidemic protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipEvent {
    /// A digest of entries
    Digest(NodeDigest),
    
    /// A request for specific entries
    Request(NodeRequest),
    
    /// A response with entries
    Response(NodeResponse),
    
    /// A direct entry update
    Update(EpidemicEntry),
    
    /// A notification of entry removal
    Removal(String),
    
    /// A node announcement
    Announcement(StorageNode, Vec<String>), // Node and known peer IDs
    
    /// A ping message
    Ping(String), // Origin node ID
    
    /// A pong response
    Pong(String, String), // Origin node ID, Respondent node ID
}

/// Node digest for the gossip protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDigest {
    /// Origin node ID
    pub origin_id: String,
    
    /// Digest entries
    pub entries: HashMap<String, DigestEntry>,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// TTL (time-to-live) for this digest in hops
    pub ttl: u8,
}

/// Digest entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestEntry {
    /// The vector clock for this entry
    pub vector_clock: VectorClock,
    
    /// Last modified timestamp
    pub last_modified: u64,
    
    /// Size in bytes
    pub size: usize,
    
    /// Region
    pub region: String,
}

/// Node request for entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRequest {
    /// Requesting node ID
    pub node_id: String,
    
    /// Keys to request
    pub keys: Vec<String>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// Node response with entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeResponse {
    /// Responding node ID
    pub node_id: String,
    
    /// Entries
    pub entries: Vec<EpidemicEntry>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// Partition strategy for gossip messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStrategy {
    /// Random partition
    Random,
    
    /// Partition by key hash
    KeyHash,
    
    /// Partition by region
    Region,
}

/// Regional consistency strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionalConsistency {
    /// Strict consistency within region
    StrictRegional,
    
    /// Eventual consistency across regions
    EventualCrossRegion,
    
    /// Strong consistency regardless of region
    StrongGlobal,
}

/// Configuration for the epidemic storage
#[derive(Debug, Clone)]
pub struct EpidemicStorageConfig {
    /// Node ID
    pub node_id: String,
    
    /// Node information
    pub node_info: StorageNode,
    
    /// Storage region
    pub region: String,
    
    /// Gossip interval in milliseconds
    pub gossip_interval_ms: u64,
    
    /// Anti-entropy interval in milliseconds
    pub anti_entropy_interval_ms: u64,
    
    /// Topology check interval in milliseconds
    pub topology_check_interval_ms: u64,
    
    /// Maximum concurrent gossip operations
    pub max_concurrent_gossip: usize,
    
    /// Maximum entries per gossip message
    pub max_entries_per_gossip: usize,
    
    /// Maximum entries per response
    pub max_entries_per_response: usize,
    
    /// Gossip fanout (number of peers to propagate to)
    pub gossip_fanout: usize,
    
    /// Gossip TTL (time-to-live) in hops
    pub gossip_ttl: u8,
    
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<StorageNode>,
    
    /// Small-world topology configuration
    pub topology_config: SmallWorldConfig,
    
    /// Partition strategy
    pub partition_strategy: PartitionStrategy,
    
    /// Regional consistency strategy
    pub regional_consistency: RegionalConsistency,
    
    /// Maximum storage entries (0 = unlimited)
    pub max_storage_entries: usize,
    
    /// Minimum verification count before accepting as stable
    pub min_verification_count: u32,
    
    /// Enable read repair
    pub enable_read_repair: bool,
    
    /// Automatic pruning interval in milliseconds
    pub pruning_interval_ms: u64,
}

impl Default for EpidemicStorageConfig {
    fn default() -> Self {
        Self {
            node_id: format!("node-{}", uuid::Uuid::new_v4()),
            node_info: StorageNode {
                id: format!("node-{}", uuid::Uuid::new_v4()),
                name: "Default Node".to_string(),
                region: "default".to_string(),
                public_key: "".to_string(),
                endpoint: "http://localhost:3000".to_string(),
            },
            region: "default".to_string(),
            gossip_interval_ms: 5000,
            anti_entropy_interval_ms: 60000,
            topology_check_interval_ms: 30000,
            max_concurrent_gossip: 10,
            max_entries_per_gossip: 100,
            max_entries_per_response: 50,
            gossip_fanout: 3,
            gossip_ttl: 3,
            bootstrap_nodes: Vec::new(),
            topology_config: SmallWorldConfig::default(),
            partition_strategy: PartitionStrategy::KeyHash,
            regional_consistency: RegionalConsistency::EventualCrossRegion,
            max_storage_entries: 0, // Unlimited
            min_verification_count: 2,
            enable_read_repair: true,
            pruning_interval_ms: 3600000, // 1 hour
        }
    }
}

/// Epidemic storage engine
pub struct EpidemicStorage {
    /// Node ID
    node_id: String,
    
    /// Storage region
    region: String,
    
    /// Local storage for entries
    storage: Arc<DashMap<String, EpidemicEntry>>,
    
    /// Small-world topology
    topology: Arc<RwLock<SmallWorldTopology>>,
    
    /// Gossip channel
    gossip_tx: Arc<RwLock<Sender<GossipEvent>>>,
    
    /// Active gossip operations semaphore
    gossip_semaphore: Arc<Semaphore>,
    
    /// Retry queue for failed operations
    retry_queue: Arc<Mutex<VecDeque<(String, Instant)>>>,
    
    /// Configuration
    config: EpidemicStorageConfig,
    
    /// Storage statistics
    stats: Arc<RwLock<StorageStats>>,
    
    /// Running background tasks
    #[allow(dead_code)]
    background_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    
    /// Flag indicating if the storage has been started
    started: Arc<std::sync::atomic::AtomicBool>,
    
    /// Entry filter for pruning
    entry_filter: Arc<Mutex<EntryFilter>>,
}

/// Entry filter for pruning and storing policies
#[derive(Default)]
struct EntryFilter {
    /// Entry priorities to keep
    priorities: Option<(i32, i32)>,
    
    /// Regions to keep
    regions: Option<HashSet<String>>,
    
    /// Maximum age in seconds
    max_age: Option<u64>,
    
    /// Maximum verification count
    max_verification: Option<u32>,
}

impl EntryFilter {
    /// Check if an entry should be kept
    fn should_keep(&self, entry: &EpidemicEntry) -> bool {
        // Check priority
        if let Some((min, max)) = self.priorities {
            if entry.entry.priority < min || entry.entry.priority > max {
                return false;
            }
        }
        
        // Check region
        if let Some(regions) = &self.regions {
            if !regions.contains(&entry.entry.region) {
                return false;
            }
        }
        
        // Check age
        if let Some(max_age) = self.max_age {
            if entry.age() > max_age {
                return false;
            }
        }
        
        // Check verification count
        if let Some(max_verification) = self.max_verification {
            if entry.verification_count > max_verification {
                return false;
            }
        }
        
        true
    }
}

impl EpidemicStorage {
    /// Create a new epidemic storage engine
    pub fn new(
        config: EpidemicStorageConfig,
        backing_storage: Option<Arc<dyn super::StorageEngine + Send + Sync>>,
    ) -> Result<Self> {
        // Create the gossip channel
        let (gossip_tx, _) = mpsc::channel(1000);
        
        // Create the storage
        let storage = Arc::new(DashMap::new());
        
        // Create the small-world topology
        let topology = Arc::new(RwLock::new(SmallWorldTopology::new(
            config.node_info.clone(),
            config.topology_config.clone(),
        )));
        
        // Initialize storage stats
        let stats = Arc::new(RwLock::new(StorageStats {
            total_entries: 0,
            total_bytes: 0,
            total_expired: 0,
            oldest_entry: None,
            newest_entry: None,
        }));
        
        // Create the storage engine
        let storage_engine = Self {
            node_id: config.node_id.clone(),
            region: config.region.clone(),
            storage,
            topology,
            gossip_tx: Arc::new(RwLock::new(gossip_tx)),
            gossip_semaphore: Arc::new(Semaphore::new(config.max_concurrent_gossip)),
            retry_queue: Arc::new(Mutex::new(VecDeque::new())),
            config,
            stats,
            background_tasks: Mutex::new(Vec::new()), // Create empty vector rather than cloning
            started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            entry_filter: Arc::new(Mutex::new(EntryFilter::default())),
        };
        
        // Initialize the storage with data from the backing storage if provided
        if let Some(_backing) = backing_storage {
            // TODO: Initialize from backing storage
        }
        
        Ok(storage_engine)
    }
    
    /// Start the epidemic storage engine
    pub async fn start(&self) -> Result<()> {
        if self.started.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        
        // Create a gossip receiver
        let (gossip_tx, gossip_rx) = mpsc::channel(1000);
        
        // Update the sender
        {
            let mut tx_guard = self.gossip_tx.write();
            *tx_guard = gossip_tx;
        } // Drop the MutexGuard here before the await point
        
        // Add bootstrap nodes to the topology
        {
            let mut topology = self.topology.write();
            for node in &self.config.bootstrap_nodes {
                topology.add_node(node.clone());
            }
            
            // Update long links
            topology.update_long_links();
        } // Drop the MutexGuard here before the await point
        
        // Start the background tasks and properly handle the return types
        let gossip_handle = self.start_gossip_task(gossip_rx);
        let anti_entropy_handle = self.start_anti_entropy_task();
        let topology_handle = self.start_topology_task();
        let pruning_handle = self.start_pruning_task();
        
        // Store the task handles - Scope the mutex guard to prevent holding across await points
        {
            let mut tasks = self.background_tasks.lock().unwrap();
            tasks.push(gossip_handle);
            tasks.push(anti_entropy_handle);
            tasks.push(topology_handle);
            tasks.push(pruning_handle);
        } // Mutex guard is dropped here
        
        // Mark as started
        self.started.store(true, std::sync::atomic::Ordering::SeqCst);
        
        info!("Epidemic storage engine started with node ID: {}", self.node_id);
        
        // Announce ourselves to bootstrap nodes
        self.announce_to_bootstrap_nodes().await?;
        
        Ok(())
    }
    
    /// Start the gossip task
    fn start_gossip_task(&self, mut gossip_rx: Receiver<GossipEvent>) -> tokio::task::JoinHandle<()> {
        let node_id = self.node_id.clone();
        let storage = self.storage.clone();
        let topology = self.topology.clone();
        let stats = self.stats.clone();
        let gossip_semaphore = self.gossip_semaphore.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            info!("Starting gossip task for node: {}", node_id);
            
            let mut gossip_interval = interval(Duration::from_millis(config.gossip_interval_ms));
            
            loop {
                tokio::select! {
                    _ = gossip_interval.tick() => {
                        let permit = match gossip_semaphore.try_acquire() {
                            Ok(permit) => permit,
                            Err(_) => {
                                debug!("Skipping gossip due to too many concurrent operations");
                                continue;
                            }
                        };
                        
                        // Safely gather all necessary information before async boundaries
                        let gossip_targets = {
                            let topology_guard = topology.read();
                            let targets = topology_guard.get_broadcast_targets(config.gossip_fanout);
                            drop(topology_guard);
                            targets
                        };
                        
                        // Safely create digest outside of await points
                        let digest_content = {
                            if !gossip_targets.is_empty() {
                                Some(create_digest(&node_id, &storage, config.max_entries_per_gossip, config.gossip_ttl))
                            } else {
                                None
                            }
                        };
                        
                        // Release the permit as soon as we're done with shared resources
                        drop(permit);
                        
                        // Now perform network operations with our extracted data
                        if let Some(digest) = digest_content {
                            for target in gossip_targets {
                                if let Err(e) = send_digest_to_node(&digest, &target).await {
                                    warn!("Failed to send digest to {}: {}", target.id, e);
                                }
                            }
                        } else {
                            debug!("No gossip targets available");
                        }
                    }
                    
                    Some(event) = gossip_rx.recv() => {
                        let permit = match gossip_semaphore.try_acquire() {
                            Ok(permit) => permit,
                            Err(_) => {
                                debug!("Skipping gossip event due to too many concurrent operations");
                                continue;
                            }
                        };
                        
                        match event {
                            GossipEvent::Digest(digest) => {
                                handle_digest(digest, &node_id, &storage, &topology, &stats).await;
                            }
                            GossipEvent::Request(request) => {
                                handle_request(request, &node_id, &storage, &topology).await;
                            }
                            GossipEvent::Response(response) => {
                                handle_response(response, &node_id, &storage, &stats).await;
                            }
                            GossipEvent::Update(entry) => {
                                handle_update(entry, &node_id, &storage, &topology, &stats, &config).await;
                            }
                            GossipEvent::Removal(key) => {
                                handle_removal(key, &node_id, &storage, &topology).await;
                            }
                            GossipEvent::Announcement(node, peers) => {
                                handle_announcement(node, peers, &topology).await;
                            }
                            GossipEvent::Ping(origin) => {
                                handle_ping(origin, &node_id, &topology).await;
                            }
                            GossipEvent::Pong(origin, respondent) => {
                                handle_pong(origin, respondent, &topology).await;
                            }
                        }
                        
                        drop(permit);
                    }
                }
            }
        })
    }
    
    /// Start the anti-entropy task
    fn start_anti_entropy_task(&self) -> tokio::task::JoinHandle<()> {
        let node_id = self.node_id.clone();
        let storage = self.storage.clone();
        let topology = self.topology.clone();
        let stats = self.stats.clone();
        let interval_ms = self.config.anti_entropy_interval_ms;
        
        tokio::spawn(async move {
            info!("Starting anti-entropy task for node: {}", node_id);
            
            let mut interval = interval(Duration::from_millis(interval_ms));
            
            loop {
                interval.tick().await;
                
                // Perform anti-entropy with random peers - safely extracting data before async boundary
                let peers_for_anti_entropy = {
                    let topology_guard = topology.read();
                    let all_neighbors = topology_guard.all_neighbors();
                    drop(topology_guard); // Release lock before await points
                    
                    // Create a thread-safe subset selection
                    let mut neighbors_copy = all_neighbors.clone();
                    
                    // Use thread-local RNG within this scope
                    {
                        use rand::seq::SliceRandom;
                        let mut rng = rand::thread_rng();
                        neighbors_copy.shuffle(&mut rng);
                    }
                    
                    // Calculate subset size and select peers
                    let subset_size = std::cmp::min(3, neighbors_copy.len());
                    neighbors_copy.into_iter().take(subset_size).collect::<Vec<_>>()
                };
                
                if !peers_for_anti_entropy.is_empty() {
                    debug!("Running anti-entropy with {} peers", peers_for_anti_entropy.len());
                    
                    let mut futures = Vec::new();
                    
                    for peer in peers_for_anti_entropy {
                        let peer_id = peer.id.clone();
                        let node_id = node_id.clone();
                        let storage = storage.clone();
                        let stats = stats.clone();
                        
                        futures.push(tokio::spawn(async move {
                            if let Err(e) = perform_anti_entropy(&node_id, &peer_id, &peer, &storage, &stats).await {
                                warn!("Anti-entropy with {} failed: {}", peer_id, e);
                            }
                        }));
                    }
                    
                    // Wait for all anti-entropy processes to complete
                    for result in join_all(futures).await {
                        if let Err(e) = result {
                            warn!("Anti-entropy task failed: {}", e);
                        }
                    }
                } else {
                    debug!("No peers available for anti-entropy");
                }
            }
        })
    }
    
    /// Start the topology maintenance task
    fn start_topology_task(&self) -> tokio::task::JoinHandle<()> {
        let node_id = self.node_id.clone();
        let topology = self.topology.clone();
        let interval_ms = self.config.topology_check_interval_ms;
        
        tokio::spawn(async move {
            info!("Starting topology maintenance task for node: {}", node_id);
            
            let mut interval = interval(Duration::from_millis(interval_ms));
            
            loop {
                interval.tick().await;
                
                // Update the topology
                {
                    let mut topology_guard = topology.write();
                    topology_guard.update_long_links();
                    
                    debug!(
                        "Topology updated: {} known nodes, {} immediate neighbors, {} long links",
                        topology_guard.node_count(),
                        topology_guard.immediate_neighbors().len(),
                        topology_guard.long_links().len()
                    );
                }
                
                // Ping random peers to check connectivity - safely extracting data before async boundary
                let peers_for_ping = {
                    let topology_guard = topology.read();
                    let all_neighbors = topology_guard.all_neighbors();
                    drop(topology_guard); // Release lock before await points
                    
                    // Create a thread-safe subset selection
                    let mut neighbors_copy = all_neighbors.clone();
                    
                    // Use thread-local RNG within this scope
                    {
                        use rand::seq::SliceRandom;
                        let mut rng = rand::thread_rng();
                        neighbors_copy.shuffle(&mut rng);
                    }
                    
                    // Select subset of peers for ping
                    let subset_size = std::cmp::min(5, neighbors_copy.len());
                    neighbors_copy.into_iter().take(subset_size).collect::<Vec<_>>()
                };
                
                if !peers_for_ping.is_empty() {
                    debug!("Pinging {} peers", peers_for_ping.len());
                    
                    let mut futures = Vec::new();
                    
                    for peer in peers_for_ping {
                        let peer_id = peer.id.clone();
                        let node_id = node_id.clone();
                        
                        futures.push(tokio::spawn(async move {
                            if let Err(e) = ping_node(&node_id, &peer).await {
                                warn!("Ping to {} failed: {}", peer_id, e);
                            }
                        }));
                    }
                    
                    // Wait for all pings to complete
                    for result in join_all(futures).await {
                        if let Err(e) = result {
                            warn!("Ping task failed: {}", e);
                        }
                    }
                }
            }
        })
    }
    
    /// Start the pruning task
    fn start_pruning_task(&self) -> tokio::task::JoinHandle<()> {
        let node_id = self.node_id.clone();
        let storage = self.storage.clone();
        let stats = self.stats.clone();
        let max_entries = self.config.max_storage_entries;
        let interval_ms = self.config.pruning_interval_ms;
        let entry_filter = self.entry_filter.clone();
        
        tokio::spawn(async move {
            info!("Starting pruning task for node: {}", node_id);
            
            let mut interval = interval(Duration::from_millis(interval_ms));
            
            loop {
                interval.tick().await;
                
                // Prune expired entries
                let mut pruned_count = 0;
                let mut pruned_bytes = 0;
                
                // Find expired entries
                let expired_keys: Vec<String> = storage
                    .iter()
                    .filter_map(|item| {
                        if item.value().is_expired() {
                            Some(item.key().clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                
                // Remove expired entries
                for key in &expired_keys {
                    if let Some((_, entry)) = storage.remove(key) {
                        pruned_count += 1;
                        pruned_bytes += entry.entry.encrypted_payload.len();
                    }
                }
                
                // Check filter criteria
                let filter = entry_filter.lock().unwrap();
                
                if filter.priorities.is_some() || filter.regions.is_some() || 
                   filter.max_age.is_some() || filter.max_verification.is_some() {
                    // Find entries that don't match the filter
                    let filtered_keys: Vec<String> = storage
                        .iter()
                        .filter_map(|item| {
                            if !filter.should_keep(item.value()) {
                                Some(item.key().clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    
                    // Remove filtered entries
                    for key in &filtered_keys {
                        if let Some((_, entry)) = storage.remove(key) {
                            pruned_count += 1;
                            pruned_bytes += entry.entry.encrypted_payload.len();
                        }
                    }
                }
                
                // Check if we need to prune due to max entries limit
                if max_entries > 0 && storage.len() > max_entries {
                    // Sort entries by priority and age
                    let mut entries: Vec<(String, i32, u64)> = storage
                        .iter()
                        .map(|item| {
                            (
                                item.key().clone(),
                                item.value().entry.priority,
                                item.value().entry.timestamp,
                            )
                        })
                        .collect();
                    
                    // Sort by priority (desc) and timestamp (asc)
                    entries.sort_by(|a, b| {
                        b.1.cmp(&a.1)
                            .then_with(|| a.2.cmp(&b.2))
                    });
                    
                    // Calculate how many entries to remove
                    let to_remove = storage.len() - max_entries;
                    
                    // Remove lowest priority and oldest entries
                    for (key, _, _) in entries.iter().skip(max_entries).take(to_remove) {
                        if let Some((_, entry)) = storage.remove(key) {
                            pruned_count += 1;
                            pruned_bytes += entry.entry.encrypted_payload.len();
                        }
                    }
                }
                
                if pruned_count > 0 {
                    debug!("Pruned {} entries ({} bytes)", pruned_count, pruned_bytes);
                    
                    // Update stats
                    let mut stats_guard = stats.write();
                    stats_guard.total_entries = storage.len();
                    stats_guard.total_expired += pruned_count;
                    // Recalculate total bytes
                    stats_guard.total_bytes = storage
                        .iter()
                        .map(|item| item.value().entry.encrypted_payload.len())
                        .sum();
                }
            }
        })
    }
    
    /// Get the gossip sender
    pub fn get_gossip_sender(&self) -> Sender<GossipEvent> {
        self.gossip_tx.read().clone()
    }
    
    /// Announce to bootstrap nodes
    async fn announce_to_bootstrap_nodes(&self) -> Result<()> {
        // Get known peers
        let known_peers = {
            let topology_guard = self.topology.read();
            topology_guard
                .all_neighbors()
                .into_iter()
                .map(|node| node.id)
                .collect::<Vec<_>>()
        };
        
        // Announce to bootstrap nodes
        for bootstrap_node in &self.config.bootstrap_nodes {
            let announcement = GossipEvent::Announcement(
                self.config.node_info.clone(),
                known_peers.clone(),
            );
            
            // Send announcement
            if let Err(e) = send_gossip_event_to_node(&announcement, bootstrap_node).await {
                warn!("Failed to announce to bootstrap node {}: {}", bootstrap_node.id, e);
            }
        }
        
        Ok(())
    }
    
    /// Get entries by a selector
    pub async fn get_entries_by_selector(&self, selector: &EntrySelector) -> Result<Vec<BlindedStateEntry>> {
        let mut result = Vec::new();
        
        for item in self.storage.iter() {
            let entry = item.value();
            
            // Check blinded IDs
            if let Some(ref blinded_ids) = selector.blinded_ids {
                if !blinded_ids.contains(&entry.entry.blinded_id) {
                    continue;
                }
            }
            
            // Check region
            if let Some(ref region) = selector.region {
                if &entry.entry.region != region {
                    continue;
                }
            }
            
            // Check priority
            if let Some(min_priority) = selector.min_priority {
                if entry.entry.priority < min_priority {
                    continue;
                }
            }
            
            if let Some(max_priority) = selector.max_priority {
                if entry.entry.priority > max_priority {
                    continue;
                }
            }
            
            // Check timestamp
            if let Some(min_timestamp) = selector.min_timestamp {
                if entry.entry.timestamp < min_timestamp {
                    continue;
                }
            }
            
            if let Some(max_timestamp) = selector.max_timestamp {
                if entry.entry.timestamp > max_timestamp {
                    continue;
                }
            }
            
            // Check if expired
            if !selector.include_expired && entry.is_expired() {
                continue;
            }
            
            // Check metadata filters
            if let Some(ref filters) = selector.metadata_filters {
                let mut matches = true;
                
                for (key, value) in filters {
                    if let Some(entry_value) = entry.entry.metadata.get(key) {
                        if entry_value != value {
                            matches = false;
                            break;
                        }
                    } else {
                        matches = false;
                        break;
                    }
                }
                
                if !matches {
                    continue;
                }
            }
            
            result.push(entry.entry.clone());
        }
        
        // Apply limit and offset
        let offset = selector.offset.unwrap_or(0);
        let limit = selector.limit.unwrap_or(result.len());
        
        let result = result
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect();
            
        Ok(result)
    }
    
    /// Set entry filter for storage policies
    pub fn set_entry_filter(
        &self,
        priorities: Option<(i32, i32)>,
        regions: Option<HashSet<String>>,
        max_age: Option<u64>,
        max_verification: Option<u32>,
    ) {
        let mut filter = self.entry_filter.lock().unwrap();
        *filter = EntryFilter {
            priorities,
            regions,
            max_age,
            max_verification,
        };
    }
    
    /// Propagate an entry to responsible nodes
    async fn propagate_entry(&self, entry: &EpidemicEntry) -> Result<()> {
        // Calculate key hash
        let key_hash = calculate_key_hash(entry.entry.blinded_id.as_bytes());
        
        // Get targets from topology
        let targets = {
            let topology_guard = self.topology.read();
            topology_guard.get_epidemic_targets(&key_hash, self.config.gossip_fanout)
        };
        
        if targets.is_empty() {
            debug!("No targets for propagation of entry {}", entry.entry.blinded_id);
            return Ok(());
        }
        
        // Create update event
        let update = GossipEvent::Update(entry.clone());
        
        // Send to targets
        let mut futures = Vec::new();
        
        for target in targets {
            let update = update.clone();
            futures.push(tokio::spawn(async move {
                if let Err(e) = send_gossip_event_to_node(&update, &target).await {
                    warn!("Failed to propagate entry to {}: {}", target.id, e);
                    Err(e)
                } else {
                    Ok(())
                }
            }));
        }
        
        // Wait for all propagations
        for result in join_all(futures).await {
            if let Err(e) = result {
                warn!("Propagation task failed: {}", e);
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl super::StorageEngine for EpidemicStorage {
    /// Store a blinded state entry
    async fn store(&self, entry: BlindedStateEntry) -> Result<StorageResponse> {
        let blinded_id = entry.blinded_id.clone();
        
        // Create epidemic entry
        let epidemic_entry = EpidemicEntry::new(entry.clone(), &self.node_id);
        
        // Store locally
        self.storage.insert(blinded_id.clone(), epidemic_entry.clone());
        
        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_entries = self.storage.len();
            stats.total_bytes += epidemic_entry.entry.encrypted_payload.len();
            
            // Update timestamp range
            if let Some(oldest) = stats.oldest_entry {
                if epidemic_entry.entry.timestamp < oldest {
                    stats.oldest_entry = Some(epidemic_entry.entry.timestamp);
                }
            } else {
                stats.oldest_entry = Some(epidemic_entry.entry.timestamp);
            }
            
            if let Some(newest) = stats.newest_entry {
                if epidemic_entry.entry.timestamp > newest {
                    stats.newest_entry = Some(epidemic_entry.entry.timestamp);
                }
            } else {
                stats.newest_entry = Some(epidemic_entry.entry.timestamp);
            }
        }
        
        // Propagate to other nodes
        if self.started.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::spawn({
                let self_clone = self.clone();
                let entry_clone = epidemic_entry.clone();
                let blinded_id_clone = blinded_id.clone();
                async move {
                    if let Err(e) = self_clone.propagate_entry(&entry_clone).await {
                        warn!("Failed to propagate entry {}: {}", blinded_id_clone, e);
                    }
                }
            });
        }
        
        Ok(StorageResponse {
            blinded_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            status: "success".to_string(),
            message: Some("Entry stored successfully".to_string()),
        })
    }

    /// Retrieve a blinded state entry by its ID
    async fn retrieve(&self, blinded_id: &str) -> Result<Option<BlindedStateEntry>> {
        // Try local storage first
        let entry_option = if let Some(entry) = self.storage.get(blinded_id) {
            // Check if expired
            if entry.is_expired() {
                // Remove if expired
                self.storage.remove(blinded_id);
                None
            } else {
                // Return a clone of the entry
                Some(entry.entry.clone())
            }
        } else {
            None
        };
        
        // Early return if found in local storage
        if entry_option.is_some() {
            return Ok(entry_option);
        }
        
        // If not found locally and we're started, try to retrieve from other nodes
        if self.started.load(std::sync::atomic::Ordering::SeqCst) && self.config.enable_read_repair {
            // Calculate key hash
            let key_hash = calculate_key_hash(blinded_id.as_bytes());
            
            // Find responsible nodes
            let responsible = {
                let topology_guard = self.topology.read();
                topology_guard.find_responsible_nodes(&key_hash, 3)
            };
            
            if !responsible.is_empty() {
                debug!("Trying to retrieve {} from {} responsible nodes", blinded_id, responsible.len());
                
                // Create a request
                let request = NodeRequest {
                    node_id: self.node_id.clone(),
                    keys: vec![blinded_id.to_string()],
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_secs(),
                };
                
                // Send the request to responsible nodes
                for node in responsible {
                    match request_entries_from_node(&request, &node).await {
                        Ok(response) => {
                            for entry in response.entries {
                                if entry.entry.blinded_id == blinded_id {
                                    // Store locally for future use
                                    self.storage.insert(blinded_id.to_string(), entry.clone());
                                    
                                    // Update stats
                                    {
                                        let mut stats = self.stats.write();
                                        stats.total_entries = self.storage.len();
                                        stats.total_bytes += entry.entry.encrypted_payload.len();
                                    }
                                    
                                    return Ok(Some(entry.entry));
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to request entry from {}: {}", node.id, e);
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }

    /// Delete a blinded state entry by its ID
    async fn delete(&self, blinded_id: &str) -> Result<bool> {
        // Remove from local storage
        let was_present = self.storage.remove(blinded_id).is_some();
        
        // Propagate removal
        if was_present && self.started.load(std::sync::atomic::Ordering::SeqCst) {
            let removal = GossipEvent::Removal(blinded_id.to_string());
            
            // Get targets
            let key_hash = calculate_key_hash(blinded_id.as_bytes());
            
            // Get targets from topology
            let targets = {
                let topology_guard = self.topology.read();
                topology_guard.get_epidemic_targets(&key_hash, self.config.gossip_fanout)
            };
            
            for target in targets {
                if let Err(e) = send_gossip_event_to_node(&removal, &target).await {
                    warn!("Failed to propagate removal to {}: {}", target.id, e);
                }
            }
        }
        
        Ok(was_present)
    }

    /// Check if a blinded state entry exists
    async fn exists(&self, blinded_id: &str) -> Result<bool> {
        // Check local storage
        if let Some(entry) = self.storage.get(blinded_id) {
            // Check if expired
            if entry.is_expired() {
                // Remove if expired
                self.storage.remove(blinded_id);
                return Ok(false);
            }
            
            return Ok(true);
        }
        
        Ok(false)
    }

    /// List blinded state entry IDs with optional pagination
    async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>> {
        let offset = offset.unwrap_or(0);
        let ids: Vec<String> = self.storage
            .iter()
            .map(|item| item.key().clone())
            .skip(offset)
            .take(limit.unwrap_or(usize::MAX))
            .collect();
            
        Ok(ids)
    }

    /// Get storage statistics
    async fn get_stats(&self) -> Result<StorageStats> {
        // Return a clone of the stats
        let stats = self.stats.read().clone();
        Ok(stats)
    }
}

impl Clone for EpidemicStorage {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id.clone(),
            region: self.region.clone(),
            storage: self.storage.clone(),
            topology: self.topology.clone(),
            gossip_tx: Arc::clone(&self.gossip_tx),
            gossip_semaphore: self.gossip_semaphore.clone(),
            retry_queue: self.retry_queue.clone(),
            config: self.config.clone(),
            stats: self.stats.clone(),
            // We don't clone background tasks, as they're tied to the original instance
            background_tasks: Mutex::new(Vec::new()),
            started: self.started.clone(),
            entry_filter: self.entry_filter.clone(),
        }
    }
}

/// Create a digest from storage using thread-safe RNG
fn create_digest(
    node_id: &str,
    storage: &DashMap<String, EpidemicEntry>,
    max_entries: usize,
    ttl: u8,
) -> NodeDigest {
    let mut entries = HashMap::new();
    
    // Select a random subset of entries if we have more than max_entries
    let keys: Vec<String> = if storage.len() > max_entries {
        // First collect all keys into a thread-local vector
        let all_keys: Vec<String> = storage.iter().map(|item| item.key().clone()).collect();
        
        // Use thread-local RNG within a contained scope
        {
            let mut keys_copy = all_keys.clone();
            // Use RNG in a contained scope
            {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                keys_copy.shuffle(&mut rng);
            }
            keys_copy.truncate(max_entries);
            keys_copy
        }
    } else {
        storage.iter().map(|item| item.key().clone()).collect()
    };
    
    // Create digest entries
    for key in keys {
        if let Some(entry) = storage.get(&key) {
            let digest_entry = DigestEntry {
                vector_clock: entry.vector_clock.clone(),
                last_modified: entry.last_modified,
                size: entry.entry.encrypted_payload.len(),
                region: entry.entry.region.clone(),
            };
            
            entries.insert(key, digest_entry);
        }
    }
    
    NodeDigest {
        origin_id: node_id.to_string(),
        entries,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs(),
        ttl,
    }
}

/// Handle a digest
async fn handle_digest(
    digest: NodeDigest,
    node_id: &str,
    storage: &DashMap<String, EpidemicEntry>,
    topology: &RwLock<SmallWorldTopology>,
    _stats: &RwLock<StorageStats>,
) {
    debug!("Received digest from {} with {} entries", digest.origin_id, digest.entries.len());
    
    // Find entries we need or have newer versions of
    let mut to_request = Vec::new();
    let mut to_send = Vec::new();
    
    for (key, digest_entry) in &digest.entries {
        match storage.get(key.as_str()) {
            Some(our_entry) => {
                match our_entry.vector_clock.compare(&digest_entry.vector_clock) {
                    VectorClockRelation::Before => {
                        // We need a newer version
                        to_request.push(key.clone());
                    }
                    VectorClockRelation::After => {
                        // We have a newer version
                        to_send.push(key.clone());
                    }
                    VectorClockRelation::Concurrent => {
                        // Concurrent updates, request to reconcile
                        to_request.push(key.clone());
                    }
                    VectorClockRelation::Equal => {
                        // Nothing to do
                    }
                }
            }
            None => {
                // We don't have this entry
                to_request.push(key.clone());
            }
        }
    }
    
    // Get the node from the topology
    let origin_node = {
        let topology_guard = topology.read();
        topology_guard.get_node_by_id(&digest.origin_id).cloned()
    };
    
    if origin_node.is_none() {
        warn!("Received digest from unknown node: {}", digest.origin_id);
        return;
    }
    
    let origin_node = origin_node.unwrap();
    
    // Request entries we need
    if !to_request.is_empty() {
        debug!("Requesting {} entries from {}", to_request.len(), digest.origin_id);
        
        let request = NodeRequest {
            node_id: node_id.to_string(),
            keys: to_request,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
        };
        
        if let Err(e) = request_entries_from_node(&request, &origin_node).await {
            warn!("Failed to request entries from {}: {}", digest.origin_id, e);
        }
    }
    
    // Send entries we have newer versions of
    if !to_send.is_empty() {
        debug!("Sending {} newer entries to {}", to_send.len(), digest.origin_id);
        
        let entries: Vec<EpidemicEntry> = to_send
            .into_iter()
            .filter_map(|key| storage.get(&key).map(|e| e.clone()))
            .collect();
            
        let response = NodeResponse {
            node_id: node_id.to_string(),
            entries,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
        };
        
        if let Err(e) = send_response_to_node(&response, &origin_node).await {
            warn!("Failed to send entries to {}: {}", digest.origin_id, e);
        }
    }
    
    // Propagate the digest if TTL > 0
    if digest.ttl > 0 {
        let mut new_digest = digest.clone();
        new_digest.ttl -= 1;
        
        // Choose a few random peers to propagate to - with thread-safety adjustments
        let propagation_peers = {
            // First, extract all necessary data under lock
            let digestion_peers = {
                let topology_guard = topology.read();
                let peers = topology_guard
                    .all_neighbors()
                    .into_iter()
                    .filter(|node| node.id != digest.origin_id && node.id != origin_node.id)
                    .collect::<Vec<_>>();
                drop(topology_guard); // Explicitly drop guard before shuffling
                peers
            };
            
            // Then apply randomization in a contained scope
            if !digestion_peers.is_empty() {
                let mut peers_copy = digestion_peers.clone();
                // Isolated RNG scope
                {
                    use rand::seq::SliceRandom;
                    let mut rng = rand::thread_rng();
                    peers_copy.shuffle(&mut rng);
                }
                
                // Take at most 2 peers
                if peers_copy.len() > 2 {
                    peers_copy.truncate(2);
                }
                peers_copy
            } else {
                Vec::new()
            }
        };
        
        for peer in propagation_peers {
            if let Err(e) = send_digest_to_node(&new_digest, &peer).await {
                warn!("Failed to propagate digest to {}: {}", peer.id, e);
            }
        }
    }
}

/// Handle a request
async fn handle_request(
    request: NodeRequest,
    node_id: &str,
    storage: &DashMap<String, EpidemicEntry>,
    topology: &RwLock<SmallWorldTopology>,
) {
    debug!("Received request from {} for {} keys", request.node_id, request.keys.len());
    
    // Find requested entries
    let entries: Vec<EpidemicEntry> = request.keys
        .iter()
        .filter_map(|key| storage.get(key).map(|e| e.clone()))
        .collect();
        
    if entries.is_empty() {
        debug!("No requested entries found");
        return;
    }
    
    // Get the requesting node from the topology
    let requester_node = {
        let topology_guard = topology.read();
        topology_guard.get_node_by_id(&request.node_id).cloned()
    };
    
    if requester_node.is_none() {
        warn!("Received request from unknown node: {}", request.node_id);
        return;
    }
    
    let requester_node = requester_node.unwrap();
    
    // Send the response
    let response = NodeResponse {
        node_id: node_id.to_string(),
        entries,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs(),
    };
    
    if let Err(e) = send_response_to_node(&response, &requester_node).await {
        warn!("Failed to send response to {}: {}", request.node_id, e);
    }
}

/// Handle a response
async fn handle_response(
    response: NodeResponse,
    _node_id: &str,
    storage: &DashMap<String, EpidemicEntry>,
    stats: &RwLock<StorageStats>,
) {
    debug!("Received response from {} with {} entries", response.node_id, response.entries.len());
    
    let mut updated_count = 0;
    let mut new_bytes = 0;
    
    // Process the entries
    for entry in response.entries {
        let blinded_id = entry.entry.blinded_id.clone();
        
        match storage.get_mut(&blinded_id) {
            Some(mut our_entry) => {
                // Check vector clocks
                let bytes_before = our_entry.entry.encrypted_payload.len();
                
                if our_entry.update_from(&entry) {
                    updated_count += 1;
                    new_bytes += our_entry.entry.encrypted_payload.len() - bytes_before;
                    
                    // Update the entry
                    our_entry.received_from = Some(response.node_id.clone());
                    our_entry.last_sync = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_else(|_| Duration::from_secs(0))
                        .as_secs();
                }
            }
            None => {
                // We don't have this entry, add it
                let mut new_entry = entry;
                new_entry.received_from = Some(response.node_id.clone());
                new_entry.last_sync = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
                
                new_bytes += new_entry.entry.encrypted_payload.len();
                updated_count += 1;
                
                storage.insert(blinded_id, new_entry);
            }
        }
    }
    
    if updated_count > 0 {
        debug!("Updated {} entries from response", updated_count);
        
        // Update stats
        let mut stats_guard = stats.write();
        stats_guard.total_entries = storage.len();
        stats_guard.total_bytes = stats_guard.total_bytes.saturating_add(new_bytes);
    }
}

/// Handle an update
async fn handle_update(
    entry: EpidemicEntry,
    node_id: &str,
    storage: &DashMap<String, EpidemicEntry>,
    topology: &RwLock<SmallWorldTopology>,
    stats: &RwLock<StorageStats>,
    config: &EpidemicStorageConfig,
) {
    let blinded_id = entry.entry.blinded_id.clone();
    debug!("Received update for entry {}", blinded_id);
    
    let mut updated = false;
    let mut new_bytes = 0;
    
    // Process the entry
    match storage.get_mut(&blinded_id) {
        Some(mut our_entry) => {
            // Check vector clocks
            let bytes_before = our_entry.entry.encrypted_payload.len();
            
            if our_entry.update_from(&entry) {
                updated = true;
                new_bytes += our_entry.entry.encrypted_payload.len() as isize - bytes_before as isize;
                
                // Update the entry
                our_entry.received_from = Some(node_id.to_string());
                our_entry.last_sync = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs();
            }
        }
        None => {
            // We don't have this entry, add it
            let mut new_entry = entry.clone();
            new_entry.received_from = Some(node_id.to_string());
            new_entry.last_sync = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs();
            
            new_bytes += new_entry.entry.encrypted_payload.len() as isize;
            updated = true;
            
            storage.insert(blinded_id.clone(), new_entry);
        }
    }
    
    if updated {
        debug!("Updated entry {} from update", blinded_id);
        
        // Update stats
        {
            let mut stats_guard = stats.write();
            stats_guard.total_entries = storage.len();
            if new_bytes >= 0 {
                stats_guard.total_bytes = stats_guard.total_bytes.saturating_add(new_bytes as usize);
            } else {
                stats_guard.total_bytes = stats_guard.total_bytes.saturating_sub((-new_bytes) as usize);
            }
        }
        
        // Propagate to peers if this is not a deterministic key for us
        let key_hash = calculate_key_hash(blinded_id.as_bytes());
        
        // Get targets from topology
        let targets = {
            let topology_guard = topology.read();
            let responsible = topology_guard.find_responsible_nodes(&key_hash, 3);
            
            // Filter out the node that sent us the update
            topology_guard.get_epidemic_targets(&key_hash, config.gossip_fanout)
                .into_iter()
                .filter(|n| n.id != node_id)
                .filter(|n| !responsible.iter().any(|r| r.id == n.id))
                .collect::<Vec<_>>()
        };
        
        if !targets.is_empty() {
            debug!("Propagating update to {} peers", targets.len());
            
            let update = GossipEvent::Update(entry);
            
            for target in targets {
                if let Err(e) = send_gossip_event_to_node(&update, &target).await {
                    warn!("Failed to propagate update to {}: {}", target.id, e);
                }
            }
        }
    }
}

/// Handle a removal
async fn handle_removal(
    key: String,
    node_id: &str,
    storage: &DashMap<String, EpidemicEntry>,
    topology: &RwLock<SmallWorldTopology>,
) {
    debug!("Received removal for entry {}", key);
    
    // Remove from storage
    let was_removed = storage.remove(&key).is_some();
    
    if was_removed {
        debug!("Removed entry {} from storage", key);
        
        // Propagate to peers
        let key_hash = calculate_key_hash(key.as_bytes());
        
        // Get targets from topology
        let targets = {
            let topology_guard = topology.read();
            
            // Filter out the node that sent us the removal
            topology_guard.get_epidemic_targets(&key_hash, 3)
                .into_iter()
                .filter(|n| n.id != node_id)
                .collect::<Vec<_>>()
        };
        
        if !targets.is_empty() {
            debug!("Propagating removal to {} peers", targets.len());
            
            let removal = GossipEvent::Removal(key);
            
            for target in targets {
                if let Err(e) = send_gossip_event_to_node(&removal, &target).await {
                    warn!("Failed to propagate removal to {}: {}", target.id, e);
                }
            }
        }
    }
}

/// Handle an announcement
async fn handle_announcement(
    node: StorageNode,
    peers: Vec<String>,
    topology: &RwLock<SmallWorldTopology>,
) {
    debug!("Received announcement from node {} with {} peers", node.id, peers.len());
    
    // Add the node to our topology
    let node_added = {
        let mut topology_guard = topology.write();
        topology_guard.add_node(node.clone())
    };
    
    if node_added {
        debug!("Added new node {} to topology", node.id);
        
        // Add known peers
        let mut topology_guard = topology.write();
        
        for peer_id in peers {
            if let Some(_peer) = topology_guard.get_node_by_id(&peer_id) {
                // We already know this peer
                continue;
            }
            
            // Create a placeholder peer node
            let peer_node = StorageNode {
                id: peer_id.clone(),
                name: format!("Node {}", peer_id),
                region: "unknown".to_string(),
                public_key: "".to_string(),
                endpoint: "".to_string(),
            };
            
            topology_guard.add_node(peer_node);
        }
        
        // Update long links
        topology_guard.update_long_links();
    }
}

/// Handle a ping
async fn handle_ping(
    origin: String,
    node_id: &str,
    topology: &RwLock<SmallWorldTopology>,
) {
    debug!("Received ping from node {}", origin);
    
    // Get the origin node from the topology
    let origin_node = {
        let topology_guard = topology.read();
        topology_guard.get_node_by_id(&origin).cloned()
    };
    
    if origin_node.is_none() {
        warn!("Received ping from unknown node: {}", origin);
        return;
    }
    
    let origin_node = origin_node.unwrap();
    
    // Send pong response
    let pong = GossipEvent::Pong(origin.clone(), node_id.to_string());
    
    if let Err(e) = send_gossip_event_to_node(&pong, &origin_node).await {
        warn!("Failed to send pong to {}: {}", origin, e);
    }
}

/// Handle a pong
async fn handle_pong(
    origin: String,
    respondent: String,
    topology: &RwLock<SmallWorldTopology>,
) {
    debug!("Received pong from node {} (responding to {})", respondent, origin);
    
    // Update the topology
    let _ = {
        let topology_guard = topology.read();
        topology_guard.get_node_by_id(&respondent).cloned()
    };
    
    // The node is already in our topology, no need to do anything
}

/// Anti-entropy process
async fn perform_anti_entropy(
    node_id: &str,
    peer_id: &str,
    peer: &StorageNode,
    storage: &DashMap<String, EpidemicEntry>,
    _stats: &RwLock<StorageStats>,
) -> Result<()> {
    debug!("Performing anti-entropy with node {}", peer_id);
    
    // Create a digest
    let digest = create_digest(node_id, storage, 1000, 0);
    
    // Send digest
    match send_digest_to_node(&digest, peer).await {
        Ok(_) => {
            debug!("Sent digest to {}", peer_id);
        }
        Err(e) => {
            warn!("Failed to send digest to {}: {}", peer_id, e);
        }
    }
    
    Ok(())
}

/// Send a digest to a node
async fn send_digest_to_node(digest: &NodeDigest, node: &StorageNode) -> Result<()> {
    debug!("Sending digest to node {} with {} entries", node.id, digest.entries.len());
    
    let event = GossipEvent::Digest(digest.clone());
    send_gossip_event_to_node(&event, node).await
}

/// Request entries from a node
async fn request_entries_from_node(request: &NodeRequest, node: &StorageNode) -> Result<NodeResponse> {
    debug!("Requesting {} entries from node {}", request.keys.len(), node.id);
    
    let event = GossipEvent::Request(request.clone());
    match send_gossip_event_to_node(&event, node).await {
        Ok(_) => {
            // TODO: Wait for response
            // This is a placeholder, in a real implementation we would have a response channel
            Ok(NodeResponse {
                node_id: node.id.clone(),
                entries: Vec::new(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_secs(),
            })
        }
        Err(e) => {
            warn!("Failed to send request to {}: {}", node.id, e);
            Err(e)
        }
    }
}

/// Send a response to a node
async fn send_response_to_node(response: &NodeResponse, node: &StorageNode) -> Result<()> {
    debug!("Sending response to node {} with {} entries", node.id, response.entries.len());
    
    let event = GossipEvent::Response(response.clone());
    send_gossip_event_to_node(&event, node).await
}

/// Send a gossip event to a node
async fn send_gossip_event_to_node(event: &GossipEvent, node: &StorageNode) -> Result<()> {
    // In a real implementation, this would send an HTTP request or use a message queue
    // For now, we'll just log it
    debug!("Would send gossip event to node {}: {:?}", node.id, event);
    
    // Simulate network delay
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    Ok(())
}

/// Ping a node
async fn ping_node(origin: &str, node: &StorageNode) -> Result<()> {
    debug!("Pinging node {}", node.id);
    
    let event = GossipEvent::Ping(origin.to_string());
    send_gossip_event_to_node(&event, node).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageEngine;
    
    #[tokio::test]
    async fn test_epidemic_storage_basic() {
        let config = EpidemicStorageConfig {
            node_id: "test-node".to_string(),
            node_info: StorageNode {
                id: "test-node".to_string(),
                name: "Test Node".to_string(),
                region: "test".to_string(),
                public_key: "".to_string(),
                endpoint: "http://localhost:3000".to_string(),
            },
            ..Default::default()
        };
        
        let storage = EpidemicStorage::new(config, None).unwrap();
        
        // Create a test entry
        let entry = BlindedStateEntry {
            blinded_id: "test-entry".to_string(),
            encrypted_payload: vec![1, 2, 3, 4],
            timestamp: 123456789,
            ttl: 3600,
            region: "test".to_string(),
            priority: 0,
            proof_hash: [0; 32],
            metadata: HashMap::new(),
        };
        
        // Store the entry
        let response = storage.store(entry.clone()).await.unwrap();
        assert_eq!(response.blinded_id, "test-entry");
        
        // Retrieve the entry
        let retrieved = storage.retrieve("test-entry").await.unwrap();
        assert!(retrieved.is_some());
        
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.blinded_id, "test-entry");
        assert_eq!(retrieved.encrypted_payload, vec![1, 2, 3, 4]);
        
        // Check existence
        let exists = storage.exists("test-entry").await.unwrap();
        assert!(exists);
        
        // List entries
        let entries = storage.list(None, None).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "test-entry");
        
        // Delete the entry
        let deleted = storage.delete("test-entry").await.unwrap();
        assert!(deleted);
        
        // Check it's gone
        let exists = storage.exists("test-entry").await.unwrap();
        assert!(!exists);
    }
}
