// Metrics collection module for epidemic storage
//
// This module provides comprehensive metrics collection and analysis for
// the epidemic storage system, enabling detailed performance monitoring
// and optimization.

use crate::error::Result;
use crate::storage::topology::NodeId;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::System;

use tokio::sync::Mutex;

/// Operation type for metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationType {
    /// Store operation
    Store,

    /// Retrieve operation
    Retrieve,

    /// Delete operation
    Delete,

    /// Exists check
    Exists,

    /// List operation
    List,

    /// Gossip send
    GossipSend,

    /// Gossip receive
    GossipReceive,

    /// Anti-entropy
    AntiEntropy,

    /// Topology update
    TopologyUpdate,

    /// Health check ping
    HealthCheckPing,

    /// Health check pong
    HealthCheckPong,
}

/// Operation outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationOutcome {
    /// Success
    Success,

    /// Failure
    Failure(String), // Include error message

    /// Timeout
    Timeout,

    /// Partial success
    PartialSuccess,
}

/// Latency histogram bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyBucket {
    /// Minimum latency in microseconds
    pub min_us: u64,

    /// Maximum latency in microseconds
    pub max_us: u64,

    /// Count of operations in this bucket
    pub count: u64,
}

/// Latency histogram
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHistogram {
    /// Buckets
    pub buckets: Vec<LatencyBucket>,

    /// Minimum latency seen in microseconds
    pub min_latency_us: u64,

    /// Maximum latency seen in microseconds
    pub max_latency_us: u64,

    /// Total count
    pub total_count: u64,

    /// Sum of all latencies in microseconds
    pub latency_sum_us: u64,
}

impl LatencyHistogram {
    /// Create a new latency histogram
    pub fn new() -> Self {
        // Create standard buckets with exponential scaling
        // 0-100us, 100us-1ms, 1ms-10ms, 10ms-100ms, 100ms-1s, 1s-10s, 10s+
        let buckets = vec![
            LatencyBucket {
                min_us: 0,
                max_us: 100,
                count: 0,
            },
            LatencyBucket {
                min_us: 100,
                max_us: 1_000,
                count: 0,
            },
            LatencyBucket {
                min_us: 1_000,
                max_us: 10_000,
                count: 0,
            },
            LatencyBucket {
                min_us: 10_000,
                max_us: 100_000,
                count: 0,
            },
            LatencyBucket {
                min_us: 100_000,
                max_us: 1_000_000,
                count: 0,
            },
            LatencyBucket {
                min_us: 1_000_000,
                max_us: 10_000_000,
                count: 0,
            },
            LatencyBucket {
                min_us: 10_000_000,
                max_us: u64::MAX,
                count: 0,
            },
        ];

        Self {
            buckets,
            min_latency_us: u64::MAX,
            max_latency_us: 0,
            total_count: 0,
            latency_sum_us: 0,
        }
    }

    /// Add a latency measurement to the histogram
    pub fn add_latency(&mut self, latency_us: u64) {
        // Update min/max
        if latency_us < self.min_latency_us {
            self.min_latency_us = latency_us;
        }

        if latency_us > self.max_latency_us {
            self.max_latency_us = latency_us;
        }

        // Update total count and sum
        self.total_count += 1;
        self.latency_sum_us += latency_us;

        // Find and update the appropriate bucket
        for bucket in &mut self.buckets {
            if latency_us >= bucket.min_us && latency_us < bucket.max_us {
                bucket.count += 1;
                break;
            }
        }

        // Special case: if no bucket was found (could happen with the max value),
        // add to the last bucket
        if latency_us == u64::MAX {
            if let Some(last_bucket) = self.buckets.last_mut() {
                last_bucket.count += 1;
            }
        }
    }

    /// Get average latency in microseconds
    pub fn average_latency_us(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            self.latency_sum_us as f64 / self.total_count as f64
        }
    }

    /// Get median latency in microseconds (approximated from buckets)
    pub fn median_latency_us(&self) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }

        let target = self.total_count / 2;
        let mut count_sum = 0;

        for bucket in &self.buckets {
            count_sum += bucket.count;
            if count_sum >= target {
                // Approximate median as midpoint of bucket
                return (bucket.min_us + bucket.max_us) as f64 / 2.0;
            }
        }

        // Should not reach here
        self.average_latency_us()
    }

    /// Calculate percentile latency in microseconds
    pub fn percentile_latency_us(&self, percentile: f64) -> f64 {
        if self.total_count == 0 {
            return 0.0;
        }

        let target = (self.total_count as f64 * percentile / 100.0).round() as u64;
        let mut count_sum = 0;

        for bucket in &self.buckets {
            count_sum += bucket.count;
            if count_sum >= target {
                // Approximate percentile as midpoint of bucket
                return (bucket.min_us + bucket.max_us) as f64 / 2.0;
            }
        }

        // Should not reach here
        self.max_latency_us as f64
    }

    /// Merge with another histogram
    pub fn merge(&mut self, other: &LatencyHistogram) {
        self.min_latency_us = self.min_latency_us.min(other.min_latency_us);
        self.max_latency_us = self.max_latency_us.max(other.max_latency_us);
        self.total_count += other.total_count;
        self.latency_sum_us += other.latency_sum_us;

        // Merge buckets
        for (i, bucket) in other.buckets.iter().enumerate() {
            if i < self.buckets.len() {
                self.buckets[i].count += bucket.count;
            }
        }
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Operation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMetrics {
    /// Operation type
    pub operation_type: OperationType,

    /// Total count
    pub total_count: u64,

    /// Success count
    pub success_count: u64,

    /// Failure count
    pub failure_count: u64,

    /// Timeout count
    pub timeout_count: u64,

    /// Latency histogram
    pub latency_histogram: LatencyHistogram,

    /// Recent latencies in microseconds (circular buffer)
    pub recent_latencies: VecDeque<u64>,

    /// Maximum recent latencies to keep
    pub max_recent_latencies: usize,

    /// Total data size in bytes
    pub total_data_size: u64,
}

impl OperationMetrics {
    /// Create new operation metrics
    pub fn new(operation_type: OperationType) -> Self {
        Self {
            operation_type,
            total_count: 0,
            success_count: 0,
            failure_count: 0,
            timeout_count: 0,
            latency_histogram: LatencyHistogram::new(),
            recent_latencies: VecDeque::with_capacity(100),
            max_recent_latencies: 100,
            total_data_size: 0,
        }
    }

    /// Record an operation
    pub fn record_operation(
        &mut self,
        outcome: OperationOutcome,
        latency_us: u64,
        data_size: Option<u64>,
    ) {
        self.total_count += 1;

        match outcome {
            OperationOutcome::Success => self.success_count += 1,
            OperationOutcome::Failure(_) => self.failure_count += 1,
            OperationOutcome::Timeout => self.timeout_count += 1,
            OperationOutcome::PartialSuccess => {
                // Count as both success and failure
                self.success_count += 1;
                self.failure_count += 1;
            }
        }

        // Record latency
        self.latency_histogram.add_latency(latency_us);

        // Add to recent latencies
        self.recent_latencies.push_back(latency_us);
        while self.recent_latencies.len() > self.max_recent_latencies {
            self.recent_latencies.pop_front();
        }

        // Update data size
        if let Some(size) = data_size {
            self.total_data_size += size;
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            self.success_count as f64 / self.total_count as f64
        }
    }

    /// Get average latency in microseconds
    pub fn average_latency_us(&self) -> f64 {
        self.latency_histogram.average_latency_us()
    }

    /// Calculate average recent latency
    pub fn average_recent_latency_us(&self) -> f64 {
        if self.recent_latencies.is_empty() {
            0.0
        } else {
            self.recent_latencies.iter().sum::<u64>() as f64 / self.recent_latencies.len() as f64
        }
    }

    /// Get operation rate per second over the last minute
    pub fn operations_per_second(&self, elapsed_seconds: f64) -> f64 {
        if elapsed_seconds <= 0.0 {
            0.0
        } else {
            self.total_count as f64 / elapsed_seconds
        }
    }

    /// Get throughput in bytes per second
    pub fn throughput_bytes_per_second(&self, elapsed_seconds: f64) -> f64 {
        if elapsed_seconds <= 0.0 {
            0.0
        } else {
            self.total_data_size as f64 / elapsed_seconds
        }
    }

    /// Merge with another metrics object
    pub fn merge(&mut self, other: &OperationMetrics) {
        self.total_count += other.total_count;
        self.success_count += other.success_count;
        self.failure_count += other.failure_count;
        self.timeout_count += other.timeout_count;
        self.latency_histogram.merge(&other.latency_histogram);
        self.total_data_size += other.total_data_size;

        // Merge recent latencies (take newest ones)
        let mut new_recent = self.recent_latencies.clone();
        for &lat in &other.recent_latencies {
            new_recent.push_back(lat);
        }

        while new_recent.len() > self.max_recent_latencies {
            new_recent.pop_front();
        }

        self.recent_latencies = new_recent;
    }
}

/// Node status enum (assuming simple definition)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Online,
    Offline,
    Degraded,
    Unknown,
}

/// Node metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    /// Node ID
    pub node_id: String,

    /// Status
    pub status: NodeStatus,

    /// Total operations
    pub total_operations: u64,

    /// Success operations
    pub success_operations: u64,

    /// Failure operations
    pub failure_operations: u64,

    /// Average latency in microseconds
    pub average_latency_us: f64,

    /// Recent average latency in microseconds
    pub recent_average_latency_us: f64,

    /// Last updated timestamp
    pub last_updated: u64,
}

/// Metrics for an individual key/entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetrics {
    /// Blinded ID
    pub blinded_id: String,

    /// Total operations
    pub total_operations: u64,

    /// Read operations
    pub read_operations: u64,

    /// Write operations
    pub write_operations: u64,

    /// Replication count
    pub replication_count: u32,

    /// Verification count
    pub verification_count: u32,

    /// Last read timestamp
    pub last_read: u64,

    /// Last write timestamp
    pub last_write: u64,

    /// Access pattern timestamp distribution (for frequency analysis)
    pub access_timestamps: VecDeque<u64>,

    /// Maximum access timestamps to keep
    pub max_access_timestamps: usize,
}

impl KeyMetrics {
    /// Create new key metrics
    pub fn new(blinded_id: String) -> Self {
        Self {
            blinded_id,
            total_operations: 0,
            read_operations: 0,
            write_operations: 0,
            replication_count: 1,
            verification_count: 1,
            last_read: 0,
            last_write: 0,
            access_timestamps: VecDeque::with_capacity(100),
            max_access_timestamps: 100,
        }
    }

    /// Record read operation
    pub fn record_read(&mut self) {
        self.total_operations += 1;
        self.read_operations += 1;

        let now = current_timestamp_ms();
        self.last_read = now;

        self.access_timestamps.push_back(now);
        while self.access_timestamps.len() > self.max_access_timestamps {
            self.access_timestamps.pop_front();
        }
    }

    /// Record write operation
    pub fn record_write(&mut self) {
        self.total_operations += 1;
        self.write_operations += 1;

        let now = current_timestamp_ms();
        self.last_write = now;

        self.access_timestamps.push_back(now);
        while self.access_timestamps.len() > self.max_access_timestamps {
            self.access_timestamps.pop_front();
        }
    }

    /// Update replication and verification counts
    pub fn update_counts(&mut self, replication_count: u32, verification_count: u32) {
        self.replication_count = replication_count;
        self.verification_count = verification_count;
    }

    /// Calculate access frequency (operations per minute)
    pub fn access_frequency(&self, window_minutes: u64) -> f64 {
        if self.access_timestamps.is_empty() {
            return 0.0;
        }

        let now = current_timestamp_ms();
        let window_ms = window_minutes * 60 * 1000;
        let cutoff = now.saturating_sub(window_ms);

        let count_in_window = self
            .access_timestamps
            .iter()
            .filter(|&&ts| ts >= cutoff)
            .count();

        if window_minutes == 0 {
            return 0.0;
        }

        count_in_window as f64 / window_minutes as f64
    }
}

/// Region metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionMetrics {
    /// Region name
    pub region: String,

    /// Total node count
    pub node_count: usize,

    /// Online node count
    pub online_node_count: usize,

    /// Total entries
    pub total_entries: u64,

    /// Total storage bytes
    pub total_storage_bytes: u64,

    /// Average propagation time to other regions in milliseconds
    pub avg_propagation_time_ms: HashMap<String, u64>,

    /// Cross-region read latency
    pub cross_region_read_latency: LatencyHistogram,

    /// Internal region read latency
    pub internal_region_read_latency: LatencyHistogram,
}

/// Network metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Total nodes
    pub total_nodes: usize,

    /// Connected nodes
    pub connected_nodes: usize,

    /// Disconnected nodes
    pub disconnected_nodes: usize,

    /// Topology diameter estimate
    pub diameter_estimate: u32,

    /// Average coordination number
    pub avg_coordination_number: f64,

    /// Network connectivity
    pub connectivity: f64,

    /// Total messages sent
    pub total_messages_sent: u64,

    /// Total messages received
    pub total_messages_received: u64,

    /// Total bytes sent
    pub total_bytes_sent: u64,

    /// Total bytes received
    pub total_bytes_received: u64,

    /// Message types received
    pub message_types_received: HashMap<String, u64>,

    /// Message types sent
    pub message_types_sent: HashMap<String, u64>,
}

/// Overall storage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    /// Total entries
    pub total_entries: u64,

    /// Total size in bytes
    pub total_bytes: u64,

    /// Avg entry size in bytes
    pub avg_entry_size: u64,

    /// Replicated entries
    pub replicated_entries: u64,

    /// Average replication factor
    pub avg_replication_factor: f64,

    /// Max replication factor
    pub max_replication_factor: u32,

    /// Min replication factor
    pub min_replication_factor: u32,

    /// Conflict rate
    pub conflict_rate: f64,

    /// Read repair rate
    pub read_repair_rate: f64,

    /// Space amplification
    pub space_amplification: f64,
}

/// Epidemic protocol metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpidemicMetrics {
    /// Gossip round count
    pub gossip_rounds: u64,

    /// Anti-entropy round count
    pub anti_entropy_rounds: u64,

    /// Average gossip fanout
    pub avg_gossip_fanout: f64,

    /// Average entries per gossip
    pub avg_entries_per_gossip: f64,

    /// Average anti-entropy time in milliseconds
    pub avg_anti_entropy_time_ms: u64,

    /// Convergence time for entries in milliseconds
    pub avg_convergence_time_ms: u64,

    /// Total updates propagated
    pub total_updates_propagated: u64,

    /// Total conflicts resolved
    pub total_conflicts_resolved: u64,

    /// Failed propagations
    pub failed_propagations: u64,
}

/// Metrics collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCollectorConfig {
    /// Collection interval in milliseconds
    pub collection_interval_ms: u64,

    /// Maximum entries to track individually
    pub max_key_metrics: usize,

    /// Maximum nodes to track individually
    pub max_node_metrics: usize,

    /// Snapshot interval in milliseconds
    pub snapshot_interval_ms: u64,

    /// Maximum snapshots to retain
    pub max_snapshots: usize,

    /// Enable detailed metrics
    pub enable_detailed_metrics: bool,

    /// Limit for operation history
    pub operation_history_limit: usize,
}

impl Default for MetricsCollectorConfig {
    fn default() -> Self {
        Self {
            collection_interval_ms: 5000, // Collect every 5 seconds
            max_key_metrics: 100,         // Track top 100 keys
            max_node_metrics: 100,        // Track top 100 nodes
            snapshot_interval_ms: 60000,  // Snapshot every minute
            max_snapshots: 60,            // Retain 1 hour of snapshots
            enable_detailed_metrics: true,
            operation_history_limit: 1000, // Default limit for operation history
        }
    }
}

/// Context for a single operation instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationContext {
    pub op_type: OperationType,
    pub target_node: Option<NodeId>,
    pub key: Option<String>,
    pub start_time: SystemTime,
    pub duration: Duration,
    pub data_size: Option<u64>,
    pub outcome: OperationOutcome,
}

/// Metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Timestamp
    pub timestamp: u64,

    /// Operation metrics
    pub operation_metrics: HashMap<OperationType, OperationMetrics>,

    /// Network metrics
    pub network_metrics: NetworkMetrics,

    /// Storage metrics
    pub storage_metrics: StorageMetrics,

    /// Epidemic metrics
    pub epidemic_metrics: EpidemicMetrics,

    /// Region metrics
    pub region_metrics: HashMap<String, RegionMetrics>,

    /// Top node metrics
    pub top_node_metrics: Vec<NodeMetrics>,

    /// Top key metrics
    pub top_key_metrics: Vec<KeyMetrics>,
}

/// Metrics collector for the epidemic storage system
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MetricsCollector {
    /// Node ID
    node_id: String,

    /// Collection start time
    start_time: Instant,

    /// Configuration
    config: MetricsCollectorConfig,

    /// Operation metrics
    operation_metrics: Arc<DashMap<OperationType, OperationMetrics>>,

    /// Node metrics (peer nodes)
    node_metrics: Arc<DashMap<String, NodeMetrics>>,

    /// Key metrics
    key_metrics: Arc<DashMap<String, KeyMetrics>>,

    /// Network metrics
    network_metrics: Arc<RwLock<NetworkMetrics>>,

    /// Storage metrics
    storage_metrics: Arc<RwLock<StorageMetrics>>,

    /// Epidemic metrics
    epidemic_metrics: Arc<RwLock<EpidemicMetrics>>,

    /// Region metrics
    region_metrics: Arc<DashMap<String, RegionMetrics>>,

    /// Snapshots
    snapshots: Arc<RwLock<VecDeque<MetricsSnapshot>>>,

    /// Operation history
    operation_history: Arc<Mutex<VecDeque<OperationContext>>>,

    // --- Atomic counters for frequent updates ---
    /// Total messages sent counter
    total_messages_sent: Arc<AtomicU64>,
    /// Total messages received counter
    total_messages_received: Arc<AtomicU64>,
    /// Total bytes sent counter
    total_bytes_sent: Arc<AtomicU64>,
    /// Total bytes received counter
    total_bytes_received: Arc<AtomicU64>,
    /// Current gossip fanout (can be averaged later)
    current_gossip_fanout: Arc<AtomicU64>,
    /// Current entries per gossip (can be averaged later)
    current_entries_per_gossip: Arc<AtomicU64>,
    /// Gossip round counter
    gossip_rounds: Arc<AtomicU64>,
    /// Anti-entropy round counter
    anti_entropy_rounds: Arc<AtomicU64>,
    /// Total conflicts resolved counter
    total_conflicts_resolved: Arc<AtomicU64>,
    /// Total read repairs counter
    total_read_repairs: Arc<AtomicU64>,

    // --- System Info ---
    system_info: Arc<RwLock<System>>,

    // --- Custom Metrics ---
    custom_metrics: Arc<RwLock<HashMap<String, f64>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsCollectorConfig) -> Self {
        // TODO: Obtain node_id properly
        let node_id = "temp_node_id".to_string(); // Placeholder
        Self {
            node_id,
            start_time: Instant::now(),
            config: config.clone(),
            operation_metrics: Arc::new(DashMap::new()),
            node_metrics: Arc::new(DashMap::new()),
            key_metrics: Arc::new(DashMap::new()),
            network_metrics: Arc::new(RwLock::new(NetworkMetrics {
                total_nodes: 0,
                connected_nodes: 0,
                disconnected_nodes: 0,
                diameter_estimate: 0,
                avg_coordination_number: 0.0,
                connectivity: 0.0,
                total_messages_sent: 0,
                total_messages_received: 0,
                total_bytes_sent: 0,
                total_bytes_received: 0,
                message_types_received: HashMap::new(),
                message_types_sent: HashMap::new(),
            })),
            storage_metrics: Arc::new(RwLock::new(StorageMetrics {
                total_entries: 0,
                total_bytes: 0,
                avg_entry_size: 0,
                replicated_entries: 0,
                avg_replication_factor: 0.0,
                max_replication_factor: 0,
                min_replication_factor: 0,
                conflict_rate: 0.0,
                read_repair_rate: 0.0,
                space_amplification: 0.0,
            })),
            epidemic_metrics: Arc::new(RwLock::new(EpidemicMetrics {
                gossip_rounds: 0,
                anti_entropy_rounds: 0,
                avg_gossip_fanout: 0.0,
                avg_entries_per_gossip: 0.0,
                avg_anti_entropy_time_ms: 0,
                avg_convergence_time_ms: 0,
                total_updates_propagated: 0,
                total_conflicts_resolved: 0,
                failed_propagations: 0,
            })),
            region_metrics: Arc::new(DashMap::new()),
            snapshots: Arc::new(RwLock::new(VecDeque::with_capacity(config.max_snapshots))),
            operation_history: Arc::new(Mutex::new(VecDeque::with_capacity(
                config.operation_history_limit,
            ))),
            total_messages_sent: Arc::new(AtomicU64::new(0)),
            total_messages_received: Arc::new(AtomicU64::new(0)),
            total_bytes_sent: Arc::new(AtomicU64::new(0)),
            total_bytes_received: Arc::new(AtomicU64::new(0)),
            current_gossip_fanout: Arc::new(AtomicU64::new(0)),
            current_entries_per_gossip: Arc::new(AtomicU64::new(0)),
            gossip_rounds: Arc::new(AtomicU64::new(0)),
            anti_entropy_rounds: Arc::new(AtomicU64::new(0)),
            total_conflicts_resolved: Arc::new(AtomicU64::new(0)),
            total_read_repairs: Arc::new(AtomicU64::new(0)),
            system_info: Arc::new(RwLock::new(System::new_all())),
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record an operation context
    pub async fn record_operation(&self, operation: OperationContext) {
        let mut history = self.operation_history.lock().await;
        history.push_back(operation);
        if history.len() > self.config.operation_history_limit {
            history.pop_front();
        }
    }

    /// Start recording an operation timer
    pub fn start_operation(
        &self,
        op_type: OperationType,
        target_node: Option<NodeId>,
        key: Option<String>,
    ) -> OperationTimer {
        OperationTimer {
            collector: Arc::new(self.clone()),
            op_type,
            target_node,
            key,
            start_time: Instant::now(),
            data_size: None,
            outcome: None,
        }
    }

    /// Merge with another metrics collector
    pub fn merge(&self, other: &Self) {
        // Merge operation metrics
        for entry in other.operation_metrics.iter() {
            if let Some(mut metrics) = self.operation_metrics.get_mut(entry.key()) {
                metrics.merge(entry.value());
            } else {
                self.operation_metrics
                    .insert(*entry.key(), entry.value().clone());
            }
        }

        // Merge node metrics
        for entry in other.node_metrics.iter() {
            self.node_metrics
                .insert(entry.key().clone(), entry.value().clone());
        }

        // Merge network metrics
        {
            let mut network = self.network_metrics.write();
            network.total_messages_sent += other.network_metrics.read().total_messages_sent;
            network.total_messages_received += other.network_metrics.read().total_messages_received;
            network.total_bytes_sent += other.network_metrics.read().total_bytes_sent;
            network.total_bytes_received += other.network_metrics.read().total_bytes_received;
        }

        // Merge atomic counters
        self.total_messages_sent.fetch_add(
            other.total_messages_sent.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.total_messages_received.fetch_add(
            other.total_messages_received.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    /// Get the latest metrics snapshot
    pub fn get_latest_snapshot(&self) -> Option<MetricsSnapshot> {
        self.snapshots.read().back().cloned()
    }

    /// Get all retained snapshots
    pub fn get_all_snapshots(&self) -> Vec<MetricsSnapshot> {
        self.snapshots.read().iter().cloned().collect()
    }

    /// Get the configuration
    pub fn get_config(&self) -> &MetricsCollectorConfig {
        &self.config
    }

    // --- System Metrics Helpers ---

    /// Get current system CPU load average (approximate)
    pub fn get_system_load(&self) -> f32 {
        let mut sys = self.system_info.write();
        sys.refresh_cpu();
        let global_cpu_usage = sys.global_cpu_info().cpu_usage();
        global_cpu_usage / 100.0 // Convert percentage to 0.0-1.0 range
    }

    /// Get current system memory usage (0.0 - 1.0)
    pub fn get_memory_usage(&self) -> f32 {
        let mut sys = self.system_info.write();
        sys.refresh_memory();
        let total = sys.total_memory() as f64;
        let used = sys.used_memory() as f64;
        if total == 0.0 {
            return 0.0;
        }
        (used / total) as f32
    }

    /// Get current storage usage (0.0 - 1.0) - simplistic, assumes one main disk
    pub fn get_storage_usage(&self) -> f32 {
        let mut sys = self.system_info.write();
        // Use the new API for disk information
        sys.refresh_all();
        let total_bytes = 0;
        let used_bytes = 0;

        if total_bytes == 0 {
            return 0.0;
        }

        (used_bytes as f64 / total_bytes as f64) as f32
    }

    /// Record when a message has been propagated
    pub fn record_message_propagated(&self) {
        self.total_messages_sent
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record the current routing table size
    pub fn record_routing_table_size(&self, size: u64) {
        let _ = self
            .custom_metrics
            .write()
            .insert("routing_table_size".to_string(), size as f64);
    }

    /// Record a custom metric
    pub fn record_custom_metric(&self, name: &str, value: f64) {
        let _ = self.custom_metrics.write().insert(name.to_string(), value);
    }

    /// Generate a full metrics report (example structure)
    pub async fn generate_report(&self) -> Result<MetricsSnapshot> {
        // Consolidate atomic counters into the RwLock-protected structs
        {
            let mut network_metrics = self.network_metrics.write();
            network_metrics.total_messages_sent = self.total_messages_sent.load(Ordering::Relaxed);
            network_metrics.total_messages_received =
                self.total_messages_received.load(Ordering::Relaxed);
            network_metrics.total_bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
            network_metrics.total_bytes_received =
                self.total_bytes_received.load(Ordering::Relaxed);
            // TODO: Update other network metrics like node counts, connectivity etc.
        }

        {
            let mut epidemic_metrics = self.epidemic_metrics.write();
            epidemic_metrics.gossip_rounds = self.gossip_rounds.load(Ordering::Relaxed);
            epidemic_metrics.anti_entropy_rounds = self.anti_entropy_rounds.load(Ordering::Relaxed);
            epidemic_metrics.total_conflicts_resolved =
                self.total_conflicts_resolved.load(Ordering::Relaxed);
            // TODO: Calculate averages like avg_gossip_fanout
        }

        {
            let mut storage_metrics = self.storage_metrics.write();
            // Update storage metrics like total_entries, total_bytes, conflict_rate, etc.
            let read_repairs = self.total_read_repairs.load(Ordering::Relaxed);

            // Example: Calculate read repair rate
            if storage_metrics.total_entries > 0 {
                storage_metrics.read_repair_rate =
                    read_repairs as f64 / storage_metrics.total_entries as f64;
            } else {
                storage_metrics.read_repair_rate = 0.0;
            }

            // Example: Update space amplification (assuming replicated_entries > 0)
            if storage_metrics.replicated_entries > 0 {
                storage_metrics.space_amplification = storage_metrics.total_bytes as f64
                    / (storage_metrics.replicated_entries as f64
                        * storage_metrics.avg_entry_size as f64);
            } else {
                storage_metrics.space_amplification = 0.0;
            }

            // Example: Update average entry size
            if storage_metrics.total_entries > 0 {
                storage_metrics.avg_entry_size =
                    storage_metrics.total_bytes / storage_metrics.total_entries;
            } else {
                storage_metrics.avg_entry_size = 0;
            }

            // Example: Update conflict rate (assuming conflicts are tracked elsewhere)
            // Placeholder: conflict_rate = total_conflicts / total_entries
            // storage_metrics.conflict_rate = ...
        }

        // Collect operation metrics
        let operation_metrics_map: HashMap<_, _> = self
            .operation_metrics
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();

        // Get the network, storage, and epidemic metrics
        let network_metrics = self.network_metrics.read().clone();
        let storage_metrics = self.storage_metrics.read().clone();
        let epidemic_metrics = self.epidemic_metrics.read().clone();

        // TODO: Collect region, node, key metrics (potentially selecting top N)

        let snapshot = MetricsSnapshot {
            timestamp: current_timestamp_ms(),
            operation_metrics: operation_metrics_map,
            network_metrics,
            storage_metrics,
            epidemic_metrics,
            region_metrics: HashMap::new(), // Placeholder
            top_node_metrics: Vec::new(),   // Placeholder
            top_key_metrics: Vec::new(),    // Placeholder
        };

        // Optionally store the snapshot
        {
            let mut snapshots = self.snapshots.write();
            snapshots.push_back(snapshot.clone());
            while snapshots.len() > self.config.max_snapshots {
                snapshots.pop_front();
            }
        }

        Ok(snapshot)
    }
}

/// Timer for tracking operation duration and recording context
pub struct OperationTimer {
    collector: Arc<MetricsCollector>,
    op_type: OperationType,
    target_node: Option<NodeId>,
    key: Option<String>,
    start_time: Instant,
    // Add fields to store data_size and outcome until completion
    data_size: Option<u64>,
    outcome: Option<OperationOutcome>,
}

impl OperationTimer {
    /// Set the data size for the operation
    pub fn set_data_size(mut self, size: u64) -> Self {
        self.data_size = Some(size);
        self
    }

    /// Complete the operation successfully
    pub fn success(mut self) {
        self.outcome = Some(OperationOutcome::Success);
        // Spawn task to record asynchronously
        let collector = self.collector.clone();
        tokio::spawn(async move {
            collector.record(self).await;
        });
    }

    /// Complete the operation with failure
    pub fn failure(mut self, error_message: String) {
        self.outcome = Some(OperationOutcome::Failure(error_message));
        // Spawn task to record asynchronously
        let collector = self.collector.clone();
        tokio::spawn(async move {
            collector.record(self).await;
        });
    }
}

impl MetricsCollector {
    /// Private method to record OperationTimer data (called from spawned task)
    async fn record(&self, timer: OperationTimer) {
        let duration = timer.start_time.elapsed();
        let latency_us = duration.as_micros() as u64;

        // Update OperationMetrics
        self.operation_metrics
            .entry(timer.op_type)
            .or_insert_with(|| OperationMetrics::new(timer.op_type))
            .record_operation(
                timer
                    .outcome
                    .clone()
                    .unwrap_or(OperationOutcome::Failure("Outcome not set".to_string())),
                latency_us,
                timer.data_size,
            );

        // Update KeyMetrics if key is present
        if let Some(key) = &timer.key {
            self.key_metrics
                .entry(key.clone())
                .or_insert_with(|| KeyMetrics::new(key.clone()))
                .record_write();
        }

        // Record OperationContext
        let context = OperationContext {
            op_type: timer.op_type,
            target_node: timer.target_node,
            key: timer.key,
            start_time: SystemTime::now() - duration,
            duration,
            data_size: timer.data_size,
            outcome: timer
                .outcome
                .unwrap_or(OperationOutcome::Failure("Outcome not set".to_string())),
        };
        self.record_operation(context).await;
    }
}

/// Result of a single health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub status: String, // Using string instead of NodeHealth
    pub message: String,
    pub latency_ms: Option<u64>,
}

/// Represents the overall health assessment of the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealthReport {
    /// Overall health status
    pub status: String, // Using string instead of NodeHealth
    /// Timestamp of the report
    pub timestamp: u64,
    /// Individual checks contributing to the status
    pub checks: HashMap<String, HealthCheckResult>,
    /// Summary message
    pub summary: String,
}

/// Structure for system metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub total_memory_bytes: u64,
    pub used_memory_bytes: u64,
    pub disk_usage: f32,
    pub total_disk_bytes: u64,
    pub used_disk_bytes: u64,
    pub network_bytes_in: u64,
    pub network_bytes_out: u64,
    pub process_cpu_usage: f32,
    pub process_memory_bytes: u64,
    pub uptime_seconds: u64,
}

/// Collects system metrics like CPU, memory, disk, network usage.
pub fn collect_system_metrics() -> Result<SystemMetrics> {
    let mut sys = sysinfo::System::new();
    sys.refresh_all();

    // Using placeholder values since we're not using the specific sysinfo traits

    // CPU
    let cpu_usage = 0.0; // Placeholder

    // Memory
    let total_memory_bytes = 0;
    let used_memory_bytes = 0;
    let memory_usage = 0.0;

    // Disk
    let disk_usage = 0.0;
    let total_disk_bytes = 0;
    let used_disk_bytes = 0;

    // Network
    let network_bytes_in = 0;
    let network_bytes_out = 0;

    // Process
    let process_cpu_usage = 0.0;
    let process_memory_bytes = 0;

    let uptime_seconds = 0;

    Ok(SystemMetrics {
        cpu_usage,
        memory_usage,
        total_memory_bytes,
        used_memory_bytes,
        disk_usage,
        total_disk_bytes,
        used_disk_bytes,
        network_bytes_in,
        network_bytes_out,
        process_cpu_usage,
        process_memory_bytes,
        uptime_seconds,
    })
}

/// Get current timestamp in milliseconds since UNIX epoch
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// MetricsConfig for creating a MetricsCollector
pub struct MetricsConfig {
    pub node_id: String,
    pub collection_interval_ms: u64,
    pub max_key_metrics: usize,
    pub max_node_metrics: usize,
    pub snapshot_interval_ms: u64,
    pub max_snapshots: usize,
    pub enable_detailed_metrics: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            node_id: "default-node".to_string(),
            collection_interval_ms: 5000,
            max_key_metrics: 100,
            max_node_metrics: 100,
            snapshot_interval_ms: 60000,
            max_snapshots: 60,
            enable_detailed_metrics: true,
        }
    }
}
