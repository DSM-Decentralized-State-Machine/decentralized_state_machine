// Metrics collection module for epidemic storage
//
// This module provides comprehensive metrics collection and analysis for 
// the epidemic storage system, enabling detailed performance monitoring
// and optimization.


use crate::types::NodeStatus;

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationOutcome {
    /// Success
    Success,
    
    /// Failure
    Failure,
    
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
        let mut buckets = Vec::new();
        
        // 0-100us, 100us-1ms, 1ms-10ms, 10ms-100ms, 100ms-1s, 1s-10s, 10s+
        buckets.push(LatencyBucket { min_us: 0, max_us: 100, count: 0 });
        buckets.push(LatencyBucket { min_us: 100, max_us: 1_000, count: 0 });
        buckets.push(LatencyBucket { min_us: 1_000, max_us: 10_000, count: 0 });
        buckets.push(LatencyBucket { min_us: 10_000, max_us: 100_000, count: 0 });
        buckets.push(LatencyBucket { min_us: 100_000, max_us: 1_000_000, count: 0 });
        buckets.push(LatencyBucket { min_us: 1_000_000, max_us: 10_000_000, count: 0 });
        buckets.push(LatencyBucket { min_us: 10_000_000, max_us: u64::MAX, count: 0 });
        
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
            OperationOutcome::Failure => self.failure_count += 1,
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
        
        let now = current_timestamp_millis();
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
        
        let now = current_timestamp_millis();
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
        
        let now = current_timestamp_millis();
        let window_ms = window_minutes * 60 * 1000;
        let cutoff = if now > window_ms { now - window_ms } else { 0 };
        
        let count_in_window = self.access_timestamps.iter()
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
#[derive(Debug, Clone)]
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
}

impl Default for MetricsCollectorConfig {
    fn default() -> Self {
        Self {
            collection_interval_ms: 5000,
            max_key_metrics: 1000,
            max_node_metrics: 1000,
            snapshot_interval_ms: 60000,
            max_snapshots: 60, // One hour of snapshots at 1min interval
            enable_detailed_metrics: true,
        }
    }
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
pub struct MetricsCollector {
    /// Node ID
    node_id: String,
    
    /// Collection start time
    start_time: Instant,
    
    /// Configuration
    config: MetricsCollectorConfig,
    
    /// Operation metrics
    operation_metrics: DashMap<OperationType, OperationMetrics>,
    
    /// Node metrics
    node_metrics: DashMap<String, NodeMetrics>,
    
    /// Key metrics
    key_metrics: DashMap<String, KeyMetrics>,
    
    /// Network metrics
    network_metrics: RwLock<NetworkMetrics>,
    
    /// Storage metrics
    storage_metrics: RwLock<StorageMetrics>,
    
    /// Epidemic metrics
    epidemic_metrics: RwLock<EpidemicMetrics>,
    
    /// Region metrics
    region_metrics: DashMap<String, RegionMetrics>,
    
    /// Snapshots
    snapshots: RwLock<VecDeque<MetricsSnapshot>>,
    
    /// Total messages sent counter
    total_messages_sent: AtomicU64,
    
    /// Total messages received counter
    total_messages_received: AtomicU64,
    
    /// Total bytes sent counter
    total_bytes_sent: AtomicU64,
    
    /// Total bytes received counter
    total_bytes_received: AtomicU64,
    
    /// Current gossip fanout
    current_gossip_fanout: AtomicU64,
    
    /// Current entries per gossip
    current_entries_per_gossip: AtomicU64,
    
    /// Gossip round counter
    gossip_rounds: AtomicU64,
    
    /// Anti-entropy round counter
    anti_entropy_rounds: AtomicU64,
}

/// Record context for operation metrics
pub struct OperationContext {
    /// Collector reference
    collector: Arc<MetricsCollector>,
    
    /// Operation type
    operation_type: OperationType,
    
    /// Start time
    start_time: Instant,
    
    /// Node ID (optional)
    node_id: Option<String>,
    
    /// Key ID (optional)
    key_id: Option<String>,
    
    /// Data size (optional)
    data_size: Option<u64>,
    
    /// Is read operation
    is_read: bool,
    
    /// Is write operation
    is_write: bool,
}

impl OperationContext {
    /// Create a new operation context
    pub fn new(
        collector: Arc<MetricsCollector>,
        operation_type: OperationType,
    ) -> Self {
        Self {
            collector,
            operation_type,
            start_time: Instant::now(),
            node_id: None,
            key_id: None,
            data_size: None,
            is_read: operation_type == OperationType::Retrieve || operation_type == OperationType::Exists,
            is_write: operation_type == OperationType::Store,
        }
    }
    
    /// Set node ID
    pub fn with_node_id(mut self, node_id: String) -> Self {
        self.node_id = Some(node_id);
        self
    }
    
    /// Set key ID
    pub fn with_key_id(mut self, key_id: String) -> Self {
        self.key_id = Some(key_id);
        self
    }
    
    /// Set data size
    pub fn with_data_size(mut self, data_size: u64) -> Self {
        self.data_size = Some(data_size);
        self
    }
    
    /// Complete the operation with the given outcome
    pub fn complete(self, outcome: OperationOutcome) {
        let latency_us = self.start_time.elapsed().as_micros() as u64;
        
        // Record operation metrics
        self.collector.record_operation(
            self.operation_type,
            outcome,
            latency_us,
            self.data_size,
        );
        
        // Record node metrics if applicable
        if let Some(node_id) = self.node_id {
            self.collector.record_node_operation(
                &node_id,
                self.operation_type,
                outcome,
                latency_us,
            );
        }
        
        // Record key metrics if applicable
        if let Some(key_id) = self.key_id {
            if self.is_read {
                self.collector.record_key_read(&key_id);
            } else if self.is_write {
                self.collector.record_key_write(&key_id);
            }
        }
    }
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(node_id: String, config: MetricsCollectorConfig) -> Self {
        let collector = Self {
            node_id,
            start_time: Instant::now(),
            config: config.clone(),
            operation_metrics: DashMap::new(),
            node_metrics: DashMap::new(),
            key_metrics: DashMap::new(),
            network_metrics: RwLock::new(NetworkMetrics {
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
            }),
            storage_metrics: RwLock::new(StorageMetrics {
                total_entries: 0,
                total_bytes: 0,
                avg_entry_size: 0,
                replicated_entries: 0,
                avg_replication_factor: 1.0,
                max_replication_factor: 1,
                min_replication_factor: 1,
                conflict_rate: 0.0,
                read_repair_rate: 0.0,
                space_amplification: 1.0,
            }),
            epidemic_metrics: RwLock::new(EpidemicMetrics {
                gossip_rounds: 0,
                anti_entropy_rounds: 0,
                avg_gossip_fanout: 0.0,
                avg_entries_per_gossip: 0.0,
                avg_anti_entropy_time_ms: 0,
                avg_convergence_time_ms: 0,
                total_updates_propagated: 0,
                total_conflicts_resolved: 0,
                failed_propagations: 0,
            }),
            region_metrics: DashMap::new(),
            snapshots: RwLock::new(VecDeque::with_capacity(config.max_snapshots)),
            total_messages_sent: AtomicU64::new(0),
            total_messages_received: AtomicU64::new(0),
            total_bytes_sent: AtomicU64::new(0),
            total_bytes_received: AtomicU64::new(0),
            current_gossip_fanout: AtomicU64::new(0),
            current_entries_per_gossip: AtomicU64::new(0),
            gossip_rounds: AtomicU64::new(0),
            anti_entropy_rounds: AtomicU64::new(0),
        };
        
        // Initialize operation metrics for all operation types
        collector.operation_metrics.insert(OperationType::Store, OperationMetrics::new(OperationType::Store));
        collector.operation_metrics.insert(OperationType::Retrieve, OperationMetrics::new(OperationType::Retrieve));
        collector.operation_metrics.insert(OperationType::Delete, OperationMetrics::new(OperationType::Delete));
        collector.operation_metrics.insert(OperationType::Exists, OperationMetrics::new(OperationType::Exists));
        collector.operation_metrics.insert(OperationType::List, OperationMetrics::new(OperationType::List));
        collector.operation_metrics.insert(OperationType::GossipSend, OperationMetrics::new(OperationType::GossipSend));
        collector.operation_metrics.insert(OperationType::GossipReceive, OperationMetrics::new(OperationType::GossipReceive));
        collector.operation_metrics.insert(OperationType::AntiEntropy, OperationMetrics::new(OperationType::AntiEntropy));
        collector.operation_metrics.insert(OperationType::TopologyUpdate, OperationMetrics::new(OperationType::TopologyUpdate));
        collector.operation_metrics.insert(OperationType::HealthCheckPing, OperationMetrics::new(OperationType::HealthCheckPing));
        collector.operation_metrics.insert(OperationType::HealthCheckPong, OperationMetrics::new(OperationType::HealthCheckPong));
        
        collector
    }
    
    /// Start the metrics collector
    pub fn start(self: &Arc<Self>) {
        let collector = self.clone();
        
        tokio::spawn(async move {
            info!("Starting metrics collector");
            
            let mut collection_interval = tokio::time::interval(
                Duration::from_millis(collector.config.collection_interval_ms)
            );
            
            let mut snapshot_interval = tokio::time::interval(
                Duration::from_millis(collector.config.snapshot_interval_ms)
            );
            
            loop {
                tokio::select! {
                    _ = collection_interval.tick() => {
                        collector.update_metrics();
                    }
                    
                    _ = snapshot_interval.tick() => {
                        collector.take_snapshot();
                    }
                }
            }
        });
    }
    
    /// Update metrics
    fn update_metrics(&self) {
        // Update network metrics
        {
            let mut network_metrics = self.network_metrics.write();
            network_metrics.total_messages_sent = self.total_messages_sent.load(Ordering::Relaxed);
            network_metrics.total_messages_received = self.total_messages_received.load(Ordering::Relaxed);
            network_metrics.total_bytes_sent = self.total_bytes_sent.load(Ordering::Relaxed);
            network_metrics.total_bytes_received = self.total_bytes_received.load(Ordering::Relaxed);
        }
        
        // Update epidemic metrics
        {
            let mut epidemic_metrics = self.epidemic_metrics.write();
            epidemic_metrics.gossip_rounds = self.gossip_rounds.load(Ordering::Relaxed);
            epidemic_metrics.anti_entropy_rounds = self.anti_entropy_rounds.load(Ordering::Relaxed);
            
            let gossip_fanout = self.current_gossip_fanout.load(Ordering::Relaxed);
            let entries_per_gossip = self.current_entries_per_gossip.load(Ordering::Relaxed);
            
            // Update running averages
            if epidemic_metrics.gossip_rounds > 0 {
                epidemic_metrics.avg_gossip_fanout = (epidemic_metrics.avg_gossip_fanout * 0.95) + 
                    (gossip_fanout as f64 * 0.05);
                epidemic_metrics.avg_entries_per_gossip = (epidemic_metrics.avg_entries_per_gossip * 0.95) + 
                    (entries_per_gossip as f64 * 0.05);
            } else {
                epidemic_metrics.avg_gossip_fanout = gossip_fanout as f64;
                epidemic_metrics.avg_entries_per_gossip = entries_per_gossip as f64;
            }
        }
        
        // Perform garbage collection of key metrics if needed
        if self.key_metrics.len() > self.config.max_key_metrics {
            self.prune_key_metrics();
        }
        
        // Perform garbage collection of node metrics if needed
        if self.node_metrics.len() > self.config.max_node_metrics {
            self.prune_node_metrics();
        }
    }
    
    /// Prune key metrics
    fn prune_key_metrics(&self) {
        // Strategy: Keep most recently accessed keys
        let mut metrics_with_timestamps: Vec<(String, u64)> = self.key_metrics
            .iter()
            .map(|entry| {
                let key = entry.key().clone();
                let last_access = std::cmp::max(entry.value().last_read, entry.value().last_write);
                (key, last_access)
            })
            .collect();
        
        // Sort by timestamp (descending)
        metrics_with_timestamps.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Keep only the most recent ones
        let to_keep = self.config.max_key_metrics / 2; // Keep half to avoid frequent pruning
        let to_remove = metrics_with_timestamps.into_iter().skip(to_keep).map(|(k, _)| k).collect::<Vec<_>>();
        
        // Remove the oldest
        for key in to_remove {
            self.key_metrics.remove(&key);
        }
    }
    
    /// Prune node metrics
    fn prune_node_metrics(&self) {
        // Strategy: Keep most recently updated node metrics
        let mut metrics_with_timestamps: Vec<(String, u64)> = self.node_metrics
            .iter()
            .map(|entry| {
                (entry.key().clone(), entry.value().last_updated)
            })
            .collect();
        
        // Sort by timestamp (descending)
        metrics_with_timestamps.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Keep only the most recent ones
        let to_keep = self.config.max_node_metrics / 2; // Keep half to avoid frequent pruning
        let to_remove = metrics_with_timestamps.into_iter().skip(to_keep).map(|(k, _)| k).collect::<Vec<_>>();
        
        // Remove the oldest
        for key in to_remove {
            self.node_metrics.remove(&key);
        }
    }
    
    /// Take a snapshot of metrics
    fn take_snapshot(&self) {
        debug!("Taking metrics snapshot");
        
        // Create the snapshot
        let snapshot = MetricsSnapshot {
            timestamp: current_timestamp_millis(),
            operation_metrics: self.operation_metrics.iter()
                .map(|entry| (*entry.key(), entry.value().clone()))
                .collect(),
            network_metrics: self.network_metrics.read().clone(),
            storage_metrics: self.storage_metrics.read().clone(),
            epidemic_metrics: self.epidemic_metrics.read().clone(),
            region_metrics: self.region_metrics.iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
            top_node_metrics: self.get_top_node_metrics(10),
            top_key_metrics: self.get_top_key_metrics(10),
        };
        
        // Add to snapshots
        let mut snapshots = self.snapshots.write();
        snapshots.push_back(snapshot);
        
        // Prune if needed
        while snapshots.len() > self.config.max_snapshots {
            snapshots.pop_front();
        }
    }
    
    /// Get top node metrics
    fn get_top_node_metrics(&self, count: usize) -> Vec<NodeMetrics> {
        let mut metrics: Vec<NodeMetrics> = self.node_metrics
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        // Sort by total operations (descending)
        metrics.sort_by(|a, b| b.total_operations.cmp(&a.total_operations));
        
        // Take top N
        metrics.truncate(count);
        metrics
    }
    
    /// Get top key metrics
    fn get_top_key_metrics(&self, count: usize) -> Vec<KeyMetrics> {
        let mut metrics: Vec<KeyMetrics> = self.key_metrics
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        // Sort by total operations (descending)
        metrics.sort_by(|a, b| b.total_operations.cmp(&a.total_operations));
        
        // Take top N
        metrics.truncate(count);
        metrics
    }
    
    /// Record an operation
    pub fn record_operation(
        &self,
        operation_type: OperationType,
        outcome: OperationOutcome,
        latency_us: u64,
        data_size: Option<u64>,
    ) {
        // Get or create operation metrics
        let mut metrics = self.operation_metrics.entry(operation_type)
            .or_insert_with(|| OperationMetrics::new(operation_type));
            
        // Record the operation
        metrics.record_operation(outcome, latency_us, data_size);
    }
    
    /// Record a node operation
    pub fn record_node_operation(
        &self,
        node_id: &str,
        operation_type: OperationType,
        outcome: OperationOutcome,
        latency_us: u64,
    ) {
        let _ = operation_type;
        // Get or create node metrics
        let mut entry = self.node_metrics.entry(node_id.to_string())
            .or_insert_with(|| NodeMetrics {
                node_id: node_id.to_string(),
                status: NodeStatus::Unknown,
                total_operations: 0,
                success_operations: 0,
                failure_operations: 0,
                average_latency_us: 0.0,
                recent_average_latency_us: 0.0,
                last_updated: current_timestamp_millis(),
            });
            
        // Update metrics
        entry.total_operations += 1;
        
        match outcome {
            OperationOutcome::Success => entry.success_operations += 1,
            OperationOutcome::Failure => entry.failure_operations += 1,
            OperationOutcome::Timeout => entry.failure_operations += 1,
            OperationOutcome::PartialSuccess => {
                entry.success_operations += 1;
                entry.failure_operations += 1;
            }
        }
        
        // Update latencies
        entry.recent_average_latency_us = (entry.recent_average_latency_us * 0.9) + (latency_us as f64 * 0.1);
        
        // Update average latency with more weight on history
        if entry.average_latency_us == 0.0 {
            entry.average_latency_us = latency_us as f64;
        } else {
            entry.average_latency_us = (entry.average_latency_us * 0.99) + (latency_us as f64 * 0.01);
        }
        
        // Update timestamp
        entry.last_updated = current_timestamp_millis();
    }
    
    /// Record a key read
    pub fn record_key_read(&self, key_id: &str) {
        if !self.config.enable_detailed_metrics {
            return;
        }
        
        let mut entry = self.key_metrics.entry(key_id.to_string())
            .or_insert_with(|| KeyMetrics::new(key_id.to_string()));
            
        entry.record_read();
    }
    
    /// Record a key write
    pub fn record_key_write(&self, key_id: &str) {
        if !self.config.enable_detailed_metrics {
            return;
        }
        
        let mut entry = self.key_metrics.entry(key_id.to_string())
            .or_insert_with(|| KeyMetrics::new(key_id.to_string()));
            
        entry.record_write();
    }
    
    /// Update key replication and verification counts
    pub fn update_key_counts(&self, key_id: &str, replication_count: u32, verification_count: u32) {
        if !self.config.enable_detailed_metrics {
            return;
        }
        
        let mut entry = self.key_metrics.entry(key_id.to_string())
            .or_insert_with(|| KeyMetrics::new(key_id.to_string()));
            
        entry.update_counts(replication_count, verification_count);
    }
    
    /// Record a message sent
    pub fn record_message_sent(&self, message_type: &str, size_bytes: u64) {
        self.total_messages_sent.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_sent.fetch_add(size_bytes, Ordering::Relaxed);
        
        let mut network_metrics = self.network_metrics.write();
        *network_metrics.message_types_sent.entry(message_type.to_string()).or_insert(0) += 1;
    }
    
    /// Record a message received
    pub fn record_message_received(&self, message_type: &str, size_bytes: u64) {
        self.total_messages_received.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_received.fetch_add(size_bytes, Ordering::Relaxed);
        
        let mut network_metrics = self.network_metrics.write();
        *network_metrics.message_types_received.entry(message_type.to_string()).or_insert(0) += 1;
    }
    
    /// Record a gossip round
    pub fn record_gossip_round(&self, fanout: u64, entries: u64) {
        self.gossip_rounds.fetch_add(1, Ordering::Relaxed);
        self.current_gossip_fanout.store(fanout, Ordering::Relaxed);
        self.current_entries_per_gossip.store(entries, Ordering::Relaxed);
    }
    
    /// Record an anti-entropy round
    pub fn record_anti_entropy_round(&self, duration_ms: u64) {
        self.anti_entropy_rounds.fetch_add(1, Ordering::Relaxed);
        
        let mut epidemic_metrics = self.epidemic_metrics.write();
        
        // Update running average of anti-entropy time
        if epidemic_metrics.anti_entropy_rounds > 0 {
            epidemic_metrics.avg_anti_entropy_time_ms = 
                (epidemic_metrics.avg_anti_entropy_time_ms * 9 + duration_ms) / 10;
        } else {
            epidemic_metrics.avg_anti_entropy_time_ms = duration_ms;
        }
    }
    
    /// Record a conflict resolution
    pub fn record_conflict_resolution(&self) {
        let mut epidemic_metrics = self.epidemic_metrics.write();
        epidemic_metrics.total_conflicts_resolved += 1;
    }
    
    /// Record a propagation
    pub fn record_propagation(&self, success: bool) {
        let mut epidemic_metrics = self.epidemic_metrics.write();
        epidemic_metrics.total_updates_propagated += 1;
        
        if !success {
            epidemic_metrics.failed_propagations += 1;
        }
    }
    
    /// Record convergence time
    pub fn record_convergence_time(&self, time_ms: u64) {
        let mut epidemic_metrics = self.epidemic_metrics.write();
        
        // Update running average of convergence time
        if epidemic_metrics.total_updates_propagated > 0 {
            epidemic_metrics.avg_convergence_time_ms = 
                (epidemic_metrics.avg_convergence_time_ms * 9 + time_ms) / 10;
        } else {
            epidemic_metrics.avg_convergence_time_ms = time_ms;
        }
    }
    
    /// Update network topology metrics
    pub fn update_network_topology(
        &self,
        total_nodes: usize,
        connected_nodes: usize,
        diameter_estimate: u32,
        avg_coordination_number: f64,
    ) {
        let mut network_metrics = self.network_metrics.write();
        network_metrics.total_nodes = total_nodes;
        network_metrics.connected_nodes = connected_nodes;
        network_metrics.disconnected_nodes = total_nodes - connected_nodes;
        network_metrics.diameter_estimate = diameter_estimate;
        network_metrics.avg_coordination_number = avg_coordination_number;
        
        // Calculate connectivity (nodes/max possible connections)
        if total_nodes > 1 {
            let max_connections = (total_nodes * (total_nodes - 1)) / 2;
            let estimated_connections = connected_nodes * avg_coordination_number as usize / 2;
            network_metrics.connectivity = estimated_connections as f64 / max_connections as f64;
        } else {
            network_metrics.connectivity = 0.0;
        }
    }
    
    /// Update storage statistics
    pub fn update_storage_stats(
        &self,
        total_entries: u64,
        total_bytes: u64,
        replicated_entries: u64,
        avg_replication_factor: f64,
        max_replication_factor: u32,
        min_replication_factor: u32,
    ) {
        let mut storage_metrics = self.storage_metrics.write();
        storage_metrics.total_entries = total_entries;
        storage_metrics.total_bytes = total_bytes;
        storage_metrics.replicated_entries = replicated_entries;
        storage_metrics.avg_replication_factor = avg_replication_factor;
        storage_metrics.max_replication_factor = max_replication_factor;
        storage_metrics.min_replication_factor = min_replication_factor;
        
        // Calculate derived metrics
        if total_entries > 0 {
            storage_metrics.avg_entry_size = total_bytes / total_entries;
            storage_metrics.space_amplification = avg_replication_factor;
        }
    }
    
    /// Update conflict and read repair rates
    pub fn update_repair_rates(&self, conflict_rate: f64, read_repair_rate: f64) {
        let mut storage_metrics = self.storage_metrics.write();
        storage_metrics.conflict_rate = conflict_rate;
        storage_metrics.read_repair_rate = read_repair_rate;
    }
    
    /// Update region metrics
    pub fn update_region_metrics(
        &self,
        region: &str,
        node_count: usize,
        online_node_count: usize,
        total_entries: u64,
        total_storage_bytes: u64,
    ) {
        let mut entry = self.region_metrics.entry(region.to_string())
            .or_insert_with(|| RegionMetrics {
                region: region.to_string(),
                node_count: 0,
                online_node_count: 0,
                total_entries: 0,
                total_storage_bytes: 0,
                avg_propagation_time_ms: HashMap::new(),
                cross_region_read_latency: LatencyHistogram::new(),
                internal_region_read_latency: LatencyHistogram::new(),
            });
            
        entry.node_count = node_count;
        entry.online_node_count = online_node_count;
        entry.total_entries = total_entries;
        entry.total_storage_bytes = total_storage_bytes;
    }
    
    /// Record cross-region propagation time
    pub fn record_cross_region_propagation(&self, from_region: &str, to_region: &str, time_ms: u64) {
        if from_region == to_region {
            return; // Skip same-region propagation
        }
        
        let mut entry = self.region_metrics.entry(from_region.to_string())
            .or_insert_with(|| RegionMetrics {
                region: from_region.to_string(),
                node_count: 0,
                online_node_count: 0,
                total_entries: 0,
                total_storage_bytes: 0,
                avg_propagation_time_ms: HashMap::new(),
                cross_region_read_latency: LatencyHistogram::new(),
                internal_region_read_latency: LatencyHistogram::new(),
            });
            
        // Update running average for this region pair
        let avg_time = entry.avg_propagation_time_ms.entry(to_region.to_string()).or_insert(time_ms);
        *avg_time = (*avg_time * 9 + time_ms) / 10; // Exponential moving average
    }
    
    /// Record cross-region read latency
    pub fn record_cross_region_read_latency(&self, region: &str, latency_us: u64) {
        let mut entry = self.region_metrics.entry(region.to_string())
            .or_insert_with(|| RegionMetrics {
                region: region.to_string(),
                node_count: 0,
                online_node_count: 0,
                total_entries: 0,
                total_storage_bytes: 0,
                avg_propagation_time_ms: HashMap::new(),
                cross_region_read_latency: LatencyHistogram::new(),
                internal_region_read_latency: LatencyHistogram::new(),
            });
            
        entry.cross_region_read_latency.add_latency(latency_us);
    }
    
    /// Record internal region read latency
    pub fn record_internal_region_read_latency(&self, region: &str, latency_us: u64) {
        let mut entry = self.region_metrics.entry(region.to_string())
            .or_insert_with(|| RegionMetrics {
                region: region.to_string(),
                node_count: 0,
                online_node_count: 0,
                total_entries: 0,
                total_storage_bytes: 0,
                avg_propagation_time_ms: HashMap::new(),
                cross_region_read_latency: LatencyHistogram::new(),
                internal_region_read_latency: LatencyHistogram::new(),
            });
            
        entry.internal_region_read_latency.add_latency(latency_us);
    }
    
    /// Create a new operation context
    pub fn create_operation_context(
        self: &Arc<Self>,
        operation_type: OperationType,
    ) -> OperationContext {
        OperationContext::new(self.clone(), operation_type)
    }
    
    /// Get the latest snapshot
    pub fn get_latest_snapshot(&self) -> Option<MetricsSnapshot> {
        let snapshots = self.snapshots.read();
        snapshots.back().cloned()
    }
    
    /// Get all snapshots
    pub fn get_all_snapshots(&self) -> Vec<MetricsSnapshot> {
        let snapshots = self.snapshots.read();
        snapshots.iter().cloned().collect()
    }
    
    /// Get snapshots in time range
    pub fn get_snapshots_in_range(&self, start_time: u64, end_time: u64) -> Vec<MetricsSnapshot> {
        let snapshots = self.snapshots.read();
        snapshots
            .iter()
            .filter(|s| s.timestamp >= start_time && s.timestamp <= end_time)
            .cloned()
            .collect()
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp_millis() -> u64 {
    use std::time::SystemTime;
    
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_latency_histogram() {
        let mut histogram = LatencyHistogram::new();
        
        // Test initial state
        assert_eq!(histogram.total_count, 0);
        assert_eq!(histogram.min_latency_us, u64::MAX);
        assert_eq!(histogram.max_latency_us, 0);
        
        // Add some latencies
        histogram.add_latency(100);
        histogram.add_latency(500);
        histogram.add_latency(5000);
        
        // Check counts
        assert_eq!(histogram.total_count, 3);
        assert_eq!(histogram.min_latency_us, 100);
        assert_eq!(histogram.max_latency_us, 5000);
        
        // Check average
        assert_eq!(histogram.average_latency_us(), (100 + 500 + 5000) as f64 / 3.0);
        
        // Check buckets
        assert_eq!(histogram.buckets[0].count, 1); // 0-100us bucket
        assert_eq!(histogram.buckets[1].count, 1); // 100us-1ms bucket
        assert_eq!(histogram.buckets[2].count, 1); // 1ms-10ms bucket
    }
    
    #[test]
    fn test_operation_metrics() {
        let mut metrics = OperationMetrics::new(OperationType::Store);
        
        // Test initial state
        assert_eq!(metrics.total_count, 0);
        assert_eq!(metrics.success_count, 0);
        assert_eq!(metrics.failure_count, 0);
        
        // Record an operation
        metrics.record_operation(OperationOutcome::Success, 100, Some(1024));
        
        // Check counts
        assert_eq!(metrics.total_count, 1);
        assert_eq!(metrics.success_count, 1);
        assert_eq!(metrics.failure_count, 0);
        assert_eq!(metrics.total_data_size, 1024);
        
        // Record a failure
        metrics.record_operation(OperationOutcome::Failure, 200, Some(512));
        
        // Check counts
        assert_eq!(metrics.total_count, 2);
        assert_eq!(metrics.success_count, 1);
        assert_eq!(metrics.failure_count, 1);
        assert_eq!(metrics.total_data_size, 1536);
        
        // Check success rate
        assert_eq!(metrics.success_rate(), 0.5);
    }
    
    #[test]
    fn test_metrics_collector() {
        let config = MetricsCollectorConfig {
            collection_interval_ms: 1000,
            max_key_metrics: 100,
            max_node_metrics: 100,
            snapshot_interval_ms: 5000,
            max_snapshots: 10,
            enable_detailed_metrics: true,
        };
        
        let collector = MetricsCollector::new("test-node".to_string(), config);
        
        // Record operations
        collector.record_operation(OperationType::Store, OperationOutcome::Success, 100, Some(1024));
        collector.record_operation(OperationType::Retrieve, OperationOutcome::Success, 50, None);
        
        // Check operation metrics
        let store_metrics = collector.operation_metrics.get(&OperationType::Store).unwrap();
        assert_eq!(store_metrics.total_count, 1);
        assert_eq!(store_metrics.success_count, 1);
        
        let retrieve_metrics = collector.operation_metrics.get(&OperationType::Retrieve).unwrap();
        assert_eq!(retrieve_metrics.total_count, 1);
        assert_eq!(retrieve_metrics.success_count, 1);
        
        // Record node operation
        collector.record_node_operation("node1", OperationType::Store, OperationOutcome::Success, 100);
        
        // Check node metrics
        let node_metrics = collector.node_metrics.get("node1").unwrap();
        assert_eq!(node_metrics.total_operations, 1);
        assert_eq!(node_metrics.success_operations, 1);
        
        // Record key operations
        collector.record_key_read("key1");
        collector.record_key_write("key1");
        
        // Check key metrics
        let key_metrics = collector.key_metrics.get("key1").unwrap();
        assert_eq!(key_metrics.total_operations, 2);
        assert_eq!(key_metrics.read_operations, 1);
        assert_eq!(key_metrics.write_operations, 1);
    }
}
