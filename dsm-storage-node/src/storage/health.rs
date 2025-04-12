// Health monitoring module for epidemic storage
//
// This module provides comprehensive health monitoring for the epidemic storage system,
// including node status tracking, network latency measurement, failure detection,
// and adaptive behavior based on network conditions.

use crate::error::Result;
use crate::storage::small_world::SmallWorldTopology;
use crate::types::{StorageNode, NodeStatus};

use tokio::sync::RwLock;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Sender, Receiver};
use tokio::time::interval;
use tracing::{debug, error, info};

/// Failure detector algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureDetectorAlgorithm {
    /// Simple timeout-based detector
    Timeout,
    
    /// Phi-accrual failure detector
    PhiAccrual,
    
    /// Adaptive failure detector
    Adaptive,
}

/// Health check message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckMessage {
    /// Ping request
    Ping {
        /// Sender node ID
        sender: String,
        
        /// Timestamp
        timestamp: u64,
        
        /// Sequence number
        sequence: u64,
    },
    
    /// Pong response
    Pong {
        /// Sender node ID
        sender: String,
        
        /// Responder node ID
        responder: String,
        
        /// Original timestamp
        request_timestamp: u64,
        
        /// Response timestamp
        response_timestamp: u64,
        
        /// Sequence number
        sequence: u64,
    },
    
    /// Status report
    StatusReport {
        /// Sender node ID
        sender: String,
        
        /// Node status
        status: NodeStatus,
        
        /// System load (0.0 - 1.0)
        system_load: f32,
        
        /// Memory usage (0.0 - 1.0)
        memory_usage: f32,
        
        /// Storage usage (0.0 - 1.0)
        storage_usage: f32,
        
        /// Uptime in seconds
        uptime: u64,
        
        /// Timestamp
        timestamp: u64,
    },
}

/// Node health information
#[derive(Debug, Clone)]
pub struct NodeHealth {
    /// Node information
    pub node: StorageNode,
    
    /// Node status
    pub status: NodeStatus,
    
    /// Last seen timestamp
    pub last_seen: Instant,
    
    /// Failure detector value (phi for phi-accrual)
    pub failure_value: f64,
    
    /// Recent ping history (RTT in milliseconds)
    pub ping_history: VecDeque<u64>,
    
    /// Average ping RTT in milliseconds
    pub avg_ping_rtt: u64,
    
    /// System load (0.0 - 1.0)
    pub system_load: f32,
    
    /// Memory usage (0.0 - 1.0)
    pub memory_usage: f32,
    
    /// Storage usage (0.0 - 1.0)
    pub storage_usage: f32,
    
    /// Success count
    pub success_count: u64,
    
    /// Failure count
    pub failure_count: u64,
    
    /// Pending pings
    pub pending_pings: HashMap<u64, Instant>,
}

impl NodeHealth {
    /// Create a new node health information
    pub fn new(node: StorageNode) -> Self {
        Self {
            node,
            status: NodeStatus::Unknown,
            last_seen: Instant::now(),
            failure_value: 0.0,
            ping_history: VecDeque::with_capacity(20),
            avg_ping_rtt: 0,
            system_load: 0.0,
            memory_usage: 0.0,
            storage_usage: 0.0,
            success_count: 0,
            failure_count: 0,
            pending_pings: HashMap::new(),
        }
    }
    
    /// Add a ping RTT measurement
    pub fn add_ping_rtt(&mut self, rtt_ms: u64) {
        // Add to history
        self.ping_history.push_back(rtt_ms);
        
        // Keep history at most 20 entries
        while self.ping_history.len() > 20 {
            self.ping_history.pop_front();
        }
        
        // Update average
        if !self.ping_history.is_empty() {
            self.avg_ping_rtt = self.ping_history.iter().sum::<u64>() / self.ping_history.len() as u64;
        }
        
        // Update last seen
        self.last_seen = Instant::now();
        
        // Update status
        self.status = NodeStatus::Online;
        
        // Record success
        self.success_count += 1;
    }
    
    /// Record a ping timeout
    pub fn record_timeout(&mut self) {
        // Update failure count
        self.failure_count += 1;
        
        // Update status if too many failures
        if self.failure_count > 3 && self.last_seen.elapsed() > Duration::from_secs(30) {
            self.status = NodeStatus::Offline;
        }
    }
    
    /// Calculate phi value for phi-accrual failure detector
    pub fn calculate_phi(&mut self) -> f64 {
        if self.ping_history.is_empty() {
            return 0.0;
        }
        
        // Calculate mean and variance
        let mean = self.avg_ping_rtt as f64;
        let variance = self.ping_history
            .iter()
            .map(|&rtt| {
                let diff = rtt as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / self.ping_history.len() as f64;
        
        let std_dev = variance.sqrt();
        
        // Calculate time since last seen
        let time_since_last_seen = self.last_seen.elapsed().as_millis() as f64;
        
        // Calculate phi value
        if std_dev > 0.0 {
            let y = (time_since_last_seen - mean) / std_dev;
            let phi = -1.0 * (1.0 - cdf(y)).ln();
            self.failure_value = phi;
            phi
        } else if time_since_last_seen > mean * 3.0 {
            self.failure_value = 10.0; // High value indicating likely failure
            10.0
        } else {
            self.failure_value = 0.0;
            0.0
        }
    }
    
    /// Check if node is suspected failed
    pub fn is_suspected_failed(&self, algorithm: FailureDetectorAlgorithm, threshold: f64) -> bool {
        match algorithm {
            FailureDetectorAlgorithm::Timeout => {
                self.last_seen.elapsed() > Duration::from_secs(30) && self.failure_count > 3
            }
            FailureDetectorAlgorithm::PhiAccrual => {
                self.failure_value > threshold
            }
            FailureDetectorAlgorithm::Adaptive => {
                // Adaptive threshold based on network conditions
                let base_threshold = threshold;
                let failure_ratio = if self.success_count + self.failure_count > 0 {
                    self.failure_count as f64 / (self.success_count + self.failure_count) as f64
                } else {
                    0.0
                };
                
                // Lower threshold (more sensitive) for nodes with high failure ratio
                let adjusted_threshold = base_threshold * (1.0 - failure_ratio * 0.5);
                
                self.failure_value > adjusted_threshold
            }
        }
    }
    
    /// Update from status report
    pub fn update_from_status_report(
        &mut self,
        status: NodeStatus,
        system_load: f32,
        memory_usage: f32,
        storage_usage: f32,
    ) {
        self.status = status;
        self.system_load = system_load;
        self.memory_usage = memory_usage;
        self.storage_usage = storage_usage;
        self.last_seen = Instant::now();
    }
}

/// Standard normal cumulative distribution function
fn cdf(x: f64) -> f64 {
    (1.0 + erf(x / 1.414_213_6)) / 2.0
}

/// Error function approximation
fn erf(x: f64) -> f64 {
    // Constants
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;
    
    // Save the sign of x
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    
    // A&S formula 7.1.26
    let t = 1.0 / (1.0 + p * x);
    let y = ((((a5 * t + a4) * t + a3) * t + a2) * t + a1) * t;
    
    sign * (1.0 - y * (-x * x).exp())
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Ping interval in milliseconds
    pub ping_interval_ms: u64,
    
    /// Ping timeout in milliseconds
    pub ping_timeout_ms: u64,
    
    /// Status report interval in milliseconds
    pub status_report_interval_ms: u64,
    
    /// Failure detector algorithm
    pub failure_detector: FailureDetectorAlgorithm,
    
    /// Phi threshold for phi-accrual failure detector
    pub phi_threshold: f64,
    
    /// Maximum concurrent pings
    pub max_concurrent_pings: usize,
    
    /// Health check batch size
    pub health_check_batch_size: usize,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            ping_interval_ms: 5000,
            ping_timeout_ms: 2000,
            status_report_interval_ms: 30000,
            failure_detector: FailureDetectorAlgorithm::PhiAccrual,
            phi_threshold: 8.0,
            max_concurrent_pings: 10,
            health_check_batch_size: 5,
        }
    }
}

/// Health monitor for epidemic storage
pub struct HealthMonitor {
    /// Node ID
    node_id: String,
    
    /// Health information for all known nodes
    node_health: Arc<RwLock<HashMap<String, NodeHealth>>>,
    
    /// Small-world topology
    topology: Arc<RwLock<SmallWorldTopology>>,
    
    /// Health check configuration
    config: HealthCheckConfig,
    
    /// Health check message sender
    message_tx: Sender<(StorageNode, HealthCheckMessage)>,
    
    /// Current sequence number for ping messages
    sequence: Arc<RwLock<u64>>,
    
    /// System start time
    start_time: Instant,
}

impl HealthMonitor {
    /// Create a new health monitor
    pub fn new(
        node_id: String,
        topology: Arc<RwLock<SmallWorldTopology>>,
        config: HealthCheckConfig,
    ) -> (Self, Receiver<(StorageNode, HealthCheckMessage)>) {
        let (message_tx, message_rx) = tokio::sync::mpsc::channel(100);
        
        let monitor = Self {
            node_id,
            node_health: Arc::new(RwLock::new(HashMap::new())),
            topology,
            config,
            message_tx,
            sequence: Arc::new(RwLock::new(0)),
            start_time: Instant::now(),
        };
        
        (monitor, message_rx)
    }
    
    /// Start the health monitor
    pub async fn start(&self) -> Result<()> {
        // Start the ping task
        self.start_ping_task();
        
        // Start the status report task
        // self.start_status_report_task();
        
        Ok(())
    }
    
    /// Start the ping task
    pub fn start_ping_task(&self) {
        let node_id = self.node_id.clone();
        let node_health = self.node_health.clone();
        let topology = self.topology.clone();
        let config = self.config.clone();
        let message_tx = self.message_tx.clone();
        let sequence = self.sequence.clone();
        
        tokio::spawn(async move {
            info!("Starting health check ping task for node: {}", node_id);
            
            let mut ping_interval = interval(Duration::from_millis(config.ping_interval_ms));
            
            loop {
                ping_interval.tick().await;
                
                // Extract all neighbors from topology before passing to the update function
                let all_nodes = {
                    let topology_guard = topology.read().await;
                    topology_guard.all_neighbors().into_iter().collect::<Vec<_>>()
                };
                
                // Update node health with extracted nodes
                Self::update_node_health_from_topology_nodes(&node_id, &node_health, all_nodes).await;
                
                // Select a batch of nodes to ping
                let nodes_to_ping = Self::select_nodes_to_ping(
                    &node_health,
                    config.health_check_batch_size,
                ).await;
                
                if nodes_to_ping.is_empty() {
                    debug!("No nodes to ping");
                    continue;
                }
                
                let current_sequence = {
                    let mut seq = sequence.write().await;
                    *seq += 1;
                    *seq
                };
                
                // Send pings
                for node in nodes_to_ping {
                    let ping_message = HealthCheckMessage::Ping {
                        sender: node_id.clone(),
                        timestamp: Self::current_timestamp_millis(),
                        sequence: current_sequence,
                    };
                    
                    // Record pending ping
                    {
                        let mut health = node_health.write().await;
                        if let Some(entry) = health.get_mut(&node.id) {
                            entry.pending_pings.insert(current_sequence, Instant::now());
                        }
                    }
                    
                    // Send ping - use try_send to avoid awaiting, which fixes the Send bound issue
                    if let Err(e) = message_tx.try_send((node.clone(), ping_message)) {
                        error!("Failed to send ping to {}: {}", node.id, e);
                    }
                }
                
                // Process timeouts
                Self::process_ping_timeouts(
                    &node_health,
                    config.ping_timeout_ms,
                    config.failure_detector,
                    config.phi_threshold,
                ).await;
            }
        });
    }

    /// Update node health with new nodes from the topology
    async fn update_node_health_from_topology_nodes(
        node_id: &str,
        node_health: &Arc<RwLock<HashMap<String, NodeHealth>>>,
        all_nodes: Vec<StorageNode>,
    ) {
        let mut health_map = node_health.write().await;
        for node in all_nodes {
            if !health_map.contains_key(&node.id) && node.id != node_id {
                health_map.insert(node.id.clone(), NodeHealth::new(node));
            }
        }
    }

    /// Start the status report task
    pub fn start_status_report_task(&self) {
        info!("Starting status report task for node: {}", self.node_id);
        tokio::spawn(async move {
            // Implementation for sending periodic status reports
        });
    }
    
    /// Process ping timeouts
    async fn process_ping_timeouts(
        node_health: &Arc<RwLock<HashMap<String, NodeHealth>>>,
        ping_timeout_ms: u64,
        failure_detector: FailureDetectorAlgorithm,
        phi_threshold: f64,
    ) {
        let mut health_map = node_health.write().await;
        for (_node_id, health) in health_map.iter_mut() {
            // Check for timed out pings
            let timeout_duration = Duration::from_millis(ping_timeout_ms);
            let timed_out_sequences: Vec<u64> = health
                .pending_pings
                .iter()
                .filter(|(_seq, time)| time.elapsed() > timeout_duration)
                .map(|(seq, _time)| *seq)
                .collect();
            
            // Remove timed out pings and record timeouts
            for seq in timed_out_sequences {
                health.pending_pings.remove(&seq);
                health.record_timeout();
            }
            
            // Update failure detection based on the algorithm
            if failure_detector == FailureDetectorAlgorithm::PhiAccrual 
               || failure_detector == FailureDetectorAlgorithm::Adaptive {
                health.calculate_phi();
            }
            
            // Check if node is suspected failed
            if health.is_suspected_failed(failure_detector, phi_threshold) {
                health.status = NodeStatus::Offline;
            }
        }
    }
    
    /// Select nodes to ping
    async fn select_nodes_to_ping(
        node_health: &Arc<RwLock<HashMap<String, NodeHealth>>>,
        batch_size: usize,
    ) -> Vec<StorageNode> {
        let health_map = node_health.read().await;
        
        // Filter eligible nodes (not currently being pinged)
        let eligible_nodes: Vec<&NodeHealth> = health_map
            .values()
            .filter(|health| {
                // Exclude nodes that already have pending pings
                health.pending_pings.is_empty() &&
                // Exclude nodes that are known to be offline
                health.status != NodeStatus::Offline
            })
            .collect();
        
        // Randomly select up to batch_size nodes
        let mut rng = rand::thread_rng();
        eligible_nodes
            .choose_multiple(&mut rng, batch_size)
            .map(|health| health.node.clone())
            .collect()
    }
    
    /// Get current timestamp in milliseconds
    fn current_timestamp_millis() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64
    }
    #[cfg(test)]
    fn test_phi_accrual() {
        let node = StorageNode {
            id: "test-node".to_string(),
            name: "Test Node".to_string(),
            region: "test".to_string(),
            public_key: "pk".to_string(),
            endpoint: "http://test.example.com".to_string(),
        };
        
        let mut health = NodeHealth::new(node.clone());
        
        // Add some consistent RTTs
        for _ in 0..10 {
            health.add_ping_rtt(100);
        }
        
        // Phi should be low for normal operation
        let phi1 = health.calculate_phi();
        assert!(phi1 < 1.0);
        
        // Simulate a delay
        std::thread::sleep(Duration::from_millis(300));
        
        // Phi should increase but still relatively low
        let phi2 = health.calculate_phi();
        assert!(phi2 > phi1);
        
        // Simulate a longer delay
        std::thread::sleep(Duration::from_millis(700));
        
        // Phi should increase significantly
        let phi3 = health.calculate_phi();
        assert!(phi3 > phi2);
    }
}
