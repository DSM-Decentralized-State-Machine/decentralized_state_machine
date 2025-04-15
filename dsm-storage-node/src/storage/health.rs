// Health monitoring module for epidemic storage
//
// This module provides comprehensive health monitoring for the epidemic storage system,
// including node status tracking, network latency measurement, failure detection,
// and adaptive behavior based on network conditions.

use crate::error::Result;
use crate::storage::routing::EpidemicRouter; // Added for potential use in status reports
use crate::storage::metrics::MetricsCollector; // Added for potential use in status reports
use crate::storage::topology::HybridTopology;
use crate::types::{StorageNode, NodeStatus};

use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Sender, Receiver};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

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
    
    impl FailureDetectorAlgorithm {
        /// Process ping timeouts and update node health
        pub async fn process_ping_timeouts(
            node_health: &Arc<RwLock<HashMap<String, NodeHealth>>>,
            ping_timeout_ms: u64,
            failure_detector: FailureDetectorAlgorithm,
            phi_threshold: f64,
        ) {
            let mut health_map = node_health.write().await;
            let timeout_duration = Duration::from_millis(ping_timeout_ms);
    
            for health in health_map.values_mut() {
                // Check for pending pings that have timed out
                let timed_out_pings: Vec<u64> = health
                    .pending_pings
                    .iter()
                    .filter(|(_, &instant)| instant.elapsed() > timeout_duration)
                    .map(|(&seq, _)| seq)
                    .collect();
    
                for seq in timed_out_pings {
                    health.pending_pings.remove(&seq);
                    health.record_timeout();
                }
    
                // Update failure status based on the failure detector
                if health.is_suspected_failed(failure_detector, phi_threshold) {
                    health.status = NodeStatus::Offline;
                }
            }
        }
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
            self.avg_ping_rtt =
                self.ping_history.iter().sum::<u64>() / self.ping_history.len() as u64;
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
        let variance = self
            .ping_history
            .iter()
            .map(|&rtt| {
                let diff = rtt as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.ping_history.len() as f64;

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
            FailureDetectorAlgorithm::PhiAccrual => self.failure_value > threshold,
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
    (1.0 + erf(x / std::f64::consts::SQRT_2)) / 2.0
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

    /// Network topology
    topology: Arc<RwLock<HybridTopology>>, // Using HybridTopology implementation

    /// Health check configuration
    config: HealthCheckConfig,

    /// Health check message sender
    message_tx: Sender<(StorageNode, HealthCheckMessage)>,

    /// Current sequence number for ping messages
    sequence: Arc<RwLock<u64>>,

    /// System start time
    start_time: Instant,

    // Added fields for status reporting
    metrics_collector: Option<Arc<MetricsCollector>>, // Optional: Link to metrics
    #[allow(dead_code)]
    router: Option<Arc<EpidemicRouter>>, // Optional: Link to router for network info
}

impl HealthMonitor {
    /// Process timeouts for pending pings and update node status
    pub async fn process_ping_timeouts(&self) {
        let ping_timeout_ms = self.config.ping_timeout_ms;
        let failure_detector = self.config.failure_detector;
        let phi_threshold = self.config.phi_threshold;
        
        FailureDetectorAlgorithm::process_ping_timeouts(
            &self.node_health,
            ping_timeout_ms,
            failure_detector,
            phi_threshold
        ).await;
    }
    /// Create a new health monitor
    pub fn new(
        node_id: String,
        topology: Arc<RwLock<HybridTopology>>, // Using HybridTopology implementation
        config: HealthCheckConfig,
        // Optional dependencies for status reporting
        metrics_collector: Option<Arc<MetricsCollector>>,
        router: Option<Arc<EpidemicRouter>>,
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
            metrics_collector,
            router,
        };

        (monitor, message_rx)
    }

    /// Start the health monitor
    pub async fn start(&self) -> Result<()> {
        // Start the ping task
        self.start_ping_task();

        // Start the status report task
        self.start_status_report_task();

        Ok(())
    }

    /// Select a batch of nodes to ping
    async fn select_nodes_to_ping(
        node_health: &Arc<RwLock<HashMap<String, NodeHealth>>>,
        batch_size: usize,
    ) -> Vec<StorageNode> {
        let health_map = node_health.read().await;
        health_map
            .values()
            .filter(|health| health.status == NodeStatus::Online)
            .take(batch_size)
            .map(|health| health.node.clone())
            .collect()
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
                    let topo_guard = topology.read().await; // Await the async read lock
                    topo_guard.all_neighbors()
                };
                if all_nodes.is_empty() {
                    debug!("No nodes to ping");
                    continue;
                }
                // Update node health with the current topology
                let mut health_map = node_health.write().await;
                for node in all_nodes {
                    if node.node_id.to_string() != node_id {
                        // Convert NodeId to String for entry key
                        let node_id_str = node.node_id.to_string();
                        // Create a StorageNode from NodeInfo
                        let storage_node = StorageNode {
                            id: node_id_str.clone(),
                            name: format!("Node {}", node_id_str),
                            region: node.region.map_or("unknown".to_string(), |r| r.to_string()),
                            public_key: "N/A".to_string(), // Not available in NodeInfo
                            endpoint: format!("http://{}", node.address),
                        };
                        
                        health_map.entry(node_id_str).or_insert_with(|| NodeHealth {
                            node: storage_node,
                            status: NodeStatus::Online,
                            last_seen: Instant::now(),
                            failure_value: 0.0,
                            ping_history: VecDeque::new(),
                            avg_ping_rtt: 0,
                            system_load: 0.0,
                            memory_usage: 0.0,
                            storage_usage: 0.0,
                            success_count: 0,
                            failure_count: 0,
                            pending_pings: HashMap::new(),
                        });
                    }
                }

                // Select a batch of nodes to ping
                let nodes_to_ping =
                    Self::select_nodes_to_ping(&node_health, config.health_check_batch_size).await;

                if nodes_to_ping.is_empty() {
                    debug!("No nodes to ping");
                    continue;
                }
                // Increment sequence
                let current_sequence = {
                    let mut seq = sequence.write().await;
                    *seq += 1;
                    *seq
                };
                
                // Process any timed out pings
                FailureDetectorAlgorithm::process_ping_timeouts(
                    &node_health,
                    config.ping_timeout_ms,
                    config.failure_detector,
                    config.phi_threshold,
                )
                .await;
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
                FailureDetectorAlgorithm::process_ping_timeouts(
                    &node_health,
                    config.ping_timeout_ms,
                    config.failure_detector,
                    config.phi_threshold,
                )
                .await;
            }
        });
    }

    /// Update node health with new nodes from the topology
    #[allow(dead_code)]
    async fn update_node_health_from_topology_nodes(
        node_id: &str,
        node_health: &Arc<RwLock<HashMap<String, NodeHealth>>>,
        all_nodes: Vec<crate::storage::topology::NodeInfo>,
    ) {
        let mut health_map = node_health.write().await;
        for node in all_nodes {
            // Convert NodeId to String for comparing and as key
            let node_id_str = node.node_id.to_string();
            
            if !health_map.contains_key(&node_id_str) && node_id_str != node_id {
                // Convert NodeInfo to StorageNode
                let storage_node = StorageNode {
                    id: node_id_str.clone(),
                    name: format!("Node {}", node_id_str),
                    region: node.region.map_or("unknown".to_string(), |r| r.to_string()),
                    public_key: "N/A".to_string(), // Not available in NodeInfo
                    endpoint: format!("http://{}", node.address),
                };
                
                health_map.insert(node_id_str, NodeHealth::new(storage_node));
            }
        }
    }

    /// Start the status report task
    pub fn start_status_report_task(&self) {
        let node_id = self.node_id.clone();
        let topology = self.topology.clone();
        let config = self.config.clone();
        let message_tx = self.message_tx.clone();
        let start_time = self.start_time;
        // Clone optional dependencies if they exist
        let metrics_collector = self.metrics_collector.clone();
        // let _router = self.router.clone(); // Not used in this simple version

        tokio::spawn(async move {
            info!("Starting status report task for node: {}", node_id);
            let mut report_interval = interval(Duration::from_millis(config.status_report_interval_ms));

            loop {
                report_interval.tick().await;

                // Gather local status information
                let status = NodeStatus::Online; // Basic status
                let uptime = start_time.elapsed().as_secs();

                // Get system metrics (placeholders - requires OS integration or metrics collector)
                let system_load = metrics_collector.as_ref().map_or(0.1, |mc| mc.get_system_load()); // Example: Get from metrics
                let memory_usage = metrics_collector.as_ref().map_or(0.2, |mc| mc.get_memory_usage()); // Example: Get from metrics
                let storage_usage = metrics_collector.as_ref().map_or(0.3, |mc| mc.get_storage_usage()); // Example: Get from metrics


                let report = HealthCheckMessage::StatusReport {
                    sender: node_id.clone(),
                    status,
                    system_load,
                    memory_usage,
                    storage_usage,
                    uptime,
                    timestamp: Self::current_timestamp_millis(),
                };

                // Select peers to send status report to (e.g., all neighbors)
                let peers = {
                    let topo_guard = topology.read().await; // Await the async read lock
                    topo_guard.all_neighbors()
                };

                if peers.is_empty() {
                    debug!("No peers to send status report to");
                    continue;
                }

                // Send status report to peers
                for peer in peers {
                    // Convert NodeInfo to StorageNode
                    let storage_node = StorageNode {
                        id: peer.node_id.to_string(),
                        name: format!("Node {}", peer.node_id),
                        region: peer.region.map_or("unknown".to_string(), |r| r.to_string()),
                        public_key: "N/A".to_string(), // Not available in NodeInfo
                        endpoint: format!("http://{}", peer.address),
                    };
                    
                    debug!("Sending status report to peer: {}", peer.node_id);
                    // Use try_send to avoid awaiting
                    if let Err(e) = message_tx.try_send((storage_node.clone(), report.clone())) {
                        error!("Failed to send status report to {}: {}", peer.node_id, e);
                    }
                }
            }
        });
    }

    /// Process an incoming health check message
    pub async fn process_message(&self, sender_node: &StorageNode, message: HealthCheckMessage) -> Result<()> {
        match message {
            HealthCheckMessage::Ping { sender, timestamp, sequence } => {
                debug!("Received Ping from {} (seq: {})", sender, sequence);
                // Respond with Pong
                let pong_message = HealthCheckMessage::Pong {
                    sender: sender.clone(), // Original sender
                    responder: self.node_id.clone(),
                    request_timestamp: timestamp,
                    response_timestamp: Self::current_timestamp_millis(),
                    sequence,
                };
                // Send pong back to the original sender
                if let Err(e) = self.message_tx.try_send((sender_node.clone(), pong_message)) {
                     error!("Failed to send Pong to {}: {}", sender, e);
                }
            }
            HealthCheckMessage::Pong { sender: _original_sender, responder, request_timestamp, response_timestamp: _, sequence } => {
                debug!("Received Pong from {} (seq: {})", responder, sequence);
                let rtt_ms = Self::current_timestamp_millis().saturating_sub(request_timestamp);

                let mut health_map = self.node_health.write().await;
                if let Some(health) = health_map.get_mut(&responder) {
                    // Check if this pong corresponds to a pending ping
                    if health.pending_pings.remove(&sequence).is_some() {
                        health.add_ping_rtt(rtt_ms);
                        // Reset failure value on successful pong if using PhiAccrual/Adaptive
                        if self.config.failure_detector != FailureDetectorAlgorithm::Timeout {
                            health.failure_value = 0.0;
                        }
                    } else {
                        warn!("Received unexpected Pong from {} (seq: {})", responder, sequence);
                    }
                } else {
                     warn!("Received Pong from unknown node {}", responder);
                     // Optionally add the node if it's unknown but responded
                     // health_map.insert(responder.clone(), NodeHealth::new(sender_node.clone()));
                     // if let Some(health) = health_map.get_mut(&responder) {
                     //    health.add_ping_rtt(rtt_ms);
                     // }
                }
            }
            HealthCheckMessage::StatusReport { sender, status, system_load, memory_usage, storage_usage, .. } => {
                debug!("Received StatusReport from {}", sender);
                let mut health_map = self.node_health.write().await;
                if let Some(health) = health_map.get_mut(&sender) {
                    health.update_from_status_report(status, system_load, memory_usage, storage_usage);
                } else {
                    warn!("Received StatusReport from unknown node {}", sender);
                    // Optionally add the node
                    // let mut new_health = NodeHealth::new(sender_node.clone());
                    // new_health.update_from_status_report(status, system_load, memory_usage, storage_usage);
                    // health_map.insert(sender.clone(), new_health);
                }
            }
        }
        Ok(())
    }

    /// Get the current status of all monitored nodes
    pub async fn get_all_node_health(&self) -> HashMap<String, NodeHealth> {
        self.node_health.read().await.clone()
    }

    /// Get suspected nodes based on the configured failure detector
    pub async fn get_suspected_nodes(&self) -> Vec<String> {
        let health_map = self.node_health.read().await;
        health_map
            .iter()
            .filter(|(_, health)| {
                health.is_suspected_failed(self.config.failure_detector, self.config.phi_threshold)
            })
            .map(|(id, _)| id.clone())
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
    #[allow(dead_code)]
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
