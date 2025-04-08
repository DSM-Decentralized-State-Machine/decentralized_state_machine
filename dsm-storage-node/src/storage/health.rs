// Health monitoring module for epidemic storage
//
// This module provides comprehensive health monitoring for the epidemic storage system,
// including node status tracking, network latency measurement, failure detection,
// and adaptive behavior based on network conditions.

use crate::error::Result;
use crate::storage::small_world::{NodeId, SmallWorldTopology};
use crate::types::{StorageNode, NodeStatus};

use parking_lot::RwLock;
use rand::seq::SliceRandom;
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
        } else {
            if time_since_last_seen > mean * 3.0 {
                self.failure_value = 10.0; // High value indicating likely failure
                10.0
            } else {
                self.failure_value = 0.0;
                0.0
            }
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
        self.start_status_report_task();
        
        Ok(())
    }
    
    /// Start the ping task
    fn start_ping_task(&self) {
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
                
                // Update node health from topology
                Self::update_node_health_from_topology(&node_id, &node_health, &topology);
                
                // Select a batch of nodes to ping
                let nodes_to_ping = Self::select_nodes_to_ping(
                    &node_health,
                    config.health_check_batch_size,
                );
                
                if nodes_to_ping.is_empty() {
                    debug!("No nodes to ping");
                    continue;
                }
                
                let current_sequence = {
                    let mut seq = sequence.write();
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
                        let mut health = node_health.write();
                        if let Some(entry) = health.get_mut(&node.id) {
                            entry.pending_pings.insert(current_sequence, Instant::now());
                        }
                    }
                    
                    // Send ping
                    if let Err(e) = message_tx.send((node.clone(), ping_message)).await {
                        error!("Failed to send ping to {}: {}", node.id, e);
                    }
                }
                
                // Process timeouts
                Self::process_ping_timeouts(
                    &node_health,
                    config.ping_timeout_ms,
                    config.failure_detector,
                    config.phi_threshold,
                );
            }
        });
    }
    
    /// Start the status report task
    fn start_status_report_task(&self) {
        let node_id = self.node_id.clone();
        let topology = self.topology.clone();
        let config = self.config.clone();
        let message_tx = self.message_tx.clone();
        let start_time = self.start_time;
        
        tokio::spawn(async move {
            info!("Starting health check status report task for node: {}", node_id);
            
            let mut status_interval = interval(Duration::from_millis(config.status_report_interval_ms));
            
            loop {
                status_interval.tick().await;
                
                // Get current status
                let status_report = HealthCheckMessage::StatusReport {
                    sender: node_id.clone(),
                    status: NodeStatus::Online,
                    system_load: Self::get_system_load(),
                    memory_usage: Self::get_memory_usage(),
                    storage_usage: Self::get_storage_usage(),
                    uptime: start_time.elapsed().as_secs(),
                    timestamp: Self::current_timestamp_millis(),
                };
                
                // Send status report to some neighbors
                let topology_guard = topology.read();
                let neighbors: Vec<StorageNode> = topology_guard
                    .all_neighbors()
                    .into_iter()
                    .take(config.health_check_batch_size)
                    .collect();
                
                drop(topology_guard);
                
                for neighbor in neighbors {
                    if let Err(e) = message_tx.send((neighbor.clone(), status_report.clone())).await {
                        error!("Failed to send status report to {}: {}", neighbor.id, e);
                    }
                }
            }
        });
    }
    
    /// Handle health check message
    pub async fn handle_message(&self, from: &StorageNode, message: HealthCheckMessage) -> Result<()> {
        match message {
            HealthCheckMessage::Ping { sender, timestamp, sequence } => {
                // Update the sender's health information
                self.update_node_health(from);
                
                // Send pong response
                let pong = HealthCheckMessage::Pong {
                    sender,
                    responder: self.node_id.clone(),
                    request_timestamp: timestamp,
                    response_timestamp: Self::current_timestamp_millis(),
                    sequence,
                };
                
                self.message_tx.send((from.clone(), pong)).await
                    .map_err(|e| crate::error::StorageNodeError::Other(format!("Failed to send pong: {}", e)))?;
            }
            HealthCheckMessage::Pong { sender, responder, request_timestamp, response_timestamp, sequence } => {
                // Verify sender
                if sender != self.node_id {
                    warn!("Received pong with wrong sender: {}", sender);
                    return Ok(());
                }
                
                // Calculate RTT
                let now = Self::current_timestamp_millis();
                let rtt = now - request_timestamp;
                
                // Update health information
                self.process_pong(from, responder, sequence, rtt);
            }
            HealthCheckMessage::StatusReport { sender, status, system_load, memory_usage, storage_usage, uptime: _, timestamp: _ } => {
                // Update health information
                self.update_node_status(from, status, system_load, memory_usage, storage_usage);
            }
        }
        
        Ok(())
    }
    
    /// Update node health from topology
    fn update_node_health_from_topology(
        node_id: &str,
        node_health: &RwLock<HashMap<String, NodeHealth>>,
        topology: &RwLock<SmallWorldTopology>,
    ) {
        let topology_guard = topology.read();
        let all_nodes: Vec<StorageNode> = topology_guard
            .all_neighbors()
            .into_iter()
            .collect();
        
        drop(topology_guard);
        
        let mut health = node_health.write();
        
        // Add new nodes
        for node in all_nodes {
            if node.id != node_id && !health.contains_key(&node.id) {
                health.insert(node.id.clone(), NodeHealth::new(node));
            }
        }
    }
    
    /// Select nodes to ping
    fn select_nodes_to_ping(
        node_health: &RwLock<HashMap<String, NodeHealth>>,
        batch_size: usize,
    ) -> Vec<StorageNode> {
        let health = node_health.read();
        
        // Create score for each node
        let mut scores: Vec<(String, f64)> = health
            .iter()
            .map(|(id, info)| {
                // Calculate score based on last seen time and status
                let last_seen_factor = info.last_seen.elapsed().as_secs_f64() / 60.0; // Time factor (minutes)
                let status_factor = match info.status {
                    NodeStatus::Online => 0.2,
                    NodeStatus::Offline => 0.8,
                    NodeStatus::Unknown => 1.0,
                    NodeStatus::Pending => 0.5,
                    NodeStatus::Suspended => 0.4,
                };
                
                let score = last_seen_factor * status_factor;
                (id.clone(), score)
            })
            .collect();
        
        // Sort by score (highest first)
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Take top batch_size
        let batch: Vec<StorageNode> = scores
            .into_iter()
            .take(batch_size)
            .filter_map(|(id, _)| health.get(&id).map(|info| info.node.clone()))
            .collect();
        
        // Add some random nodes for exploration
        if batch.len() < batch_size && health.len() > batch_size {
            let mut all_nodes: Vec<StorageNode> = health
                .values()
                .map(|info| info.node.clone())
                .filter(|node| !batch.iter().any(|n| n.id == node.id))
                .collect();
            
            all_nodes.shuffle(&mut rand::thread_rng());
            
            let remaining = batch_size - batch.len();
            let mut final_batch = batch;
            final_batch.extend(all_nodes.into_iter().take(remaining));
            
            final_batch
        } else {
            batch
        }
    }
    
    /// Process ping timeouts
    fn process_ping_timeouts(
        node_health: &RwLock<HashMap<String, NodeHealth>>,
        timeout_ms: u64,
        algorithm: FailureDetectorAlgorithm,
        phi_threshold: f64,
    ) {
        let mut health = node_health.write();
        let now = Instant::now();
        
        for health_info in health.values_mut() {
            // Check for timed out pings
            let timed_out: Vec<u64> = health_info
                .pending_pings
                .iter()
                .filter(|(_, &ping_time)| now.duration_since(ping_time).as_millis() > timeout_ms as u128)
                .map(|(&seq, _)| seq)
                .collect();
            
            // Process timeouts
            for seq in timed_out {
                health_info.pending_pings.remove(&seq);
                health_info.record_timeout();
            }
            
            // Calculate phi value for phi-accrual detector
            if algorithm == FailureDetectorAlgorithm::PhiAccrual || 
               algorithm == FailureDetectorAlgorithm::Adaptive {
                health_info.calculate_phi();
            }
            
            // Update status based on failure detector
            if health_info.is_suspected_failed(algorithm, phi_threshold) {
                health_info.status = NodeStatus::Offline;
            }
        }
    }
    
    /// Process pong response
    fn process_pong(&self, from: &StorageNode, responder: String, sequence: u64, rtt: u64) {
        let mut health = self.node_health.write();
        
        // Get or create health info
        let health_info = match health.get_mut(&from.id) {
            Some(info) => info,
            None => {
                let new_info = NodeHealth::new(from.clone());
                health.insert(from.id.clone(), new_info);
                health.get_mut(&from.id).unwrap()
            }
        };
        
        // Remove pending ping
        health_info.pending_pings.remove(&sequence);
        
        // Update RTT and status
        health_info.add_ping_rtt(rtt);
        
        // If this is a different responder than expected, add it to known nodes
        if responder != from.id {
            debug!("Received pong with different responder: {} (expected {})", responder, from.id);
            
            // We might want to update the topology here
        }
    }
    
    /// Update node health
    fn update_node_health(&self, node: &StorageNode) {
        let mut health = self.node_health.write();
        
        if let Some(health_info) = health.get_mut(&node.id) {
            health_info.last_seen = Instant::now();
            if health_info.status == NodeStatus::Unknown || health_info.status == NodeStatus::Offline {
                health_info.status = NodeStatus::Pending;
            }
        } else {
            health.insert(node.id.clone(), NodeHealth::new(node.clone()));
        }
    }
    
    /// Update node status
    fn update_node_status(
        &self,
        node: &StorageNode,
        status: NodeStatus,
        system_load: f32,
        memory_usage: f32,
        storage_usage: f32,
    ) {
        let mut health = self.node_health.write();
        
        if let Some(health_info) = health.get_mut(&node.id) {
            health_info.update_from_status_report(status, system_load, memory_usage, storage_usage);
        } else {
            let mut new_info = NodeHealth::new(node.clone());
            new_info.update_from_status_report(status, system_load, memory_usage, storage_usage);
            health.insert(node.id.clone(), new_info);
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
    
    /// Get system load (simplified)
    fn get_system_load() -> f32 {
        // In a real implementation, this would use system APIs to get actual load
        // Placeholder implementation
        0.5
    }
    
    /// Get memory usage (simplified)
    fn get_memory_usage() -> f32 {
        // In a real implementation, this would use system APIs to get actual memory usage
        // Placeholder implementation
        0.4
    }
    
    /// Get storage usage (simplified)
    fn get_storage_usage() -> f32 {
        // In a real implementation, this would use system APIs to get actual storage usage
        // Placeholder implementation
        0.3
    }
    
    /// Get health information for a node
    pub fn get_node_health(&self, node_id: &str) -> Option<NodeHealth> {
        let health = self.node_health.read();
        health.get(node_id).cloned()
    }
    
    /// Get all node health information
    pub fn get_all_node_health(&self) -> HashMap<String, NodeHealth> {
        let health = self.node_health.read();
        health.clone()
    }
    
    /// Get online nodes
    pub fn get_online_nodes(&self) -> Vec<StorageNode> {
        let health = self.node_health.read();
        health
            .values()
            .filter(|info| info.status == NodeStatus::Online)
            .map(|info| info.node.clone())
            .collect()
    }
    
    /// Get nodes by status
    pub fn get_nodes_by_status(&self, status: NodeStatus) -> Vec<StorageNode> {
        let health = self.node_health.read();
        health
            .values()
            .filter(|info| info.status == status)
            .map(|info| info.node.clone())
            .collect()
    }
    
    /// Get node count by status
    pub fn get_node_count_by_status(&self) -> HashMap<NodeStatus, usize> {
        let health = self.node_health.read();
        let mut counts = HashMap::new();
        
        for info in health.values() {
            *counts.entry(info.status).or_insert(0) += 1;
        }
        
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_node_health() {
        let node = StorageNode {
            id: "test-node".to_string(),
            name: "Test Node".to_string(),
            region: "test".to_string(),
            public_key: "pk".to_string(),
            endpoint: "http://test.example.com".to_string(),
        };
        
        let mut health = NodeHealth::new(node.clone());
        
        // Test initial state
        assert_eq!(health.status, NodeStatus::Unknown);
        assert_eq!(health.ping_history.len(), 0);
        assert_eq!(health.avg_ping_rtt, 0);
        
        // Test adding ping RTT
        health.add_ping_rtt(100);
        assert_eq!(health.ping_history.len(), 1);
        assert_eq!(health.avg_ping_rtt, 100);
        assert_eq!(health.status, NodeStatus::Online);
        
        // Test multiple RTTs
        health.add_ping_rtt(200);
        assert_eq!(health.ping_history.len(), 2);
        assert_eq!(health.avg_ping_rtt, 150);
        
        // Test timeout
        health.record_timeout();
        assert_eq!(health.failure_count, 1);
        assert_eq!(health.status, NodeStatus::Online); // Still online, not enough failures
        
        // Test phi calculation
        let phi = health.calculate_phi();
        assert!(phi >= 0.0);
        
        // Test status report
        health.update_from_status_report(NodeStatus::Offline, 0.5, 0.4, 0.3);
        assert_eq!(health.status, NodeStatus::Offline);
        assert_eq!(health.system_load, 0.5);
        assert_eq!(health.memory_usage, 0.4);
        assert_eq!(health.storage_usage, 0.3);
    }
    
    #[test]
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
