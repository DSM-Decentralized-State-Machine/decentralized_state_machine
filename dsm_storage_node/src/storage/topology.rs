use std::collections::{HashMap, HashSet, BTreeMap};
use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;
use std::net::{SocketAddr, IpAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use blake3::Hasher;
use serde::{Serialize, Deserialize};
use rand::{Rng, thread_rng};
use tracing::{info, warn};

use parking_lot::RwLock as PLRwLock;

use crate::error::StorageNodeError;
use crate::network::NetworkClient;
use crate::storage::metrics::MetricsCollector;

/// Quantum-resistant node identifier (256-bit)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl NodeId {
    /// Create a new random NodeId with cryptographic randomness
    pub fn random() -> Self {
        let mut rng = thread_rng();
        let mut id = [0u8; 32];
        rng.fill(&mut id);
        NodeId(id)
    }

    /// Create a NodeId from device-specific entropy
    pub fn from_device_entropy(device_salt: &[u8], app_id: &str) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(device_salt);
        hasher.update(app_id.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(result.as_bytes());
        NodeId(bytes)
    }

    /// Create a NodeId from string representation (hex encoded)
    pub fn from_string(s: &str) -> Result<Self, crate::error::StorageNodeError> {
        if s.len() != 64 {
            return Err(crate::error::StorageNodeError::InvalidNodeId(format!(
                "Invalid NodeId length: {}",
                s.len()
            )));
        }

        let bytes = match hex::decode(s) {
            Ok(b) => b,
            Err(e) => {
                return Err(crate::error::StorageNodeError::InvalidNodeId(format!(
                    "Invalid NodeId hex: {}",
                    e
                )))
            }
        };

        if bytes.len() != 32 {
            return Err(crate::error::StorageNodeError::InvalidNodeId(format!(
                "Decoded length is not 32 bytes: {}",
                bytes.len()
            )));
        }

        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(NodeId(id))
    }

    /// XOR distance for efficient routing
    pub fn xor_distance(&self, other: &NodeId) -> Distance {
        let mut result = [0u8; 32];
        result
            .iter_mut()
            .zip(self.0.iter().zip(other.0.iter()))
            .for_each(|(r, (a, b))| *r = a ^ b);
        Distance(result)
    }

    /// Geographic distance based on IP prefix
    pub fn geographic_proximity(&self, other: &NodeId, ip_a: &IpAddr, ip_b: &IpAddr) -> f64 {
        // Combine XOR distance with IP-based geographic proximity
        let xor_dist = self.xor_distance(other).as_f64();

        // Check if IPs are in same /16 subnet (rough geographic indicator)
        if let (IpAddr::V4(ip_a_v4), IpAddr::V4(ip_b_v4)) = (ip_a, ip_b) {
            let ip_a_bytes = ip_a_v4.octets();
            let ip_b_bytes = ip_b_v4.octets();

            // Same /16 subnet suggests geographic proximity
            if ip_a_bytes[0] == ip_b_bytes[0] && ip_a_bytes[1] == ip_b_bytes[1] {
                return xor_dist * 0.8; // Reduce distance for same subnet
            }
        }

        xor_dist
    }
}

/// Distance metric with multiple components for better routing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    /// Convert to floating point for weighted calculations
    pub fn as_f64(&self) -> f64 {
        let mut value = 0.0;
        for (i, &byte) in self.0.iter().enumerate() {
            value += (byte as f64) * 2f64.powi(-8 * (i as i32 + 1));
        }
        value
    }

    /// Calculate bucket index for routing
    pub fn bucket_index(&self) -> usize {
        for i in 0..32 {
            let byte = self.0[i];
            if byte != 0 {
                return i * 8 + byte.leading_zeros() as usize;
            }
        }
        256 // All bytes are zero
    }
}

impl Ord for Distance {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in 0..32 {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Distance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Calculate a quantum-resistant hash for any key
pub fn calculate_key_hash(key: &str) -> NodeId {
    let mut hasher = Hasher::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(result.as_bytes());
    NodeId(bytes)
}

/// Connection types for the hybrid topology
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    /// Structural connections based on XOR distance (DHT-like)
    Structural,
    /// Long-range connections (small-world property)
    LongRange,
    /// Geographic region-based connections (cross-region replication)
    Geographic,
    /// Reputation-based connections (performance optimization)
    Reputation,
}

/// Node information with extended metadata
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// Unique node identifier
    pub node_id: NodeId,
    /// Network address
    pub address: SocketAddr,
    /// Last successful communication time
    pub last_seen: u64,
    /// Node reputation score (0-100)
    pub reputation: u8,
    /// Geographic region identifier
    pub region: Option<u8>,
    /// Connection type
    pub connection_type: ConnectionType,
    /// Connection quality metrics
    pub metrics: NodeMetrics,
}

/// Performance metrics for nodes
#[derive(Debug, Clone, Default)]
pub struct NodeMetrics {
    /// Average response time in milliseconds
    pub avg_response_time: f64,
    /// Success rate of communications (0.0-1.0)
    pub success_rate: f64,
    /// Data transfer rate in bytes/second
    pub transfer_rate: f64,
    /// Available storage space in bytes
    pub available_storage: u64,
}

/// Configuration for the hybrid topology
#[derive(Debug, Clone)]
pub struct HybridTopologyConfig {
    /// Number of structural connections to maintain
    pub structural_connection_count: usize,
    /// Number of long-range connections
    pub long_range_connection_count: usize,
    /// Number of geographic connections per region
    pub geographic_connections_per_region: usize,
    /// Minimum number of regions to maintain connections with
    pub min_region_coverage: usize,
    /// Alpha parameter for epidemic dissemination
    pub epidemic_alpha: f64,
    /// Beta parameter for epidemic dissemination
    pub epidemic_beta: f64,
    /// Minimum reputation to consider for connections
    pub min_reputation_threshold: u8,
    /// Refresh interval for routing table in seconds
    pub refresh_interval_seconds: u64,
}

impl Default for HybridTopologyConfig {
    fn default() -> Self {
        HybridTopologyConfig {
            structural_connection_count: 20,
            long_range_connection_count: 15,
            geographic_connections_per_region: 5,
            min_region_coverage: 3,
            epidemic_alpha: 0.8,
            epidemic_beta: 0.2,
            min_reputation_threshold: 50,
            refresh_interval_seconds: 300,
        }
    }
}

/// Optimal hybrid topology combining multiple network structures
pub struct HybridTopology {
    /// Local node identifier
    local_id: NodeId,
    /// Configuration parameters
    config: HybridTopologyConfig,
    /// Structural routing table (DHT-like)
    routing_buckets: Vec<Vec<NodeInfo>>,
    /// Long-range connections (small-world property)
    long_range_connections: Vec<NodeInfo>,
    /// Geographic region connections (cross-region replication)
    geographic_connections: HashMap<u8, Vec<NodeInfo>>,
    /// Reputation-based preferred connections
    reputation_connections: Vec<NodeInfo>,
    /// All known nodes for quick lookups
    all_nodes: HashMap<NodeId, NodeInfo>,
    /// Recently seen messages to prevent loops (message ID -> timestamp)
    seen_messages: PLRwLock<HashMap<[u8; 32], u64>>,
    /// Local node region
    local_region: Option<u8>,
    /// Network client for communication
    #[allow(dead_code)]
    network_client: Option<Arc<dyn NetworkClient + Send + Sync>>,
    /// Metrics collector
    #[allow(dead_code)]
    metrics_collector: Option<Arc<MetricsCollector>>,
    /// Last routing table refresh time
    last_refresh: u64,
}

impl Clone for HybridTopology {
    fn clone(&self) -> Self {
        HybridTopology {
            local_id: self.local_id.clone(),
            config: self.config.clone(),
            routing_buckets: self.routing_buckets.clone(),
            long_range_connections: self.long_range_connections.clone(),
            geographic_connections: self.geographic_connections.clone(),
            reputation_connections: self.reputation_connections.clone(),
            all_nodes: self.all_nodes.clone(),
            seen_messages: PLRwLock::new(self.seen_messages.read().clone()),
            local_region: self.local_region,
            network_client: self.network_client.clone(),
            metrics_collector: self.metrics_collector.clone(),
            last_refresh: self.last_refresh,
        }
    }
}

impl HybridTopology {
    /// Create a new hybrid topology
    pub fn new(local_id: NodeId, config: HybridTopologyConfig, local_region: Option<u8>) -> Self {
        let mut routing_buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            routing_buckets.push(Vec::with_capacity(config.structural_connection_count));
        }

        HybridTopology {
            local_id,
            config,
            routing_buckets,
            long_range_connections: Vec::new(),
            geographic_connections: HashMap::new(),
            reputation_connections: Vec::new(),
            all_nodes: HashMap::new(),
            seen_messages: PLRwLock::new(HashMap::new()),
            local_region,
            network_client: None,
            metrics_collector: None,
            last_refresh: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Set the network client for communication
    pub fn set_network_client(&mut self, client: Arc<dyn NetworkClient>) {
        self.network_client = Some(client);
    }

    /// Set the metrics collector
    pub fn set_metrics_collector(&mut self, collector: Arc<MetricsCollector>) {
        self.metrics_collector = Some(collector);
    }

    /// Add a node to the topology with appropriate categorization
    pub fn add_node(
        &mut self,
        node_id: NodeId,
        address: SocketAddr,
        region: Option<u8>,
        reputation: u8,
    ) -> Result<(), StorageNodeError> {
        if node_id == self.local_id {
            return Ok(()); // Don't add self
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Determine the best connection type for this node
        let connection_type = self.determine_connection_type(&node_id, region);

        let node_info = NodeInfo {
            node_id: node_id.clone(),
            address,
            last_seen: now,
            reputation,
            region,
            connection_type: connection_type.clone(),
            metrics: NodeMetrics::default(),
        };

        // Add to the appropriate collections
        match connection_type {
            ConnectionType::Structural => {
                let distance = self.local_id.xor_distance(&node_id);
                let bucket_idx = distance.bucket_index();

                let bucket = &mut self.routing_buckets[bucket_idx];

                // Remove existing entry if present
                if let Some(pos) = bucket.iter().position(|n| n.node_id == node_id) {
                    bucket.remove(pos);
                }

                bucket.push(node_info.clone());

                // If bucket is full, remove least recently seen
                if bucket.len() > self.config.structural_connection_count {
                    bucket.sort_by_key(|n| std::cmp::Reverse(n.last_seen));
                    bucket.truncate(self.config.structural_connection_count);
                }
            }
            ConnectionType::LongRange => {
                // Remove if already exists
                if let Some(pos) = self
                    .long_range_connections
                    .iter()
                    .position(|n| n.node_id == node_id)
                {
                    self.long_range_connections.remove(pos);
                }

                self.long_range_connections.push(node_info.clone());

                // Limit the number of long-range connections
                if self.long_range_connections.len() > self.config.long_range_connection_count {
                    self.long_range_connections
                        .sort_by_key(|n| std::cmp::Reverse(n.last_seen));
                    self.long_range_connections
                        .truncate(self.config.long_range_connection_count);
                }
            }
            ConnectionType::Geographic => {
                if let Some(reg) = region {
                    let region_connections = self.geographic_connections.entry(reg).or_default();

                    // Remove if already exists
                    if let Some(pos) = region_connections.iter().position(|n| n.node_id == node_id)
                    {
                        region_connections.remove(pos);
                    }

                    region_connections.push(node_info.clone());

                    // Limit the number of connections per region
                    if region_connections.len() > self.config.geographic_connections_per_region {
                        region_connections.sort_by_key(|n| std::cmp::Reverse(n.last_seen));
                        region_connections.truncate(self.config.geographic_connections_per_region);
                    }
                }
            }
            ConnectionType::Reputation => {
                // Only add if reputation is above threshold
                if reputation >= self.config.min_reputation_threshold {
                    // Remove if already exists
                    if let Some(pos) = self
                        .reputation_connections
                        .iter()
                        .position(|n| n.node_id == node_id)
                    {
                        self.reputation_connections.remove(pos);
                    }

                    self.reputation_connections.push(node_info.clone());

                    // Sort by reputation and keep the best
                    self.reputation_connections
                        .sort_by_key(|n| std::cmp::Reverse(n.reputation));
                    self.reputation_connections.truncate(20); // Keep top 20
                }
            }
        }

        // Add to all nodes map for quick lookups
        self.all_nodes.insert(node_id, node_info);

        Ok(())
    }

    /// Determine the best connection type for a node
    fn determine_connection_type(&self, node_id: &NodeId, region: Option<u8>) -> ConnectionType {
        let distance = self.local_id.xor_distance(node_id);
        let bucket_idx = distance.bucket_index();

        // Check if we need geographic diversity
        if let (Some(local_region), Some(node_region)) = (self.local_region, region) {
            if local_region != node_region {
                let region_connections = self
                    .geographic_connections
                    .get(&node_region)
                    .unwrap_or(&Vec::new())
                    .to_vec();
                if region_connections.len() < self.config.geographic_connections_per_region {
                    return ConnectionType::Geographic;
                }
            }
        }

        // Check if we need structural connections in this bucket
        let bucket = &self.routing_buckets[bucket_idx];
        if bucket.len() < self.config.structural_connection_count {
            return ConnectionType::Structural;
        }

        // If we have enough structural connections, consider long-range
        if self.long_range_connections.len() < self.config.long_range_connection_count {
            return ConnectionType::LongRange;
        }

        // Default to reputation-based
        ConnectionType::Reputation
    }
    /// Find the closest nodes to a target ID
    pub fn find_closest_nodes(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        let mut closest = BTreeMap::new();
        let target_distance = self.local_id.xor_distance(target);
        let bucket_idx = target_distance.bucket_index();

        // First check the target bucket
        for node in &self.routing_buckets[bucket_idx] {
            let dist = node.node_id.xor_distance(target);
            closest.insert(dist, node.clone());
        }

        // Then check adjacent buckets in expanding order
        let mut i = 1;
        while closest.len() < count * 2 && (bucket_idx >= i || bucket_idx + i < 256) {
            if bucket_idx >= i {
                for node in &self.routing_buckets[bucket_idx - i] {
                    let dist = node.node_id.xor_distance(target);
                    closest.insert(dist, node.clone());
                }
            }

            if bucket_idx + i < 256 {
                for node in &self.routing_buckets[bucket_idx + i] {
                    let dist = node.node_id.xor_distance(target);
                    closest.insert(dist, node.clone());
                }
            }

            i += 1;
        }

        // Also check long-range and reputation connections
        for node in &self.long_range_connections {
            let dist = node.node_id.xor_distance(target);
            closest.insert(dist, node.clone());
        }

        for node in &self.reputation_connections {
            let dist = node.node_id.xor_distance(target);
            closest.insert(dist, node.clone());
        }

        // Return the closest nodes
        closest
            .into_iter()
            .take(count)
            .map(|(_, node)| node)
            .collect()
    }

    /// Get the nodes responsible for storing a particular key
    pub fn get_responsible_nodes(&self, key: &str, replication_factor: usize) -> Vec<NodeInfo> {
        let key_id = calculate_key_hash(key);
        self.find_closest_nodes(&key_id, replication_factor)
    }

    /// Propagate a message throughout the network using optimized epidemic distribution
    pub fn propagate_message(
        &self,
        message_id: [u8; 32],
        data: Vec<u8>,
        ttl: u8,
    ) -> Result<(), StorageNodeError> {
        // Check if we've seen this message before
        {
            let seen_messages = self.seen_messages.read();
            if seen_messages.contains_key(&message_id) {
                return Ok(());
            }
        }

        // Mark as seen
        {
            let mut seen_messages = self.seen_messages.write();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            seen_messages.insert(message_id, now);

            // Clean up old messages
            let cutoff = now - 3600; // 1 hour
            seen_messages.retain(|_, timestamp| *timestamp > cutoff);
        }

        // If TTL is 0, don't propagate further
        if ttl == 0 {
            return Ok(());
        }

        let new_ttl = ttl - 1;

        // Select nodes to propagate to using optimal epidemic distribution
        if let Some(network_client) = &self.network_client {
            // Build the target set with different probabilities based on connection type
            let mut targets = HashSet::new();

            // Always include all structural connections
            for bucket in &self.routing_buckets {
                for node in bucket {
                    targets.insert(node.address);
                }
            }

            // Include some long-range connections (with probability alpha)
            let mut rng = thread_rng();
            for node in &self.long_range_connections {
                if rng.gen::<f64>() < self.config.epidemic_alpha {
                    targets.insert(node.address);
                }
            }

            // Include some geographic connections (with probability beta)
            for region_nodes in self.geographic_connections.values() {
                for node in region_nodes {
                    if rng.gen::<f64>() < self.config.epidemic_beta {
                        targets.insert(node.address);
                    }
                }
            }

            // Include high-reputation nodes with high probability
            for node in &self.reputation_connections {
                let prob = (node.reputation as f64) / 100.0;
                if rng.gen::<f64>() < prob {
                    targets.insert(node.address);
                }
            }

            // Send the message to all selected targets
            for target in targets {
                match network_client.send_message(target, message_id, data.clone(), new_ttl) {
                    Ok(_) => {
                        if let Some(metrics) = &self.metrics_collector {
                            metrics.record_message_propagated();
                        }
                    }
                    Err(e) => {
                        warn!("Failed to propagate message to {}: {:?}", target, e);
                        // Continue with other targets even if one fails
                    }
                }
            }

            Ok(())
        } else {
            Err(StorageNodeError::NetworkClientNotSet)
        }
    }

    /// Refresh the routing table periodically
    pub fn refresh_if_needed(&mut self) -> Result<bool, StorageNodeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now - self.last_refresh < self.config.refresh_interval_seconds {
            return Ok(false);
        }

        info!("Refreshing routing table");
        self.last_refresh = now;

        // Remove stale nodes
        let stale_threshold = now - 3600; // 1 hour

        // Clean routing buckets
        for bucket in &mut self.routing_buckets {
            bucket.retain(|node| node.last_seen > stale_threshold);
        }

        // Clean long-range connections
        self.long_range_connections
            .retain(|node| node.last_seen > stale_threshold);

        // Clean geographic connections
        for nodes in self.geographic_connections.values_mut() {
            nodes.retain(|node| node.last_seen > stale_threshold);
        }

        // Clean reputation connections
        self.reputation_connections
            .retain(|node| node.last_seen > stale_threshold);

        // Clean all_nodes map
        self.all_nodes
            .retain(|_, node| node.last_seen > stale_threshold);

        // Perform active network discovery to find new nodes
        if let Some(network_client) = &self.network_client {
            // For each bucket that needs more nodes, perform a lookup
            for i in 0..256 {
                let bucket = &self.routing_buckets[i];
                if bucket.len() < self.config.structural_connection_count / 2 {
                    // Create a target ID in this bucket
                    let mut target_bytes = self.local_id.0;
                    if i < 8 {
                        // Flip bits in the first byte
                        target_bytes[0] ^= 1 << (7 - i);
                    } else {
                        // Flip bits in other bytes
                        let byte_idx = i / 8;
                        let bit_idx = 7 - (i % 8);
                        target_bytes[byte_idx] ^= 1 << bit_idx;
                    }

                    let target = NodeId(target_bytes);

                    // Find nodes close to this target
                    if let Err(e) = network_client.find_nodes(&target) {
                        warn!("Failed to find nodes for bucket {}: {:?}", i, e);
                    }
                }
            }

            // Check if we need more geographic diversity
            if self.local_region.is_some() {
                let mut missing_regions = Vec::new();

                // Look for regions with too few connections
                for region in 0..8u8 {
                    // Assume 8 possible regions
                    if Some(region) != self.local_region {
                        let count = self
                            .geographic_connections
                            .get(&region)
                            .map_or(0, |v| v.len());
                        if count < self.config.geographic_connections_per_region {
                            missing_regions.push(region);
                        }
                    }
                }

                // Try to find nodes in missing regions
                for region in missing_regions {
                    if let Err(e) = network_client.find_nodes_in_region(region) {
                        warn!("Failed to find nodes in region {}: {:?}", region, e);
                    }
                }
            }
        }

        // Record metrics
        if let Some(metrics) = &self.metrics_collector {
            metrics.record_routing_table_size(self.all_nodes.len() as u64);
            metrics.record_custom_metric(
                "geographic_diversity",
                self.geographic_connections.len() as f64,
            );
        }

        Ok(true)
    }

    /// Update node reputation based on performance
    pub fn update_node_reputation(
        &mut self,
        node_id: &NodeId,
        success: bool,
        response_time_ms: Option<u64>,
    ) {
        if let Some(node) = self.all_nodes.get_mut(node_id) {
            // Update last seen timestamp
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            node.last_seen = now;

            // Update reputation
            if success {
                node.reputation = node.reputation.saturating_add(1).min(100);

                // Update metrics
                if let Some(response_time) = response_time_ms {
                    // Update exponential moving average of response time
                    node.metrics.avg_response_time =
                        node.metrics.avg_response_time * 0.9 + (response_time as f64) * 0.1;

                    // Update success rate
                    node.metrics.success_rate = node.metrics.success_rate * 0.9 + 0.1;
                }
            } else {
                node.reputation = node.reputation.saturating_sub(1);

                // Update success rate
                node.metrics.success_rate *= 0.9;
            }

            // If reputation changes significantly, consider changing connection type
            if node.reputation >= self.config.min_reputation_threshold
                && node.connection_type != ConnectionType::Reputation
            {
                // Move to reputation-based connections if reputation is high
                let old_type = node.connection_type.clone();
                node.connection_type = ConnectionType::Reputation;

                // Remove from old collection and add to new
                match old_type {
                    ConnectionType::Structural => {
                        let distance = self.local_id.xor_distance(node_id);
                        let bucket_idx = distance.bucket_index();
                        let bucket = &mut self.routing_buckets[bucket_idx];
                        if let Some(pos) = bucket.iter().position(|n| n.node_id == *node_id) {
                            bucket.remove(pos);
                        }
                    }

                    ConnectionType::LongRange => {
                        if let Some(pos) = self
                            .long_range_connections
                            .iter()
                            .position(|n| n.node_id == *node_id)
                        {
                            self.long_range_connections.remove(pos);
                        }
                    }
                    ConnectionType::Geographic => {
                        if let Some(region) = node.region {
                            if let Some(region_connections) =
                                self.geographic_connections.get_mut(&region)
                            {
                                if let Some(pos) = region_connections
                                    .iter()
                                    .position(|n| n.node_id == *node_id)
                                {
                                    region_connections.remove(pos);
                                }
                            }
                        }
                    }
                    ConnectionType::Reputation => {} // Already in reputation connections
                }

                // Add to reputation connections
                self.reputation_connections.push(node.clone());

                // Sort and limit
                self.reputation_connections
                    .sort_by_key(|n| std::cmp::Reverse(n.reputation));
                self.reputation_connections.truncate(20);
            }
        }
    }

    /// Get all neighbors (combining all connection types)
    pub fn all_neighbors(&self) -> Vec<NodeInfo> {
        let mut all_nodes = Vec::new();

        // Add structural connections
        for bucket in &self.routing_buckets {
            all_nodes.extend(bucket.iter().cloned());
        }

        // Add long-range connections
        all_nodes.extend(self.long_range_connections.iter().cloned());

        // Add geographic connections
        for nodes in self.geographic_connections.values() {
            all_nodes.extend(nodes.iter().cloned());
        }

        // Add reputation-based connections
        all_nodes.extend(self.reputation_connections.iter().cloned());

        // Remove duplicates by converting to a map and back
        let node_map: HashMap<_, _> = all_nodes
            .into_iter()
            .map(|node| (node.node_id.clone(), node))
            .collect();

        node_map.into_values().collect()
    }

    /// Get immediate neighbors (closest nodes in XOR space)
    pub fn immediate_neighbors(&self) -> Vec<NodeInfo> {
        let mut immediate = Vec::new();

        // Get nodes from appropriate routing buckets
        for bucket in &self.routing_buckets {
            if !bucket.is_empty() {
                immediate.extend(bucket.iter().cloned());
            }
        }

        // Sort by distance
        immediate.sort_by(|a, b| {
            let dist_a = self.local_id.xor_distance(&a.node_id);
            let dist_b = self.local_id.xor_distance(&b.node_id);
            dist_a.cmp(&dist_b)
        });

        // Limit to a reasonable number
        if immediate.len() > self.config.structural_connection_count {
            immediate.truncate(self.config.structural_connection_count);
        }

        immediate
    }

    /// Get long-range links
    pub fn long_links(&self) -> Vec<NodeInfo> {
        self.long_range_connections.clone()
    }

    /// Get a specific node by ID
    pub fn get_node(&self, node_id: &NodeId) -> Option<NodeInfo> {
        self.all_nodes.get(node_id).cloned()
    }

    /// Get all nodes
    pub fn get_all_nodes(&self) -> Vec<NodeInfo> {
        self.all_nodes.values().cloned().collect()
    }

    /// Find responsible nodes for a key
    pub fn find_responsible_nodes(&self, key: &str, count: usize) -> Vec<NodeInfo> {
        self.get_responsible_nodes(key, count)
    }

    /// Get node connections
    pub fn get_node_connections(&self) -> Vec<(NodeId, Vec<NodeId>)> {
        // Currently we don't track connections between other nodes
        // This is just a placeholder returning our own connections
        let my_connections: Vec<NodeId> = self
            .all_neighbors()
            .into_iter()
            .map(|node| node.node_id)
            .collect();

        vec![(self.local_id.clone(), my_connections)]
    }
}
