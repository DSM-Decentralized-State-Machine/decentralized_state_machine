// Small-world topology implementation for efficient epidemic coordination
//
// This module provides a small-world topology implementation that allows
// for efficient routing and epidemic dissemination in distributed storage nodes.

use crate::types::StorageNode;
use rand::{Rng, seq::SliceRandom};
use std::collections::{HashMap, HashSet};

/// Distance metric for nodes in the topology
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Distance(u128);

impl Distance {
    /// Create a new distance from a u128 value
    pub fn new(value: u128) -> Self {
        Self(value)
    }

    /// Get the inner value
    pub fn value(&self) -> u128 {
        self.0
    }

    /// Get the logarithmic bucket for the distance
    pub fn log2_bucket(&self) -> u8 {
        if self.0 == 0 {
            return 0;
        }

        128 - self.0.leading_zeros() as u8
    }
}

/// A node ID in the small-world topology
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId {
    /// The raw ID as bytes
    raw: [u8; 32],
}

impl NodeId {
    /// Create a new node ID from a string
    pub fn from_string(id: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(id.as_bytes());
        let hash = hasher.finalize();

        let mut raw = [0u8; 32];
        raw.copy_from_slice(hash.as_bytes());

        Self { raw }
    }

    /// Create a new node ID from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { raw: bytes }
    }

    /// Create a random node ID
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut raw = [0u8; 32];
        rng.fill(&mut raw);
        Self { raw }
    }

    /// Get the raw bytes
    #[allow(clippy::needless_borrows_for_generic_args)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.raw
    }

    /// Get a hex string representation
    pub fn to_hex(&self) -> String {
        hex::encode(self.raw)
    }

    /// Calculate the XOR distance to another node ID
    pub fn xor_distance(&self, other: &NodeId) -> Distance {
        let mut result = 0u128;

        // XOR the first 16 bytes to create the distance
        for (_i, (&self_byte, &other_byte)) in
            self.raw.iter().zip(other.raw.iter()).enumerate().take(16)
        {
            let xor = self_byte ^ other_byte;
            result = (result << 8) | xor as u128;
        }

        Distance(result)
    }

    /// Calculate the XOR distance to a key hash
    pub fn xor_distance_to_key(&self, key_hash: &[u8; 32]) -> Distance {
        let mut result = 0u128;

        // XOR the first 16 bytes to create the distance
        for (_i, (&self_byte, &key_byte)) in
            self.raw.iter().zip(key_hash.iter()).enumerate().take(16)
        {
            let xor = self_byte ^ key_byte;
            result = (result << 8) | xor as u128;
        }

        Distance(result)
    }

    /// Generate a finger node ID at a specific position
    pub fn finger(base: &NodeId, position: usize) -> NodeId {
        let mut raw = base.raw;

        // Flip the bit at the specified position
        let byte_pos = position / 8;
        let bit_pos = position % 8;

        if byte_pos < raw.len() {
            raw[byte_pos] ^= 1 << bit_pos;
        }

        NodeId { raw }
    }
}

impl From<&StorageNode> for NodeId {
    fn from(node: &StorageNode) -> Self {
        NodeId::from_string(&node.id)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            hex::encode(self.raw).chars().take(16).collect::<String>()
        )
    }
}

/// Small-world network topology
#[derive(Debug)]
pub struct SmallWorldTopology {
    /// The ID of the local node
    self_id: NodeId,

    /// Immediate neighbors (closest in ID space)
    immediate_neighbors: Vec<StorageNode>,

    /// Long-range connections (fingers)
    long_links: Vec<StorageNode>,

    /// All known nodes
    known_nodes: HashMap<NodeId, StorageNode>,

    /// Routing table grouped by distance buckets
    routing_buckets: HashMap<u8, Vec<StorageNode>>,

    /// Maximum nodes per bucket
    max_bucket_size: usize,

    /// Maximum number of immediate neighbors
    max_immediate_neighbors: usize,

    /// Maximum number of long-range links
    max_long_links: usize,
}

impl SmallWorldTopology {
    /// Create a new small-world topology centered on the given node
    pub fn new(self_node: StorageNode, config: SmallWorldConfig) -> Self {
        let self_id = NodeId::from(&self_node);

        let mut topology = Self {
            self_id,
            immediate_neighbors: Vec::with_capacity(config.max_immediate_neighbors),
            long_links: Vec::with_capacity(config.max_long_links),
            known_nodes: HashMap::new(),
            routing_buckets: HashMap::new(),
            max_bucket_size: config.max_bucket_size,
            max_immediate_neighbors: config.max_immediate_neighbors,
            max_long_links: config.max_long_links,
        };

        // Add self to known nodes
        topology
            .known_nodes
            .insert(NodeId::from(&self_node), self_node);

        topology
    }

    /// Add a node to the topology
    pub fn add_node(&mut self, node: StorageNode) -> bool {
        let node_id = NodeId::from(&node);

        // Skip if it's the local node
        if node_id == self.self_id {
            return false;
        }

        // Add to known nodes
        let is_new = !self.known_nodes.contains_key(&node_id);

        if is_new {
            // Calculate distance to the node
            let distance = self.self_id.xor_distance(&node_id);
            let bucket = distance.log2_bucket();

            // Add to known nodes
            self.known_nodes.insert(node_id.clone(), node.clone());

            // Try to add to immediate neighbors if we have space
            if self.immediate_neighbors.len() < self.max_immediate_neighbors {
                self.immediate_neighbors.push(node.clone());

                // Sort immediate neighbors by distance
                self.immediate_neighbors.sort_by(|a, b| {
                    let a_id = NodeId::from(a);
                    let b_id = NodeId::from(b);
                    let a_dist = self.self_id.xor_distance(&a_id);
                    let b_dist = self.self_id.xor_distance(&b_id);
                    a_dist.cmp(&b_dist)
                });
            } else {
                // Check if it's closer than our furthest immediate neighbor
                let furthest_neighbor = self.immediate_neighbors.last().unwrap();
                let furthest_id = NodeId::from(furthest_neighbor);
                let furthest_dist = self.self_id.xor_distance(&furthest_id);

                if distance < furthest_dist {
                    // Replace the furthest neighbor
                    self.immediate_neighbors.pop();
                    self.immediate_neighbors.push(node.clone());

                    // Sort immediate neighbors by distance
                    self.immediate_neighbors.sort_by(|a, b| {
                        let a_id = NodeId::from(a);
                        let b_id = NodeId::from(b);
                        let a_dist = self.self_id.xor_distance(&a_id);
                        let b_dist = self.self_id.xor_distance(&b_id);
                        a_dist.cmp(&b_dist)
                    });
                }
            }

            // Update routing buckets
            let bucket_entry = self.routing_buckets.entry(bucket).or_default();

            if bucket_entry.len() < self.max_bucket_size {
                bucket_entry.push(node.clone());
            } else {
                // Replace a random entry in the full bucket
                let index = rand::thread_rng().gen_range(0..self.max_bucket_size);
                bucket_entry[index] = node.clone();
            }
        }

        is_new
    }

    /// Update the long-range links
    pub fn update_long_links(&mut self) {
        // Clear current long links
        self.long_links.clear();

        // Calculate optimal finger positions based on XOR metric
        let mut finger_positions = Vec::new();

        // Use logarithmically increasing bit positions
        for i in 0..8 {
            for j in 0..8 {
                let pos = i * 8 + j;
                if self.long_links.len() < self.max_long_links {
                    finger_positions.push(pos);
                }
            }
        }

        // Find the best nodes for each finger position
        for pos in finger_positions {
            // Calculate the ideal finger ID
            let finger_id = NodeId::finger(&self.self_id, pos);

            // Find the closest node to this finger ID
            if let Some(closest) = self.find_closest_node(&finger_id, 1, None) {
                if !self.long_links.contains(&closest) {
                    self.long_links.push(closest);
                }
            }
        }

        // Ensure we have enough long links by adding random known nodes if needed
        if self.long_links.len() < self.max_long_links {
            let mut candidates: Vec<&StorageNode> = self
                .known_nodes
                .values()
                .filter(|n| !self.long_links.contains(n) && NodeId::from(*n) != self.self_id)
                .collect();

            candidates.shuffle(&mut rand::thread_rng());

            for candidate in candidates {
                if self.long_links.len() >= self.max_long_links {
                    break;
                }

                self.long_links.push(candidate.clone());
            }
        }
    }

    /// Find the closest nodes to a given ID
    pub fn find_closest_nodes(
        &self,
        id: &NodeId,
        count: usize,
        exclude: Option<&HashSet<NodeId>>,
    ) -> Vec<StorageNode> {
        // First, find the closest bucket
        let closest: Vec<StorageNode> = self
            .known_nodes
            .iter()
            .filter(|(node_id, _)| {
                **node_id != self.self_id
                    && (exclude.is_none() || !exclude.unwrap().contains(node_id))
            })
            .map(|(node_id, node)| {
                let distance = id.xor_distance(node_id);
                (node.clone(), distance)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter(|(_, dist)| dist.value() > 0) // Skip exact matches
            .take(count)
            .map(|(node, _)| node)
            .collect();

        closest
    }

    /// Find the closest node to a given ID
    pub fn find_closest_node(
        &self,
        id: &NodeId,
        skip: usize,
        exclude: Option<&HashSet<NodeId>>,
    ) -> Option<StorageNode> {
        let closest = self.find_closest_nodes(id, skip + 1, exclude);
        closest.into_iter().nth(skip)
    }

    /// Find responsible nodes for a key
    #[allow(clippy::needless_borrows_for_generic_args)]
    pub fn find_responsible_nodes(&self, key_hash: &[u8; 32], count: usize) -> Vec<StorageNode> {
        // Convert the key hash to a target ID
        let target_id = NodeId::from_bytes(*key_hash);

        // Find closest nodes to the target ID
        self.find_closest_nodes(&target_id, count, None)
    }

    /// Get all neighbors for epidemic propagation
    pub fn get_epidemic_targets(
        &self,
        key_hash: &[u8; 32],
        propagation_factor: usize,
    ) -> Vec<StorageNode> {
        let mut targets = Vec::new();

        // Add a subset of immediate neighbors
        let immediate_count = std::cmp::min(propagation_factor, self.immediate_neighbors.len());
        if immediate_count > 0 {
            targets.extend(
                self.immediate_neighbors
                    .iter()
                    .take(immediate_count)
                    .cloned(),
            );
        }

        // Add a subset of long links
        let long_count = std::cmp::min(propagation_factor / 2, self.long_links.len());
        if long_count > 0 {
            // Prioritize long links closest to the key
            let mut long_links = self.long_links.clone();
            long_links.sort_by(|a, b| {
                let a_id = NodeId::from(a);
                let b_id = NodeId::from(b);
                let a_dist = a_id.xor_distance_to_key(key_hash);
                let b_dist = b_id.xor_distance_to_key(key_hash);
                a_dist.cmp(&b_dist)
            });

            targets.extend(long_links.iter().take(long_count).cloned());
        }

        // Deduplicate
        targets.dedup_by(|a, b| a.id == b.id);

        targets
    }

    /// Get all neighbors for a general broadcast
    pub fn get_broadcast_targets(&self, fanout: usize) -> Vec<StorageNode> {
        let mut targets = Vec::new();

        // Add all immediate neighbors
        targets.extend(self.immediate_neighbors.iter().cloned());

        // Add all long links
        targets.extend(self.long_links.iter().cloned());

        // Deduplicate
        targets.dedup_by(|a, b| a.id == b.id);

        // Limit to fanout
        if targets.len() > fanout {
            targets.truncate(fanout);
        }

        targets
    }

    /// Get the number of known nodes
    pub fn node_count(&self) -> usize {
        self.known_nodes.len()
    }

    /// Get the immediate neighbors
    pub fn immediate_neighbors(&self) -> &[StorageNode] {
        &self.immediate_neighbors
    }

    /// Get the long links
    pub fn long_links(&self) -> &[StorageNode] {
        &self.long_links
    }

    /// Get all neighbors (combined immediate and long-range)
    pub fn all_neighbors(&self) -> Vec<StorageNode> {
        let mut all = Vec::new();
        all.extend(self.immediate_neighbors.iter().cloned());
        all.extend(self.long_links.iter().cloned());
        all.dedup_by(|a, b| a.id == b.id);
        all
    }

    /// Get the self ID
    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    /// Get a node by ID
    pub fn get_node(&self, id: &NodeId) -> Option<&StorageNode> {
        self.known_nodes.get(id)
    }

    /// Get a node by string ID
    pub fn get_node_by_id(&self, id: &str) -> Option<&StorageNode> {
        let node_id = NodeId::from_string(id);
        self.known_nodes.get(&node_id)
    }

    /// Calculate an estimated network diameter
    pub fn estimated_diameter(&self) -> u32 {
        // The diameter of a small-world network scales logarithmically with the number of nodes
        let node_count = self.known_nodes.len() as f64;
        (node_count.ln() / 2f64.ln()).ceil() as u32
    }
}

/// Configuration for the small-world topology
#[derive(Debug, Clone)]
pub struct SmallWorldConfig {
    /// Maximum number of nodes per bucket
    pub max_bucket_size: usize,

    /// Maximum number of immediate neighbors
    pub max_immediate_neighbors: usize,

    /// Maximum number of long-range links
    pub max_long_links: usize,
}

impl Default for SmallWorldConfig {
    fn default() -> Self {
        Self {
            max_bucket_size: 8,
            max_immediate_neighbors: 16,
            max_long_links: 16,
        }
    }
}

/// Calculate a consistent hash for a key
pub fn calculate_key_hash(key: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node(id: &str) -> StorageNode {
        StorageNode {
            id: id.to_string(),
            name: format!("Node {}", id),
            region: "test".to_string(),
            public_key: "pk".to_string(),
            endpoint: format!("http://node{}.example.com", id),
        }
    }

    #[test]
    fn test_node_id_distance() {
        let node1 = NodeId::from_string("node1");
        let node2 = NodeId::from_string("node2");

        let dist1_2 = node1.xor_distance(&node2);
        let dist2_1 = node2.xor_distance(&node1);

        assert_eq!(dist1_2, dist2_1);
        assert!(dist1_2.value() > 0);
    }

    #[test]
    fn test_small_world_topology() {
        let self_node = create_test_node("self");
        let config = SmallWorldConfig::default();

        let mut topology = SmallWorldTopology::new(self_node.clone(), config);

        // Add some nodes
        for i in 1..20 {
            let node = create_test_node(&format!("node{}", i));
            topology.add_node(node);
        }

        // Update long links
        topology.update_long_links();

        // Verify immediate neighbors
        assert!(!topology.immediate_neighbors().is_empty());

        // Verify long links
        assert!(!topology.long_links().is_empty());

        // Verify node count
        assert_eq!(topology.node_count(), 20);
    }

    #[test]
    fn test_find_responsible_nodes() {
        let self_node = create_test_node("self");
        let config = SmallWorldConfig::default();

        let mut topology = SmallWorldTopology::new(self_node.clone(), config);

        // Add some nodes
        for i in 1..20 {
            let node = create_test_node(&format!("node{}", i));
            topology.add_node(node);
        }

        // Update long links
        topology.update_long_links();

        // Get responsible nodes for a key
        let key = b"test_key";
        let key_hash = calculate_key_hash(key);

        let responsible = topology.find_responsible_nodes(&key_hash, 3);

        assert_eq!(responsible.len(), 3);
    }
}
