// Routing module for epidemic storage with distributed topology
//
// This module implements efficient routing strategies for the distributed topology
// to ensure optimal message delivery and request handling.

use crate::storage::topology::{NodeId, HybridTopology, Distance, calculate_key_hash};
use crate::types::StorageNode;

// Add From implementations for convenience
impl From<&StorageNode> for NodeId {
    fn from(node: &StorageNode) -> Self {
        NodeId::from_string(&node.id).expect("Failed to create NodeId from StorageNode")
    }
}

impl From<&crate::storage::topology::NodeInfo> for NodeId {
    fn from(node: &crate::storage::topology::NodeInfo) -> Self {
        node.node_id.clone()
    }
}

// Add From implementation for NodeInfo to StorageNode conversion
impl From<&crate::storage::topology::NodeInfo> for StorageNode {
    fn from(node_info: &crate::storage::topology::NodeInfo) -> Self {
        StorageNode {
            id: node_info.node_id.to_string(),
            name: format!("Node {}", node_info.node_id),
            region: node_info
                .region
                .map_or_else(|| "unknown".to_string(), |r| r.to_string()),
            public_key: "key-placeholder".to_string(), // Placeholder
            endpoint: node_info.address.to_string(),
        }
    }
}

impl From<crate::storage::topology::NodeInfo> for StorageNode {
    fn from(node_info: crate::storage::topology::NodeInfo) -> Self {
        StorageNode::from(&node_info)
    }
}

use dashmap::DashMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Routing table entry
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    /// Target node
    pub node: StorageNode,

    /// Route cost metric (lower is better)
    pub cost: u32,

    /// Route distance
    pub distance: Distance,

    /// Next hop node
    pub next_hop: Option<StorageNode>,

    /// Last updated timestamp
    pub last_updated: Instant,

    /// Success count
    pub success_count: u32,

    /// Failure count
    pub failure_count: u32,
}

/// Routing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Greedy routing (always choose the closest node)
    Greedy,

    /// Perimeter routing (route around obstacles)
    Perimeter,

    /// Probabilistic routing (choose with probability)
    Probabilistic,

    /// Hybrid routing (combine strategies)
    Hybrid,
}

/// Routing table for the distributed topology
pub struct RoutingTable {
    /// Node ID of the local node
    self_id: NodeId,

    /// Routing entries
    entries: DashMap<NodeId, RoutingEntry>,

    // Removed unused topology field
    /// Route cache for frequently accessed destinations
    route_cache: DashMap<NodeId, Vec<StorageNode>>,

    /// Failed routes
    failed_routes: DashMap<(NodeId, NodeId), Instant>,

    /// Routing strategy
    strategy: RoutingStrategy,

    /// Maximum route cache size
    max_cache_size: usize,

    /// Maximum route cache age
    max_cache_age: Duration,
    topology: Arc<parking_lot::RwLock<HybridTopology>>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(
        self_id: NodeId,
        topology: Arc<parking_lot::RwLock<HybridTopology>>,
        strategy: RoutingStrategy,
    ) -> Self {
        Self {
            self_id,
            entries: DashMap::new(),
            topology,
            route_cache: DashMap::new(),
            failed_routes: DashMap::new(),
            strategy,
            max_cache_size: 1000,
            max_cache_age: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Update routing entry
    pub fn update_entry(&self, node: StorageNode, cost: u32, next_hop: Option<StorageNode>) {
        let node_id = NodeId::from(&node);

        if node_id == self.self_id {
            return; // Don't route to self
        }

        let distance = self.self_id.xor_distance(&node_id);

        let entry = RoutingEntry {
            node: node.clone(),
            cost,
            distance,
            next_hop,
            last_updated: Instant::now(),
            success_count: 0,
            failure_count: 0,
        };

        self.entries.insert(node_id, entry);

        // Invalidate cache entries that might use this node
        let mut to_remove = Vec::new();
        for kv in self.route_cache.iter() {
            let cached_route = kv.value();
            if cached_route.iter().any(|n| n.id == node.id) {
                to_remove.push(kv.key().clone());
            }
        }

        for key in to_remove {
            self.route_cache.remove(&key);
        }
    }

    /// Find the next hop for a target node
    pub fn find_next_hop(&self, target: &NodeId) -> Option<StorageNode> {
        if let Some(entry) = self.entries.get(target) {
            // Direct route known
            if let Some(next_hop) = &entry.next_hop {
                return Some(next_hop.clone());
            } else {
                return Some(entry.node.clone());
            }
        }

        // Check cache
        if let Some(cached_route) = self.route_cache.get(target) {
            if !cached_route.is_empty() {
                return Some(cached_route[0].clone());
            }
        }

        // No direct route, use topology to find the closest node
        let topology_guard = self.topology.read();

        match self.strategy {
            RoutingStrategy::Greedy => self.greedy_routing(target, &topology_guard),
            RoutingStrategy::Perimeter => self.perimeter_routing(target, &topology_guard),
            RoutingStrategy::Probabilistic => self.probabilistic_routing(target, &topology_guard),
            RoutingStrategy::Hybrid => self.hybrid_routing(target, &topology_guard),
        }
    }

    /// Find the best route to a target
    pub fn find_route(&self, target: &NodeId, max_hops: usize) -> Option<Vec<StorageNode>> {
        // Check cache first
        if let Some(cached_route) = self.route_cache.get(target) {
            if !cached_route.is_empty() && cached_route.len() <= max_hops {
                return Some(cached_route.clone());
            }
        }

        // Calculate route
        let route = self.calculate_route(target, max_hops)?;

        // Cache the route if it's not too long
        if !route.is_empty() && route.len() <= max_hops {
            self.route_cache.insert(target.clone(), route.clone());

            // Prune cache if too large
            if self.route_cache.len() > self.max_cache_size {
                self.prune_cache();
            }
        }

        Some(route)
    }

    /// Calculate a route to the target
    fn calculate_route(&self, target: &NodeId, max_hops: usize) -> Option<Vec<StorageNode>> {
        // If we have a direct entry, use it
        if let Some(entry) = self.entries.get(target) {
            if let Some(next_hop) = &entry.next_hop {
                return Some(vec![next_hop.clone(), entry.node.clone()]);
            } else {
                return Some(vec![entry.node.clone()]);
            }
        }

        // Use breadth-first search to find a route
        let topology_guard = self.topology.read();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut paths: HashMap<NodeId, Vec<StorageNode>> = HashMap::new();

        // Start with immediate neighbors
        for neighbor in topology_guard.immediate_neighbors() {
            let neighbor_id = NodeId::from(&neighbor);
            visited.insert(neighbor_id.clone());
            queue.push_back(neighbor_id.clone());
            paths.insert(neighbor_id, vec![neighbor.clone().into()]);
        }

        // Also consider long links
        for link in topology_guard.long_links() {
            let link_id = NodeId::from(&link);
            if !visited.contains(&link_id) {
                visited.insert(link_id.clone());
                queue.push_back(link_id.clone());
                paths.insert(link_id, vec![link.clone().into()]);
            }
        }

        while let Some(current_id) = queue.pop_front() {
            // Found the target
            if &current_id == target {
                return paths.get(&current_id).cloned();
            }

            // Get the current path
            let current_path = match paths.get(&current_id) {
                Some(path) => path.clone(),
                None => continue,
            };

            // Too many hops, skip
            if current_path.len() >= max_hops {
                continue;
            }

            // Get the current node
            let current_node = match topology_guard.get_node(&current_id) {
                Some(node) => StorageNode::from(node),
                None => continue,
            };

            // Get neighbors of the current node
            let neighbors = self.get_node_neighbors(&current_node, &topology_guard);

            for neighbor in neighbors {
                let neighbor_id = NodeId::from(&neighbor);

                // Skip visited nodes
                if visited.contains(&neighbor_id) {
                    continue;
                }

                // Skip failed routes
                if self
                    .failed_routes
                    .contains_key(&(current_id.clone(), neighbor_id.clone()))
                {
                    continue;
                }

                // Add to visited
                visited.insert(neighbor_id.clone());

                // Create new path
                let mut new_path = current_path.clone();
                new_path.push(neighbor.clone());

                // Add to queue and paths
                queue.push_back(neighbor_id.clone());
                paths.insert(neighbor_id, new_path);
            }
        }

        // No route found
        None
    }

    /// Get neighbors of a node from topology
    fn get_node_neighbors(
        &self,
        node: &StorageNode,
        topology: &HybridTopology,
    ) -> Vec<StorageNode> {
        // This is a simplified approach; in a real implementation, we would need
        // to query the node for its neighbors or use a more sophisticated approach
        let node_id = NodeId::from(node);

        // Find nodes that might be neighbors of this node
        let mut potential_neighbors = Vec::new();

        // Assume nodes close to this node in ID space might be its neighbors
        potential_neighbors.extend(
            topology
                .find_closest_nodes(&node_id, 5)
                .into_iter()
                .map(StorageNode::from),
        );

        potential_neighbors
    }

    /// Mark a route as failed
    pub fn mark_route_failed(&self, from: &NodeId, to: &NodeId) {
        self.failed_routes
            .insert((from.clone(), to.clone()), Instant::now());

        // Invalidate cache entries that might use this route
        let mut to_remove = Vec::new();
        for kv in self.route_cache.iter() {
            let cached_route = kv.value();
            for i in 0..cached_route.len().saturating_sub(1) {
                let node1 = NodeId::from(&cached_route[i]);
                let node2 = NodeId::from(&cached_route[i + 1]);

                if (node1 == *from && node2 == *to) || (node1 == *to && node2 == *from) {
                    to_remove.push(kv.key().clone());
                    break;
                }
            }
        }

        for key in to_remove {
            self.route_cache.remove(&key);
        }

        // Update failure count in routing entry
        if let Some(mut entry) = self.entries.get_mut(to) {
            entry.failure_count += 1;
        }
    }

    /// Mark a route as successful
    pub fn mark_route_success(&self, to: &NodeId) {
        // Update success count in routing entry
        if let Some(mut entry) = self.entries.get_mut(to) {
            entry.success_count += 1;
        }

        // Remove from failed routes
        let mut to_remove = Vec::new();
        for kv in self.failed_routes.iter() {
            let (from, target) = kv.key();
            if target == to {
                to_remove.push((from.clone(), target.clone()));
            }
        }

        for key in to_remove {
            self.failed_routes.remove(&key);
        }
    }

    /// Prune the route cache
    fn prune_cache(&self) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        // Remove old entries
        for kv in self.route_cache.iter() {
            let key = kv.key();
            if let Some(entry) = self.entries.get(key) {
                if now.duration_since(entry.last_updated) > self.max_cache_age {
                    to_remove.push(key.clone());
                }
            } else {
                // No corresponding entry, remove
                to_remove.push(key.clone());
            }
        }

        for key in to_remove {
            self.route_cache.remove(&key);
        }

        // If still too large, remove oldest entries
        if self.route_cache.len() > self.max_cache_size {
            let mut entries: Vec<_> = self.entries.iter().collect();
            entries.sort_by_key(|e| e.last_updated);

            let to_remove = entries.len() - self.max_cache_size / 2;
            for entry in entries.iter().take(to_remove) {
                self.route_cache.remove(entry.key());
            }
        }
    }

    /// Greedy routing strategy (always choose the closest node)
    fn greedy_routing(&self, target: &NodeId, topology: &HybridTopology) -> Option<StorageNode> {
        let closest = topology.find_closest_nodes(target, 1);

        if !closest.is_empty() {
            Some(closest[0].clone().into())
        } else {
            None
        }
    }

    /// Perimeter routing strategy (route around obstacles)
    fn perimeter_routing(&self, target: &NodeId, topology: &HybridTopology) -> Option<StorageNode> {
        let mut closest = topology.find_closest_nodes(target, 5);

        // Filter out failed routes
        let target_dist = self.self_id.xor_distance(target);
        closest.retain(|node| {
            let node_id = NodeId::from(node);
            let node_dist = node_id.xor_distance(target);

            // Keep if the node is closer to the target than we are, and not a failed route
            node_dist < target_dist
                && !self
                    .failed_routes
                    .contains_key(&(self.self_id.clone(), node_id))
        });

        if !closest.is_empty() {
            Some(closest[0].clone().into())
        } else {
            self.greedy_routing(target, topology)
        }
    }

    /// Probabilistic routing strategy (choose with probability)
    fn probabilistic_routing(
        &self,
        target: &NodeId,
        topology: &HybridTopology,
    ) -> Option<StorageNode> {
        let closest = topology.find_closest_nodes(target, 3);

        if !closest.is_empty() {
            // Simple probabilistic approach - choose randomly from top 3
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            closest
                .choose(&mut rng)
                .map(|n| StorageNode::from(n.clone()))
        } else {
            None
        }
    }

    /// Hybrid routing strategy (combine strategies)
    fn hybrid_routing(&self, target: &NodeId, topology: &HybridTopology) -> Option<StorageNode> {
        // Try greedy first
        let greedy_result = self.greedy_routing(target, topology);

        if let Some(node) = &greedy_result {
            let node_id = NodeId::from(node);

            // If this route has failed before, try perimeter
            if self
                .failed_routes
                .contains_key(&(self.self_id.clone(), node_id))
            {
                return self.perimeter_routing(target, topology);
            }
        }
        greedy_result
    }

    /// Find responsible nodes for a hash key
    pub fn find_responsible_nodes(&self, key: &[u8], count: usize) -> Vec<StorageNode> {
        let key_hash = calculate_key_hash(std::str::from_utf8(key).unwrap_or_default());
        let target_id =
            NodeId::from_string(&key_hash.to_string()).unwrap_or_else(|_| self.self_id.clone());
        let topology_guard = self.topology.read();
        topology_guard
            .find_closest_nodes(&target_id, count)
            .into_iter()
            .map(StorageNode::from)
            .collect()
    }

    /// Find responsible nodes for a blinded ID
    pub fn find_responsible_nodes_for_id(
        &self,
        blinded_id: &str,
        count: usize,
    ) -> Vec<StorageNode> {
        self.find_responsible_nodes(blinded_id.as_bytes(), count)
    }
}

/// Router for the epidemic storage system
pub struct EpidemicRouter {
    /// Local node ID
    self_id: NodeId,

    /// Routing table
    routing_table: Arc<RoutingTable>,

    // Removed unused topology field
    /// Routing strategy
    strategy: RoutingStrategy,

    /// Maximum hops for routing
    max_hops: usize,
}

impl EpidemicRouter {
    /// Create a new epidemic router
    pub fn new(
        self_id: NodeId,
        topology: Arc<parking_lot::RwLock<HybridTopology>>,
        strategy: RoutingStrategy,
        max_hops: usize,
    ) -> Self {
        let routing_table = Arc::new(RoutingTable::new(
            self_id.clone(),
            topology,
            RoutingStrategy::Greedy,
        ));

        Self {
            self_id,
            routing_table,
            strategy,
            max_hops,
        }
    }

    /// Find the next hop for a target node
    pub fn find_next_hop(&self, target: &NodeId) -> Option<StorageNode> {
        self.routing_table.find_next_hop(target)
    }

    /// Find a route to a target node
    pub fn find_route(&self, target: &NodeId) -> Option<Vec<StorageNode>> {
        self.routing_table.find_route(target, self.max_hops)
    }

    /// Find responsible nodes for a key
    pub fn find_responsible_nodes(&self, key: &[u8], count: usize) -> Vec<StorageNode> {
        self.routing_table.find_responsible_nodes(key, count)
    }

    /// Find responsible nodes for a blinded ID
    pub fn find_responsible_nodes_for_id(
        &self,
        blinded_id: &str,
        count: usize,
    ) -> Vec<StorageNode> {
        self.routing_table
            .find_responsible_nodes_for_id(blinded_id, count)
    }

    /// Update routing table with a new node
    pub fn update_node(&self, node: StorageNode, cost: u32, next_hop: Option<StorageNode>) {
        self.routing_table.update_entry(node, cost, next_hop);
    }

    /// Mark a route as failed
    pub fn mark_route_failed(&self, from: &NodeId, to: &NodeId) {
        self.routing_table.mark_route_failed(from, to);
    }

    /// Mark a route as successful
    pub fn mark_route_success(&self, to: &NodeId) {
        self.routing_table.mark_route_success(to);
    }

    /// Get the routing table
    pub fn routing_table(&self) -> Arc<RoutingTable> {
        self.routing_table.clone()
    }

    /// Get the self ID
    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    /// Get the routing strategy
    pub fn strategy(&self) -> RoutingStrategy {
        self.strategy
    }

    /// Set the routing strategy
    pub fn set_strategy(&mut self, strategy: RoutingStrategy) {
        self.strategy = strategy;
    }

    /// Get the maximum hops
    pub fn max_hops(&self) -> usize {
        self.max_hops
    }

    /// Set the maximum hops
    pub fn set_max_hops(&mut self, max_hops: usize) {
        self.max_hops = max_hops;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::topology::HybridTopologyConfig;
    use std::net::SocketAddr;

    // Simple test struct for routing table tests
    #[derive(Debug, Clone)]
    struct TestNode {
        node_id: String,
        endpoint: String,
        #[allow(dead_code)]
        rtt_ms: u32,
        region: String,
        public_key: Vec<u8>,
    }

    impl From<TestNode> for StorageNode {
        fn from(node: TestNode) -> Self {
            StorageNode {
                id: node.node_id.clone(),
                name: format!("Node {}", node.node_id),
                region: node.region.clone(),
                public_key: hex::encode(&node.public_key),
                endpoint: node.endpoint.clone(),
            }
        }
    }

    #[test]
    fn test_routing_table() {
        // Create a simple routing table for testing
        // Using a valid 64-character hex string for NodeId (32 bytes)
        let self_id =
            NodeId::from_string("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let topology = Arc::new(parking_lot::RwLock::new(HybridTopology::new(
            self_id.clone(),
            HybridTopologyConfig::default(),
            None,
        )));
        let table = RoutingTable::new(self_id.clone(), topology.clone(), RoutingStrategy::Greedy);

        // Create test nodes
        let node1 = TestNode {
            node_id: "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            endpoint: "endpoint1".to_string(),
            rtt_ms: 100,
            region: "us-west".to_string(),
            public_key: vec![1, 2, 3],
        };

        let node2 = TestNode {
            node_id: "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            endpoint: "endpoint2".to_string(),
            rtt_ms: 150,
            region: "us-east".to_string(),
            public_key: vec![4, 5, 6],
        };

        // Add nodes to topology
        {
            let mut topo = topology.write();
            let node1_id = NodeId::from_string(&node1.node_id).unwrap();
            let node2_id = NodeId::from_string(&node2.node_id).unwrap();

            // Parse string addresses to SocketAddr
            let addr1 = node1
                .endpoint
                .parse::<SocketAddr>()
                .unwrap_or_else(|_| "127.0.0.1:8000".parse().unwrap());
            let addr2 = node2
                .endpoint
                .parse::<SocketAddr>()
                .unwrap_or_else(|_| "127.0.0.1:8001".parse().unwrap());

            // Parse region strings to u8
            let region1 = Some(1u8); // Simplified mapping
            let region2 = Some(2u8); // Simplified mapping

            // Call add_node with the required individual parameters
            topo.add_node(node1_id.clone(), addr1, region1, 80).unwrap();

            // Call add_node with the required individual parameters
            topo.add_node(node2_id.clone(), addr2, region2, 75).unwrap();
        }

        // Add entries to routing table
        table.update_entry(node1.clone().into(), 100, None);
        table.update_entry(node2.clone().into(), 150, None);

        // Test direct node lookup through topology
        let node1_id = NodeId::from_string(&node1.node_id).unwrap();
        let node2_id = NodeId::from_string(&node2.node_id).unwrap();

        // Test find_next_hop with direct lookup
        let next_hop1 = table.find_next_hop(&node1_id);
        assert!(next_hop1.is_some());
        let next_hop1_unwrapped = next_hop1.unwrap();
        assert_eq!(next_hop1_unwrapped.id, node1.node_id);

        let next_hop2 = table.find_next_hop(&node2_id);
        assert!(next_hop2.is_some());
        let next_hop2_unwrapped = next_hop2.unwrap();
        assert_eq!(next_hop2_unwrapped.id, node2.node_id);

        // Test mark_route_failed and mark_route_success
        table.mark_route_failed(&self_id, &node1_id);
        assert!(table
            .failed_routes
            .contains_key(&(self_id.clone(), node1_id.clone())));

        table.mark_route_success(&node1_id);
        assert!(!table
            .failed_routes
            .contains_key(&(self_id.clone(), node1_id.clone())));
    }
}
