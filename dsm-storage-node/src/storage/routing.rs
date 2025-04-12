// Routing module for epidemic storage with small-world topology
//
// This module implements efficient routing strategies for the small-world topology
// to ensure optimal message delivery and request handling.

use crate::storage::small_world::{NodeId, SmallWorldTopology, Distance, calculate_key_hash};
use crate::types::StorageNode;

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

/// Routing table for the small-world topology
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
    topology: Arc<parking_lot::RwLock<SmallWorldTopology>>,
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(
        self_id: NodeId,
        topology: Arc<parking_lot::RwLock<SmallWorldTopology>>,
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
            let neighbor_id = NodeId::from(neighbor);
            visited.insert(neighbor_id.clone());
            queue.push_back(neighbor_id.clone());
            paths.insert(neighbor_id, vec![neighbor.clone()]);
        }

        // Also consider long links
        for link in topology_guard.long_links() {
            let link_id = NodeId::from(link);
            if !visited.contains(&link_id) {
                visited.insert(link_id.clone());
                queue.push_back(link_id.clone());
                paths.insert(link_id, vec![link.clone()]);
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
                Some(node) => node,
                None => continue,
            };

            // Get neighbors of the current node
            let neighbors = self.get_node_neighbors(current_node, &topology_guard);

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
        topology: &SmallWorldTopology,
    ) -> Vec<StorageNode> {
        // This is a simplified approach; in a real implementation, we would need
        // to query the node for its neighbors or use a more sophisticated approach
        let node_id = NodeId::from(node);

        // Find nodes that might be neighbors of this node
        let mut potential_neighbors = Vec::new();

        // Assume nodes close to this node in ID space might be its neighbors
        potential_neighbors.extend(topology.find_closest_nodes(&node_id, 5, None));

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
    fn greedy_routing(
        &self,
        target: &NodeId,
        topology: &SmallWorldTopology,
    ) -> Option<StorageNode> {
        let closest = topology.find_closest_nodes(target, 1, None);

        if !closest.is_empty() {
            Some(closest[0].clone())
        } else {
            None
        }
    }

    /// Perimeter routing strategy (route around obstacles)
    fn perimeter_routing(
        &self,
        target: &NodeId,
        topology: &SmallWorldTopology,
    ) -> Option<StorageNode> {
        let mut closest = topology.find_closest_nodes(target, 5, None);

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
            Some(closest[0].clone())
        } else {
            // Fall back to greedy if perimeter doesn't work
            self.greedy_routing(target, topology)
        }
    }

    /// Probabilistic routing strategy (choose with probability)
    fn probabilistic_routing(
        &self,
        target: &NodeId,
        topology: &SmallWorldTopology,
    ) -> Option<StorageNode> {
        let closest = topology.find_closest_nodes(target, 3, None);

        if !closest.is_empty() {
            // Simple probabilistic approach - choose randomly from top 3
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            closest.choose(&mut rng).cloned()
        } else {
            None
        }
    }

    /// Hybrid routing strategy (combine strategies)
    fn hybrid_routing(
        &self,
        target: &NodeId,
        topology: &SmallWorldTopology,
    ) -> Option<StorageNode> {
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

    /// Find responsible nodes for a key
    pub fn find_responsible_nodes(&self, key: &[u8], count: usize) -> Vec<StorageNode> {
        let key_hash = calculate_key_hash(key);
        let topology_guard = self.topology.read();
        topology_guard.find_responsible_nodes(&key_hash, count)
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
        topology: Arc<parking_lot::RwLock<SmallWorldTopology>>,
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
    use crate::storage::small_world::SmallWorldConfig;

    #[test]
    fn test_routing_table() {
        // Create test nodes
        let self_id = NodeId::from_string("self");
        let node1 = StorageNode {
            id: "node1".to_string(),
            name: "Node 1".to_string(),
            region: "test".to_string(),
            public_key: "pk1".to_string(),
            endpoint: "http://node1.example.com".to_string(),
        };
        let node2 = StorageNode {
            id: "node2".to_string(),
            name: "Node 2".to_string(),
            region: "test".to_string(),
            public_key: "pk2".to_string(),
            endpoint: "http://node2.example.com".to_string(),
        };

        // Create topology with an empty immediate neighbors list to prevent any potential hanging
        let self_node = StorageNode {
            id: "self".to_string(),
            name: "Self Node".to_string(),
            region: "test".to_string(),
            public_key: "pk-self".to_string(),
            endpoint: "http://self.example.com".to_string(),
        };

        let config = SmallWorldConfig {
            max_bucket_size: 4,
            max_immediate_neighbors: 4,
            max_long_links: 4,
        };

        let topology = SmallWorldTopology::new(self_node, config);

        // Add test nodes to topology explicitly
        {
            let mut topo = topology.clone();
            topo.add_node(node1.clone());
            topo.add_node(node2.clone());
        }

        let topology_arc = Arc::new(parking_lot::RwLock::new(topology));

        // Create routing table with a smaller cache to avoid excessive memory usage
        let table = RoutingTable::new(
            self_id.clone(),
            topology_arc.clone(),
            RoutingStrategy::Greedy,
        );

        // Add entries
        table.update_entry(node1.clone(), 1, None);
        table.update_entry(node2.clone(), 2, Some(node1.clone()));

        // Test find_next_hop with direct lookup (avoiding any potential routing calculation)
        let node1_id = NodeId::from_string("node1");
        let node2_id = NodeId::from_string("node2");

        // Test with entries we explicitly added
        let next_hop1 = table.find_next_hop(&node1_id);
        assert!(next_hop1.is_some());
        assert_eq!(next_hop1.unwrap().id, node1.id);

        let next_hop2 = table.find_next_hop(&node2_id);
        assert!(next_hop2.is_some());
        assert_eq!(next_hop2.unwrap().id, node1.id);

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
