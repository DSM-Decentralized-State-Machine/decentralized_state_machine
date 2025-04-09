// Vector clock implementation for epidemic coordination
//
// This module provides a vector clock implementation that allows proper
// causal ordering of events in a distributed system, which is essential
// for epidemic coordination protocols.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vector clock relation between two clocks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorClockRelation {
    /// This clock happens before the other
    Before,

    /// This clock happens after the other
    After,

    /// This clock is concurrent with the other
    Concurrent,

    /// This clock is equal to the other
    Equal,
}

/// Vector clock for tracking causal relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorClock {
    /// Map of node IDs to logical clock values
    pub counters: HashMap<String, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    /// Create a vector clock with a single entry
    pub fn with_node(node_id: String, value: u64) -> Self {
        let mut counters = HashMap::new();
        counters.insert(node_id, value);
        Self { counters }
    }

    /// Increment the counter for a node
    pub fn increment(&mut self, node_id: &str) {
        let counter = self.counters.entry(node_id.to_string()).or_insert(0);
        *counter += 1;
    }

    /// Get the counter value for a node
    pub fn get(&self, node_id: &str) -> u64 {
        *self.counters.get(node_id).unwrap_or(&0)
    }

    /// Set the counter value for a node
    pub fn set(&mut self, node_id: &str, value: u64) {
        self.counters.insert(node_id.to_string(), value);
    }

    /// Merge with another vector clock, taking the maximum values
    pub fn merge(&mut self, other: &VectorClock) {
        for (node_id, &counter) in &other.counters {
            let entry = self.counters.entry(node_id.clone()).or_insert(0);
            *entry = std::cmp::max(*entry, counter);
        }
    }

    /// Compare this vector clock with another, determining their causal relationship
    pub fn compare(&self, other: &VectorClock) -> VectorClockRelation {
        let mut self_gt = false;
        let mut other_gt = false;

        // Check all counters in self
        for (node_id, &self_counter) in &self.counters {
            let other_counter = other.get(node_id);

            match self_counter.cmp(&other_counter) {
                std::cmp::Ordering::Greater => self_gt = true,
                std::cmp::Ordering::Less => other_gt = true,
                std::cmp::Ordering::Equal => {}
            }

            // Early exit - concurrent detected
            if self_gt && other_gt {
                return VectorClockRelation::Concurrent;
            }
        }

        // Check all counters in other that might not be in self
        for (node_id, &other_counter) in &other.counters {
            if !self.counters.contains_key(node_id) && other_counter > 0 {
                other_gt = true;
            }

            // Early exit - concurrent detected
            if self_gt && other_gt {
                return VectorClockRelation::Concurrent;
            }
        }

        // Determine the relationship
        match (self_gt, other_gt) {
            (true, false) => VectorClockRelation::After,
            (false, true) => VectorClockRelation::Before,
            (false, false) => VectorClockRelation::Equal,
            (true, true) => VectorClockRelation::Concurrent,
        }
    }

    /// Check if this vector clock dominates another
    pub fn dominates(&self, other: &VectorClock) -> bool {
        matches!(
            self.compare(other),
            VectorClockRelation::After | VectorClockRelation::Equal
        )
    }

    /// Return a compact JSON representation of the clock
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Create a vector clock from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

// Custom implementation for maximum digest space efficiency
impl std::fmt::Display for VectorClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut entries: Vec<(&String, &u64)> = self.counters.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        write!(f, "{{")?;
        for (i, (node_id, counter)) in entries.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            write!(f, "{}:{}", node_id, counter)?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_comparison() {
        // Setup clocks
        let mut clock1 = VectorClock::new();
        clock1.set("node1", 1);
        clock1.set("node2", 2);

        let mut clock2 = VectorClock::new();
        clock2.set("node1", 2);
        clock2.set("node2", 2);

        let mut clock3 = VectorClock::new();
        clock3.set("node1", 1);
        clock3.set("node2", 3);

        // Tests
        assert_eq!(clock1.compare(&clock1), VectorClockRelation::Equal);
        assert_eq!(clock1.compare(&clock2), VectorClockRelation::Before);
        assert_eq!(clock2.compare(&clock1), VectorClockRelation::After);
        assert_eq!(clock1.compare(&clock3), VectorClockRelation::Before);
        assert_eq!(clock3.compare(&clock1), VectorClockRelation::After);
        assert_eq!(clock2.compare(&clock3), VectorClockRelation::Concurrent);
        assert_eq!(clock3.compare(&clock2), VectorClockRelation::Concurrent);
    }

    #[test]
    fn test_vector_clock_merge() {
        let mut clock1 = VectorClock::new();
        clock1.set("node1", 1);
        clock1.set("node2", 2);

        let mut clock2 = VectorClock::new();
        clock2.set("node1", 2);
        clock2.set("node3", 3);

        clock1.merge(&clock2);

        assert_eq!(clock1.get("node1"), 2);
        assert_eq!(clock1.get("node2"), 2);
        assert_eq!(clock1.get("node3"), 3);
    }

    #[test]
    fn test_vector_clock_json() {
        let mut clock = VectorClock::new();
        clock.set("node1", 1);
        clock.set("node2", 2);

        let json = clock.to_json();
        let parsed = VectorClock::from_json(&json).unwrap();

        assert_eq!(clock, parsed);
    }
}
