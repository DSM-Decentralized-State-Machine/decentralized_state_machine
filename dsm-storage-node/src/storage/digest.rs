// Optimized digest generation for epidemic storage
//
// This module provides efficient digest generation and comparison algorithms
// for minimizing bandwidth consumption during epidemic protocol synchronization.

use crate::error::Result;
use crate::storage::vector_clock::VectorClock;
// Forward declaration of the EpidemicEntry type we'll define
#[derive(Debug, Clone)]
pub struct EpidemicEntry {
    pub entry: crate::types::BlindedStateEntry,
    pub vector_clock: VectorClock,
    pub last_modified: u64,
    pub last_sync: u64,
    pub received_from: Option<String>,
    pub propagation_count: u32,
    pub verification_count: u32,
    pub origin_region: String,
}
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// A compact representation of an entry for digest generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestEntry {
    /// Vector clock for causal ordering
    pub vector_clock: VectorClock,

    /// Hash of the payload
    pub hash: [u8; 32],

    /// Last modified timestamp
    pub timestamp: u64,

    /// Entry size in bytes
    pub size: usize,
}

/// A compact digest of storage entries for efficient synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDigest {
    /// Digest entries
    pub entries: HashMap<String, DigestEntry>,

    /// Node ID that generated the digest
    pub node_id: String,

    /// Region
    pub region: String,

    /// Generation timestamp
    pub timestamp: u64,

    /// Digest type
    pub digest_type: DigestType,

    /// Merkle tree root hash (for tree digests)
    pub merkle_root: Option<[u8; 32]>,
}

/// Type of digest
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum DigestType {
    /// Full digest contains all entries
    Full,

    /// Incremental digest contains only changed entries since a timestamp
    Incremental,

    /// Delta digest contains only the specified entries
    Delta,

    /// Region digest contains entries from a specific region
    Region,

    /// Bloom digest uses a bloom filter for efficient set difference
    Bloom,

    /// Merkle digest uses a merkle tree for efficient set reconciliation
    Merkle,
}

/// Digest difference result
#[derive(Debug, Clone)]
pub struct DigestDiff {
    /// Entries only in the first digest
    pub only_in_first: HashSet<String>,

    /// Entries only in the second digest
    pub only_in_second: HashSet<String>,

    /// Entries in both but different (conflicting)
    pub conflicts: HashMap<String, (DigestEntry, DigestEntry)>,

    /// Total entries compared
    pub total_compared: usize,
}

/// Merkle tree node for efficient digest comparison
#[derive(Debug, Clone)]
pub struct MerkleNode {
    /// Hash of this node
    pub hash: [u8; 32],

    /// Entries in this node (leaf nodes only)
    pub entries: Option<Vec<String>>,

    /// Children nodes
    pub children: Vec<MerkleNode>,
}

/// Digest generator for epidemic storage
#[derive(Debug)]
pub struct DigestGenerator {
    /// Node ID
    #[allow(dead_code)]
    node_id: String,

    /// Region
    region: String,

    /// Bloom filter size for bloom digests (bits)
    #[allow(dead_code)]
    bloom_filter_size: usize,

    /// Bloom filter hash count
    #[allow(dead_code)]
    bloom_hash_count: usize,

    /// Maximum entries per digest
    max_entries_per_digest: usize,

    /// Merkle tree branching factor
    merkle_branching_factor: usize,
}

impl DigestGenerator {
    /// Create a new digest generator
    pub fn new(node_id: String, region: String) -> Self {
        Self {
            node_id,
            region,
            bloom_filter_size: 8192, // 1KB bloom filter
            bloom_hash_count: 5,
            max_entries_per_digest: 1000,
            merkle_branching_factor: 4,
        }
    }

    /// Generate a full digest from entries
    pub fn generate_full_digest<'a, I>(&self, entries: I) -> Result<StorageDigest>
    where
        I: IntoIterator<Item = &'a EpidemicEntry>,
    {
        let mut digest_entries = HashMap::new();

        // Process entries
        for entry in entries {
            digest_entries.insert(
                entry.entry.blinded_id.clone(),
                self.create_digest_entry(entry),
            );
        }

        // Limit entries if needed
        if digest_entries.len() > self.max_entries_per_digest {
            debug!(
                "Limiting digest from {} to {} entries",
                digest_entries.len(),
                self.max_entries_per_digest
            );

            // Keep only up to max_entries_per_digest with most recent timestamps
            let mut entries_vec: Vec<(String, DigestEntry)> = digest_entries.into_iter().collect();
            entries_vec.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp)); // Sort by timestamp (desc)
            entries_vec.truncate(self.max_entries_per_digest);
            digest_entries = entries_vec.into_iter().collect();
        }

        Ok(StorageDigest {
            entries: digest_entries,
            node_id: self.node_id.clone(),
            region: self.region.clone(),
            timestamp: self.current_timestamp(),
            digest_type: DigestType::Full,
            merkle_root: None,
        })
    }

    /// Generate an incremental digest since a specific timestamp
    pub fn generate_incremental_digest<'a, I>(
        &self,
        entries: I,
        since_timestamp: u64,
    ) -> Result<StorageDigest>
    where
        I: IntoIterator<Item = &'a EpidemicEntry>,
    {
        let mut digest_entries = HashMap::new();

        // Process entries
        for entry in entries {
            // Only include entries modified since the timestamp
            if entry.last_modified >= since_timestamp {
                digest_entries.insert(
                    entry.entry.blinded_id.clone(),
                    self.create_digest_entry(entry),
                );
            }
        }

        // Limit entries if needed (same as full digest)
        if digest_entries.len() > self.max_entries_per_digest {
            debug!(
                "Limiting incremental digest from {} to {} entries",
                digest_entries.len(),
                self.max_entries_per_digest
            );

            let mut entries_vec: Vec<(String, DigestEntry)> = digest_entries.into_iter().collect();
            entries_vec.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp)); // Sort by timestamp (desc)
            entries_vec.truncate(self.max_entries_per_digest);
            digest_entries = entries_vec.into_iter().collect();
        }

        Ok(StorageDigest {
            entries: digest_entries,
            node_id: self.node_id.clone(),
            region: self.region.clone(),
            timestamp: self.current_timestamp(),
            digest_type: DigestType::Incremental,
            merkle_root: None,
        })
    }

    /// Generate a delta digest for specific entries
    pub fn generate_delta_digest<'a, I>(
        &self,
        entries: I,
        ids: &HashSet<String>,
    ) -> Result<StorageDigest>
    where
        I: IntoIterator<Item = &'a EpidemicEntry>,
    {
        let mut digest_entries = HashMap::new();

        // Process entries
        for entry in entries {
            if ids.contains(&entry.entry.blinded_id) {
                digest_entries.insert(
                    entry.entry.blinded_id.clone(),
                    self.create_digest_entry(entry),
                );
            }
        }

        Ok(StorageDigest {
            entries: digest_entries,
            node_id: self.node_id.clone(),
            region: self.region.clone(),
            timestamp: self.current_timestamp(),
            digest_type: DigestType::Delta,
            merkle_root: None,
        })
    }

    /// Generate a region digest
    pub fn generate_region_digest<'a, I>(
        &self,
        entries: I,
        target_region: &str,
    ) -> Result<StorageDigest>
    where
        I: IntoIterator<Item = &'a EpidemicEntry>,
    {
        let mut digest_entries = HashMap::new();

        // Process entries
        for entry in entries {
            if entry.entry.region == target_region {
                digest_entries.insert(
                    entry.entry.blinded_id.clone(),
                    self.create_digest_entry(entry),
                );
            }
        }

        // Limit entries if needed (same as full digest)
        if digest_entries.len() > self.max_entries_per_digest {
            debug!(
                "Limiting region digest from {} to {} entries",
                digest_entries.len(),
                self.max_entries_per_digest
            );

            let mut entries_vec: Vec<(String, DigestEntry)> = digest_entries.into_iter().collect();
            entries_vec.sort_by(|a, b| b.1.timestamp.cmp(&a.1.timestamp)); // Sort by timestamp (desc)
            entries_vec.truncate(self.max_entries_per_digest);
            digest_entries = entries_vec.into_iter().collect();
        }

        Ok(StorageDigest {
            entries: digest_entries,
            node_id: self.node_id.clone(),
            region: target_region.to_string(),
            timestamp: self.current_timestamp(),
            digest_type: DigestType::Region,
            merkle_root: None,
        })
    }

    /// Generate a bloom filter digest
    pub fn generate_bloom_digest<'a, I>(&self, entries: I) -> Result<StorageDigest>
    where
        I: IntoIterator<Item = &'a EpidemicEntry>,
    {
        // This would normally use a bloom filter library
        // For simplicity, we'll just use a hash set of IDs

        // Extract entry IDs into a set
        let ids: HashSet<String> = entries
            .into_iter()
            .map(|e| e.entry.blinded_id.clone())
            .collect();

        // Create a hash representing a bloom filter
        let bloom_hash = self.compute_bloom_filter_hash(&ids);

        // Create an empty digest with the bloom hash
        Ok(StorageDigest {
            entries: HashMap::new(), // No actual entries
            node_id: self.node_id.clone(),
            region: self.region.clone(),
            timestamp: self.current_timestamp(),
            digest_type: DigestType::Bloom,
            merkle_root: Some(bloom_hash),
        })
    }

    /// Generate a Merkle tree digest
    pub fn generate_merkle_digest<'a, I>(&self, entries: I) -> Result<StorageDigest>
    where
        I: IntoIterator<Item = &'a EpidemicEntry>,
    {
        let mut entry_map = HashMap::new();

        // Process entries
        for entry in entries {
            entry_map.insert(
                entry.entry.blinded_id.clone(),
                self.create_digest_entry(entry),
            );
        }

        // Build the Merkle tree
        let tree = self.build_merkle_tree(&entry_map);

        // Extract the root hash
        let root_hash = tree.map(|node| node.hash);

        Ok(StorageDigest {
            entries: HashMap::new(), // No entries, just the Merkle root
            node_id: self.node_id.clone(),
            region: self.region.clone(),
            timestamp: self.current_timestamp(),
            digest_type: DigestType::Merkle,
            merkle_root: root_hash,
        })
    }

    /// Compare two digests to find differences
    pub fn compare_digests(&self, digest1: &StorageDigest, digest2: &StorageDigest) -> DigestDiff {
        let mut only_in_first = HashSet::new();
        let mut only_in_second = HashSet::new();
        let mut conflicts = HashMap::new();

        // First, check entries only in digest1
        for (id, entry1) in &digest1.entries {
            match digest2.entries.get(id) {
                Some(entry2) => {
                    // Check if they differ
                    if entry1.hash != entry2.hash || entry1.vector_clock != entry2.vector_clock {
                        conflicts.insert(id.clone(), (entry1.clone(), entry2.clone()));
                    }
                }
                None => {
                    only_in_first.insert(id.clone());
                }
            }
        }

        // Then, check entries only in digest2
        for id in digest2.entries.keys() {
            if !digest1.entries.contains_key(id) {
                only_in_second.insert(id.clone());
            }
        }

        DigestDiff {
            only_in_first,
            only_in_second,
            conflicts,
            total_compared: digest1.entries.len() + digest2.entries.len(),
        }
    }

    /// Create a digest entry from an epidemic entry
    fn create_digest_entry(&self, entry: &EpidemicEntry) -> DigestEntry {
        // Compute hash of the payload
        let mut hasher = Hasher::new();
        hasher.update(&entry.entry.encrypted_payload);
        let hash = hasher.finalize();

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(hash.as_bytes());

        DigestEntry {
            vector_clock: entry.vector_clock.clone(),
            hash: hash_bytes,
            timestamp: entry.last_modified,
            size: entry.entry.encrypted_payload.len(),
        }
    }

    /// Compute a hash representing a bloom filter
    fn compute_bloom_filter_hash(&self, ids: &HashSet<String>) -> [u8; 32] {
        // This is a simplified simulation of a bloom filter hash
        let mut hasher = Hasher::new();

        // Sort ids for deterministic hashing
        let mut sorted_ids: Vec<&String> = ids.iter().collect();
        sorted_ids.sort();

        // Hash each ID
        for id in sorted_ids {
            hasher.update(id.as_bytes());
        }

        // Get the result
        let hash = hasher.finalize();

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(hash.as_bytes());

        hash_bytes
    }

    /// Build a Merkle tree from entries
    fn build_merkle_tree(&self, entries: &HashMap<String, DigestEntry>) -> Option<MerkleNode> {
        if entries.is_empty() {
            return None;
        }

        // For leaf nodes, we group entries in buckets
        if entries.len() <= self.merkle_branching_factor {
            // Create a leaf node containing these entries
            let mut hasher = Hasher::new();

            // Sort keys for deterministic hashing
            let mut keys: Vec<&String> = entries.keys().collect();
            keys.sort();

            for key in &keys {
                if let Some(entry) = entries.get(*key) {
                    // Hash the key and vector clock
                    hasher.update(key.as_bytes());
                    hasher.update(entry.hash.as_ref());
                }
            }

            let hash = hasher.finalize();

            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());

            return Some(MerkleNode {
                hash: hash_bytes,
                entries: Some(keys.iter().map(|s| (*s).clone()).collect()),
                children: Vec::new(),
            });
        }

        // For internal nodes, split the entries into groups
        let mut groups: Vec<HashMap<String, DigestEntry>> = Vec::new();
        for _ in 0..self.merkle_branching_factor {
            groups.push(HashMap::new());
        }

        // Distribute entries among groups based on hash
        for (key, entry) in entries {
            // Use a hash of the key to determine which group
            let mut hasher = Hasher::new();
            hasher.update(key.as_bytes());
            let hash = hasher.finalize();

            // Use first byte modulo branching factor
            let group_index = (hash.as_bytes()[0] as usize) % self.merkle_branching_factor;
            groups[group_index].insert(key.clone(), entry.clone());
        }

        // Build child nodes
        let mut children = Vec::new();
        for group in groups {
            if let Some(child) = self.build_merkle_tree(&group) {
                children.push(child);
            }
        }

        if children.is_empty() {
            return None;
        }

        // Create parent node hash from children
        let mut hasher = Hasher::new();
        for child in &children {
            hasher.update(&child.hash);
        }

        let hash = hasher.finalize();

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(hash.as_bytes());

        Some(MerkleNode {
            hash: hash_bytes,
            entries: None,
            children,
        })
    }

    /// Get the current timestamp
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs()
    }

    /// Serialize a digest to bytes
    pub fn serialize_digest(&self, digest: &StorageDigest) -> Result<Vec<u8>> {
        bincode::serialize(digest).map_err(|e| {
            crate::error::StorageNodeError::Serialization(format!(
                "Failed to serialize digest: {}",
                e
            ))
        })
    }

    /// Deserialize a digest from bytes
    pub fn deserialize_digest(&self, bytes: &[u8]) -> Result<StorageDigest> {
        bincode::deserialize(bytes).map_err(|e| {
            crate::error::StorageNodeError::Serialization(format!(
                "Failed to deserialize digest: {}",
                e
            ))
        })
    }
}

/// Digest registry for tracking peer digests
pub struct DigestRegistry {
    #[allow(dead_code)]
    /// Node ID
    node_id: String,

    /// Last seen digests from peers
    peer_digests: HashMap<String, StorageDigest>,

    /// Last digest generation timestamps by type
    last_generation: HashMap<DigestType, u64>,

    /// Known difference sets
    difference_sets: HashMap<String, DigestDiff>,
}
impl DigestRegistry {
    /// Create a new digest registry
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            peer_digests: HashMap::new(),
            last_generation: HashMap::new(),
            difference_sets: HashMap::new(),
        }
    }

    /// Register a peer digest
    pub fn register_peer_digest(&mut self, peer_id: &str, digest: StorageDigest) {
        self.peer_digests.insert(peer_id.to_string(), digest);
    }

    /// Get a peer digest
    pub fn get_peer_digest(&self, peer_id: &str) -> Option<&StorageDigest> {
        self.peer_digests.get(peer_id)
    }

    /// Register a digest generation
    pub fn register_generation(&mut self, digest_type: DigestType, timestamp: u64) {
        self.last_generation.insert(digest_type, timestamp);
    }

    /// Get the last generation timestamp for a digest type
    pub fn get_last_generation(&self, digest_type: DigestType) -> Option<u64> {
        self.last_generation.get(&digest_type).cloned()
    }

    /// Register a difference set
    pub fn register_difference_set(&mut self, peer_id: &str, diff: DigestDiff) {
        self.difference_sets.insert(peer_id.to_string(), diff);
    }

    /// Get a difference set
    pub fn get_difference_set(&self, peer_id: &str) -> Option<&DigestDiff> {
        self.difference_sets.get(peer_id)
    }

    /// Clear old digests
    pub fn clear_old_digests(&mut self, max_age_secs: u64) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        self.peer_digests
            .retain(|_, digest| current_time - digest.timestamp <= max_age_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::digest::EpidemicEntry;
    use crate::types::BlindedStateEntry;
    use std::collections::HashMap;

    fn create_test_entry(
        blinded_id: &str,
        payload: Vec<u8>,
        node_id: &str,
        counter: u64,
    ) -> EpidemicEntry {
        let entry = BlindedStateEntry {
            blinded_id: blinded_id.to_string(),
            encrypted_payload: payload,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            ttl: 3600,
            region: "test-region".to_string(),
            priority: 0,
            proof_hash: [0; 32],
            metadata: HashMap::new(),
        };

        let mut vector_clock = VectorClock::new();
        vector_clock.set(node_id, counter);

        EpidemicEntry {
            entry,
            vector_clock,
            last_modified: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            last_sync: 0,
            received_from: Some(node_id.to_string()),
            propagation_count: 0,
            verification_count: 1,
            origin_region: "test-region".to_string(),
        }
    }

    #[test]
    fn test_full_digest_generation() {
        let generator = DigestGenerator::new("test-node".to_string(), "test-region".to_string());

        // Create some test entries
        let entries = vec![
            create_test_entry("entry1", vec![1, 2, 3], "node1", 1),
            create_test_entry("entry2", vec![4, 5, 6], "node2", 1),
            create_test_entry("entry3", vec![7, 8, 9], "node3", 1),
        ];

        // Generate a full digest
        let digest = generator.generate_full_digest(&entries).unwrap();

        // Verify digest
        assert_eq!(digest.entries.len(), 3);
        assert_eq!(digest.node_id, "test-node");
        assert_eq!(digest.region, "test-region");
        assert_eq!(digest.digest_type, DigestType::Full);
        assert!(digest.merkle_root.is_none());

        // Check that all entries are included
        assert!(digest.entries.contains_key("entry1"));
        assert!(digest.entries.contains_key("entry2"));
        assert!(digest.entries.contains_key("entry3"));
    }

    #[test]
    fn test_digest_comparison() {
        let generator = DigestGenerator::new("test-node".to_string(), "test-region".to_string());

        // Create first set of entries
        let mut entries1 = vec![
            create_test_entry("entry1", vec![1, 2, 3], "node1", 1),
            create_test_entry("entry2", vec![4, 5, 6], "node2", 1),
            create_test_entry("common", vec![7, 8, 9], "node3", 1),
        ];

        // Create second set of entries (different)
        let entries2 = vec![
            create_test_entry("common", vec![7, 8, 9], "node3", 1), // Same
            create_test_entry("entry3", vec![10, 11, 12], "node4", 1), // New
            create_test_entry("conflict", vec![13, 14, 15], "node5", 1), // Different
        ];

        // Create a third entry with conflict
        let mut entries3 = vec![
            create_test_entry("conflict", vec![16, 17, 18], "node6", 2), // Different
        ];

        // Generate digests
        let digest1 = generator.generate_full_digest(&entries1).unwrap();
        let digest2 = generator.generate_full_digest(&entries2).unwrap();
        let digest3 = generator.generate_full_digest(&entries3).unwrap();

        // Compare digests
        let diff = generator.compare_digests(&digest1, &digest2);

        // Verify differences
        assert_eq!(diff.only_in_first.len(), 2); // entry1, entry2
        assert_eq!(diff.only_in_second.len(), 2); // entry3, conflict
        assert_eq!(diff.conflicts.len(), 0); // No conflicts yet

        // Add conflict entry to both lists and compare again
        entries1.push(create_test_entry("conflict", vec![13, 14, 15], "node5", 1));
        entries3[0] = create_test_entry("conflict", vec![16, 17, 18], "node6", 2);

        let digest1b = generator.generate_full_digest(&entries1).unwrap();

        let diff2 = generator.compare_digests(&digest1b, &digest3);

        // Verify conflict
        assert_eq!(diff2.conflicts.len(), 1);
        assert!(diff2.conflicts.contains_key("conflict"));
    }
}
