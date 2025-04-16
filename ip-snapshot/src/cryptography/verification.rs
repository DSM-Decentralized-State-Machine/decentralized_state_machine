use std::collections::{HashMap, HashSet};
use blake3::Hasher;
use sha3::{Sha3_256, Digest};

use crate::error::{Result, SnapshotError};
use crate::types::{IpEntry, SnapshotMetadata};
use crate::cryptography::canonicalization::canonicalize_ip_entries;
use crate::cryptography::hash::{HashDigest, HashAlgorithm, Hashable};

/// Verification context for batch operations
#[allow(dead_code)]
pub struct VerificationContext {
    /// Currently verified entries
    verified_entries: HashSet<String>,

    /// Verification errors
    errors: Vec<String>,

    /// Verification statistics
    stats: VerificationStats,
}

/// Verification statistics
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct VerificationStats {
    /// Total entries processed
    pub total_entries: usize,

    /// Valid entries
    pub valid_entries: usize,

    /// Invalid entries
    pub invalid_entries: usize,

    /// Country count
    pub country_count: usize,

    /// Flagged IPs (VPN/proxy)
    pub flagged_ips: usize,

    /// Hash verification success
    pub hash_verification_success: bool,
}

#[allow(dead_code)]
impl VerificationContext {
    /// Create a new verification context
    pub fn new() -> Self {
        Self {
            verified_entries: HashSet::new(),
            errors: Vec::new(),
            stats: VerificationStats::default(),
        }
    }

    /// Get verification statistics
    pub fn stats(&self) -> &VerificationStats {
        &self.stats
    }

    /// Get verification errors
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Add a verification error
    fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }

    /// Check if verification succeeded
    pub fn is_successful(&self) -> bool {
        self.errors.is_empty() && self.stats.hash_verification_success
    }

    /// Verify an IP entry's integrity
    pub fn verify_entry(&mut self, entry: &IpEntry) -> bool {
        let ip_str = entry.ip.to_string();

        // Skip if already verified
        if self.verified_entries.contains(&ip_str) {
            return true;
        }

        self.stats.total_entries += 1;

        // Verify entry hash
        let entry_valid = entry.verify_integrity();

        if entry_valid {
            self.stats.valid_entries += 1;
        } else {
            self.stats.invalid_entries += 1;
            self.add_error(format!("Invalid entry hash for IP: {}", ip_str));
        }

        // Track flagged IPs for statistics
        if entry.legitimacy_score < 50 {
            self.stats.flagged_ips += 1;
        }

        // Add to verified entries
        self.verified_entries.insert(ip_str);

        entry_valid
    }

    /// Verify a batch of entries
    pub fn verify_entries(&mut self, entries: &[IpEntry]) -> bool {
        let mut all_valid = true;

        // Verify each entry
        for entry in entries {
            if !self.verify_entry(entry) {
                all_valid = false;
                // Continue verifying other entries
            }
        }

        // Calculate country statistics
        let mut countries = HashSet::new();
        for entry in entries {
            if let Some(geo) = &entry.geo {
                if let Some(country_code) = &geo.country_code {
                    countries.insert(country_code.clone());
                }
            }
        }
        self.stats.country_count = countries.len();

        all_valid
    }

    /// Verify a snapshot's integrity
    pub fn verify_snapshot(&mut self, entries: &[IpEntry], metadata: &SnapshotMetadata) -> bool {
        // First verify all entries
        let entries_valid = self.verify_entries(entries);

        // Verify metadata hash
        let hash_valid = if metadata.data_hash.is_empty() {
            // No hash to verify
            true
        } else {
            // Calculate our own hash
            match calculate_entries_hash(entries, HashAlgorithm::Blake3) {
                Ok(calculated_hash) => {
                    let valid = calculated_hash.to_hex() == metadata.data_hash;
                    if !valid {
                        self.add_error(format!(
                            "Metadata hash mismatch. Expected: {}, calculated: {}",
                            metadata.data_hash,
                            calculated_hash.to_hex()
                        ));
                    }
                    valid
                }
                Err(e) => {
                    self.add_error(format!("Failed to calculate entries hash: {}", e));
                    false
                }
            }
        };

        self.stats.hash_verification_success = hash_valid;

        entries_valid && hash_valid
    }
}

/// Calculate hash of a collection of IP entries
#[allow(dead_code)]
pub fn calculate_entries_hash(entries: &[IpEntry], algorithm: HashAlgorithm) -> Result<HashDigest> {
    // Canonicalize entries
    let canonical_data = canonicalize_ip_entries(entries)?;

    // Hash the canonical data
    match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = Hasher::new();
            hasher.update(&canonical_data);
            let hash = hasher.finalize();
            Ok(HashDigest::new(*hash.as_bytes(), HashAlgorithm::Blake3))
        }
        HashAlgorithm::Sha3_256 => {
            let mut hasher = Sha3_256::new();
            hasher.update(&canonical_data);
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            Ok(HashDigest::new(bytes, HashAlgorithm::Sha3_256))
        }
    }
}

/// Verify a single entry's integrity
#[allow(dead_code)]
pub fn verify_entry_integrity(entry: &IpEntry) -> bool {
    let current_hash = entry.verification_hash.clone();

    // Calculate expected hash
    let calculated_hash = match entry.canonicalize() {
        Ok(canonical) => {
            let mut hasher = Hasher::new();
            hasher.update(&canonical);
            hex::encode(hasher.finalize().as_bytes())
        }
        Err(_) => return false,
    };

    // Compare hashes
    current_hash == calculated_hash
}

/// Calculate a Merkle tree root from entries
#[allow(dead_code)]
pub fn calculate_merkle_root(entries: &[IpEntry]) -> Result<HashDigest> {
    // Get sorted hashes
    let mut leaf_hashes = Vec::with_capacity(entries.len());

    for entry in entries {
        // Get canonical form of the entry
        let canonical = entry.canonicalize()?;

        // Hash the canonical form
        let hash = canonical.as_slice().hash(HashAlgorithm::Blake3)?;
        leaf_hashes.push(hash);
    }

    // Sort hashes for deterministic ordering
    leaf_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    // Calculate Merkle root
    calculate_merkle_tree_root(&leaf_hashes)
}

/// Calculate a Merkle tree root from sorted leaf hashes
#[allow(dead_code)]
pub fn calculate_merkle_tree_root(leaves: &[HashDigest]) -> Result<HashDigest> {
    if leaves.is_empty() {
        return Err(SnapshotError::Cryptographic(
            "Cannot calculate Merkle root from empty leaves".to_string(),
        ));
    }

    if leaves.len() == 1 {
        return Ok(leaves[0].clone());
    }

    // Group leaves into pairs and hash them
    let mut next_level = Vec::with_capacity(leaves.len().div_ceil(2));

    for chunk in leaves.chunks(2) {
        let left = &chunk[0];
        let right = if chunk.len() > 1 { &chunk[1] } else { left };

        // Combine the pair of hashes
        let combined = format!("{}{}", left.to_hex(), right.to_hex());
        let hash = combined.hash(HashAlgorithm::Blake3)?;

        next_level.push(hash);
    }

    // Recursively calculate the next level
    calculate_merkle_tree_root(&next_level)
}

/// Generate a cryptographic proof that an entry is included in the snapshot
#[allow(dead_code)]
pub fn generate_inclusion_proof(entry: &IpEntry, entries: &[IpEntry]) -> Result<InclusionProof> {
    // Get all hashes in deterministic order
    let mut leaf_hashes = Vec::with_capacity(entries.len());
    let mut indices = HashMap::new();

    for (i, e) in entries.iter().enumerate() {
        // Get canonical form of the entry
        let canonical = e.canonicalize()?;

        // Hash the canonical form
        let hash = canonical.as_slice().hash(HashAlgorithm::Blake3)?;
        leaf_hashes.push(hash.clone());

        // Map entry IP to its index
        indices.insert(e.ip.to_string(), i);
    }

    // Find the target entry
    let target_ip = entry.ip.to_string();
    let target_index = *indices.get(&target_ip).ok_or_else(|| {
        SnapshotError::Cryptographic(format!("Entry with IP {} not found in entries", target_ip))
    })?;

    // Calculate proof path
    let mut proof_indices = Vec::new();
    let mut proof_hashes = Vec::new();
    let mut current_index = target_index;
    let mut level_size = leaf_hashes.len();
    let mut level_hashes = leaf_hashes;

    while level_size > 1 {
        // Determine sibling index and hash
        let is_right = current_index % 2 == 1;
        let sibling_index = if is_right {
            current_index - 1
        } else {
            current_index + 1
        };

        // Add sibling to proof if it exists
        if sibling_index < level_size {
            proof_indices.push(sibling_index);
            proof_hashes.push(level_hashes[sibling_index].clone());
        }

        // Calculate next level
        let mut next_level = Vec::with_capacity(level_size.div_ceil(2));

        for chunk in level_hashes.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() > 1 { &chunk[1] } else { left };

            // Combine the pair of hashes
            let combined = format!("{}{}", left.to_hex(), right.to_hex());
            let hash = combined.hash(HashAlgorithm::Blake3)?;

            next_level.push(hash);
        }

        // Update for next iteration
        current_index /= 2;
        level_size = next_level.len();
        level_hashes = next_level;
    }

    // Root hash is the only hash in the final level
    let root_hash = level_hashes.into_iter().next().unwrap();

    Ok(InclusionProof {
        entry_index: target_index,
        entry_hash: entry
            .canonicalize()?
            .as_slice()
            .hash(HashAlgorithm::Blake3)?,
        proof_indices,
        proof_hashes,
        root_hash,
    })
}

/// A cryptographic proof that an entry is included in a snapshot
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct InclusionProof {
    /// Index of the entry in the snapshot
    pub entry_index: usize,

    /// Hash of the entry
    pub entry_hash: HashDigest,

    /// Indices of proof nodes in their respective levels
    pub proof_indices: Vec<usize>,

    /// Hashes in the proof path
    pub proof_hashes: Vec<HashDigest>,

    /// Root hash of the Merkle tree
    pub root_hash: HashDigest,
}

#[allow(dead_code)]
impl InclusionProof {
    /// Verify this inclusion proof
    pub fn verify(&self, entry: &IpEntry) -> Result<bool> {
        // Verify the entry hash
        let calculated_entry_hash = entry
            .canonicalize()?
            .as_slice()
            .hash(HashAlgorithm::Blake3)?;

        if calculated_entry_hash != self.entry_hash {
            return Ok(false);
        }

        // Reconstruct root hash from proof
        let mut current_hash = self.entry_hash.clone();
        let mut current_index = self.entry_index;

        for proof_hash in self.proof_hashes.iter() {
            let is_right = current_index % 2 == 1;

            // Combine with proof hash in the correct order
            let combined = if is_right {
                format!("{}{}", proof_hash.to_hex(), current_hash.to_hex())
            } else {
                format!("{}{}", current_hash.to_hex(), proof_hash.to_hex())
            };

            // Hash the combination
            current_hash = combined.hash(HashAlgorithm::Blake3)?;

            // Update index for next level
            current_index /= 2;
        }

        // Final hash should match root hash
        Ok(current_hash == self.root_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::types::{GeoInformation, NetworkInformation};

    fn create_test_entry(ip: IpAddr, legitimacy_score: u8) -> IpEntry {
        let now = Utc::now();

        let mut entry = IpEntry {
            ip,
            first_seen: now,
            last_seen: now,
            connection_count: 1,
            geo: Some(GeoInformation {
                country_code: Some("US".to_string()),
                country_name: Some("United States".to_string()),
                city: None,
                coordinates: None,
                continent_code: None,
                time_zone: None,
            }),
            network: NetworkInformation::default(),
            legitimacy_score,
            verification_hash: String::new(), // Will be calculated
        };

        // Calculate verification hash
        if let Ok(canonical) = entry.canonicalize() {
            let mut hasher = Hasher::new();
            hasher.update(&canonical);
            entry.verification_hash = hex::encode(hasher.finalize().as_bytes());
        }

        entry
    }

    #[test]
    fn test_verify_entry() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let entry = create_test_entry(ip, 85);

        // Verify the entry
        let mut context = VerificationContext::new();
        assert!(context.verify_entry(&entry));

        // Check stats
        assert_eq!(context.stats().total_entries, 1);
        assert_eq!(context.stats().valid_entries, 1);
        assert_eq!(context.stats().invalid_entries, 0);

        // Try with invalid hash
        let mut invalid_entry = entry.clone();
        invalid_entry.verification_hash = "invalid_hash".to_string();

        let mut context = VerificationContext::new();
        assert!(!context.verify_entry(&invalid_entry));

        // Check stats
        assert_eq!(context.stats().total_entries, 1);
        assert_eq!(context.stats().valid_entries, 0);
        assert_eq!(context.stats().invalid_entries, 1);
    }

    #[test]
    fn test_verify_entries() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 25), // Flagged as VPN
            create_test_entry(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 95),
        ];

        // Verify entries
        let mut context = VerificationContext::new();
        assert!(context.verify_entries(&entries));

        // Check stats
        assert_eq!(context.stats().total_entries, 3);
        assert_eq!(context.stats().valid_entries, 3);
        assert_eq!(context.stats().invalid_entries, 0);
        assert_eq!(context.stats().country_count, 1); // All from US
        assert_eq!(context.stats().flagged_ips, 1); // One VPN
    }

    #[test]
    fn test_calculate_entries_hash() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 75),
        ];

        // Calculate hash
        let hash = calculate_entries_hash(&entries, HashAlgorithm::Blake3).unwrap();

        // Same entries should produce same hash
        let hash2 = calculate_entries_hash(&entries, HashAlgorithm::Blake3).unwrap();
        assert_eq!(hash, hash2);

        // Different entries should produce different hash
        let entries2 = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 75), // Different IP
        ];

        let hash3 = calculate_entries_hash(&entries2, HashAlgorithm::Blake3).unwrap();
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_merkle_tree() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 75),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 95),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        ];

        // Calculate Merkle root
        let root = calculate_merkle_root(&entries).unwrap();

        // Same entries should produce same root
        let root2 = calculate_merkle_root(&entries).unwrap();
        assert_eq!(root, root2);

        // Different entries should produce different root
        let entries2 = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 75), // Different IP
            create_test_entry(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 95),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        ];

        let root3 = calculate_merkle_root(&entries2).unwrap();
        assert_ne!(root, root3);
    }

    #[test]
    fn test_inclusion_proof() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 75),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 95),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
        ];

        // Generate proof for the third entry
        let proof = generate_inclusion_proof(&entries[2], &entries).unwrap();

        // Verify the proof
        let valid = proof.verify(&entries[2]).unwrap();
        assert!(valid);

        // Invalid entry should fail verification
        let invalid_entry = create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 85);
        let invalid = proof.verify(&invalid_entry).unwrap();
        assert!(!invalid);
    }
}
