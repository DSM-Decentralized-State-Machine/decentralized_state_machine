use std::collections::HashMap;
use blake3::Hasher;
use serde::{Serialize, Deserialize};
use rand::{thread_rng, RngCore};
use hex::encode;
use chrono::{DateTime, Utc};
use tracing::debug;

use crate::error::{Result, SnapshotError};
use crate::types::IpEntry;
use crate::cryptography::hash::{HashDigest, HashAlgorithm, Hashable};
use crate::cryptography::verification::{calculate_merkle_root, calculate_entries_hash};

/// A cryptographic commitment to a snapshot of IP addresses
///
/// This structure implements a tamper-evident, binding commitment that can be
/// published as evidence of the snapshot contents without revealing the actual data.
/// It uses a combination of Merkle trees and salt-based commitments for enhanced security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotCommitment {
    /// Unique identifier for this commitment
    pub id: String,

    /// Creation timestamp
    pub timestamp: DateTime<Utc>,

    /// Merkle root of all IP entries
    pub merkle_root: HashDigest,

    /// Total number of IPs committed to
    pub total_ips: usize,

    /// Commitment salt (random value to prevent brute-force attacks)
    pub salt: [u8; 32],

    /// Secondary verification hash using SHA3-256
    pub secondary_hash: HashDigest,

    /// Distribution entropy source (for deterministic allocation)
    pub distribution_entropy: [u8; 32],

    /// Cryptographic binding to external systems (e.g., blockchain)
    pub external_binding: Option<ExternalBinding>,

    /// Statistics commitments (country counts, etc.)
    pub stats_commitment: StatsCommitment,
}

/// Binding to external cryptographic systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalBinding {
    /// System identifier (e.g., "ethereum", "dsm")
    pub system: String,

    /// Block or sequence number
    pub sequence_number: u64,

    /// Transaction or commitment ID
    pub transaction_id: String,

    /// Timestamp of binding
    pub timestamp: DateTime<Utc>,

    /// Signature or proof
    pub signature: Option<String>,
}

/// Commitment to statistical properties without revealing exact data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsCommitment {
    /// Country distribution commitment
    pub country_distribution: HashDigest,

    /// ASN distribution commitment
    pub asn_distribution: HashDigest,

    /// Legitimacy score distribution commitment
    pub legitimacy_distribution: HashDigest,

    /// Summary statistics commitment
    pub summary_hash: HashDigest,
}

#[allow(dead_code)]
impl SnapshotCommitment {
    /// Create a new snapshot commitment from a set of IP entries
    pub fn new(entries: &[IpEntry]) -> Result<Self> {
        // Generate random salt
        let mut salt = [0u8; 32];
        thread_rng().fill_bytes(&mut salt);

        // Generate distribution entropy
        let mut distribution_entropy = [0u8; 32];
        thread_rng().fill_bytes(&mut distribution_entropy);

        // Calculate Merkle root
        let merkle_root = calculate_merkle_root(entries)?;

        // Calculate secondary hash using SHA3-256
        let secondary_hash = calculate_entries_hash(entries, HashAlgorithm::Sha3_256)?;

        // Create stats commitment
        let stats_commitment = StatsCommitment::new(entries)?;

        // Generate a unique ID based on timestamp and merkle root
        let timestamp = Utc::now();
        let id_source = format!("{}-{}", timestamp, merkle_root.to_hex());
        let mut id_hasher = Hasher::new();
        id_hasher.update(id_source.as_bytes());
        let id = encode(&id_hasher.finalize().as_bytes()[0..16]);

        Ok(Self {
            id,
            timestamp,
            merkle_root,
            total_ips: entries.len(),
            salt,
            secondary_hash,
            distribution_entropy,
            external_binding: None,
            stats_commitment,
        })
    }

    /// Verify that a set of entries matches this commitment
    pub fn verify(&self, entries: &[IpEntry]) -> Result<bool> {
        // Check entry count
        if entries.len() != self.total_ips {
            return Ok(false);
        }

        // Calculate and verify Merkle root
        let calculated_root = calculate_merkle_root(entries)?;
        if calculated_root != self.merkle_root {
            return Ok(false);
        }

        // Calculate and verify secondary hash
        let calculated_secondary = calculate_entries_hash(entries, HashAlgorithm::Sha3_256)?;
        if calculated_secondary != self.secondary_hash {
            return Ok(false);
        }

        // Verify stats commitment
        if !self.stats_commitment.verify(entries)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Add external binding information
    #[allow(dead_code)]
    pub fn add_external_binding(
        &mut self,
        system: &str,
        sequence_number: u64,
        transaction_id: &str,
        signature: Option<String>,
    ) {
        self.external_binding = Some(ExternalBinding {
            system: system.to_string(),
            sequence_number,
            transaction_id: transaction_id.to_string(),
            timestamp: Utc::now(),
            signature,
        });
    }

    /// Export commitment as bytes for publication
    pub fn export(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            SnapshotError::Cryptographic(format!("Failed to serialize commitment: {}", e))
        })
    }

    /// Import commitment from bytes
    pub fn import(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| {
            SnapshotError::Cryptographic(format!("Failed to deserialize commitment: {}", e))
        })
    }

    /// Generate a compact proof data structure for verification
    #[allow(dead_code)]
    pub fn generate_compact_proof(&self) -> CompactCommitmentProof {
        CompactCommitmentProof {
            id: self.id.clone(),
            timestamp: self.timestamp,
            merkle_root: self.merkle_root.to_hex(),
            secondary_hash: self.secondary_hash.to_hex(),
            total_ips: self.total_ips,
            salt: encode(self.salt),
            has_external_binding: self.external_binding.is_some(),
        }
    }
}

/// Compact commitment proof for easy verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactCommitmentProof {
    /// Commitment ID
    pub id: String,

    /// Creation timestamp
    pub timestamp: DateTime<Utc>,

    /// Merkle root (hex encoded)
    pub merkle_root: String,

    /// Secondary hash (hex encoded)
    pub secondary_hash: String,

    /// Total IPs
    pub total_ips: usize,

    /// Salt (hex encoded)
    pub salt: String,

    /// Whether external binding exists
    pub has_external_binding: bool,
}

#[allow(dead_code)]
impl StatsCommitment {
    /// Create a new stats commitment from IP entries
    pub fn new(entries: &[IpEntry]) -> Result<Self> {
        // Extract country distribution
        let mut country_counts: HashMap<String, usize> = HashMap::new();
        let mut asn_counts: HashMap<u32, usize> = HashMap::new();
        let mut legitimacy_scores = Vec::new();

        for entry in entries {
            // Country distribution
            if let Some(geo) = &entry.geo {
                if let Some(country_code) = &geo.country_code {
                    *country_counts.entry(country_code.clone()).or_insert(0) += 1;
                }
            }

            // ASN distribution
            if let Some(asn) = entry.network.asn {
                *asn_counts.entry(asn).or_insert(0) += 1;
            }

            // Legitimacy score distribution
            legitimacy_scores.push(entry.legitimacy_score);
        }

        // Create country distribution commitment
        let country_distribution = country_counts.hash(HashAlgorithm::Blake3)?;

        // Create ASN distribution commitment
        let asn_distribution = asn_counts.hash(HashAlgorithm::Blake3)?;

        // Create legitimacy score distribution commitment
        let legitimacy_distribution = legitimacy_scores.hash(HashAlgorithm::Blake3)?;

        // Create summary hash
        let summary = format!(
            "countries:{},asns:{},ips:{},legitimate:{}",
            country_counts.len(),
            asn_counts.len(),
            entries.len(),
            legitimacy_scores.iter().filter(|&&s| s >= 50).count()
        );

        let summary_hash = summary.hash(HashAlgorithm::Blake3)?;

        Ok(Self {
            country_distribution,
            asn_distribution,
            legitimacy_distribution,
            summary_hash,
        })
    }

    /// Verify that entries match this stats commitment
    pub fn verify(&self, entries: &[IpEntry]) -> Result<bool> {
        // Recalculate stats commitments
        let recalculated = Self::new(entries)?;

        // Compare all commitment fields
        let country_match = self.country_distribution == recalculated.country_distribution;
        let asn_match = self.asn_distribution == recalculated.asn_distribution;
        let legitimacy_match = self.legitimacy_distribution == recalculated.legitimacy_distribution;
        let summary_match = self.summary_hash == recalculated.summary_hash;

        Ok(country_match && asn_match && legitimacy_match && summary_match)
    }
}

/// Calculate allocation weight for an IP based on commitment data
///
/// This function deterministically derives a weight for token allocation
/// based on the IP and commitment entropy, without revealing the actual IP.
#[allow(dead_code)]
pub fn calculate_allocation_weight(ip_hash: &str, commitment: &SnapshotCommitment) -> Result<f64> {
    // Combine IP hash with commitment entropy
    let mut hasher = Hasher::new();
    hasher.update(ip_hash.as_bytes());
    hasher.update(&commitment.distribution_entropy);
    hasher.update(&commitment.salt);
    let combined_hash = hasher.finalize();

    // Extract first 8 bytes as a u64
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&combined_hash.as_bytes()[0..8]);
    let value = u64::from_le_bytes(bytes);

    // Normalize to range [0.0, 1.0]
    let normalized = value as f64 / u64::MAX as f64;

    Ok(normalized)
}

/// Generate a deterministic allocation of tokens based on commitment
///
/// This function distributes tokens to IPs in a verifiable, deterministic way
/// that can be audited against the commitment, without revealing actual IPs.
#[allow(dead_code)]
pub fn generate_token_allocation(
    ip_hashes: &[String],
    commitment: &SnapshotCommitment,
    total_tokens: u64,
) -> Result<HashMap<String, u64>> {
    // Verify that the number of IP hashes matches the commitment
    if ip_hashes.len() != commitment.total_ips {
        return Err(SnapshotError::Cryptographic(format!(
            "IP count mismatch: {} hashes vs {} in commitment",
            ip_hashes.len(),
            commitment.total_ips
        )));
    }

    // Calculate weights for each IP
    let mut weights = Vec::with_capacity(ip_hashes.len());
    let mut total_weight = 0.0;

    for hash in ip_hashes {
        let weight = calculate_allocation_weight(hash, commitment)?;
        total_weight += weight;
        weights.push((hash.clone(), weight));
    }

    // Allocate tokens proportionally
    let mut allocations = HashMap::new();
    let mut allocated = 0u64;

    for (hash, weight) in &weights {
        let share = (*weight / total_weight) * (total_tokens as f64);
        let allocation = share.round() as u64;

        allocations.insert(hash.clone(), allocation);
        allocated += allocation;
    }

    // Handle any rounding errors
    if allocated != total_tokens {
        let difference = total_tokens as i64 - allocated as i64;

        match difference.cmp(&0) {
            std::cmp::Ordering::Greater => {
                // Allocate extra tokens to the IP with highest weight
                if let Some((hash, _)) = weights
                    .iter()
                    .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                {
                    *allocations.get_mut(hash).unwrap() += difference as u64;
                }
            }
            std::cmp::Ordering::Less => {
                // Remove tokens from the IP with lowest weight
                if let Some((hash, _)) = weights
                    .iter()
                    .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                {
                    let current = allocations.get_mut(hash).unwrap();
                    *current = current.saturating_sub((-difference) as u64);
                }
            }
            std::cmp::Ordering::Equal => {} // No adjustment needed
        }
    }

    Ok(allocations)
}

/// Create a binding suitable for DSM protocol integration
///
/// This function creates a commitment that can be used with the DSM protocol.
/// It's designed to be forward-compatible with future DSM integration, while
/// being usable independently in the current implementation.
#[allow(dead_code)]
pub fn create_dsm_binding(commitment: &SnapshotCommitment) -> Result<Vec<u8>> {
    // Prepare the binding data
    let binding = serde_json::json!({
        "type": "ip_snapshot",
        "commitment_id": commitment.id,
        "merkle_root": commitment.merkle_root.to_hex(),
        "secondary_hash": commitment.secondary_hash.to_hex(),
        "timestamp": commitment.timestamp,
        "total_ips": commitment.total_ips,
        "stats_summary": {
            "country_distribution": commitment.stats_commitment.country_distribution.to_hex(),
            "legitimacy_distribution": commitment.stats_commitment.legitimacy_distribution.to_hex(),
            "summary_hash": commitment.stats_commitment.summary_hash.to_hex(),
        },
        // Include commitment salt XORed with entropy for future verification
        "verification_seed": encode(xor_bytes(&commitment.salt, &commitment.distribution_entropy)),
    });

    // Serialize to canonical JSON
    let binding_json = serde_json::to_string(&binding).map_err(|e| {
        SnapshotError::Cryptographic(format!("Failed to serialize DSM binding: {}", e))
    })?;

    debug!("Created DSM binding: {}", binding_json);

    Ok(binding_json.into_bytes())
}

/// XOR two byte arrays together
#[allow(dead_code)]
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::types::{GeoInformation, NetworkInformation};

    fn create_test_entry(ip: IpAddr, country: &str, legitimacy_score: u8) -> IpEntry {
        let now = Utc::now();

        let mut entry = IpEntry {
            ip,
            first_seen: now,
            last_seen: now,
            connection_count: 1,
            geo: Some(GeoInformation {
                country_code: Some(country.to_string()),
                country_name: Some("Test Country".to_string()),
                city: None,
                coordinates: None,
                continent_code: None,
                time_zone: None,
            }),
            network: NetworkInformation {
                asn: Some(12345),
                asn_org: Some("Test ISP".to_string()),
                latency: HashMap::new(),
                tcp_fingerprint: None,
                user_agents: Vec::new(),
                proxy_headers: HashMap::new(),
                network_range: None,
            },
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
    fn test_snapshot_commitment() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), "US", 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "CN", 75),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), "JP", 95),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), "DE", 80),
        ];

        // Create commitment
        let commitment = SnapshotCommitment::new(&entries).unwrap();

        // Verify same entries
        let valid = commitment.verify(&entries).unwrap();
        assert!(valid);

        // Modify an entry
        let mut modified_entries = entries.clone();
        modified_entries[1] = create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), "CN", 75);

        // Verify modified entries (should fail)
        let invalid = commitment.verify(&modified_entries).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_export_import() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), "US", 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "CN", 75),
        ];

        // Create commitment
        let commitment = SnapshotCommitment::new(&entries).unwrap();

        // Export
        let exported = commitment.export().unwrap();

        // Import
        let imported = SnapshotCommitment::import(&exported).unwrap();

        // Verify they match
        assert_eq!(commitment.id, imported.id);
        assert_eq!(commitment.merkle_root, imported.merkle_root);
        assert_eq!(commitment.secondary_hash, imported.secondary_hash);
        assert_eq!(commitment.salt, imported.salt);
    }

    #[test]
    fn test_token_allocation() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), "US", 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "CN", 75),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), "JP", 95),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), "DE", 80),
        ];

        // Create commitment
        let commitment = SnapshotCommitment::new(&entries).unwrap();

        // Create IP hashes
        let ip_hashes: Vec<String> = entries
            .iter()
            .map(|e| {
                let mut hasher = Hasher::new();
                hasher.update(e.ip.to_string().as_bytes());
                encode(hasher.finalize().as_bytes())
            })
            .collect();

        // Allocate tokens
        let total_tokens = 1000u64;
        let allocations = generate_token_allocation(&ip_hashes, &commitment, total_tokens).unwrap();

        // Verify total matches
        let allocated: u64 = allocations.values().sum();
        assert_eq!(allocated, total_tokens);

        // Verify deterministic behavior
        let allocations2 =
            generate_token_allocation(&ip_hashes, &commitment, total_tokens).unwrap();
        assert_eq!(allocations, allocations2);
    }

    #[test]
    fn test_dsm_binding() {
        let entries = vec![
            create_test_entry(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), "US", 85),
            create_test_entry(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "CN", 75),
        ];

        // Create commitment
        let commitment = SnapshotCommitment::new(&entries).unwrap();

        // Create DSM binding
        let binding = create_dsm_binding(&commitment).unwrap();

        // Parse binding JSON to verify structure
        let binding_json: serde_json::Value = serde_json::from_slice(&binding).unwrap();

        assert_eq!(binding_json["type"], "ip_snapshot");
        assert_eq!(binding_json["commitment_id"], commitment.id);
        assert_eq!(binding_json["merkle_root"], commitment.merkle_root.to_hex());
        assert_eq!(binding_json["total_ips"], commitment.total_ips);
    }
}
