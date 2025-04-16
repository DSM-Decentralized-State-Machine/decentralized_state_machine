use std::path::Path;
use chrono::Utc;
use tokio::fs;
use serde_json::Value;
use blake3::Hasher;
use tracing::{info, warn};

use crate::error::{Result, SnapshotError};
use crate::types::{VerificationResult, IpEntry};

/// Verify a snapshot's cryptographic integrity
pub async fn verify_snapshot<P: AsRef<Path>>(snapshot_path: P) -> Result<VerificationResult> {
    let path = snapshot_path.as_ref();
    info!("Verifying snapshot integrity: {:?}", path);

    // Read the snapshot file
    let content = fs::read_to_string(path)
        .await
        .map_err(|e| SnapshotError::Validation(format!("Failed to read snapshot file: {}", e)))?;

    // Parse as JSON
    let data: Value = serde_json::from_str(&content)
        .map_err(|e| SnapshotError::Validation(format!("Failed to parse snapshot JSON: {}", e)))?;

    // Determine the type of snapshot file
    let file_type = determine_file_type(&data)?;

    match file_type {
        SnapshotFileType::Raw => verify_raw_snapshot(&data).await,
        SnapshotFileType::Export => verify_export_snapshot(&data).await,
        SnapshotFileType::Hash => verify_hash_snapshot(&data).await,
        SnapshotFileType::Analysis => verify_analysis_snapshot(&data).await,
        SnapshotFileType::DsmCompatible => verify_dsm_snapshot(&data).await,
        SnapshotFileType::Attestation => verify_attestation(&data).await,
    }
}

/// Snapshot file types for verification
enum SnapshotFileType {
    /// Raw snapshot with entries and metadata
    Raw,

    /// Exported snapshot with multiple snapshots
    Export,

    /// Hash verification file
    Hash,

    /// Analysis file
    Analysis,

    /// DSM-compatible snapshot
    DsmCompatible,

    /// Attestation file
    Attestation,
}

/// Determine the type of snapshot file
fn determine_file_type(data: &Value) -> Result<SnapshotFileType> {
    // Check for export format
    if data.get("export_format").is_some() {
        // Hash export
        if data.get("export_format").and_then(|v| v.as_str()) == Some("blake3") {
            return Ok(SnapshotFileType::Hash);
        }

        // Regular export
        return Ok(SnapshotFileType::Export);
    }

    // Check for analysis format
    if data.get("analysis_version").is_some() {
        return Ok(SnapshotFileType::Analysis);
    }

    // Check for DSM-compatible format
    if data.get("dsm_id").is_some() {
        return Ok(SnapshotFileType::DsmCompatible);
    }

    // Check for attestation format
    if data.get("attestation_type").is_some() {
        return Ok(SnapshotFileType::Attestation);
    }

    // Default to raw snapshot
    Ok(SnapshotFileType::Raw)
}

/// Verify a raw snapshot file
async fn verify_raw_snapshot(data: &Value) -> Result<VerificationResult> {
    // Parse metadata and entries
    let metadata = data.get("metadata").ok_or_else(|| {
        SnapshotError::Validation("Missing metadata section in snapshot".to_string())
    })?;

    let entries = data.get("entries").ok_or_else(|| {
        SnapshotError::Validation("Missing entries section in snapshot".to_string())
    })?;

    // Parse as array of entries
    let entries: Vec<IpEntry> = serde_json::from_value(entries.clone())
        .map_err(|e| SnapshotError::Validation(format!("Failed to parse entries: {}", e)))?;

    // Verify each entry's hash
    let mut all_entries_valid = true;
    let mut invalid_entries = 0;

    for entry in &entries {
        if !entry.verify_integrity() {
            all_entries_valid = false;
            invalid_entries += 1;
            warn!("Entry for IP {} failed integrity check", entry.ip);
        }
    }

    // Extract key metadata
    let timestamp = metadata
        .get("start_time")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
        .unwrap_or_default();

    let data_hash = metadata
        .get("data_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Calculate our own hash
    let calculated_hash = calculate_entries_hash(&entries);

    // Check if hashes match
    let hash_valid = if data_hash.is_empty() {
        // No hash to compare
        true
    } else {
        data_hash == calculated_hash
    };

    // Final validation result
    let is_valid = all_entries_valid && hash_valid;

    // Count countries
    let mut countries = std::collections::HashSet::new();
    let mut flagged_ips = 0;

    for entry in &entries {
        if let Some(geo) = &entry.geo {
            if let Some(country_code) = &geo.country_code {
                countries.insert(country_code.clone());
            }
        }

        if entry.legitimacy_score < 50 {
            flagged_ips += 1;
        }
    }

    let error_msg = if !is_valid {
        if !all_entries_valid {
            Some(format!(
                "{} entries failed integrity check",
                invalid_entries
            ))
        } else if !hash_valid {
            Some(format!(
                "Data hash mismatch. Expected: {}, got: {}",
                data_hash, calculated_hash
            ))
        } else {
            Some("Unknown integrity error".to_string())
        }
    } else {
        None
    };

    Ok(VerificationResult {
        is_valid,
        error: error_msg,
        timestamp,
        ip_count: entries.len(),
        country_count: countries.len(),
        flagged_ips,
        hash: calculated_hash,
    })
}

/// Verify an exported snapshot file
async fn verify_export_snapshot(data: &Value) -> Result<VerificationResult> {
    // Parse export data
    let export_timestamp = data
        .get("export_timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
        .unwrap_or_default();

    let snapshots = data.get("snapshots").ok_or_else(|| {
        SnapshotError::Validation("Missing snapshots section in export".to_string())
    })?;

    let snapshots_array = snapshots.as_array().ok_or_else(|| {
        SnapshotError::Validation("Snapshots section is not an array".to_string())
    })?;

    // Verify export hash
    let export_hash = data
        .get("export_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Create a copy without the export_hash field for hash calculation
    let mut data_for_hash = data.clone();
    if let Some(obj) = data_for_hash.as_object_mut() {
        obj.remove("export_hash");
    }

    // Calculate hash
    let mut hasher = Hasher::new();
    hasher.update(serde_json::to_string(&data_for_hash).unwrap().as_bytes());
    let calculated_hash = hex::encode(hasher.finalize().as_bytes());

    // Check if export hash is valid
    let hash_valid = export_hash.is_empty() || export_hash == calculated_hash;

    // Count IPs and countries across all snapshots
    let mut ip_count = 0;
    let mut country_count = 0;
    let mut flagged_ips = 0;

    for snapshot in snapshots_array {
        ip_count += snapshot
            .get("entries_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        // Count countries from metadata if available
        if let Some(metadata) = snapshot.get("metadata") {
            country_count = country_count.max(
                metadata
                    .get("country_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize,
            );

            flagged_ips += metadata
                .get("flagged_ip_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
        }
    }

    let error_msg = if !hash_valid {
        Some(format!(
            "Export hash mismatch. Expected: {}, got: {}",
            export_hash, calculated_hash
        ))
    } else {
        None
    };

    Ok(VerificationResult {
        is_valid: hash_valid,
        error: error_msg,
        timestamp: export_timestamp,
        ip_count,
        country_count,
        flagged_ips,
        hash: calculated_hash,
    })
}

/// Verify a hash-only snapshot file
async fn verify_hash_snapshot(data: &Value) -> Result<VerificationResult> {
    // Parse hash data
    let export_timestamp = data
        .get("export_timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
        .unwrap_or_default();

    let snapshots = data.get("snapshots").ok_or_else(|| {
        SnapshotError::Validation("Missing snapshots section in hash export".to_string())
    })?;

    let snapshots_array = snapshots.as_array().ok_or_else(|| {
        SnapshotError::Validation("Snapshots section is not an array".to_string())
    })?;

    // Verify master hash
    let master_hash = data
        .get("master_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Calculate master hash
    let mut master_hasher = Hasher::new();
    for snapshot in snapshots_array {
        let hash = snapshot
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        master_hasher.update(hash.as_bytes());
    }
    let calculated_master_hash = hex::encode(master_hasher.finalize().as_bytes());

    // Check if master hash is valid
    let hash_valid = master_hash.is_empty() || master_hash == calculated_master_hash;

    // Count IPs across all snapshots
    let mut ip_count = 0;

    for snapshot in snapshots_array {
        ip_count += snapshot
            .get("entry_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
    }

    let error_msg = if !hash_valid {
        Some(format!(
            "Master hash mismatch. Expected: {}, got: {}",
            master_hash, calculated_master_hash
        ))
    } else {
        None
    };

    Ok(VerificationResult {
        is_valid: hash_valid,
        error: error_msg,
        timestamp: export_timestamp,
        ip_count,
        country_count: snapshots_array.len(), // Use number of snapshots as proxy for countries
        flagged_ips: 0,                       // Not available in hash-only export
        hash: calculated_master_hash,
    })
}

/// Verify an analysis snapshot file
async fn verify_analysis_snapshot(data: &Value) -> Result<VerificationResult> {
    // Parse analysis data
    let analysis_timestamp = data
        .get("analysis_timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
        .unwrap_or_default();

    // Verify verification hash
    let verification_hash = data
        .get("verification_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Create a copy without the verification_hash field for hash calculation
    let mut data_for_hash = data.clone();
    if let Some(obj) = data_for_hash.as_object_mut() {
        obj.remove("verification_hash");
    }

    // Calculate hash
    let mut hasher = Hasher::new();
    hasher.update(serde_json::to_string(&data_for_hash).unwrap().as_bytes());
    let calculated_hash = hex::encode(hasher.finalize().as_bytes());

    // Check if verification hash is valid
    let hash_valid = verification_hash.is_empty() || verification_hash == calculated_hash;

    // Extract statistics
    let total_ips = data
        .get("legitimacy_analysis")
        .and_then(|v| v.get("total"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let flagged_ips = data
        .get("legitimacy_analysis")
        .and_then(|v| v.get("flagged"))
        .and_then(|v| v.get("count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let country_count = data
        .get("geo_distribution")
        .and_then(|v| v.get("total_countries"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let error_msg = if !hash_valid {
        Some(format!(
            "Verification hash mismatch. Expected: {}, got: {}",
            verification_hash, calculated_hash
        ))
    } else {
        None
    };

    Ok(VerificationResult {
        is_valid: hash_valid,
        error: error_msg,
        timestamp: analysis_timestamp,
        ip_count: total_ips,
        country_count,
        flagged_ips,
        hash: calculated_hash,
    })
}

/// Verify a DSM-compatible snapshot file
async fn verify_dsm_snapshot(data: &Value) -> Result<VerificationResult> {
    // Parse DSM data
    let timestamp = data
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
        .unwrap_or_default();

    let _dsm_id = data
        .get("dsm_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let _original_id = data
        .get("original_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let _verification_nonce = data
        .get("verification_nonce")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let entries = data.get("entries").ok_or_else(|| {
        SnapshotError::Validation("Missing entries section in DSM snapshot".to_string())
    })?;

    let entries_array = entries
        .as_array()
        .ok_or_else(|| SnapshotError::Validation("Entries section is not an array".to_string()))?;

    // Verify DSM hash
    let dsm_hash = data
        .get("dsm_verification_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Create a copy without the dsm_verification_hash field for hash calculation
    let mut data_for_hash = data.clone();
    if let Some(obj) = data_for_hash.as_object_mut() {
        obj.remove("dsm_verification_hash");
    }

    // Calculate hash
    let mut hasher = Hasher::new();
    hasher.update(serde_json::to_string(&data_for_hash).unwrap().as_bytes());
    let calculated_hash = hex::encode(hasher.finalize().as_bytes());

    // Check if DSM hash is valid
    let hash_valid = dsm_hash.is_empty() || dsm_hash == calculated_hash;

    // Count countries and flagged IPs
    let mut countries = std::collections::HashSet::new();
    let mut flagged_ips = 0;

    for entry in entries_array {
        if let Some(country_code) = entry.get("country_code").and_then(|v| v.as_str()) {
            if !country_code.is_empty() {
                countries.insert(country_code.to_string());
            }
        }

        if let Some(score) = entry.get("legitimacy_score").and_then(|v| v.as_u64()) {
            if score < 50 {
                flagged_ips += 1;
            }
        }
    }

    let error_msg = if !hash_valid {
        Some(format!(
            "DSM verification hash mismatch. Expected: {}, got: {}",
            dsm_hash, calculated_hash
        ))
    } else {
        None
    };

    Ok(VerificationResult {
        is_valid: hash_valid,
        error: error_msg,
        timestamp,
        ip_count: entries_array.len(),
        country_count: countries.len(),
        flagged_ips,
        hash: calculated_hash,
    })
}

/// Verify an attestation file
async fn verify_attestation(data: &Value) -> Result<VerificationResult> {
    // Parse attestation data
    let timestamp = data
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
        .unwrap_or_default();

    let _attestation_type = data
        .get("attestation_type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let snapshots = data.get("snapshots").ok_or_else(|| {
        SnapshotError::Validation("Missing snapshots section in attestation".to_string())
    })?;

    let snapshots_array = snapshots.as_array().ok_or_else(|| {
        SnapshotError::Validation("Snapshots section is not an array".to_string())
    })?;

    // Verify commitment
    let commitment = data
        .get("commitment")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // Calculate Merkle root
    let mut merkle_leaves = Vec::new();

    for snapshot in snapshots_array {
        let hash_hex = snapshot
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let hash_bytes = hex::decode(hash_hex)
            .map_err(|e| SnapshotError::Validation(format!("Failed to decode hash: {}", e)))?;

        // Ensure hash is exactly 32 bytes
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes[0..32]);

        merkle_leaves.push(hash_array);
    }

    // Calculate Merkle root
    let merkle_root = calculate_merkle_root(&merkle_leaves);
    let calculated_commitment = hex::encode(merkle_root);

    // Check if commitment is valid
    let commitment_valid = commitment.is_empty() || commitment == calculated_commitment;

    // Count IPs (if available)
    let mut ip_count = 0;

    for snapshot in snapshots_array {
        if let Some(count) = snapshot.get("entry_count").and_then(|v| v.as_u64()) {
            ip_count += count as usize;
        }
    }

    let error_msg = if !commitment_valid {
        Some(format!(
            "Commitment mismatch. Expected: {}, got: {}",
            commitment, calculated_commitment
        ))
    } else {
        None
    };

    Ok(VerificationResult {
        is_valid: commitment_valid,
        error: error_msg,
        timestamp,
        ip_count,
        country_count: snapshots_array.len(), // Use number of snapshots as proxy
        flagged_ips: 0,                       // Not available in attestation
        hash: calculated_commitment,
    })
}

/// Calculate the hash of entries
fn calculate_entries_hash(entries: &[IpEntry]) -> String {
    // Sort entries by IP for deterministic ordering
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by(|a, b| a.ip.to_string().cmp(&b.ip.to_string()));

    // Hash each entry's verification hash
    let mut hasher = Hasher::new();

    for entry in &sorted_entries {
        hasher.update(entry.verification_hash.as_bytes());
    }

    hex::encode(hasher.finalize().as_bytes())
}

/// Calculate Merkle root hash from leaves
fn calculate_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut next_level = Vec::new();

    // Process pairs of leaves
    for chunk in leaves.chunks(2) {
        let mut hasher = Hasher::new();

        // Add first leaf
        hasher.update(&chunk[0]);

        // Add second leaf if it exists, otherwise duplicate first leaf
        if chunk.len() > 1 {
            hasher.update(&chunk[1]);
        } else {
            hasher.update(&chunk[0]);
        }

        // Add hash to next level
        let hash = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(hash.as_bytes());

        next_level.push(hash_array);
    }

    // Recursively calculate next level
    calculate_merkle_root(&next_level)
}
