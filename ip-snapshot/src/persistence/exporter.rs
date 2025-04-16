use std::path::Path;
use std::collections::HashMap;
use tokio::fs;
use chrono::{Utc, Timelike, Datelike};
use serde_json::{json, Value};
use blake3::Hasher;
use tracing::info;
use csv::Writer;

use crate::error::{Result, SnapshotError, ExportError};
use crate::persistence::snapshot_store::SnapshotStore;

/// Export snapshot data to JSON format
pub async fn export_json(store: &SnapshotStore, output_path: &Path) -> Result<()> {
    info!("Exporting snapshots to JSON: {:?}", output_path);

    // Get all snapshot metadata
    let snapshots = store.list_snapshots();

    // Prepare export container
    let mut export_data = json!({
        "export_timestamp": Utc::now(),
        "export_format": "json",
        "snapshots": Vec::<Value>::new(),
    });

    // Array to hold snapshot data
    let mut snapshot_array = Vec::new();

    // Process each snapshot
    for metadata in snapshots {
        let snapshot_id = &metadata.id;

        // Load snapshot data
        let (entries, _) = store.load_snapshot(snapshot_id).await?;

        // Calculate verification hash
        let hash = store.calculate_snapshot_hash(snapshot_id).await?;

        // Create snapshot object
        let snapshot_data = json!({
            "id": snapshot_id,
            "metadata": metadata,
            "entries_count": entries.len(),
            "verification_hash": hash,
        });

        snapshot_array.push(snapshot_data);
    }

    // Add snapshots to export data
    export_data["snapshots"] = json!(snapshot_array);

    // Calculate export verification hash
    let mut hasher = Hasher::new();
    hasher.update(serde_json::to_string(&export_data).unwrap().as_bytes());
    let export_hash = hex::encode(hasher.finalize().as_bytes());

    // Add export hash
    export_data["export_hash"] = json!(export_hash);

    // Write to file
    let json_str = serde_json::to_string_pretty(&export_data)
        .map_err(|e| SnapshotError::Export(format!("Failed to serialize export data: {}", e)))?;

    fs::write(output_path, json_str)
        .await
        .map_err(|e| SnapshotError::Export(format!("Failed to write export file: {}", e)))?;

    info!(
        "Export completed successfully. Wrote {} snapshots.",
        snapshot_array.len()
    );

    Ok(())
}

/// Export snapshot data to CSV format
pub async fn export_csv(store: &SnapshotStore, output_path: &Path) -> Result<()> {
    info!("Exporting snapshots to CSV: {:?}", output_path);

    // Get all snapshot metadata
    let snapshots = store.list_snapshots();

    // Create the output file
    let file = tokio::fs::File::create(output_path)
        .await
        .map_err(|e| SnapshotError::Export(format!("Failed to create CSV file: {}", e)))?;

    // Convert to std File for csv crate compatibility
    let std_file = file.into_std().await;

    // Create CSV writer
    let mut writer = Writer::from_writer(std_file);

    // Write header
    writer
        .write_record([
            "snapshot_id",
            "ip",
            "first_seen",
            "last_seen",
            "connection_count",
            "country_code",
            "city",
            "latitude",
            "longitude",
            "asn",
            "asn_org",
            "legitimacy_score",
            "verification_hash",
        ])
        .map_err(|e| SnapshotError::from(ExportError::Csv(e)))?;

    // Track total entries exported
    let mut total_entries = 0;

    // Store the snapshot count before processing
    let snapshot_count = snapshots.len();

    // Process each snapshot
    for metadata in snapshots {
        let snapshot_id = &metadata.id;

        // Load snapshot data
        let (entries, _) = store.load_snapshot(snapshot_id).await?;

        // Write each entry as a CSV row
        for entry in &entries {
            // Prepare CSV record
            let record = vec![
                snapshot_id.clone(),
                entry.ip.to_string(),
                entry.first_seen.to_rfc3339(),
                entry.last_seen.to_rfc3339(),
                entry.connection_count.to_string(),
                entry
                    .geo
                    .as_ref()
                    .and_then(|g| g.country_code.clone())
                    .unwrap_or_default(),
                entry
                    .geo
                    .as_ref()
                    .and_then(|g| g.city.clone())
                    .unwrap_or_default(),
                entry
                    .geo
                    .as_ref()
                    .and_then(|g| g.coordinates.map(|(lat, _)| lat.to_string()))
                    .unwrap_or_default(),
                entry
                    .geo
                    .as_ref()
                    .and_then(|g| g.coordinates.map(|(_, lon)| lon.to_string()))
                    .unwrap_or_default(),
                entry
                    .network
                    .asn
                    .map(|asn| asn.to_string())
                    .unwrap_or_default(),
                entry.network.asn_org.clone().unwrap_or_default(),
                entry.legitimacy_score.to_string(),
                entry.verification_hash.clone(),
            ];

            // Write record
            writer
                .write_record(&record)
                .map_err(|e| SnapshotError::Export(format!("CSV export error: {}", e)))?;

            total_entries += 1;
        }
    }

    // Flush the writer
    writer
        .flush()
        .map_err(|e| SnapshotError::Export(format!("CSV export error: {}", e)))?;

    info!(
        "Export completed successfully. Wrote {} entries across {} snapshots.",
        total_entries, snapshot_count
    );

    Ok(())
}

/// Export snapshot cryptographic hash verification only
pub async fn export_hash(store: &SnapshotStore, output_path: &Path) -> Result<()> {
    info!("Exporting snapshot hashes: {:?}", output_path);

    // Get all snapshot metadata
    let snapshots = store.list_snapshots();

    // Prepare hash verification data
    let mut hash_data = json!({
        "export_timestamp": Utc::now(),
        "export_format": "blake3",
        "snapshots": Vec::<Value>::new(),
    });

    // Array to hold snapshot hashes
    let mut snapshot_hashes = Vec::new();

    // Process each snapshot
    for metadata in snapshots {
        let snapshot_id = &metadata.id;

        // Calculate verification hash
        let hash = store.calculate_snapshot_hash(snapshot_id).await?;

        // Get entry count
        let (entries, _) = store.load_snapshot(snapshot_id).await?;

        // Create hash object
        let hash_object = json!({
            "id": snapshot_id,
            "hash": hash,
            "timestamp": metadata.start_time,
            "entry_count": entries.len(),
        });

        snapshot_hashes.push(hash_object);
    }

    // Add snapshots to hash data
    hash_data["snapshots"] = json!(snapshot_hashes);

    // Calculate master verification hash (hash of all snapshot hashes)
    let mut master_hasher = Hasher::new();
    let snapshot_count = snapshot_hashes.len();
    for hash_obj in snapshot_hashes {
        master_hasher.update(hash_obj["hash"].as_str().unwrap().as_bytes());
    }
    let master_hash = hex::encode(master_hasher.finalize().as_bytes());

    // Add master hash
    hash_data["master_hash"] = json!(master_hash);

    // Write to file
    let json_str = serde_json::to_string_pretty(&hash_data)
        .map_err(|e| SnapshotError::Export(format!("Failed to serialize hash data: {}", e)))?;

    fs::write(output_path, json_str)
        .await
        .map_err(|e| SnapshotError::Export(format!("Failed to write hash file: {}", e)))?;

    info!(
        "Hash export completed successfully for {} snapshots. Master hash: {}",
        snapshot_count, master_hash
    );

    Ok(())
}

/// Export detailed snapshot analysis with comprehensive statistics and visualizations
#[allow(dead_code)]
pub async fn export_analysis(store: &SnapshotStore, output_path: &Path) -> Result<()> {
    info!(
        "Generating comprehensive snapshot analysis: {:?}",
        output_path
    );

    // Get all snapshot metadata
    let snapshots = store.list_snapshots();

    // Prepare analysis container
    let mut analysis_data = json!({
        "analysis_timestamp": Utc::now(),
        "analysis_version": "1.0",
        "snapshots_analyzed": snapshots.len(),
        "geo_distribution": {},
        "temporal_analysis": {},
        "legitimacy_analysis": {},
        "asn_analysis": {},
        "snapshot_comparison": {},
    });

    // Analyze geographic distribution
    let mut country_counts: HashMap<String, usize> = HashMap::new();
    let mut country_legitimate: HashMap<String, usize> = HashMap::new();
    let mut country_flagged: HashMap<String, usize> = HashMap::new();

    // Analyze ASN distribution
    let mut asn_counts: HashMap<u32, usize> = HashMap::new();
    let mut asn_names: HashMap<u32, String> = HashMap::new();

    // Analyze temporal patterns
    let mut hour_distribution: HashMap<u8, usize> = HashMap::new();
    let mut day_distribution: HashMap<u8, usize> = HashMap::new();

    // Total IPs analyzed
    let mut total_ips = 0;
    let mut legitimate_ips = 0;
    let mut flagged_ips = 0;

    // Process each snapshot
    for metadata in &snapshots {
        let snapshot_id = &metadata.id;

        // Load snapshot data
        let (entries, _) = store.load_snapshot(snapshot_id).await?;
        total_ips += entries.len();

        // Analyze each entry
        for entry in &entries {
            // Geographic analysis
            if let Some(geo) = &entry.geo {
                if let Some(country_code) = &geo.country_code {
                    *country_counts.entry(country_code.clone()).or_insert(0) += 1;

                    if entry.legitimacy_score >= 50 {
                        *country_legitimate.entry(country_code.clone()).or_insert(0) += 1;
                        legitimate_ips += 1;
                    } else {
                        *country_flagged.entry(country_code.clone()).or_insert(0) += 1;
                        flagged_ips += 1;
                    }
                }
            }

            // ASN analysis
            if let Some(asn) = entry.network.asn {
                *asn_counts.entry(asn).or_insert(0) += 1;

                if let Some(org) = &entry.network.asn_org {
                    asn_names.insert(asn, org.clone());
                }
            }

            // Temporal analysis
            let hour = entry.first_seen.hour() as u8;
            let day = entry.first_seen.weekday().num_days_from_monday() as u8;

            *hour_distribution.entry(hour).or_insert(0) += 1;
            *day_distribution.entry(day).or_insert(0) += 1;
        }
    }

    // Format geo distribution
    let mut geo_data = Vec::new();
    for (country, count) in country_counts.iter() {
        geo_data.push(json!({
            "country_code": country,
            "total": count,
            "legitimate": country_legitimate.get(country).unwrap_or(&0),
            "flagged": country_flagged.get(country).unwrap_or(&0),
            "percentage": (*count as f64 / total_ips as f64 * 100.0)
        }));
    }

    // Sort by count
    geo_data.sort_by(|a, b| {
        let a_count = a["total"].as_u64().unwrap_or(0);
        let b_count = b["total"].as_u64().unwrap_or(0);
        b_count.cmp(&a_count)
    });

    // Format ASN distribution
    let mut asn_data = Vec::new();
    for (asn, count) in asn_counts.iter() {
        asn_data.push(json!({
            "asn": asn,
            "organization": asn_names.get(asn).unwrap_or(&"Unknown".to_string()),
            "count": count,
            "percentage": (*count as f64 / total_ips as f64 * 100.0)
        }));
    }

    // Sort by count
    asn_data.sort_by(|a, b| {
        let a_count = a["count"].as_u64().unwrap_or(0);
        let b_count = b["count"].as_u64().unwrap_or(0);
        b_count.cmp(&a_count)
    });

    // Format temporal analysis
    let mut hour_data = Vec::new();
    for hour in 0..24 {
        let count = hour_distribution.get(&(hour as u8)).unwrap_or(&0);
        hour_data.push(json!({
            "hour": hour,
            "count": count,
            "percentage": (*count as f64 / total_ips as f64 * 100.0)
        }));
    }

    let mut day_data = Vec::new();
    let days = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ];
    for day in 0..7 {
        let count = day_distribution.get(&(day as u8)).unwrap_or(&0);
        day_data.push(json!({
            "day": day,
            "day_name": days[day as usize],
            "count": count,
            "percentage": (*count as f64 / total_ips as f64 * 100.0)
        }));
    }

    // Format legitimacy analysis
    let legitimacy_data = json!({
        "legitimate": {
            "count": legitimate_ips,
            "percentage": (legitimate_ips as f64 / total_ips as f64 * 100.0)
        },
        "flagged": {
            "count": flagged_ips,
            "percentage": (flagged_ips as f64 / total_ips as f64 * 100.0)
        },
        "total": total_ips
    });

    // Add data to analysis container
    analysis_data["geo_distribution"] = json!({
        "countries": geo_data,
        "total_countries": country_counts.len()
    });

    analysis_data["asn_analysis"] = json!({
        "asns": asn_data,
        "total_asns": asn_counts.len()
    });

    analysis_data["temporal_analysis"] = json!({
        "hourly": hour_data,
        "daily": day_data
    });

    analysis_data["legitimacy_analysis"] = legitimacy_data;

    // Compare snapshots if multiple exist
    if snapshots.len() > 1 {
        let _comparison_data: Vec<serde_json::Value> = Vec::new();

        // Track IPs across snapshots
        let mut ip_tracking: HashMap<String, Vec<String>> = HashMap::new();

        for metadata in &snapshots {
            let snapshot_id = &metadata.id;
            let (entries, _) = store.load_snapshot(snapshot_id).await?;

            for entry in &entries {
                let ip_str = entry.ip.to_string();
                ip_tracking
                    .entry(ip_str)
                    .and_modify(|snapshots| snapshots.push(snapshot_id.clone()))
                    .or_insert_with(|| vec![snapshot_id.clone()]);
            }
        }

        // Calculate overlap statistics
        let mut ips_in_all = 0;
        let mut ips_in_single = 0;

        for snapshot_list in ip_tracking.values() {
            if snapshot_list.len() == snapshots.len() {
                ips_in_all += 1;
            } else if snapshot_list.len() == 1 {
                ips_in_single += 1;
            }
        }

        // Add comparison stats
        analysis_data["snapshot_comparison"] = json!({
            "unique_ips_total": ip_tracking.len(),
            "ips_in_all_snapshots": ips_in_all,
            "ips_in_single_snapshot": ips_in_single,
            "overlap_percentage": (ips_in_all as f64 / ip_tracking.len() as f64 * 100.0)
        });
    }

    // Calculate verification hash for the analysis
    let mut hasher = Hasher::new();
    hasher.update(serde_json::to_string(&analysis_data).unwrap().as_bytes());
    let analysis_hash = hex::encode(hasher.finalize().as_bytes());

    // Add verification hash
    analysis_data["verification_hash"] = json!(analysis_hash);

    // Write to file
    let json_str = serde_json::to_string_pretty(&analysis_data)
        .map_err(|e| SnapshotError::Export(format!("Failed to serialize analysis data: {}", e)))?;

    fs::write(output_path, json_str)
        .await
        .map_err(|e| SnapshotError::Export(format!("Failed to write analysis file: {}", e)))?;

    info!(
        "Analysis completed successfully. Analyzed {} IPs across {} snapshots.",
        total_ips,
        snapshots.len()
    );

    Ok(())
}

/// Export a snapshot in a format suitable for integration with DSM protocol
#[allow(dead_code)]
pub async fn export_dsm_compatible(
    store: &SnapshotStore,
    snapshot_id: &str,
    output_path: &Path,
) -> Result<()> {
    info!("Exporting DSM-compatible snapshot: {}", snapshot_id);

    // Load snapshot
    let (entries, metadata) = store.load_snapshot(snapshot_id).await?;

    // Create a deterministic snapshot ID for DSM
    let mut hasher = Hasher::new();
    hasher.update(snapshot_id.as_bytes());
    hasher.update(metadata.verification_nonce.as_bytes());
    let dsm_id = hex::encode(&hasher.finalize().as_bytes()[0..16]);

    // Prepare DSM-compatible format
    let mut dsm_data = json!({
        "dsm_id": dsm_id,
        "original_id": snapshot_id,
        "timestamp": metadata.start_time,
        "verification_nonce": metadata.verification_nonce,
        "verification_hash": metadata.data_hash,
        "ip_count": entries.len(),
        "entries": Vec::<Value>::new(),
    });

    // Prepare entry data in DSM-compatible format
    let mut dsm_entries = Vec::new();

    for entry in &entries {
        // Format entry data with minimal required fields
        let dsm_entry = json!({
            "ip": entry.ip.to_string(),
            "country_code": entry.geo.as_ref().and_then(|g| g.country_code.clone()).unwrap_or_default(),
            "asn": entry.network.asn.unwrap_or(0),
            "legitimacy_score": entry.legitimacy_score,
            "verification_hash": entry.verification_hash,
        });

        dsm_entries.push(dsm_entry);
    }

    // Sort entries deterministically by IP for verifiability
    dsm_entries.sort_by(|a, b| {
        a["ip"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["ip"].as_str().unwrap_or_default())
    });

    // Add entries to DSM data
    dsm_data["entries"] = json!(dsm_entries);

    // Calculate final verification hash
    let mut dsm_hasher = Hasher::new();
    dsm_hasher.update(serde_json::to_string(&dsm_data).unwrap().as_bytes());
    let dsm_hash = hex::encode(dsm_hasher.finalize().as_bytes());

    // Add final hash
    dsm_data["dsm_verification_hash"] = json!(dsm_hash);

    // Write to file
    let json_str = serde_json::to_string_pretty(&dsm_data)
        .map_err(|e| SnapshotError::Export(format!("Failed to serialize DSM data: {}", e)))?;

    fs::write(output_path, json_str)
        .await
        .map_err(|e| SnapshotError::Export(format!("Failed to write DSM file: {}", e)))?;

    info!(
        "DSM-compatible export completed successfully for snapshot {}. DSM ID: {}",
        snapshot_id, dsm_id
    );

    Ok(())
}

/// Minimal secure export for attestation purposes
#[allow(dead_code)]
pub async fn export_attestation(store: &SnapshotStore, output_path: &Path) -> Result<()> {
    info!("Generating cryptographic attestation for snapshots");

    // Get all snapshot metadata
    let snapshots = store.list_snapshots();

    // Prepare attestation data
    let mut attestation = json!({
        "timestamp": Utc::now(),
        "attestation_type": "blake3",
        "snapshots": [],
        "commitment": "",
    });

    // Create vector for snapshot hashes
    let mut snapshot_hashes = Vec::new();

    // Process each snapshot
    for metadata in snapshots {
        let snapshot_id = &metadata.id;

        // Calculate hash
        let hash = store.calculate_snapshot_hash(snapshot_id).await?;

        snapshot_hashes.push(json!({
            "id": snapshot_id,
            "hash": hash,
            "timestamp": metadata.start_time,
        }));
    }

    // Add snapshot hashes to attestation
    attestation["snapshots"] = json!(snapshot_hashes);

    // Generate Merkle tree root as commitment
    let mut merkle_leaves: Vec<[u8; 32]> = Vec::new();

    for hash_obj in snapshot_hashes.iter() {
        let hash_hex = hash_obj["hash"].as_str().unwrap();
        let hash_bytes = hex::decode(hash_hex)
            .map_err(|e| SnapshotError::Export(format!("Failed to decode hash: {}", e)))?;

        // Ensure hash is exactly 32 bytes
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes[0..32]);

        merkle_leaves.push(hash_array);
    }

    // Calculate Merkle root (simplified implementation)
    let merkle_root = calculate_merkle_root(&merkle_leaves);

    // Add commitment
    attestation["commitment"] = json!(hex::encode(merkle_root));

    // Write to file
    let json_str = serde_json::to_string_pretty(&attestation)
        .map_err(|e| SnapshotError::Export(format!("Failed to serialize attestation: {}", e)))?;

    fs::write(output_path, json_str)
        .await
        .map_err(|e| SnapshotError::Export(format!("Failed to write attestation file: {}", e)))?;

    info!(
        "Attestation generated successfully. Commitment: {}",
        hex::encode(merkle_root)
    );

    Ok(())
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
