use std::path::Path;
use tokio::fs;
use chrono::Utc;
use serde_json::{json, Value};
use tracing::{info, warn, error};
use csv::Writer;
use std::collections::HashMap;

use crate::error::{Result, SnapshotError, ExportError};
use crate::persistence::snapshot_store::SnapshotStore;
use crate::types::SnapshotMetadata;

/// Export snapshot data to JSON format
pub async fn export_json(store: &SnapshotStore, output_path: &Path) -> Result<()> {
    info!("Exporting snapshots to JSON: {:?}", output_path);

    // Get all snapshot metadata
    let snapshots = store.list_snapshots();
    
    // If no snapshots but we have IP entries in memory, create an auto-snapshot
    if snapshots.is_empty() && store.get_ip_count() > 0 {
        info!("No snapshots found but {} IPs in memory. Creating auto-snapshot.", store.get_ip_count());
        
        // Create an auto-snapshot with the current timestamp
        let snapshot_id = format!("snapshot_{}", Utc::now().format("%Y%m%d_%H%M%S"));
        
        // Build metadata
        let metadata = SnapshotMetadata {
            id: snapshot_id.clone(),
            description: "Auto-generated snapshot from export".to_string(),
            created_at: Utc::now(),
            ip_count: 0, // Will be updated by the store
            country_count: 0, // Will be updated by the store
            start_time: Utc::now().checked_sub_signed(chrono::Duration::minutes(10)).unwrap_or(Utc::now()),
            end_time: Some(Utc::now()),
            flagged_ip_count: 0,
            top_countries: HashMap::new(),
            collection_params: "Auto-export collection".to_string(),
            data_hash: uuid::Uuid::new_v4().to_string(),
        };
        
        // Create the snapshot
        match store.create_snapshot(&snapshot_id, metadata).await {
            Ok(count) => {
                info!("Created auto-snapshot {} with {} IPs", snapshot_id, count);
            }
            Err(e) => {
                error!("Failed to create auto-snapshot: {}", e);
            }
        }
    }
    
    // Refresh snapshot list
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

        // Create snapshot object with just metadata if there are no entries
        let snapshot_data = match store.load_snapshot(snapshot_id).await {
            Ok((entries, _)) => {
                json!({
                    "id": snapshot_id,
                    "metadata": metadata,
                    "entries_count": entries.len(),
                    "has_entries": !entries.is_empty(),
                })
            },
            Err(e) => {
                warn!("Could not load snapshot {}: {}", snapshot_id, e);
                json!({
                    "id": snapshot_id,
                    "metadata": metadata,
                    "entries_count": 0,
                    "has_entries": false,
                    "error": format!("Failed to load: {}", e),
                })
            }
        };

        snapshot_array.push(snapshot_data);
    }

    // Add snapshots to export data
    export_data["snapshots"] = json!(snapshot_array);

    // Also include some stats to make this more useful
    if let Ok(stats) = store.get_stats().await {
        export_data["stats"] = stats;
    }

    // Create parent directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).await.map_err(|e| {
                SnapshotError::Export(format!("Failed to create export directory: {}", e))
            })?;
        }
    }

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

    // Create parent directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).await.map_err(|e| {
                SnapshotError::Export(format!("Failed to create export directory: {}", e))
            })?;
        }
    }

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
        match store.load_snapshot(snapshot_id).await {
            Ok((entries, _)) => {
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
                    ];

                    // Write record
                    writer
                        .write_record(&record)
                        .map_err(|e| SnapshotError::Export(format!("CSV export error: {}", e)))?;

                    total_entries += 1;
                }
            },
            Err(e) => {
                warn!("Failed to load snapshot {} for CSV export: {}", snapshot_id, e);
                // Write a single row with the error
                let error_record = vec![
                    snapshot_id.clone(),
                    "ERROR".to_string(),
                    Utc::now().to_rfc3339(),
                    Utc::now().to_rfc3339(),
                    "0".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    format!("Error: {}", e),
                ];
                
                writer
                    .write_record(&error_record)
                    .map_err(|e| SnapshotError::Export(format!("CSV export error: {}", e)))?;
            }
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
