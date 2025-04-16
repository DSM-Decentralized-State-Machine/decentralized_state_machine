use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::fs;
use parking_lot::RwLock;
use chrono::Utc;
use blake3::Hasher;
use dashmap::DashMap;
use tracing::{info, error, debug};

use crate::types::{IpEntry, SnapshotMetadata};
use crate::error::{Result, SnapshotError};

/// Storage mechanism for IP snapshots with transactional integrity guarantees
pub struct SnapshotStore {
    /// Base directory for storing snapshots
    base_dir: PathBuf,

    /// Snapshot metadata cache
    metadata_cache: Arc<DashMap<String, SnapshotMetadata>>,

    /// Current transaction
    current_transaction: Arc<RwLock<Option<SnapshotTransaction>>>,
}

/// Snapshot transaction for atomic operations
struct SnapshotTransaction {
    /// Transaction ID
    id: String,

    /// Snapshot ID
    snapshot_id: String,

    /// Transaction directory
    tx_dir: PathBuf,

    /// Metadata file path
    metadata_path: PathBuf,

    /// Data file path
    data_path: PathBuf,

    /// Transaction state
    state: TransactionState,
}

/// Transaction state
#[allow(dead_code)]
enum TransactionState {
    /// Transaction started
    Started,

    /// Transaction committed
    Committed,

    /// Transaction rolled back
    RolledBack,
}

#[allow(dead_code)]
impl SnapshotStore {
    /// Create a new snapshot store
    pub async fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        // Create base directory if it doesn't exist
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).await.map_err(|e| {
                SnapshotError::Database(format!("Failed to create base directory: {}", e))
            })?;
        }

        // Initialize metadata cache
        let metadata_cache = Arc::new(DashMap::new());

        // Load existing snapshots
        Self::load_existing_snapshots(&base_dir, &metadata_cache).await?;

        Ok(Self {
            base_dir,
            metadata_cache,
            current_transaction: Arc::new(RwLock::new(None)),
        })
    }

    /// Load existing snapshots
    async fn load_existing_snapshots(
        base_dir: &Path,
        metadata_cache: &Arc<DashMap<String, SnapshotMetadata>>,
    ) -> Result<()> {
        // Get all snapshot directories
        let mut entries = fs::read_dir(base_dir).await.map_err(|e| {
            SnapshotError::Database(format!("Failed to read base directory: {}", e))
        })?;

        // Process each snapshot
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            SnapshotError::Database(format!("Failed to read directory entry: {}", e))
        })? {
            let path = entry.path();

            // Check if it's a directory
            if path.is_dir() {
                let snapshot_id = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                // Try to load metadata
                let metadata_path = path.join("metadata.json");
                if metadata_path.exists() {
                    match fs::read_to_string(&metadata_path).await {
                        Ok(content) => match serde_json::from_str::<SnapshotMetadata>(&content) {
                            Ok(metadata) => {
                                metadata_cache.insert(snapshot_id.to_string(), metadata);
                                debug!("Loaded snapshot {}", snapshot_id);
                            }
                            Err(e) => {
                                error!(
                                    "Failed to parse metadata for snapshot {}: {}",
                                    snapshot_id, e
                                );
                            }
                        },
                        Err(e) => {
                            error!(
                                "Failed to read metadata for snapshot {}: {}",
                                snapshot_id, e
                            );
                        }
                    }
                }
            }
        }

        info!("Loaded {} snapshots", metadata_cache.len());

        Ok(())
    }

    /// Begin a new snapshot transaction
    async fn begin_transaction(&self, snapshot_id: &str) -> Result<SnapshotTransaction> {
        // Check if there's already a transaction in progress
        {
            let tx_guard = self.current_transaction.read();
            if tx_guard.is_some() {
                return Err(SnapshotError::Database(
                    "Transaction already in progress".to_string(),
                ));
            }
        } // Lock is dropped here

        // Generate transaction ID
        let tx_id = format!("tx-{}-{}", snapshot_id, Utc::now().timestamp_millis());

        // Create transaction directory
        let tx_dir = self.base_dir.join("transactions").join(&tx_id);
        fs::create_dir_all(&tx_dir).await.map_err(|e| {
            SnapshotError::Database(format!("Failed to create transaction directory: {}", e))
        })?;

        // Create paths
        let metadata_path = tx_dir.join("metadata.json");
        let data_path = tx_dir.join("data.json");

        // Create transaction
        let transaction = SnapshotTransaction {
            id: tx_id,
            snapshot_id: snapshot_id.to_string(),
            tx_dir,
            metadata_path,
            data_path,
            state: TransactionState::Started,
        };

        // Store transaction
        *self.current_transaction.write() = Some(transaction.clone());

        Ok(transaction)
    }

    /// Commit a transaction
    async fn commit_transaction(&self, transaction: &SnapshotTransaction) -> Result<()> {
        // Check transaction state
        match transaction.state {
            TransactionState::Started => {}
            TransactionState::Committed => {
                return Err(SnapshotError::Database(
                    "Transaction already committed".to_string(),
                ));
            }
            TransactionState::RolledBack => {
                return Err(SnapshotError::Database(
                    "Transaction already rolled back".to_string(),
                ));
            }
        }

        // Create snapshot directory
        let snapshot_dir = self.base_dir.join(&transaction.snapshot_id);
        fs::create_dir_all(&snapshot_dir).await.map_err(|e| {
            SnapshotError::Database(format!("Failed to create snapshot directory: {}", e))
        })?;

        // Move files from transaction to snapshot directory
        let target_metadata_path = snapshot_dir.join("metadata.json");
        let target_data_path = snapshot_dir.join("data.json");

        // Copy metadata
        fs::copy(&transaction.metadata_path, &target_metadata_path)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to copy metadata: {}", e)))?;

        // Copy data
        fs::copy(&transaction.data_path, &target_data_path)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to copy data: {}", e)))?;

        // Update transaction state and clear current transaction
        // Move this after all async operations to avoid holding lock across awaits
        {
            let mut tx = self.current_transaction.write();
            if let Some(tx) = tx.as_mut() {
                tx.state = TransactionState::Committed;
            }
            *tx = None; // Clear current transaction
        }

        // Clean up transaction directory
        let _ = fs::remove_dir_all(&transaction.tx_dir).await;

        Ok(())
    }

    /// Rollback a transaction
    async fn rollback_transaction(&self, transaction: &SnapshotTransaction) -> Result<()> {
        // Check transaction state
        match transaction.state {
            TransactionState::Started => {}
            TransactionState::Committed => {
                return Err(SnapshotError::Database(
                    "Transaction already committed".to_string(),
                ));
            }
            TransactionState::RolledBack => {
                return Err(SnapshotError::Database(
                    "Transaction already rolled back".to_string(),
                ));
            }
        }

        // Update transaction state and store the directory to clean up
        let tx_dir = transaction.tx_dir.clone();
        {
            let mut tx = self.current_transaction.write();
            if let Some(tx) = tx.as_mut() {
                tx.state = TransactionState::RolledBack;
            }
            // Clear current transaction
            *tx = None;
        }

        // Clean up transaction directory after releasing the lock
        let _ = fs::remove_dir_all(&tx_dir).await;

        Ok(())
    }

    /// Save a snapshot
    pub async fn save_snapshot(
        &self,
        snapshot_id: &str,
        entries: Vec<IpEntry>,
        metadata: SnapshotMetadata,
    ) -> Result<()> {
        // Begin transaction
        let transaction = self.begin_transaction(snapshot_id).await?;

        // Write metadata
        let metadata_json =
            serde_json::to_string_pretty(&metadata).map_err(|e| SnapshotError::Serialization(e))?;

        fs::write(&transaction.metadata_path, metadata_json)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to write metadata: {}", e)))?;

        // Write data
        let data_json =
            serde_json::to_string_pretty(&entries).map_err(|e| SnapshotError::Serialization(e))?;

        fs::write(&transaction.data_path, data_json)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to write data: {}", e)))?;

        // Commit transaction
        self.commit_transaction(&transaction).await?;

        // Update metadata cache
        self.metadata_cache
            .insert(snapshot_id.to_string(), metadata);

        Ok(())
    }

    /// Load a snapshot
    pub async fn load_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<(Vec<IpEntry>, SnapshotMetadata)> {
        // Get snapshot directory
        let snapshot_dir = self.base_dir.join(snapshot_id);

        // Check if directory exists
        if !snapshot_dir.exists() {
            return Err(SnapshotError::NotFound(format!(
                "Snapshot {} not found",
                snapshot_id
            )));
        }

        // Load metadata
        let metadata_path = snapshot_dir.join("metadata.json");
        let metadata_str = fs::read_to_string(&metadata_path)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to read metadata: {}", e)))?;

        let metadata = serde_json::from_str::<SnapshotMetadata>(&metadata_str)
            .map_err(|e| SnapshotError::Serialization(e))?;

        // Load data
        let data_path = snapshot_dir.join("data.json");
        let data_str = fs::read_to_string(&data_path)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to read data: {}", e)))?;

        let entries = serde_json::from_str::<Vec<IpEntry>>(&data_str)
            .map_err(|e| SnapshotError::Serialization(e))?;

        Ok((entries, metadata))
    }

    /// Get snapshot metadata
    pub fn get_snapshot_metadata(&self, snapshot_id: &str) -> Option<SnapshotMetadata> {
        self.metadata_cache
            .get(snapshot_id)
            .map(|entry| entry.clone())
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Vec<SnapshotMetadata> {
        self.metadata_cache
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Delete a snapshot
    pub async fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        // Get snapshot directory
        let snapshot_dir = self.base_dir.join(snapshot_id);

        // Check if directory exists
        if !snapshot_dir.exists() {
            return Err(SnapshotError::NotFound(format!(
                "Snapshot {} not found",
                snapshot_id
            )));
        }

        // Delete directory
        fs::remove_dir_all(&snapshot_dir)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to delete snapshot: {}", e)))?;

        // Remove from cache
        self.metadata_cache.remove(snapshot_id);

        Ok(())
    }

    /// Calculate snapshot hash
    pub async fn calculate_snapshot_hash(&self, snapshot_id: &str) -> Result<String> {
        // Get snapshot data
        let (entries, metadata) = self.load_snapshot(snapshot_id).await?;

        // Create a hasher
        let mut hasher = Hasher::new();

        // Add metadata to the hash
        let metadata_json =
            serde_json::to_string(&metadata).map_err(|e| SnapshotError::Serialization(e))?;
        hasher.update(metadata_json.as_bytes());

        // Sort entries by IP for deterministic ordering
        let mut sorted_entries = entries;
        sorted_entries.sort_by(|a, b| a.ip.to_string().cmp(&b.ip.to_string()));

        // Add each entry's verification hash to the hasher
        for entry in &sorted_entries {
            hasher.update(entry.verification_hash.as_bytes());
        }

        // Return the hash as hex
        Ok(hex::encode(hasher.finalize().as_bytes()))
    }

    /// Export snapshot data as JSON
    pub async fn export_snapshot_json(&self, snapshot_id: &str, output_path: &Path) -> Result<()> {
        // Load snapshot
        let (entries, metadata) = self.load_snapshot(snapshot_id).await?;

        // Create export data
        let export_data = serde_json::json!({
            "metadata": metadata,
            "entries": entries,
            "export_time": Utc::now(),
            "hash": self.calculate_snapshot_hash(snapshot_id).await?,
        });

        // Write to file
        let json_str = serde_json::to_string_pretty(&export_data)
            .map_err(|e| SnapshotError::Serialization(e))?;

        fs::write(output_path, json_str)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to write export file: {}", e)))?;

        Ok(())
    }

    /// Copy a snapshot with a new ID
    pub async fn copy_snapshot(&self, source_id: &str, target_id: &str) -> Result<()> {
        // Load source snapshot
        let (entries, mut metadata) = self.load_snapshot(source_id).await?;

        // Update metadata for the copy
        metadata.id = target_id.to_string();

        // Save as new snapshot
        self.save_snapshot(target_id, entries, metadata).await
    }

    /// Verify snapshot integrity
    pub async fn verify_snapshot_integrity(&self, snapshot_id: &str) -> Result<bool> {
        // Load snapshot
        let (entries, metadata) = self.load_snapshot(snapshot_id).await?;

        // Verify each entry's integrity
        for entry in &entries {
            if !entry.verify_integrity() {
                return Ok(false);
            }
        }

        // Verify metadata hash matches calculated hash
        let calculated_hash = self.calculate_snapshot_hash(snapshot_id).await?;
        if metadata.data_hash != calculated_hash && !metadata.data_hash.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get snapshot statistics
    pub async fn get_snapshot_stats(&self, snapshot_id: &str) -> Result<serde_json::Value> {
        // Load snapshot
        let (entries, metadata) = self.load_snapshot(snapshot_id).await?;

        // Calculate country statistics
        let mut country_counts: HashMap<String, usize> = HashMap::new();
        let mut asn_counts: HashMap<u32, usize> = HashMap::new();
        let mut legitimate_count = 0;
        let mut vpn_count = 0;

        for entry in &entries {
            // Count by country
            if let Some(geo) = &entry.geo {
                if let Some(country_code) = &geo.country_code {
                    *country_counts.entry(country_code.clone()).or_insert(0) += 1;
                }
            }

            // Count by ASN
            if let Some(asn) = entry.network.asn {
                *asn_counts.entry(asn).or_insert(0) += 1;
            }

            // Count by legitimacy
            if entry.legitimacy_score >= 50 {
                legitimate_count += 1;
            } else {
                vpn_count += 1;
            }
        }

        // Sort countries by count
        let mut country_stats: Vec<(String, usize)> = country_counts.into_iter().collect();
        country_stats.sort_by(|a, b| b.1.cmp(&a.1));

        // Get top 10 countries
        let top_countries: Vec<serde_json::Value> = country_stats
            .iter()
            .take(10)
            .map(|(code, count)| {
                serde_json::json!({
                    "country_code": code,
                    "count": count,
                    "percentage": (*count as f64 / entries.len() as f64 * 100.0)
                })
            })
            .collect();

        // Sort ASNs by count
        let mut asn_stats: Vec<(u32, usize)> = asn_counts.into_iter().collect();
        asn_stats.sort_by(|a, b| b.1.cmp(&a.1));

        // Get top 10 ASNs
        let top_asns: Vec<serde_json::Value> = asn_stats
            .iter()
            .take(10)
            .map(|(asn, count)| {
                serde_json::json!({
                    "asn": asn,
                    "count": count,
                    "percentage": (*count as f64 / entries.len() as f64 * 100.0)
                })
            })
            .collect();

        // Build statistics object
        let stats = serde_json::json!({
            "snapshot_id": snapshot_id,
            "total_ips": entries.len(),
            "legitimate_ips": legitimate_count,
            "vpn_ips": vpn_count,
            "countries": {
                "total": country_stats.len(),
                "top10": top_countries
            },
            "asns": {
                "total": asn_stats.len(),
                "top10": top_asns
            },
            "integrity_verified": self.verify_snapshot_integrity(snapshot_id).await?,
            "created_at": metadata.start_time,
            "finalized_at": metadata.end_time,
        });

        Ok(stats)
    }

    /// Get base directory
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

impl Clone for SnapshotStore {
    fn clone(&self) -> Self {
        Self {
            base_dir: self.base_dir.clone(),
            metadata_cache: self.metadata_cache.clone(),
            current_transaction: self.current_transaction.clone(),
        }
    }
}

impl Clone for SnapshotTransaction {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            snapshot_id: self.snapshot_id.clone(),
            tx_dir: self.tx_dir.clone(),
            metadata_path: self.metadata_path.clone(),
            data_path: self.data_path.clone(),
            state: match self.state {
                TransactionState::Started => TransactionState::Started,
                TransactionState::Committed => TransactionState::Committed,
                TransactionState::RolledBack => TransactionState::RolledBack,
            },
        }
    }
}
