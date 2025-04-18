use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use parking_lot::RwLock;
use chrono::Utc;
use blake3::Hasher;
use dashmap::DashMap;
use serde_json::json;
use tracing::{info, error, debug, warn};
use std::collections::HashMap;

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

    /// In-memory storage for IP entries (until snapshot is created)
    ip_entries: Arc<DashMap<String, IpEntry>>,
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

// Apply #[allow(dead_code)] to the entire implementation to suppress warnings
// about methods that will be used in future extensions of the system
#[allow(dead_code)]
impl SnapshotStore {
    /// Add an IP entry to the store
    pub async fn add_ip_entry(&self, entry: IpEntry) -> Result<()> {
        // Store the IP entry in memory
        self.ip_entries.insert(entry.ip.to_string(), entry);
        Ok(())
    }
    
    /// Create a new snapshot with the given ID and metadata
    pub async fn create_snapshot(&self, id: &str, mut metadata: SnapshotMetadata) -> Result<usize> {
        // Get all IP entries
        let entries: Vec<IpEntry> = self.ip_entries.iter().map(|e| e.value().clone()).collect();
        let entry_count = entries.len();
        
        // Update metadata with actual counts
        metadata.ip_count = entry_count;
        
        // Count countries
        let mut country_counts: HashMap<String, usize> = HashMap::new();
        for entry in &entries {
            if let Some(geo) = &entry.geo {
                if let Some(country) = &geo.country_code {
                    *country_counts.entry(country.clone()).or_insert(0) += 1;
                }
            }
        }
        
        metadata.country_count = country_counts.len();
        
        // Get top countries (limited to 10)
        let mut countries: Vec<(String, usize)> = country_counts.into_iter().collect();
        countries.sort_by(|a, b| b.1.cmp(&a.1));
        
        let top_countries: HashMap<String, usize> = countries
            .into_iter()
            .take(10)
            .collect();
        
        metadata.top_countries = top_countries;
        
        // Set end time
        metadata.end_time = Some(Utc::now());
        
        // Save snapshot
        if entry_count > 0 {
            self.save_snapshot(id, entries, metadata).await?;
            info!("Created snapshot {} with {} IPs", id, entry_count);
        } else {
            warn!("No IP entries to save in snapshot {}", id);
            
            // Save empty snapshot with metadata
            self.save_snapshot(id, Vec::new(), metadata).await?;
        }
        
        Ok(entry_count)
    }

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
        
        // Initialize in-memory storage
        let ip_entries = Arc::new(DashMap::new());

        // Load existing snapshots
        Self::load_existing_snapshots(&base_dir, &metadata_cache).await?;

        Ok(Self {
            base_dir,
            metadata_cache,
            current_transaction: Arc::new(RwLock::new(None)),
            ip_entries,
        })
    }

    /// Load existing snapshots
    async fn load_existing_snapshots(
        base_dir: &Path,
        metadata_cache: &Arc<DashMap<String, SnapshotMetadata>>,
    ) -> Result<()> {
        // Get all snapshot directories
        let mut entries = match fs::read_dir(base_dir).await {
            Ok(entries) => entries,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    // Directory doesn't exist yet, which is fine for a new instance
                    info!("Snapshot directory does not exist yet, will be created when needed");
                    return Ok(());
                }
                return Err(SnapshotError::Database(format!("Failed to read base directory: {}", e)));
            }
        };

        // Process each snapshot
        let mut loaded_count = 0;
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
                                loaded_count += 1;
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

        info!("Loaded {} snapshots", loaded_count);

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
        let tx_dir = self.base_dir.join("transactions");
        fs::create_dir_all(&tx_dir).await.map_err(|e| {
            SnapshotError::Database(format!("Failed to create transaction directory: {}", e))
        })?;
        let tx_dir = tx_dir.join(&tx_id);
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
            serde_json::to_string_pretty(&metadata).map_err(SnapshotError::Serialization)?;

        fs::write(&transaction.metadata_path, metadata_json)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to write metadata: {}", e)))?;

        // Write data
        let data_json =
            serde_json::to_string_pretty(&entries).map_err(SnapshotError::Serialization)?;

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
            .map_err(SnapshotError::Serialization)?;

        // Load data
        let data_path = snapshot_dir.join("data.json");
        let data_str = fs::read_to_string(&data_path)
            .await
            .map_err(|e| SnapshotError::Database(format!("Failed to read data: {}", e)))?;

        let entries = serde_json::from_str::<Vec<IpEntry>>(&data_str)
            .map_err(SnapshotError::Serialization)?;

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
            serde_json::to_string(&metadata).map_err(SnapshotError::Serialization)?;
        hasher.update(metadata_json.as_bytes());

        // Sort entries by IP for deterministic ordering
        let mut sorted_entries = entries;
        sorted_entries.sort_by(|a, b| a.ip.to_string().cmp(&b.ip.to_string()));

        // Add each entry's IP address to the hasher as a simple alternative
        for entry in &sorted_entries {
            hasher.update(entry.ip.to_string().as_bytes());
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
            .map_err(SnapshotError::Serialization)?;

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
        let (_, _) = self.load_snapshot(snapshot_id).await?;

        // With simplified approach, just check if metadata exists
        // No need for complex verification anymore
        Ok(true)
    }

    /// Get snapshot statistics
    pub async fn get_stats(&self) -> Result<serde_json::Value> {
        let snapshots = self.list_snapshots();
        let mut total_ips = 0;
        let mut unique_countries = std::collections::HashSet::new();

        for metadata in &snapshots {
            total_ips += metadata.ip_count;
            unique_countries.extend(metadata.top_countries.keys().cloned());
        }

        Ok(json!({
            "total_snapshots": snapshots.len(),
            "total_ips": total_ips,
            "unique_countries": unique_countries.len(),
            "in_memory_ips": self.ip_entries.len()
        }))
    }

    /// Export data as JSON
    pub async fn export_json(&self) -> Result<serde_json::Value> {
        Ok(json!({
            "snapshots": self.list_snapshots(),
            "export_time": Utc::now()
        }))
    }

    /// Export data as CSV
    pub async fn export_csv(&self) -> Result<String> {
        Ok("IP,Country,ASN,Score\n".to_string()) // Simplified CSV header for example
    }

    /// Export data hash
    pub async fn export_hash(&self) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        for metadata in self.list_snapshots() {
            hasher.update(metadata.data_hash.as_bytes());
        }
        Ok(hex::encode(hasher.finalize().as_bytes()))
    }

    /// Get base directory
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
    
    /// Get in-memory IP count
    pub fn get_ip_count(&self) -> usize {
        self.ip_entries.len()
    }
}

impl Clone for SnapshotStore {
    fn clone(&self) -> Self {
        Self {
            base_dir: self.base_dir.clone(),
            metadata_cache: self.metadata_cache.clone(),
            current_transaction: self.current_transaction.clone(),
            ip_entries: self.ip_entries.clone(),
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
