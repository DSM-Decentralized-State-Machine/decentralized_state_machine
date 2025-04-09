// Storage module for DSM Storage Node
//
// This module defines the storage interfaces and implementations
// for the DSM Storage Node as described in Section 16.2 of the whitepaper

use crate::error::Result;
use crate::types::storage_types::{
    DataRetrievalRequest, DataSubmissionRequest, StorageResponse, StorageStats,
};
use crate::types::BlindedStateEntry;
use crate::types::StorageNode;
use async_trait::async_trait;
use std::sync::Arc;

pub mod distributed_storage;
pub mod memory_storage;
pub mod pruning;
pub mod sql_storage;
pub mod vector_clock;
pub mod small_world;
pub mod epidemic_storage;

/// Storage configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageConfig {
    /// Database path
    pub database_path: String,
    /// Default TTL for entries (0 = no expiration)
    pub default_ttl: u64,
    /// Enable pruning
    pub enable_pruning: bool,
    /// Pruning interval in seconds
    pub pruning_interval: u64,
}

/// Storage engine interface
#[async_trait]
pub trait StorageEngine: Send + Sync {
    /// Store a blinded state entry
    async fn store(&self, entry: BlindedStateEntry) -> Result<StorageResponse>;

    /// Retrieve a blinded state entry by its ID
    async fn retrieve(&self, blinded_id: &str) -> Result<Option<BlindedStateEntry>>;

    /// Delete a blinded state entry by its ID
    async fn delete(&self, blinded_id: &str) -> Result<bool>;

    /// Check if a blinded state entry exists
    async fn exists(&self, blinded_id: &str) -> Result<bool>;

    /// List blinded state entry IDs with optional pagination
    async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>>;

    /// Get storage statistics
    async fn get_stats(&self) -> Result<StorageStats>;
}

/// Storage factory for creating different storage engine implementations
pub struct StorageFactory {
    /// Configuration for the storage node
    config: StorageConfig,
}

impl StorageFactory {
    /// Create a new storage factory with the given configuration
    pub fn new(config: StorageConfig) -> Self {
        Self { config }
    }
    
    /// Create a memory storage engine
    pub fn create_memory_storage(&self) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let memory_storage = memory_storage::MemoryStorage::new();
        Ok(Arc::new(memory_storage))
    }
    
    /// Create a SQL storage engine
    pub fn create_sql_storage(&self) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let sql_storage = sql_storage::SqlStorage::new(&self.config.database_path)?;
        Ok(Arc::new(sql_storage))
    }
    
    /// Create an epidemic storage engine with small-world topology
    pub async fn create_epidemic_storage(
        &self,
        node_id: String,
        node_info: crate::types::StorageNode,
        bootstrap_nodes: Vec<crate::types::StorageNode>,
        backing_storage: Option<Arc<dyn StorageEngine + Send + Sync>>,
    ) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        use epidemic_storage::{EpidemicStorage, EpidemicStorageConfig};
        use small_world::SmallWorldConfig;
        
        // Create epidemic storage configuration
        let epidemic_config = EpidemicStorageConfig {
            node_id: node_id.clone(),
            node_info: node_info.clone(),
            region: node_info.region.clone(),
            gossip_interval_ms: 5000, // 5 seconds
            anti_entropy_interval_ms: 60000, // 1 minute
            topology_check_interval_ms: 30000, // 30 seconds
            max_concurrent_gossip: 10,
            max_entries_per_gossip: 100,
            max_entries_per_response: 50,
            gossip_fanout: 3,
            gossip_ttl: 3,
            bootstrap_nodes,
            topology_config: SmallWorldConfig {
                max_bucket_size: 8,
                max_immediate_neighbors: 16,
                max_long_links: 16,
            },
            partition_strategy: epidemic_storage::PartitionStrategy::KeyHash,
            regional_consistency: epidemic_storage::RegionalConsistency::EventualCrossRegion,
            max_storage_entries: 100000, // 100k entries by default
            min_verification_count: 2,
            enable_read_repair: true,
            pruning_interval_ms: 3600000, // 1 hour
        };
        
        // Create the epidemic storage
        let storage = EpidemicStorage::new(epidemic_config, backing_storage)?;
        
        // Start the epidemic storage
        storage.start().await?;
        
        Ok(Arc::new(storage))
    }
    
    /// Create a distributed storage engine
    pub fn create_distributed_storage(
        &self,
        local_storage: Arc<dyn StorageEngine + Send + Sync>,
        node_id: String,
        storage_nodes: Vec<crate::types::StorageNode>,
        replication_factor: usize,
        max_hops: usize,
    ) -> Result<Arc<dyn StorageEngine + Send + Sync>> {
        let distributed_storage = distributed_storage::DistributedStorage::new(
            local_storage,
            node_id,
            storage_nodes,
            replication_factor,
            max_hops,
        )?;
        
        Ok(Arc::new(distributed_storage))
    }
}

/// Storage provider for the storage node
pub struct StorageProvider {
    /// Primary storage engine
    pub primary: Arc<dyn StorageEngine>,

    /// Backup storage engine (optional)
    pub backup: Option<Arc<dyn StorageEngine>>,

    /// Node information
    pub node: StorageNode,

    /// Default TTL for stored entries (0 = no expiration)
    pub default_ttl: u64,

    /// Default region for stored entries
    pub default_region: String,
}

impl StorageProvider {
    /// Create a new storage provider
    pub fn new(
        primary: Arc<dyn StorageEngine>,
        backup: Option<Arc<dyn StorageEngine>>,
        node: StorageNode,
        default_ttl: u64,
        default_region: String,
    ) -> Self {
        Self {
            primary,
            backup,
            node,
            default_ttl,
            default_region,
        }
    }

    /// Store data from a submission request
    pub async fn store(&self, request: DataSubmissionRequest) -> Result<StorageResponse> {
        // Extract or use defaults for the entry fields
        let ttl = request.ttl.unwrap_or(self.default_ttl);
        let region = request
            .region
            .unwrap_or_else(|| self.default_region.clone());
        let priority = request.priority.unwrap_or(0);
        let metadata = request.metadata.unwrap_or_default();

        // Validate proof hash or generate a default one
        let proof_hash = match request.proof_hash {
            Some(hash) => hash,
            None => {
                // Generate a hash from the payload
                let mut hasher = blake3::Hasher::new();
                hasher.update(&request.payload);
                let hash = hasher.finalize();

                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(hash.as_bytes());
                hash_bytes
            }
        };

        // Create the blinded state entry
        let entry = BlindedStateEntry {
            blinded_id: request.blinded_id,
            encrypted_payload: request.payload,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            ttl,
            region,
            priority,
            proof_hash,
            metadata,
        };

        // Store in primary storage
        let response = self.primary.store(entry.clone()).await?;

        // If backup storage is available, store there as well
        if let Some(backup) = &self.backup {
            // Store in backup, but don't fail the request if backup fails
            if let Err(e) = backup.store(entry).await {
                tracing::warn!("Failed to store in backup storage: {}", e);
            }
        }

        Ok(response)
    }

    /// Retrieve data from a retrieval request
    pub async fn retrieve(
        &self,
        request: DataRetrievalRequest,
    ) -> Result<Option<BlindedStateEntry>> {
        // Try to retrieve from primary storage
        match self.primary.retrieve(&request.blinded_id).await {
            Ok(Some(entry)) => return Ok(Some(entry)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("Error retrieving from primary storage: {}", e);
                // Continue to try backup if available
            }
        }

        // If not found in primary and backup is available, try backup
        if let Some(backup) = &self.backup {
            match backup.retrieve(&request.blinded_id).await {
                Ok(Some(entry)) => {
                    // Found in backup but not in primary, restore to primary
                    if let Err(e) = self.primary.store(entry.clone()).await {
                        tracing::warn!("Failed to restore entry to primary storage: {}", e);
                    }

                    return Ok(Some(entry));
                }
                Ok(None) => return Ok(None),
                Err(e) => {
                    tracing::warn!("Error retrieving from backup storage: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(None)
    }

    /// Delete data by its blinded ID
    pub async fn delete(&self, blinded_id: &str) -> Result<bool> {
        let mut primary_result = false;
        let mut backup_result = false;

        // Delete from primary storage
        match self.primary.delete(blinded_id).await {
            Ok(result) => primary_result = result,
            Err(e) => {
                tracing::warn!("Error deleting from primary storage: {}", e);
                // Continue to try backup
            }
        }

        // Delete from backup if available
        if let Some(backup) = &self.backup {
            match backup.delete(blinded_id).await {
                Ok(result) => backup_result = result,
                Err(e) => {
                    tracing::warn!("Error deleting from backup storage: {}", e);
                }
            }
        }

        // Return true if deleted from either primary or backup
        Ok(primary_result || backup_result)
    }

    /// Check if data exists by its blinded ID
    pub async fn exists(&self, blinded_id: &str) -> Result<bool> {
        // Check primary storage
        match self.primary.exists(blinded_id).await {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => {
                tracing::warn!("Error checking existence in primary storage: {}", e);
                // Continue to check backup
            }
        }

        // If not found in primary and backup is available, check backup
        if let Some(backup) = &self.backup {
            match backup.exists(blinded_id).await {
                Ok(true) => return Ok(true),
                Ok(false) => return Ok(false),
                Err(e) => {
                    tracing::warn!("Error checking existence in backup storage: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(false)
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> Result<StorageStats> {
        // Get primary storage stats
        let primary_stats = self.primary.get_stats().await?;

        // Return primary stats
        Ok(primary_stats)
    }
}
