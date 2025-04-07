// In-memory storage implementation for DSM Storage Node
//
// This is a simple in-memory storage implementation for testing and development.

use crate::error::Result;
use crate::types::storage_types::StorageStats;
use crate::types::BlindedStateEntry;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

/// In-memory storage engine
pub struct MemoryStorage {
    /// Storage map
    store: Arc<DashMap<String, BlindedStateEntry>>,
    /// Total bytes stored
    total_bytes: AtomicU64,
    /// Total entries
    total_entries: AtomicU64,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    /// Create a new in-memory storage engine
    pub fn new() -> Self {
        info!("Creating new in-memory storage engine");
        Self {
            store: Arc::new(DashMap::new()),
            total_bytes: AtomicU64::new(0),
            total_entries: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl super::StorageEngine for MemoryStorage {
    /// Store a blinded state entry
    async fn store(
        &self,
        entry: BlindedStateEntry,
    ) -> Result<crate::types::storage_types::StorageResponse> {
        let blinded_id = entry.blinded_id.clone();

        // Calculate entry size (approximate)
        let entry_size = entry.encrypted_payload.len() as u64 + entry.blinded_id.len() as u64 + 64; // Base overhead for other fields

        // Check if the entry already exists
        let exists = self.store.contains_key(&blinded_id);

        if exists {
            // Update existing entry
            if let Some(mut existing) = self.store.get_mut(&blinded_id) {
                // Adjust storage size
                let old_size = existing.encrypted_payload.len() as u64;
                self.total_bytes.fetch_add(entry_size, Ordering::SeqCst);
                self.total_bytes.fetch_sub(old_size, Ordering::SeqCst);

                // Update entry
                *existing = entry;
            }
        } else {
            // Add new entry
            self.store.insert(blinded_id.clone(), entry);
            self.total_bytes.fetch_add(entry_size, Ordering::SeqCst);
            self.total_entries.fetch_add(1, Ordering::SeqCst);
        }

        debug!("Stored entry with ID {}", blinded_id);

        Ok(crate::types::storage_types::StorageResponse {
            blinded_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            status: "success".to_string(),
            message: Some("Entry stored successfully".to_string()),
        })
    }

    /// Retrieve a blinded state entry by its ID
    async fn retrieve(&self, blinded_id: &str) -> Result<Option<BlindedStateEntry>> {
        debug!("Retrieving entry with ID {}", blinded_id);

        if let Some(entry) = self.store.get(blinded_id) {
            // Check if entry has expired
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());

            if entry.ttl > 0 && entry.timestamp + entry.ttl < now {
                debug!("Entry with ID {} has expired", blinded_id);
                return Ok(None);
            }

            return Ok(Some(entry.clone()));
        }

        debug!("Entry with ID {} not found", blinded_id);
        Ok(None)
    }

    /// Delete a blinded state entry by its ID
    async fn delete(&self, blinded_id: &str) -> Result<bool> {
        debug!("Deleting entry with ID {}", blinded_id);

        if let Some((_, entry)) = self.store.remove(blinded_id) {
            // Adjust storage size
            let entry_size =
                entry.encrypted_payload.len() as u64 + entry.blinded_id.len() as u64 + 64; // Base overhead for other fields

            self.total_bytes.fetch_sub(entry_size, Ordering::SeqCst);
            self.total_entries.fetch_sub(1, Ordering::SeqCst);

            debug!("Deleted entry with ID {}", blinded_id);
            return Ok(true);
        }

        debug!("Entry with ID {} not found for deletion", blinded_id);
        Ok(false)
    }

    /// Check if a blinded state entry exists
    async fn exists(&self, blinded_id: &str) -> Result<bool> {
        debug!("Checking if entry with ID {} exists", blinded_id);

        if let Some(entry) = self.store.get(blinded_id) {
            // Check if entry has expired
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());

            if entry.ttl > 0 && entry.timestamp + entry.ttl < now {
                debug!("Entry with ID {} has expired", blinded_id);
                return Ok(false);
            }

            return Ok(true);
        }

        debug!("Entry with ID {} not found", blinded_id);
        Ok(false)
    }

    /// List blinded state entry IDs with optional pagination
    async fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<String>> {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);

        debug!("Listing entries with offset {} and limit {}", offset, limit);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        // Filter out expired entries and apply pagination
        let mut entries: Vec<String> = self
            .store
            .iter()
            .filter(|entry| {
                let e = entry.value();
                e.ttl == 0 || e.timestamp + e.ttl >= now
            })
            .map(|entry| entry.key().clone())
            .skip(offset)
            .take(limit)
            .collect();

        debug!("Found {} entries", entries.len());

        // Sort entries by ID for consistency
        entries.sort();

        Ok(entries)
    }

    /// Get storage statistics
    async fn get_stats(&self) -> Result<StorageStats> {
        debug!("Getting storage statistics");

        Ok(StorageStats {
            total_entries: self.total_entries.load(Ordering::SeqCst) as usize,
            total_bytes: self.total_bytes.load(Ordering::SeqCst) as usize,
            total_expired: 0,   // Not tracked in memory storage
            oldest_entry: None, // Not tracked in memory storage
            newest_entry: None, // Not tracked in memory storage
        })
    }
}
