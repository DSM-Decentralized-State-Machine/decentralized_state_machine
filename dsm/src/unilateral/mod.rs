//! Unilateral Transaction Module
//!
//! This module implements unilateral transactions that don't require immediate counterparty
//! participation. It provides inbox functionality for storing and processing asynchronous messages.

use crate::types::error::DsmError;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::fs;
use uuid::Uuid;

/// Inbox entry for unilateral transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxEntry {
    /// Entry ID (used for reference and deletion)
    pub id: String,

    /// Sender genesis hash
    pub sender_genesis_hash: String,

    /// Recipient genesis hash
    pub recipient_genesis_hash: String,

    /// Transaction payload
    pub transaction: Vec<u8>,

    /// Transaction signature
    pub signature: Vec<u8>,

    /// Timestamp
    pub timestamp: u64,

    /// Expiration timestamp (0 = never)
    pub expires_at: u64,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Interface for inbox storage
#[async_trait]
pub trait InboxStorage: Send + Sync {
    /// Store an inbox entry
    async fn store_entry(&self, entry: &InboxEntry) -> Result<(), DsmError>;

    /// Get inbox entries for a recipient
    async fn get_entries(&self, recipient_id: &str) -> Result<Vec<InboxEntry>, DsmError>;

    /// Delete an inbox entry
    async fn delete_entry(&self, recipient_id: &str, entry_id: &str) -> Result<(), DsmError>;
}

/// File-based inbox storage implementation
pub struct FileInboxStorage {
    base_dir: PathBuf,
}

impl Default for FileInboxStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl FileInboxStorage {
    /// Create a new file-based inbox storage
    pub fn new() -> Self {
        let home_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());

        let base_dir = PathBuf::from(home_dir)
            .join(".dsm_config")
            .join("unilateral");

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&base_dir).unwrap_or_else(|_| {
            eprintln!("Warning: Failed to create unilateral storage directory");
        });

        Self { base_dir }
    }

    /// Get the path to the inbox directory for a recipient
    fn get_inbox_dir(&self, recipient_id: &str) -> PathBuf {
        self.base_dir.join(recipient_id)
    }

    /// Get the path to an inbox entry file
    fn get_entry_path(&self, recipient_id: &str, entry_id: &str) -> PathBuf {
        self.get_inbox_dir(recipient_id)
            .join(format!("{}.json", entry_id))
    }
}

#[async_trait]
impl InboxStorage for FileInboxStorage {
    async fn store_entry(&self, entry: &InboxEntry) -> Result<(), DsmError> {
        // Create recipient directory if it doesn't exist
        let inbox_dir = self.get_inbox_dir(&entry.recipient_genesis_hash);
        fs::create_dir_all(&inbox_dir).await.map_err(|e| {
            DsmError::storage(format!("Failed to create inbox directory: {}", e), Some(e))
        })?;

        // Serialize entry
        let entry_json = serde_json::to_string_pretty(entry).map_err(|e| {
            DsmError::serialization(format!("Failed to serialize inbox entry: {}", e), Some(e))
        })?;

        // Write to file
        let entry_path = self.get_entry_path(&entry.recipient_genesis_hash, &entry.id);
        fs::write(&entry_path, entry_json).await.map_err(|e| {
            DsmError::storage(format!("Failed to write inbox entry: {}", e), Some(e))
        })?;

        Ok(())
    }

    async fn get_entries(&self, recipient_id: &str) -> Result<Vec<InboxEntry>, DsmError> {
        let inbox_dir = self.get_inbox_dir(recipient_id);

        // Check if directory exists
        if !inbox_dir.exists() {
            return Ok(Vec::new());
        }

        // Read directory entries
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(&inbox_dir).await.map_err(|e| {
            DsmError::storage(format!("Failed to read inbox directory: {}", e), Some(e))
        })?;

        // Process each file
        while let Some(entry) = dir.next_entry().await.map_err(|e| {
            DsmError::storage(
                format!("Failed to read inbox directory entry: {}", e),
                Some(e),
            )
        })? {
            let path = entry.path();

            // Skip non-JSON files
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            // Read and parse file
            let content = fs::read_to_string(&path).await.map_err(|e| {
                DsmError::storage(format!("Failed to read inbox entry file: {}", e), Some(e))
            })?;

            let inbox_entry: InboxEntry = serde_json::from_str(&content).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to deserialize inbox entry: {}", e),
                    Some(e),
                )
            })?;

            entries.push(inbox_entry);
        }

        Ok(entries)
    }

    async fn delete_entry(&self, recipient_id: &str, entry_id: &str) -> Result<(), DsmError> {
        let entry_path = self.get_entry_path(recipient_id, entry_id);

        // Check if file exists
        if !entry_path.exists() {
            return Err(DsmError::not_found(
                "Inbox entry",
                Some(format!(
                    "Entry {} for recipient {} not found",
                    entry_id, recipient_id
                )),
            ));
        }

        // Delete file
        fs::remove_file(&entry_path).await.map_err(|e| {
            DsmError::storage(format!("Failed to delete inbox entry: {}", e), Some(e))
        })?;

        Ok(())
    }
}

/// In-memory inbox storage implementation (for testing)
pub struct MemoryInboxStorage {
    entries: Arc<RwLock<HashMap<String, HashMap<String, InboxEntry>>>>,
}

impl Default for MemoryInboxStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryInboxStorage {
    /// Create a new in-memory inbox storage
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl InboxStorage for MemoryInboxStorage {
    async fn store_entry(&self, entry: &InboxEntry) -> Result<(), DsmError> {
        let mut entries = self.entries.write();

        // Get or create recipient inbox
        let recipient_inbox = entries
            .entry(entry.recipient_genesis_hash.clone())
            .or_default();

        // Store entry
        recipient_inbox.insert(entry.id.clone(), entry.clone());

        Ok(())
    }

    async fn get_entries(&self, recipient_id: &str) -> Result<Vec<InboxEntry>, DsmError> {
        let entries = self.entries.read();

        // Get recipient inbox
        let recipient_inbox = entries.get(recipient_id).cloned();

        match recipient_inbox {
            Some(inbox) => Ok(inbox.values().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }

    async fn delete_entry(&self, recipient_id: &str, entry_id: &str) -> Result<(), DsmError> {
        let mut entries = self.entries.write();

        // Get recipient inbox
        let recipient_inbox = entries.get_mut(recipient_id);

        match recipient_inbox {
            Some(inbox) => {
                // Remove entry
                if inbox.remove(entry_id).is_none() {
                    return Err(DsmError::not_found(
                        "Inbox entry",
                        Some(format!(
                            "Entry {} for recipient {} not found",
                            entry_id, recipient_id
                        )),
                    ));
                }

                Ok(())
            }
            None => Err(DsmError::not_found(
                "Inbox",
                Some(format!("Inbox for recipient {} not found", recipient_id)),
            )),
        }
    }
}

/// Inbox manager for handling unilateral transactions
pub struct InboxManager {
    storage: Box<dyn InboxStorage + Send + Sync>,
}

impl InboxManager {
    /// Create a new inbox manager with file-based storage
    pub fn new() -> Self {
        Self {
            storage: Box::new(FileInboxStorage::new()),
        }
    }

    /// Create a new inbox manager with in-memory storage (for testing)
    pub fn new_in_memory() -> Self {
        Self {
            storage: Box::new(MemoryInboxStorage::new()),
        }
    }

    /// Store an inbox entry
    pub async fn store_entry(&self, entry: InboxEntry) -> Result<(), DsmError> {
        self.storage.store_entry(&entry).await
    }

    /// Get inbox entries for a recipient
    pub async fn get_inbox_entries(&self, recipient_id: &str) -> Result<Vec<InboxEntry>, DsmError> {
        self.storage.get_entries(recipient_id).await
    }

    /// Delete an inbox entry
    pub async fn delete_entry(&self, recipient_id: &str, entry_id: &str) -> Result<(), DsmError> {
        self.storage.delete_entry(recipient_id, entry_id).await
    }
}

impl Default for InboxManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a new unilateral transaction and send it to the recipient's inbox
///
/// # Arguments
///
/// * `sender_id` - The sender's identity ID
/// * `recipient_id` - The recipient's identity ID
/// * `data` - The transaction data
/// * `metadata` - Optional metadata for the transaction
/// * `inbox_manager` - The inbox manager to use
///
/// # Returns
///
/// * The ID of the created inbox entry
pub async fn send_unilateral_transaction(
    sender_id: &str,
    recipient_id: &str,
    data: Vec<u8>,
    metadata: Option<HashMap<String, String>>,
    inbox_manager: &InboxManager,
) -> Result<String, DsmError> {
    // Create signature (in a real implementation, this would be a cryptographic signature)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&data);
    hasher.update(sender_id.as_bytes());
    hasher.update(recipient_id.as_bytes());
    let signature = hasher.finalize().as_bytes().to_vec();

    // Create inbox entry
    let entry_id = Uuid::new_v4().to_string();
    let entry = InboxEntry {
        id: entry_id.clone(),
        sender_genesis_hash: sender_id.to_string(),
        recipient_genesis_hash: recipient_id.to_string(),
        transaction: data,
        signature,
        timestamp: chrono::Utc::now().timestamp() as u64,
        expires_at: 0, // Never expires
        metadata: metadata.unwrap_or_default(),
    };

    // Store entry in recipient's inbox
    inbox_manager.store_entry(entry).await?;

    Ok(entry_id)
}

/// Process unilateral transactions from an inbox
///
/// # Arguments
///
/// * `recipient_id` - The recipient's identity ID
/// * `entries` - The inbox entries to process
/// * `inbox_manager` - The inbox manager to use
///
/// # Returns
///
/// * A list of processed entry IDs
pub async fn process_unilateral_transactions(
    recipient_id: &str,
    entries: Vec<InboxEntry>,
    inbox_manager: &InboxManager,
) -> Result<Vec<String>, DsmError> {
    let mut processed_ids = Vec::new();

    for entry in entries {
        // Verify the entry is for this recipient
        if entry.recipient_genesis_hash != recipient_id {
            continue;
        }

        // Verify signature (in a real implementation, this would verify a cryptographic signature)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entry.transaction);
        hasher.update(entry.sender_genesis_hash.as_bytes());
        hasher.update(entry.recipient_genesis_hash.as_bytes());
        let computed_signature = hasher.finalize().as_bytes().to_vec();

        if entry.signature != computed_signature {
            continue;
        }

        // Process the transaction (in a real implementation, this would apply the transaction)
        // For now, we just delete the entry from the inbox
        inbox_manager.delete_entry(recipient_id, &entry.id).await?;

        processed_ids.push(entry.id);
    }

    Ok(processed_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_and_process_unilateral_transaction() {
        // Create in-memory inbox manager for testing
        let inbox_manager = InboxManager::new_in_memory();

        // Send a transaction
        let sender_id = "sender123";
        let recipient_id = "recipient456";
        let data = b"test transaction data".to_vec();

        let entry_id = send_unilateral_transaction(
            sender_id,
            recipient_id,
            data.clone(),
            None,
            &inbox_manager,
        )
        .await
        .unwrap();

        // Check inbox
        let entries = inbox_manager.get_inbox_entries(recipient_id).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, entry_id);
        assert_eq!(entries[0].sender_genesis_hash, sender_id);
        assert_eq!(entries[0].recipient_genesis_hash, recipient_id);
        assert_eq!(entries[0].transaction, data);

        // Process the transaction
        let processed = process_unilateral_transactions(recipient_id, entries, &inbox_manager)
            .await
            .unwrap();

        assert_eq!(processed.len(), 1);
        assert_eq!(processed[0], entry_id);

        // Check inbox is empty
        let entries = inbox_manager.get_inbox_entries(recipient_id).await.unwrap();
        assert_eq!(entries.len(), 0);
    }
}
