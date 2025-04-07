// Unilateral Transaction API for DSM Storage Node
//
// This module implements API handlers for unilateral transaction inbox functionality.

use crate::error::{Result, StorageNodeError};
use crate::storage::StorageEngine;
use crate::types::BlindedStateEntry;
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

/// Unilateral transaction inbox entry
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

/// Wrapper for inbox submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxSubmission {
    /// Entry to submit
    pub entry: InboxEntry,
}

/// Store an inbox entry
#[axum::debug_handler]
pub async fn store_inbox_entry(
    State(storage): State<Arc<dyn StorageEngine + Send + Sync>>,
    Json(submission): Json<InboxSubmission>,
) -> Result<impl IntoResponse> {
    info!("Storing inbox entry: {}", submission.entry.id);

    // Validate entry
    if submission.entry.id.is_empty() {
        return Err(StorageNodeError::InvalidState(
            "Entry ID cannot be empty".into(),
        ));
    }

    if submission.entry.transaction.is_empty() {
        return Err(StorageNodeError::InvalidState(
            "Transaction cannot be empty".into(),
        ));
    }

    // Create a BlindedStateEntry from the inbox entry
    let entry = BlindedStateEntry {
        blinded_id: format!(
            "inbox:{}:{}",
            submission.entry.recipient_genesis_hash, submission.entry.id
        ),
        encrypted_payload: bincode::serialize(&submission.entry).map_err(|e| {
            StorageNodeError::Serialization(format!("Failed to serialize inbox entry: {}", e))
        })?,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        ttl: if submission.entry.expires_at > 0 {
            submission.entry.expires_at
                - std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
        } else {
            0 // No expiration
        },
        region: "global".to_string(),
        priority: 1, // Standard priority
        proof_hash: {
            // Hash the entry for verification
            let mut hasher = blake3::Hasher::new();
            hasher.update(&bincode::serialize(&submission.entry).unwrap_or_default());
            let hash = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            hash_bytes
        },
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("type".to_string(), "inbox_entry".to_string());
            metadata.insert(
                "sender".to_string(),
                submission.entry.sender_genesis_hash.clone(),
            );
            metadata.insert(
                "recipient".to_string(),
                submission.entry.recipient_genesis_hash.clone(),
            );
            metadata.insert(
                "timestamp".to_string(),
                submission.entry.timestamp.to_string(),
            );
            metadata
        },
    };

    // Store the entry
    let response = storage.store(entry).await?;

    Ok((StatusCode::OK, Json(response)))
}

/// Get inbox entries for a recipient
#[axum::debug_handler]
pub async fn get_inbox_entries(
    State(storage): State<Arc<dyn StorageEngine + Send + Sync>>,
    Path(recipient_genesis): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    info!("Getting inbox entries for recipient: {}", recipient_genesis);

    // Limit and offset parameters
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(100);
    let offset = params
        .get("offset")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(0);

    // Get all blinded IDs with the inbox prefix for this recipient
    let prefix = format!("inbox:{}:", recipient_genesis);

    // This requires a custom implementation in StorageEngine to list entries with a prefix
    // For now, we'll retrieve all entries and filter
    let all_ids = storage.list(Some(limit + offset), None).await?;

    // Filter to only include entries for this recipient
    let inbox_ids: Vec<String> = all_ids
        .into_iter()
        .filter(|id| id.starts_with(&prefix))
        .collect();

    // Apply pagination
    let paginated_ids = if offset < inbox_ids.len() {
        inbox_ids[offset..].iter().take(limit).cloned().collect()
    } else {
        Vec::new()
    };

    // Retrieve each entry
    let mut entries = Vec::new();
    for id in paginated_ids {
        if let Some(entry) = storage.retrieve(&id).await? {
            // Deserialize the inbox entry
            if let Ok(inbox_entry) = bincode::deserialize::<InboxEntry>(&entry.encrypted_payload) {
                entries.push(inbox_entry);
            } else {
                warn!("Failed to deserialize inbox entry: {}", id);
            }
        }
    }

    Ok((StatusCode::OK, Json(entries)))
}

/// Delete an inbox entry
#[axum::debug_handler]
pub async fn delete_inbox_entry(
    State(storage): State<Arc<dyn StorageEngine + Send + Sync>>,
    Path((recipient_genesis, entry_id)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    let blinded_id = format!("inbox:{}:{}", recipient_genesis, entry_id);
    info!("Deleting inbox entry: {}", blinded_id);

    // Delete the entry
    let deleted = storage.delete(&blinded_id).await?;

    if deleted {
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "message": format!("Inbox entry {} deleted", entry_id),
            })),
        ))
    } else {
        Err(StorageNodeError::NotFound(format!(
            "Inbox entry with ID {} not found",
            entry_id
        )))
    }
}
