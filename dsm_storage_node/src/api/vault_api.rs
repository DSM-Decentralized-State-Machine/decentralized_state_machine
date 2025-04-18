// Vault API for DSM Storage Node
//
// This module implements API handlers for Deterministic Limbo Vaults (DLVs).

use crate::api::AppState;
use crate::error::{Result, StorageNodeError};
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

/// Vault status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaultStatus {
    /// Vault is active and locked
    Active,

    /// Vault has been unlocked
    Unlocked {
        /// Timestamp when the vault was unlocked
        timestamp: u64,

        /// Identity that unlocked the vault
        recipient_id: String,

        /// Transaction used to unlock
        unlock_transaction_hash: String,
    },

    /// Vault has expired without being unlocked
    Expired {
        /// Timestamp when the vault expired
        timestamp: u64,
    },

    /// Vault has been canceled by its creator
    Canceled {
        /// Timestamp when the vault was canceled
        timestamp: u64,

        /// Reason for cancellation
        reason: String,
    },
}

/// Vault data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    /// Vault ID
    pub id: String,

    /// Vault creator ID
    pub creator_id: String,

    /// Creation timestamp
    pub creation_timestamp: u64,

    /// Expiration timestamp (0 = no expiration)
    pub expiration_timestamp: u64,

    /// Vault status
    pub status: VaultStatus,

    /// Vault metadata
    pub metadata: HashMap<String, String>,

    /// Encrypted vault content
    pub encrypted_content: Vec<u8>,

    /// Optional recipient ID
    pub recipient_id: Option<String>,
}

/// Vault submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSubmission {
    /// Vault data
    pub vault: VaultData,

    /// Creator's signature
    pub signature: Vec<u8>,
}

/// Store a vault
#[axum::debug_handler]
pub async fn store_vault(
    State(state): State<Arc<AppState>>,
    Json(submission): Json<VaultSubmission>,
) -> Result<impl IntoResponse> {
    info!("Storing vault: {}", submission.vault.id);

    // Validate vault
    if submission.vault.id.is_empty() {
        return Err(StorageNodeError::InvalidState(
            "Vault ID cannot be empty".into(),
        ));
    }

    if submission.vault.encrypted_content.is_empty() {
        return Err(StorageNodeError::InvalidState(
            "Encrypted content cannot be empty".into(),
        ));
    }

    // Create a BlindedStateEntry from the vault
    let entry = BlindedStateEntry {
        blinded_id: format!("vault:{}", submission.vault.id),
        encrypted_payload: bincode::serialize(&submission.vault).map_err(|e| {
            StorageNodeError::Serialization(format!("Failed to serialize vault: {}", e))
        })?,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        ttl: if submission.vault.expiration_timestamp > 0 {
            submission.vault.expiration_timestamp
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
            hasher.update(&bincode::serialize(&submission.vault).unwrap_or_default());
            let hash = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            hash_bytes
        },
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("type".to_string(), "vault".to_string());
            metadata.insert("creator".to_string(), submission.vault.creator_id.clone());
            if let Some(recipient) = &submission.vault.recipient_id {
                metadata.insert("recipient".to_string(), recipient.clone());
            }
            metadata.insert(
                "status".to_string(),
                format!("{:?}", submission.vault.status),
            );
            metadata.insert(
                "created_at".to_string(),
                submission.vault.creation_timestamp.to_string(),
            );
            metadata
        },
    };

    // Store the entry
    let response = state.storage.store(entry).await?;

    // Also create an index entry for the creator
    let creator_index_id = format!("vault_by_creator:{}", submission.vault.creator_id);

    // Get existing vault IDs for this creator
    let vault_ids = match state.storage.retrieve(&creator_index_id).await? {
        Some(entry) => {
            // Deserialize the list of vault IDs
            let mut ids: Vec<String> =
                bincode::deserialize(&entry.encrypted_payload).map_err(|e| {
                    StorageNodeError::Serialization(format!(
                        "Failed to deserialize vault IDs: {}",
                        e
                    ))
                })?;

            // Add the new vault ID if not already present
            if !ids.contains(&submission.vault.id) {
                ids.push(submission.vault.id.clone());
            }

            ids
        }
        None => {
            // Create a new list with this vault ID
            vec![submission.vault.id.clone()]
        }
    };

    // Store the updated index
    let creator_index_entry = BlindedStateEntry {
        blinded_id: creator_index_id,
        encrypted_payload: bincode::serialize(&vault_ids).map_err(|e| {
            StorageNodeError::Serialization(format!("Failed to serialize vault IDs: {}", e))
        })?,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        ttl: 0, // No expiration for indexes
        region: "global".to_string(),
        priority: 1,
        proof_hash: {
            // Generate a hash for the index
            let mut hasher = blake3::Hasher::new();
            hasher.update(&bincode::serialize(&vault_ids).unwrap_or_default());
            let hash = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            hash_bytes
        },
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("type".to_string(), "vault_index".to_string());
            metadata.insert("creator".to_string(), submission.vault.creator_id.clone());
            metadata
        },
    };

    // Store the creator index
    state.storage.store(creator_index_entry).await?;

    // If there's a recipient, also create an index for them
    if let Some(recipient_id) = &submission.vault.recipient_id {
        let recipient_index_id = format!("vault_by_recipient:{}", recipient_id);

        // Get existing vault IDs for this recipient
        let vault_ids = match state.storage.retrieve(&recipient_index_id).await? {
            Some(entry) => {
                // Deserialize the list of vault IDs
                let mut ids: Vec<String> =
                    bincode::deserialize(&entry.encrypted_payload).map_err(|e| {
                        StorageNodeError::Serialization(format!(
                            "Failed to deserialize vault IDs: {}",
                            e
                        ))
                    })?;

                // Add the new vault ID if not already present
                if !ids.contains(&submission.vault.id) {
                    ids.push(submission.vault.id.clone());
                }

                ids
            }
            None => {
                // Create a new list with this vault ID
                vec![submission.vault.id.clone()]
            }
        };

        // Store the updated index
        let recipient_index_entry = BlindedStateEntry {
            blinded_id: recipient_index_id,
            encrypted_payload: bincode::serialize(&vault_ids).map_err(|e| {
                StorageNodeError::Serialization(format!("Failed to serialize vault IDs: {}", e))
            })?,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            ttl: 0, // No expiration for indexes
            region: "global".to_string(),
            priority: 1,
            proof_hash: {
                // Generate a hash for the index
                let mut hasher = blake3::Hasher::new();
                hasher.update(&bincode::serialize(&vault_ids).unwrap_or_default());
                let hash = hasher.finalize();
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(hash.as_bytes());
                hash_bytes
            },
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("type".to_string(), "vault_index".to_string());
                metadata.insert("recipient".to_string(), recipient_id.clone());
                metadata
            },
        };

        // Store the recipient index
        state.storage.store(recipient_index_entry).await?;
    }

    Ok((StatusCode::OK, Json(response)))
}

/// Get a vault by ID
#[axum::debug_handler]
pub async fn get_vault(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<impl IntoResponse> {
    let blinded_id = format!("vault:{}", vault_id);
    info!("Retrieving vault: {}", blinded_id);

    // Retrieve the vault
    match state.storage.retrieve(&blinded_id).await? {
        Some(entry) => {
            // Deserialize the vault
            let vault: VaultData = bincode::deserialize(&entry.encrypted_payload).map_err(|e| {
                StorageNodeError::Serialization(format!("Failed to deserialize vault: {}", e))
            })?;

            Ok((StatusCode::OK, Json(vault)))
        }
        None => Err(StorageNodeError::NotFound(format!(
            "Vault with ID {} not found",
            vault_id
        ))),
    }
}

/// Get vaults by creator ID
#[axum::debug_handler]
pub async fn get_vaults_by_creator(
    State(state): State<Arc<AppState>>,
    Path(creator_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    let index_id = format!("vault_by_creator:{}", creator_id);
    info!("Retrieving vaults for creator: {}", creator_id);

    // Limit parameter (default to 100)
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(100);

    // Retrieve the vault IDs
    match state.storage.retrieve(&index_id).await? {
        Some(entry) => {
            // Deserialize the list of vault IDs
            let vault_ids: Vec<String> =
                bincode::deserialize(&entry.encrypted_payload).map_err(|e| {
                    StorageNodeError::Serialization(format!(
                        "Failed to deserialize vault IDs: {}",
                        e
                    ))
                })?;

            // Retrieve each vault
            let mut vaults = Vec::new();
            for id in vault_ids.iter().take(limit) {
                let blinded_id = format!("vault:{}", id);
                if let Some(entry) = state.storage.retrieve(&blinded_id).await? {
                    // Deserialize the vault
                    match bincode::deserialize::<VaultData>(&entry.encrypted_payload) {
                        Ok(vault) => {
                            vaults.push(vault);
                        }
                        Err(e) => {
                            warn!("Failed to deserialize vault {}: {}", id, e);
                        }
                    }
                }
            }

            Ok((StatusCode::OK, Json(vaults)))
        }
        None => {
            // No vaults found
            Ok((StatusCode::OK, Json(Vec::<VaultData>::new())))
        }
    }
}

/// Get vaults by recipient ID
#[axum::debug_handler]
pub async fn get_vaults_by_recipient(
    State(state): State<Arc<AppState>>,
    Path(recipient_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    let index_id = format!("vault_by_recipient:{}", recipient_id);
    info!("Retrieving vaults for recipient: {}", recipient_id);

    // Limit parameter (default to 100)
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(100);

    // Retrieve the vault IDs
    match state.storage.retrieve(&index_id).await? {
        Some(entry) => {
            // Deserialize the list of vault IDs
            let vault_ids: Vec<String> =
                bincode::deserialize(&entry.encrypted_payload).map_err(|e| {
                    StorageNodeError::Serialization(format!(
                        "Failed to deserialize vault IDs: {}",
                        e
                    ))
                })?;

            // Retrieve each vault
            let mut vaults = Vec::new();
            for id in vault_ids.iter().take(limit) {
                let blinded_id = format!("vault:{}", id);
                if let Some(entry) = state.storage.retrieve(&blinded_id).await? {
                    // Deserialize the vault
                    match bincode::deserialize::<VaultData>(&entry.encrypted_payload) {
                        Ok(vault) => {
                            vaults.push(vault);
                        }
                        Err(e) => {
                            warn!("Failed to deserialize vault {}: {}", id, e);
                        }
                    }
                }
            }

            Ok((StatusCode::OK, Json(vaults)))
        }
        None => {
            // No vaults found
            Ok((StatusCode::OK, Json(Vec::<VaultData>::new())))
        }
    }
}

/// Update a vault's status
#[axum::debug_handler]
pub async fn update_vault_status(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
    Json(status_update): Json<HashMap<String, serde_json::Value>>,
) -> Result<impl IntoResponse> {
    let blinded_id = format!("vault:{}", vault_id);
    info!("Updating vault status: {}", blinded_id);

    // Retrieve the vault
    match state.storage.retrieve(&blinded_id).await? {
        Some(entry) => {
            // Deserialize the vault
            let mut vault: VaultData =
                bincode::deserialize(&entry.encrypted_payload).map_err(|e| {
                    StorageNodeError::Serialization(format!("Failed to deserialize vault: {}", e))
                })?;

            // Update the status based on the request
            if let Some(serde_json::Value::String(status_type)) = status_update.get("status_type") {
                match status_type.as_str() {
                    "unlocked" => {
                        let timestamp = status_update
                            .get("timestamp")
                            .and_then(|v| v.as_u64())
                            .unwrap_or_else(|| {
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs())
                            });

                        let recipient_id = status_update
                            .get("recipient_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let unlock_transaction_hash = status_update
                            .get("unlock_transaction_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        vault.status = VaultStatus::Unlocked {
                            timestamp,
                            recipient_id,
                            unlock_transaction_hash,
                        };
                    }
                    "expired" => {
                        let timestamp = status_update
                            .get("timestamp")
                            .and_then(|v| v.as_u64())
                            .unwrap_or_else(|| {
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs())
                            });

                        vault.status = VaultStatus::Expired { timestamp };
                    }
                    "canceled" => {
                        let timestamp = status_update
                            .get("timestamp")
                            .and_then(|v| v.as_u64())
                            .unwrap_or_else(|| {
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map_or(0, |d| d.as_secs())
                            });

                        let reason = status_update
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("No reason provided")
                            .to_string();

                        vault.status = VaultStatus::Canceled { timestamp, reason };
                    }
                    "active" => {
                        vault.status = VaultStatus::Active;
                    }
                    _ => {
                        return Err(StorageNodeError::InvalidState(format!(
                            "Invalid status type: {}",
                            status_type
                        )));
                    }
                }

                // Update the vault metadata
                vault
                    .metadata
                    .insert("status".to_string(), format!("{:?}", vault.status));

                // Store the updated vault
                let updated_entry = BlindedStateEntry {
                    blinded_id: blinded_id.clone(),
                    encrypted_payload: bincode::serialize(&vault).map_err(|e| {
                        StorageNodeError::Serialization(format!("Failed to serialize vault: {}", e))
                    })?,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    ttl: entry.ttl,
                    region: entry.region,
                    priority: entry.priority,
                    proof_hash: entry.proof_hash,
                    metadata: entry.metadata,
                };

                state.storage.store(updated_entry).await?;

                Ok((StatusCode::OK, Json(vault)))
            } else {
                Err(StorageNodeError::InvalidState(
                    "Missing status_type in request".into(),
                ))
            }
        }
        None => Err(StorageNodeError::NotFound(format!(
            "Vault with ID {} not found",
            vault_id
        ))),
    }
}
