// API handlers for DSM Storage Node
//
// This module implements the API route handlers for the storage node.

use crate::api::AppState;
use crate::error::{Result, StorageNodeError};
use crate::types::storage_types::{DataRetrievalRequest, DataSubmissionRequest};
use crate::types::BlindedStateEntry;
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Store data handler
#[axum::debug_handler]
pub async fn store_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DataSubmissionRequest>,
) -> Result<impl IntoResponse> {
    info!("Storing data with blinded ID: {}", request.blinded_id);

    // Validate request
    if request.blinded_id.is_empty() {
        return Err(StorageNodeError::InvalidState(
            "Blinded ID cannot be empty".into(),
        ));
    }

    if request.payload.is_empty() {
        return Err(StorageNodeError::InvalidState(
            "Payload cannot be empty".into(),
        ));
    }

    // Create blinded state entry
    let entry = BlindedStateEntry {
        blinded_id: request.blinded_id.clone(),
        encrypted_payload: request.payload.clone(), // Clone to avoid move
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        ttl: request.ttl.unwrap_or(0),
        region: request.region.unwrap_or_else(|| "global".to_string()),
        priority: request.priority.unwrap_or(0),
        proof_hash: request.proof_hash.unwrap_or_else(|| {
            // Generate a hash from the payload
            let mut hasher = blake3::Hasher::new();
            hasher.update(&request.payload);
            let hash = hasher.finalize();

            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(hash.as_bytes());
            hash_bytes
        }),
        metadata: request.metadata.unwrap_or_else(HashMap::new),
    };

    // Store entry
    let response = state.storage.store(entry).await?;

    Ok((StatusCode::OK, Json(response)))
}

/// Retrieve data handler
#[axum::debug_handler]
pub async fn retrieve_data(
    State(state): State<Arc<AppState>>,
    Path(blinded_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    info!("Retrieving data with blinded ID: {}", blinded_id);

    // Check for requester ID and signature in query parameters
    let requester_id = params.get("requester_id").cloned();
    let signature = params.get("signature").cloned();

    // Create retrieval request
    let request = DataRetrievalRequest {
        blinded_id: blinded_id.clone(),
        requester_id,
        signature,
    };

    // Retrieve entry
    let entry = state.storage.retrieve(&request.blinded_id).await?;

    match entry {
        Some(entry) => {
            debug!("Entry found with ID: {}", blinded_id);
            Ok((StatusCode::OK, Json(entry)))
        }
        None => {
            debug!("Entry not found with ID: {}", blinded_id);
            Err(StorageNodeError::NotFound(format!(
                "Entry with ID {} not found",
                blinded_id
            )))
        }
    }
}

/// Delete data handler
#[axum::debug_handler]
pub async fn delete_data(
    State(state): State<Arc<AppState>>,
    Path(blinded_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    info!("Deleting data with blinded ID: {}", blinded_id);

    // Check for signature in query parameters
    let _signature = params.get("signature").cloned();

    // TODO: Verify signature if provided

    // Delete entry
    let deleted = state.storage.delete(&blinded_id).await?;

    if deleted {
        debug!("Entry deleted with ID: {}", blinded_id);
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "success",
                "message": format!("Entry with ID {} deleted", blinded_id),
            })),
        ))
    } else {
        debug!("Entry not found for deletion with ID: {}", blinded_id);
        Err(StorageNodeError::NotFound(format!(
            "Entry with ID {} not found",
            blinded_id
        )))
    }
}

/// Check if data exists handler
#[axum::debug_handler]
pub async fn exists_data(
    State(state): State<Arc<AppState>>,
    Path(blinded_id): Path<String>,
) -> Result<impl IntoResponse> {
    debug!("Checking if data exists with blinded ID: {}", blinded_id);

    // Check if entry exists
    let exists = state.storage.exists(&blinded_id).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "exists": exists,
        })),
    ))
}

/// List data handler
#[axum::debug_handler]
pub async fn list_data(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    // Parse query parameters
    let limit = params.get("limit").and_then(|l| l.parse::<usize>().ok());
    let offset = params.get("offset").and_then(|o| o.parse::<usize>().ok());

    debug!("Listing data with limit: {:?}, offset: {:?}", limit, offset);

    // List entries
    let entries = state.storage.list(limit, offset).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "entries": entries,
            "count": entries.len(),
            "limit": limit,
            "offset": offset,
        })),
    ))
}

/// Get node stats handler
#[axum::debug_handler]
pub async fn node_stats(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse> {
    debug!("Getting node stats");

    // Get storage stats
    let stats = state.storage.get_stats().await?;

    // Get staking status
    let staking_status = state.staking_service.get_status().await?;

    // Get DSM version
    let dsm_version = dsm::version();

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "storage": stats,
            "staking": {
                "enabled": staking_status.enabled,
                "staked_amount": staking_status.staked_amount,
                "pending_rewards": staking_status.pending_rewards,
                "apy": staking_status.apy,
                "reputation": staking_status.reputation,
                "last_reward_time": staking_status.last_reward_time,
            },
            "dsm_version": dsm_version,
            "uptime": 0, // TODO: Track uptime
            "timestamp": timestamp,
        })),
    ))
}

/// Health check handler
pub async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        })),
    )
}
