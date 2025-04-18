// Rewards API Module for DSM Storage Node
//
// This module implements the API endpoints for reward management
// using the Deterministic Limbo Vault (DLV) system.

use crate::error::Result;
use crate::staking::rewards::{RateSchedule, Ratio, StorageMetrics, StorageReceipt};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// Using the State type from axum extract instead of dsm

use super::AppState;

/// Create the rewards API router
pub fn rewards_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/rewards/receipts", post(submit_receipt))
        .route("/rewards/vaults", get(list_vaults))
        .route("/rewards/vaults/:id", get(get_vault))
        .route("/rewards/schedule", get(get_rate_schedule))
        .route("/rewards/schedule", post(update_rate_schedule))
        .route("/rewards/calculate/:node_id", get(calculate_rewards))
        .route("/rewards/vault", post(create_reward_vault))
}

/// Storage receipt submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSubmission {
    /// Node ID that provided the service
    pub node_id: String,

    /// Client ID that received the service
    pub client_id: String,

    /// Service period start (timestamp)
    pub period_start: u64,

    /// Service period end (timestamp)
    pub period_end: u64,

    /// Storage metrics
    pub metrics: StorageMetrics,

    /// Client's signature
    pub client_signature: Vec<u8>,

    /// Node's signature
    pub node_signature: Vec<u8>,
}

/// Rate schedule update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateScheduleUpdate {
    /// Base rate per byte per day
    pub base_rate_per_byte_day: u64,

    /// Rate per retrieval
    pub retrieval_rate: u64,

    /// Rate per operation
    pub operation_rate: u64,

    /// Uptime multiplier
    pub uptime_multiplier: f64,

    /// Region multipliers
    pub region_multipliers: HashMap<String, f64>,
}

/// Reward vault creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardVaultRequest {
    /// Total amount of tokens
    pub token_amount: u64,

    /// Token ID
    pub token_id: String,

    /// When to distribute (timestamp)
    pub distribution_time: u64,

    /// Recipients (node_id -> percentage)
    pub recipients: HashMap<String, f64>,

    /// Creator's public key
    pub creator_public_key: Vec<u8>,

    /// Creator's private key (simplified for demo)
    pub creator_private_key: Vec<u8>,
}

/// Submit a storage receipt
async fn submit_receipt(
    State(state): State<Arc<AppState>>,
    Json(submission): Json<ReceiptSubmission>,
) -> Result<StatusCode> {
    // Create a receipt hash
    let mut hasher = blake3::Hasher::new();
    hasher.update(submission.node_id.as_bytes());
    hasher.update(submission.client_id.as_bytes());
    hasher.update(&submission.period_start.to_le_bytes());
    hasher.update(&submission.period_end.to_le_bytes());

    // Add storage metrics to hash
    let metrics_bytes =
        bincode::serialize(&submission.metrics).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    hasher.update(&metrics_bytes);

    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(hash.as_bytes());

    // Create the receipt
    let receipt = StorageReceipt {
        node_id: submission.node_id,
        client_id: submission.client_id,
        service_period: (submission.period_start, submission.period_end),
        storage_metrics: submission.metrics,
        receipt_hash: hash_bytes,
        client_signature: submission.client_signature,
        node_signature: submission.node_signature,
    };

    // Process the receipt
    state.staking_service.process_receipt(receipt)?;

    Ok(StatusCode::CREATED)
}

/// List all reward vaults
async fn list_vaults(State(state): State<Arc<AppState>>) -> Result<Json<Vec<serde_json::Value>>> {
    let reward_manager = state.staking_service.get_reward_manager()?;

    let vaults = reward_manager.get_vaults()?;

    // Convert to JSON
    let vault_list = vaults
        .iter()
        .map(|v| {
            serde_json::json!({
                "id": v.vault_id,
                "purpose": v.purpose,
                "creator": v.creator_id,
                "token_amount": v.token_amount,
                "token_id": v.token_id,
                "created_at": v.created_at,
                "distribution_time": v.distribution_time,
                "recipients_count": v.recipients.len(),
                "status": v.status,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(vault_list))
}

/// Get a specific vault
async fn get_vault(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let reward_manager = state.staking_service.get_reward_manager()?;

    let vault = reward_manager.get_vault(&vault_id)?;

    // Convert recipients to percentages
    let recipients = vault
        .recipients
        .iter()
        .map(|(node_id, ratio)| (node_id.clone(), ratio.as_f64() * 100.0))
        .collect::<HashMap<_, _>>();

    // Create JSON response
    let response = serde_json::json!({
        "id": vault.vault_id,
        "purpose": vault.purpose,
        "creator": vault.creator_id,
        "token_amount": vault.token_amount,
        "token_id": vault.token_id,
        "created_at": vault.created_at,
        "distribution_time": vault.distribution_time,
        "recipients": recipients,
        "status": vault.status,
    });

    Ok(Json(response))
}

/// Get current rate schedule
async fn get_rate_schedule(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<RateScheduleUpdate>> {
    // Access the rate schedule (in a real implementation, we'd have a getter)
    // For this demo, we'll return a fixed schedule
    let schedule = RateScheduleUpdate {
        base_rate_per_byte_day: 100,
        retrieval_rate: 10,
        operation_rate: 5,
        uptime_multiplier: 1.0,
        region_multipliers: HashMap::new(),
    };

    Ok(Json(schedule))
}

/// Update rate schedule
async fn update_rate_schedule(
    State(state): State<Arc<AppState>>,
    Json(update): Json<RateScheduleUpdate>,
) -> Result<StatusCode> {
    let reward_manager = state.staking_service.get_reward_manager()?;

    // Convert to RateSchedule
    let schedule = RateSchedule {
        base_rate_per_byte_day: update.base_rate_per_byte_day,
        retrieval_rate: update.retrieval_rate,
        operation_rate: update.operation_rate,
        uptime_multiplier: update.uptime_multiplier,
        region_multipliers: update.region_multipliers,
    };

    // Update the schedule
    reward_manager.update_rate_schedule(schedule)?;

    Ok(StatusCode::OK)
}

/// Calculate rewards for a node
async fn calculate_rewards(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let reward_manager = state.staking_service.get_reward_manager()?;

    // Calculate for the last 30 days
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let period_start = now - (30 * 86400); // 30 days ago
    let period_end = now;

    let rewards = reward_manager.calculate_node_rewards(&node_id, period_start, period_end)?;

    let response = serde_json::json!({
        "node_id": node_id,
        "period_start": period_start,
        "period_end": period_end,
        "calculated_rewards": rewards,
    });

    Ok(Json(response))
}

/// Create a reward vault
async fn create_reward_vault(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RewardVaultRequest>,
) -> Result<Json<serde_json::Value>> {
    let reward_manager = state.staking_service.get_reward_manager()?;

    // Convert percentages to ratios
    let mut recipients = HashMap::new();
    for (node_id, percentage) in &request.recipients {
        recipients.insert(node_id.clone(), Ratio::new(*percentage / 100.0));
    }

    // Create a reference state (simplified for demo)
    let device_info =
        dsm::types::state_types::DeviceInfo::new("test_device", request.creator_public_key.clone());

    let reference_state = dsm::types::state_types::State::new_genesis(
        vec![1, 2, 3, 4], // Simplified entropy
        device_info,
    );

    // Create the vault
    let vault_id = reward_manager.create_reward_vault(
        (&request.creator_public_key, &request.creator_private_key),
        request.token_amount,
        &request.token_id,
        request.distribution_time,
        recipients,
        &reference_state,
    )?;

    let response = serde_json::json!({
        "vault_id": vault_id,
        "token_amount": request.token_amount,
        "token_id": request.token_id,
        "distribution_time": request.distribution_time,
        "recipients_count": request.recipients.len(),
    });

    Ok(Json(response))
}
