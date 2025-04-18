// API module for DSM Storage Node
//
// This module implements the HTTP API for the storage node

use crate::error::{Result, StorageNodeError};
// Removed unused import

use crate::staking::StakingService;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;

mod handlers;
mod middleware;
mod mpc_api;
mod rewards_api;
mod unilateral_api;
mod vault_api;

pub use handlers::*;
pub use mpc_api::*;
pub use rewards_api::*;
pub use unilateral_api::*;
pub use vault_api::*;

/// Application state shared with all routes
#[derive(Clone)]
pub struct AppState {
    /// Storage engine
    pub storage: Arc<dyn crate::storage::StorageEngine + Send + Sync>,
    /// Staking service
    pub staking_service: Arc<StakingService>,
}
/// API Error response
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// Error message
    pub message: String,
    /// Error code
    pub code: String,
    /// Optional additional details
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code.as_str() {
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "BAD_REQUEST" => StatusCode::BAD_REQUEST,
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "FORBIDDEN" => StatusCode::FORBIDDEN,
            "CONFLICT" => StatusCode::CONFLICT,
            "TOO_MANY_REQUESTS" => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(self);

        (status, body).into_response()
    }
}

/// Convert StorageNodeError to an API error
impl From<StorageNodeError> for ApiError {
    fn from(err: StorageNodeError) -> Self {
        let (code, message) = match err {
            StorageNodeError::NetworkClientNotSet => {
                ("NETWORK_ERROR", "Network client not set".to_string())
            }
            StorageNodeError::InvalidNodeId(msg) => ("INVALID_NODE_ID", msg),
            StorageNodeError::Timeout => ("TIMEOUT", "Operation timed out".to_string()),
            StorageNodeError::Internal => ("INTERNAL_ERROR", "Internal server error".to_string()),
            StorageNodeError::Configuration => {
                ("CONFIGURATION_ERROR", "Configuration error".to_string())
            }
            StorageNodeError::NotFound(msg) => ("NOT_FOUND", msg),
            StorageNodeError::Storage(msg) => ("STORAGE_ERROR", msg),
            StorageNodeError::Config(msg) => ("CONFIG_ERROR", msg),
            StorageNodeError::Encryption(msg) => ("ENCRYPTION_ERROR", msg),
            StorageNodeError::Distribution(msg) => ("DISTRIBUTION_ERROR", msg),
            StorageNodeError::NodeManagement(msg) => ("NODE_MANAGEMENT_ERROR", msg),
            StorageNodeError::Staking(msg) => ("STAKING_ERROR", msg),
            StorageNodeError::Authentication(msg) => ("AUTHENTICATION_ERROR", msg),
            StorageNodeError::InvalidState(msg) => ("INVALID_STATE", msg),
            StorageNodeError::Database(msg) => ("DATABASE_ERROR", msg),
            StorageNodeError::Serialization(msg) => ("SERIALIZATION_ERROR", msg),
            StorageNodeError::IO(err) => ("IO_ERROR", err.to_string()),
            StorageNodeError::Json(err) => ("JSON_ERROR", err.to_string()),
            StorageNodeError::Sqlite(err) => ("SQLITE_ERROR", err.to_string()),
            StorageNodeError::Request(err) => ("REQUEST_ERROR", err.to_string()),
            StorageNodeError::Network(err) => ("NETWORK_ERROR", err.to_string()),
            StorageNodeError::Unknown(msg) => ("UNKNOWN_ERROR", msg),
            StorageNodeError::RateLimitExceeded(msg) => ("RATE_LIMIT_EXCEEDED", msg),
            StorageNodeError::TaskCancelled(msg) => ("TASK_CANCELLED", msg),
            StorageNodeError::TaskFailed(msg) => ("TASK_FAILED", msg),
            StorageNodeError::QueueFull(msg) => ("QUEUE_FULL", msg),
            StorageNodeError::ReceiveFailure(msg) => ("RECEIVE_FAILURE", msg),
            StorageNodeError::InvalidOperation(msg) => ("INVALID_OPERATION", msg),
            StorageNodeError::InvalidInput(msg) => ("INVALID_INPUT", msg),
            StorageNodeError::ConcurrencyLimitExceeded => (
                "CONCURRENCY_LIMIT_EXCEEDED",
                "Concurrency limit exceeded".to_string(),
            ),
        };

        Self {
            message,
            code: code.to_string(),
            details: None,
        }
    }
}

/// API Server
pub struct ApiServer {
    /// Application state
    app_state: Arc<AppState>,
    /// Server bind address
    bind_address: String,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(
        storage: Arc<dyn crate::storage::StorageEngine + Send + Sync>,
        staking_service: Arc<StakingService>,
        bind_address: String,
    ) -> Self {
        let app_state = Arc::new(AppState {
            storage,
            staking_service,
        });

        Self {
            app_state,
            bind_address,
        }
    }

    /// Start the API server
    pub async fn start(&self) -> Result<()> {
        // Create router with routes
        let app = self.create_router().layer(TraceLayer::new_for_http());

        // Parse the bind address
        let addr = self
            .bind_address
            .parse()
            .map_err(|e| StorageNodeError::Config(format!("Invalid bind address: {}", e)))?;

        info!("Starting API server on {}", self.bind_address);

        // Start the server
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .map_err(|e| StorageNodeError::Config(format!("Server error: {}", e)))?;

        Ok(())
    }

    /// Create the API router
    fn create_router(&self) -> Router {
        // Build the router
        Router::new()
            .route("/health", get(handlers::health_check))
            .route("/stats", get(handlers::node_stats))
            // General data storage
            .route("/data", post(handlers::store_data))
            .route("/data/:blinded_id", get(handlers::retrieve_data))
            .route("/data/:blinded_id", delete(handlers::delete_data))
            .route("/data/:blinded_id/exists", get(handlers::exists_data))
            .route("/data", get(handlers::list_data))
            // Unilateral transaction inbox
            .route("/inbox", post(store_inbox_entry))
            .route("/inbox/:recipient_genesis", get(get_inbox_entries))
            .route(
                "/inbox/:recipient_genesis/:entry_id",
                delete(delete_inbox_entry),
            )
            // Vault API
            .route("/vault", post(store_vault))
            .route("/vault/:vault_id", get(get_vault))
            .route("/vault/creator/:creator_id", get(get_vaults_by_creator))
            .route(
                "/vault/recipient/:recipient_id",
                get(get_vaults_by_recipient),
            )
            .route("/vault/:vault_id/status", put(update_vault_status))
            // Rewards API
            .merge(rewards_api::rewards_routes())
            // Share application state
            .with_state(self.app_state.clone())
    }
}
