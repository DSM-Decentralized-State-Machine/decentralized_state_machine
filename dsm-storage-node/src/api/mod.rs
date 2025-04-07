// API module for DSM Storage Node
//
// This module implements the HTTP API for the storage node

use crate::error::{Result, StorageNodeError};
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
mod unilateral;
mod vault;

pub use handlers::*;
pub use unilateral::*;
pub use vault::*;

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
    /// Storage engine
    storage: Arc<dyn crate::storage::StorageEngine + Send + Sync>,
    /// Server bind address
    bind_address: String,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(
        storage: Arc<dyn crate::storage::StorageEngine + Send + Sync>,
        bind_address: String,
    ) -> Self {
        Self {
            storage,
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
        // We're using with_state instead of extensions
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
            .route("/inbox", post(unilateral::store_inbox_entry))
            .route(
                "/inbox/:recipient_genesis",
                get(unilateral::get_inbox_entries),
            )
            .route(
                "/inbox/:recipient_genesis/:entry_id",
                delete(unilateral::delete_inbox_entry),
            )
            // Vault API
            .route("/vault", post(vault::store_vault))
            .route("/vault/:vault_id", get(vault::get_vault))
            .route(
                "/vault/creator/:creator_id",
                get(vault::get_vaults_by_creator),
            )
            .route(
                "/vault/recipient/:recipient_id",
                get(vault::get_vaults_by_recipient),
            )
            .route("/vault/:vault_id/status", put(vault::update_vault_status))
            .with_state(self.storage.clone())
    }
}
