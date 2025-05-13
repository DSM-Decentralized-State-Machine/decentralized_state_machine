// DSM Storage Node API Module
//
// This module implements the HTTP REST API for the storage node, providing endpoints for data operations,
// node management, and administrative functions. The API is built using the Axum framework and provides
// a comprehensive set of endpoints for interacting with the DSM Storage Node.
//
// # API Endpoints
//
// The API is organized into several logical groups:
//
// * **Data Operations**: Core storage functionality (get, put, delete, list)
// * **Inbox API**: Message delivery for unilateral transactions
// * **Vault API**: Secure storage for sensitive data with access controls
// * **Rewards API**: Integration with the DSM staking and rewards system
// * **Node Management**: Status, configuration, and peer management
//
// # Authentication
//
// The API supports multiple authentication methods:
// - API tokens
// - Public key signatures
// - Certificate-based authentication
//
// # Error Handling
//
// All API endpoints use standardized error responses with consistent status codes
// and structured error messages to simplify client-side error handling.
//
// # Examples
//
// ## Basic Usage
//
// ```rust
// use dsm_storage_node::api::ApiServer;
// use dsm_storage_node::storage::SqliteStorageEngine;
// use dsm_storage_node::staking::StakingService;
// use std::sync::Arc;
//
// async fn start_server() -> Result<(), Box<dyn std::error::Error>> {
//     // Initialize storage and staking services
//     let storage = Arc::new(SqliteStorageEngine::new("data/storage.db")?);
//     let staking = Arc::new(StakingService::new(/* config */)?);
//
//     // Create and start API server
//     let api = ApiServer::new(storage, staking, "127.0.0.1:8765".to_string());
//     api.start().await?;
//
//     Ok(())
// }
// ```
//
// ## Using the API with curl
//
// ```bash
// # Store data
// curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@file.bin" http://localhost:8765/data
//
// # Retrieve data
// curl -X GET http://localhost:8765/data/b43f1d...
//
// # Check node status
// curl -X GET http://localhost:8765/health
// ```

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

/// Application state shared with all routes.
///
/// This struct holds references to core components that are needed by
/// request handlers, such as the storage engine and staking service.
/// The state is cloned for each request but uses Arc internally to
/// avoid expensive deep copies.
#[derive(Clone)]
pub struct AppState {
    /// Storage engine for persisting and retrieving data
    pub storage: Arc<dyn crate::storage::StorageEngine + Send + Sync>,
    /// Staking service for rewards and validation
    pub staking_service: Arc<StakingService>,
}

/// API Error response model.
///
/// This struct provides a standardized format for all error responses
/// from the API. It includes a human-readable message, a machine-readable
/// error code, and optional structured details for more complex errors.
///
/// Error codes are mapped to appropriate HTTP status codes in the
/// `IntoResponse` implementation.
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// Human-readable error message
    pub message: String,
    /// Machine-readable error code (e.g., "NOT_FOUND", "BAD_REQUEST")
    pub code: String,
    /// Optional additional structured details about the error
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

/// Convert StorageNodeError to an API error.
///
/// This implementation maps internal storage node errors to API-friendly
/// error responses with appropriate status codes and messages.
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

/// The main API server for the DSM Storage Node.
///
/// This struct represents the HTTP server that exposes the storage node's
/// functionality via a RESTful API. It handles initialization, routing, and
/// starting the server on the specified address.
///
/// # Examples
///
/// ```rust,no_run
/// use dsm_storage_node::api::ApiServer;
/// use dsm_storage_node::storage::StorageEngine;
/// use dsm_storage_node::staking::StakingService;
/// use std::sync::Arc;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let storage = Arc::new(StorageEngine::new(/* config */)?);
///     let staking = Arc::new(StakingService::new(/* config */)?);
///     
///     let server = ApiServer::new(storage, staking, "127.0.0.1:8765".to_string());
///     server.start().await?;
///     
///     Ok(())
/// }
/// ```
pub struct ApiServer {
    /// Application state shared with all request handlers
    app_state: Arc<AppState>,
    /// Server bind address in the format "IP:port"
    bind_address: String,
}

impl ApiServer {
    /// Create a new API server instance.
    ///
    /// This constructor initializes the API server with the required dependencies
    /// and prepares it for starting. It does not actually start the server -
    /// call `start()` to begin serving requests.
    ///
    /// # Parameters
    ///
    /// * `storage` - An Arc-wrapped storage engine implementation
    /// * `staking_service` - An Arc-wrapped staking service implementation
    /// * `bind_address` - The address and port to bind the server to (e.g., "127.0.0.1:8765")
    ///
    /// # Returns
    ///
    /// A new `ApiServer` instance ready to be started
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

    /// Start the API server and begin serving requests.
    ///
    /// This method binds to the configured address and port, sets up the
    /// HTTP server with all routes, and begins handling incoming requests.
    /// It is an async method that doesn't return until the server is shut down
    /// or encounters an error.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the server was successfully started and then gracefully shut down
    /// * `Err` if there was an error starting or running the server
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

    /// Create the API router with all defined routes.
    ///
    /// This method defines all the HTTP endpoints for the API server,
    /// including their HTTP methods, paths, and handler functions.
    /// It also attaches the application state to the router.
    ///
    /// # Returns
    ///
    /// An Axum `Router` configured with all API endpoints
    fn create_router(&self) -> Router {
        // Build the router
        Router::new()
            // Health and status endpoints
            .route("/health", get(handlers::health_check))
            .route("/stats", get(handlers::node_stats))
            // General data storage endpoints
            .route("/data", post(handlers::store_data))
            .route("/data/:blinded_id", get(handlers::retrieve_data))
            .route("/data/:blinded_id", delete(handlers::delete_data))
            .route("/data/:blinded_id/exists", get(handlers::exists_data))
            .route("/data", get(handlers::list_data))
            // Unilateral transaction inbox endpoints
            .route("/inbox", post(store_inbox_entry))
            .route("/inbox/:recipient_genesis", get(get_inbox_entries))
            .route(
                "/inbox/:recipient_genesis/:entry_id",
                delete(delete_inbox_entry),
            )
            // Vault API endpoints
            .route("/vault", post(store_vault))
            .route("/vault/:vault_id", get(get_vault))
            .route("/vault/creator/:creator_id", get(get_vaults_by_creator))
            .route(
                "/vault/recipient/:recipient_id",
                get(get_vaults_by_recipient),
            )
            .route("/vault/:vault_id/status", put(update_vault_status))
            // Rewards API endpoints
            .merge(rewards_api::rewards_routes())
            // Share application state
            .with_state(self.app_state.clone())
    }
}
