use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use axum::{
    routing::{get, post},
    Router,
    extract::Json,
    http::{StatusCode, header, Method},
    response::{IntoResponse, Response},
};
use tower_http::{
    trace::TraceLayer,
    cors::{CorsLayer, Any},
    // CompressionLayer is not available in the compatible version
    // compression::CompressionLayer,
};
use tokio::sync::mpsc;
use tracing::{info, error, debug};

use crate::error::{Result, SnapshotError};
use crate::config::SnapshotConfig;
use crate::persistence::snapshot_store::SnapshotStore;
use crate::ip_collector::{IpCollector, CollectorCommand};
use crate::types::ApiResponse;

mod handlers;
mod metrics;
mod middleware;
mod rate_limit;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// IP collector command sender
    collector_tx: mpsc::Sender<CollectorCommand>,

    /// Snapshot store
    store: Arc<SnapshotStore>,

    /// Configuration
    #[allow(dead_code)]
    pub(crate) config: SnapshotConfig,
}

/// Start the API server
pub async fn start_api_server(
    listen_addr: String,
    store: SnapshotStore,
    config: SnapshotConfig,
) -> Result<()> {
    // Parse address
    let addr = SocketAddr::from_str(&listen_addr)
        .map_err(|e| SnapshotError::Api(format!("Invalid listen address: {}", e)))?;

    // Initialize IP collector
    let collector = IpCollector::new(config.clone(), Arc::new(store.clone())).await?;
    let collector_tx = collector.command_sender();

    // Spawn collector service using a proper LocalSet for thread-local tasks
    let local = tokio::task::LocalSet::new();
    
    // This needs to run on the LocalSet
    local.spawn_local(async move {
        collector.run().await;
    });

    // Create shared state
    let state = AppState {
        collector_tx,
        store: Arc::new(store),
        config,
    };

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);

    // Build router
    let app = Router::new()
        // Public endpoints
        .route("/health", get(handlers::health_check))
        .route("/stats", get(handlers::get_stats))
        .route("/", get(handlers::index))
        // IP collection endpoints (passive - extracts real client IPs transparently)
        .route("/api/ping", get(handlers::passive_collect))
        .route("/api/beacon", get(handlers::passive_collect))
        .route("/api/status", get(handlers::passive_collect))
        .route("/api/metrics", get(handlers::passive_collect))
        // Admin endpoints (protected by token)
        .route("/admin/start", post(handlers::start_collection))
        .route("/admin/stop", post(handlers::stop_collection))
        .route("/admin/snapshot", post(handlers::create_snapshot))
        .route("/admin/snapshots", get(handlers::list_snapshots))
        .route("/admin/clear", post(handlers::clear_data))
        // Export endpoints (protected by token)
        .route("/admin/export/json", get(handlers::export_json))
        .route("/admin/export/csv", get(handlers::export_csv))
        .route("/admin/export/hash", get(handlers::export_hash))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        // CompressionLayer removed as it's not available in the compatible version
        // .layer(CompressionLayer::new())
        .layer(middleware::extract_real_ip_layer())
        .with_state(state);

    // Start server
    info!("Starting IP collection server on {}", addr);
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    
    // Run the LocalSet and server together
    local.run_until(async move {
        axum::Server::bind(&addr)
            .serve(make_service)
            .await
            .map_err(|e| SnapshotError::Api(format!("Server error: {}", e)))
    }).await?;

    Ok(())
}
/// Handle API errors with appropriate status codes and structured responses
impl IntoResponse for SnapshotError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            SnapshotError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            SnapshotError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            SnapshotError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            SnapshotError::RateLimit(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
            SnapshotError::Api(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            SnapshotError::Database(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, &format!("{}", self)),
        };

        // Construct error response
        let response = ApiResponse::<()>::error(error_message.to_string());
        let body = Json(response);

        // Log error details for non-client errors
        if status.as_u16() >= 500 {
            error!("Server error: {}", self);
        } else {
            debug!("Client error: {}", self);
        }

        (status, body).into_response()
    }
}
