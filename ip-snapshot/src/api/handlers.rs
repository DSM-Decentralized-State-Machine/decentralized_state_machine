use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{State, Query, ConnectInfo, Extension},
    response::IntoResponse,
    Json,
};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use chrono::Utc;
use tokio::sync::mpsc;
use tokio::fs;

use crate::error::{Result, SnapshotError};
use crate::api::AppState;
use crate::ip_collector::CollectorCommand;
use crate::types::ApiResponse;

/// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    StatusCode::OK
}

#[allow(dependency_on_unit_never_type_fallback)]
/// Index endpoint
pub async fn index() -> impl IntoResponse {
    let version = env!("CARGO_PKG_VERSION");
    let response = json!({
        "name": "DSM IP Snapshot Collection Service",
        "version": version,
        "timestamp": Utc::now(),
        "status": "operational"
    });

    Json(ApiResponse::success(response))
}

/// Passive IP collection endpoint
/// This endpoint appears to provide a service to the client
/// but its primary purpose is to extract and record their real IP
pub async fn passive_collect(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(real_ip): Extension<Option<IpAddr>>,
) -> Result<impl IntoResponse> {
    // Extract the client's IP address, prioritizing X-Forwarded-For or other proxy headers
    let client_ip = real_ip.unwrap_or_else(|| addr.ip());

    // Add IP to collector
    let cmd_tx = state.collector_tx.clone();
    cmd_tx
        .send(CollectorCommand::AddIp(client_ip))
        .await
        .map_err(|e| {
            SnapshotError::Internal(format!("Failed to send collection command: {}", e))
        })?;

    // Return a benign response that doesn't indicate collection
    let response = json!({
        "status": "online",
        "timestamp": Utc::now(),
        "server_time": Utc::now().to_rfc3339(),
        "message": "Service is operational"
    });

    Ok(Json(ApiResponse::success(response)))
}

/// Collection statistics endpoint
pub async fn get_stats(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Create response channel
    let (tx, mut rx) = mpsc::channel::<Result<crate::types::CollectionStats>>(1);

    // Request stats from collector
    let cmd_tx = state.collector_tx.clone();
    cmd_tx
        .send(CollectorCommand::GetStats(tx))
        .await
        .map_err(|e| SnapshotError::Internal(format!("Failed to send stats command: {}", e)))?;

    // Wait for response
    let stats = rx
        .recv()
        .await
        .ok_or_else(|| SnapshotError::Internal("Failed to receive stats response".to_string()))??;

    // Return statistics
    Ok(Json(ApiResponse::success(stats)))
}

/// Admin: Start collection
pub async fn start_collection(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Verify admin token
    // This would check for proper authentication in production

    // Send command to start collection
    let cmd_tx = state.collector_tx.clone();
    cmd_tx
        .send(CollectorCommand::StartCollection)
        .await
        .map_err(|e| SnapshotError::Internal(format!("Failed to send start command: {}", e)))?;

    // Return success response
    let response = json!({
        "action": "start_collection",
        "timestamp": Utc::now(),
        "message": "IP collection started successfully"
    });

    Ok(Json(ApiResponse::success(response)))
}

/// Admin: Stop collection
pub async fn stop_collection(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Verify admin token

    // Send command to stop collection
    let cmd_tx = state.collector_tx.clone();
    cmd_tx
        .send(CollectorCommand::StopCollection)
        .await
        .map_err(|e| SnapshotError::Internal(format!("Failed to send stop command: {}", e)))?;

    // Return success response
    let response = json!({
        "action": "stop_collection",
        "timestamp": Utc::now(),
        "message": "IP collection stopped successfully"
    });

    Ok(Json(ApiResponse::success(response)))
}

/// Admin: Create snapshot
pub async fn create_snapshot(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Verify admin token

    // Create response channel - only use rx since we don't need to send
    let (_, mut rx) = mpsc::channel::<String>(1);

    // Send create snapshot command to collector with response channel
    let cmd_tx = state.collector_tx.clone();
    cmd_tx
        .send(CollectorCommand::CreateSnapshot)
        .await
        .map_err(|e| {
            SnapshotError::Internal(format!("Failed to send create snapshot command: {}", e))
        })?;

    // Wait for response
    let snapshot_id = rx.recv().await.ok_or_else(|| {
        SnapshotError::Internal("Failed to receive snapshot response".to_string())
    })?;

    // Return success response
    let response = json!({
        "action": "create_snapshot",
        "snapshot_id": snapshot_id,
        "timestamp": Utc::now(),
        "message": "Snapshot created successfully"
    });

    Ok(Json(ApiResponse::success(response)))
}

/// Admin: List snapshots
pub async fn list_snapshots(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Verify admin token

    // Get snapshots from store
    let snapshots = state.store.list_snapshots();

    // Return snapshot list
    Ok(Json(ApiResponse::success(snapshots)))
}

/// Admin: Clear collected data
pub async fn clear_data(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Verify admin token

    // Send clear command to collector
    let cmd_tx = state.collector_tx.clone();
    cmd_tx
        .send(CollectorCommand::Clear)
        .await
        .map_err(|e| SnapshotError::Internal(format!("Failed to send clear command: {}", e)))?;

    // Return success response
    let response = json!({
        "action": "clear_data",
        "timestamp": Utc::now(),
        "message": "Collection data cleared successfully"
    });

    Ok(Json(ApiResponse::success(response)))
}

/// Admin: Export snapshots as JSON
pub async fn export_json(
    State(state): State<AppState>,
    Query(params): Query<ExportParams>,
) -> Result<impl IntoResponse> {
    // Verify admin token

    // Create temporary output file
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join(format!("export-{}.json", Utc::now().timestamp()));

    // Export data to JSON
    crate::persistence::exporter::export_json(&state.store, &output_path).await?;

    // Read the exported file
    let content = fs::read_to_string(&output_path)
        .await
        .map_err(|e| SnapshotError::Export(format!("Failed to read export file: {}", e)))?;

    // Clean up temporary file if requested
    if !params.keep_file.unwrap_or(false) {
        let _ = fs::remove_file(&output_path).await;
    }

    // Return file content or path
    if params.return_content.unwrap_or(true) {
        // Parse JSON and return as structured response
        let content: Value = serde_json::from_str(&content).unwrap_or_else(|_| json!({}));
        Ok(Json(ApiResponse::success(content)))
    } else {
        // Return file path
        let response = json!({
            "export_path": output_path.to_string_lossy(),
            "timestamp": Utc::now(),
        });
        Ok(Json(ApiResponse::success(response)))
    }
}

/// Admin: Export snapshots as CSV
pub async fn export_csv(
    State(state): State<AppState>,
    Query(params): Query<ExportParams>,
) -> Result<impl IntoResponse> {
    // Verify admin token

    // Create temporary output file
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join(format!("export-{}.csv", Utc::now().timestamp()));

    // Export data to CSV
    crate::persistence::exporter::export_csv(&state.store, &output_path).await?;

    // Clean up temporary file if requested
    if !params.keep_file.unwrap_or(false) {
        let _ = fs::remove_file(&output_path).await;
    }

    // Return file path (we don't parse CSV content for return)
    let response = json!({
        "export_path": output_path.to_string_lossy(),
        "timestamp": Utc::now(),
    });

    Ok(Json(ApiResponse::success(response)))
}

/// Admin: Export cryptographic hash verification
pub async fn export_hash(State(state): State<AppState>) -> Result<impl IntoResponse> {
    // Verify admin token

    // Create temporary output file
    let temp_dir = std::env::temp_dir();
    let output_path = temp_dir.join(format!("hash-verification-{}.json", Utc::now().timestamp()));

    // Export hash verification
    crate::persistence::exporter::export_hash(&state.store, &output_path).await?;

    // Read the exported file
    let content = fs::read_to_string(&output_path).await.map_err(|e| {
        SnapshotError::Export(format!("Failed to read hash verification file: {}", e))
    })?;

    // Clean up temporary file
    let _ = fs::remove_file(&output_path).await;

    // Parse JSON and return as structured response
    let content: Value = serde_json::from_str(&content).unwrap_or_else(|_| json!({}));

    Ok(Json(ApiResponse::success(content)))
}

/// Export parameters
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ExportParams {
    /// Whether to return the content in the response
    pub return_content: Option<bool>,

    /// Whether to keep the temporary file
    pub keep_file: Option<bool>,

    /// Optional snapshot ID to export (otherwise exports all)
    pub snapshot_id: Option<String>,
}
