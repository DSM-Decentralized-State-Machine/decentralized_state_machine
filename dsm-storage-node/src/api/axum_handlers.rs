// Axum-specific handlers for the MPC API
//
// This file contains the route handlers that connect the Axum HTTP framework
// to our MPC functionality.

use crate::api::{mpc_api, AppState};
use crate::error::Result;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;

/// Handler for entropy generation requests
pub async fn generate_entropy(
    State(state): State<Arc<AppState>>,
    Path(process_id): Path<String>,
    Json(request): Json<mpc_api::EntropyRequest>,
) -> Result<impl IntoResponse> {
    // Call the MPC API handler
    let response = mpc_api::handle_entropy_request(
        process_id,
        request,
        state.storage.clone(),
    ).await?;
    
    // Return the successful response
    Ok((StatusCode::OK, Json(response)))
}

/// Handler for retrieving an entropy contribution
pub async fn get_entropy(
    State(state): State<Arc<AppState>>,
    Path((process_id, node_id)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    // Call the MPC API handler
    match mpc_api::get_entropy_contribution(
        process_id,
        node_id,
        state.storage.clone(),
    ).await? {
        Some(entropy) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "entropy": entropy,
                "found": true
            })),
        )),
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "found": false,
                "message": "Entropy contribution not found"
            })),
        )),
    }
}
