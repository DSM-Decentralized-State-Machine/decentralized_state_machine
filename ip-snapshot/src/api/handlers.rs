use std::net::{IpAddr, SocketAddr};
use axum::{
    extract::{ConnectInfo, State, Extension},
    response::IntoResponse,
    Json,
};
use tracing::info;
use chrono::Utc;

use crate::api::AppState;
use crate::ip_collector::CollectorCommand;
use crate::types::{ApiResponse, IpSource};

/// Explicit IP submission endpoint 
pub async fn submit_ip(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = addr.ip();
    
    info!("Received explicit IP submission from: {}", client_ip);
    
    // Send collection command with explicit submission source
    let _ = state
        .collector_tx
        .send(CollectorCommand::CollectIp {
            ip: client_ip,
            source: IpSource::ExplicitSubmission,
            user_agent: None,
        })
        .await;
        
    Json(ApiResponse::success(json!({
        "message": "IP submitted successfully",
        "ip": client_ip.to_string(),
        "timestamp": Utc::now()
    })))
}
