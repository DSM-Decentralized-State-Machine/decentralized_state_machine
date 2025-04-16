// filepath: /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/api/handlers/redirect.rs
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{Html, Redirect},
};
use std::net::SocketAddr;
use tracing::info;

use crate::api::AppState;
use crate::ip_collector::CollectorCommand;
use crate::types::IpSource;

/// Redirects to a target URL while collecting the IP
pub async fn redirect_collector(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Redirect {
    // Get the real client IP (this will use X-Forwarded-For if available)
    let client_ip = addr.ip();

    // Log the IP visit (silently)
    info!("Redirecting visitor from IP: {}", client_ip);

    // Send collection command to the collector service
    let _ = state
        .collector_tx
        .send(CollectorCommand::CollectIp {
            ip: client_ip,
            source: IpSource::WebVisit,
            user_agent: None,
        })
        .await;

    // Redirect to desired destination
    Redirect::to("https://google.com")
}

/// Embed tracking pixel that collects IP (invisible)
pub async fn tracking_pixel(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> (StatusCode, &'static [u8]) {
    // Get the real client IP
    let client_ip = addr.ip();

    // Silently collect the IP
    let _ = state
        .collector_tx
        .send(CollectorCommand::CollectIp {
            ip: client_ip,
            source: IpSource::WebVisit,
            user_agent: None,
        })
        .await;

    // Return a tiny transparent 1x1 pixel GIF
    (
        StatusCode::OK,
        // Transparent 1x1 pixel GIF
        &[
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff,
            0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00,
            0x3b,
        ],
    )
}

/// Embed a fake landing page that looks legitimate but collects IPs
pub async fn landing_page(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Html<String> {
    // Get the real client IP
    let client_ip = addr.ip();

    // Silently collect the IP
    let _ = state
        .collector_tx
        .send(CollectorCommand::CollectIp {
            ip: client_ip,
            source: IpSource::WebVisit,
            user_agent: None,
        })
        .await;

    // Return a simple HTML page
    Html(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Information Portal</title>
            <meta http-equiv="refresh" content="5;url=https://google.com" />
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                .container { max-width: 800px; margin: 0 auto; }
                h1 { color: #333; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to the Information Portal</h1>
                <p>This page is temporarily unavailable or has moved.</p>
                <p>You will be redirected in 5 seconds...</p>
            </div>
        </body>
        </html>
        "#
        .to_string(),
    )
}
