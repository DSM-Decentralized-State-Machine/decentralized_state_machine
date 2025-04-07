// DSM Server Implementation

// Removed unused base64 imports
use clap::Parser;
use dsm::{
    api::identity_api, crypto, interfaces::network_face, types::error::DsmError,
    unilateral::InboxManager, vault::DLVManager,
};
// Removed unused serde imports
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing_subscriber;

#[derive(Parser)]
#[clap(
    author = "DSM Team",
    version = "1.0",
    about = "Decentralized State Machine Server"
)]
struct Cli {
    /// IP address to bind to
    #[clap(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on
    #[clap(long, default_value = "8421")]
    port: u16,

    /// Data directory
    #[clap(long, default_value = "./data")]
    data_dir: String,

    /// Verbose mode
    #[clap(long)]
    verbose: bool,
}

// Server State
struct AppState {
    directory: DirectoryService,
    inbox_manager: Arc<RwLock<InboxManager>>,
    vault_manager: Arc<RwLock<DLVManager>>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            inbox_manager: self.inbox_manager.clone(),
            vault_manager: self.vault_manager.clone(),
        }
    }
}

// Directory Service for storing data
#[derive(Clone)]
struct DirectoryService {
    identities: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl DirectoryService {
    fn new() -> Self {
        Self {
            identities: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // Removed unused methods that were never called

    async fn store_identity(&self, id: &str, data: &[u8]) -> Result<(), DsmError> {
        let mut identities = self.identities.write().await;
        identities.insert(id.to_string(), data.to_vec());
        Ok(())
    }

    async fn get_identity(&self, id: &str) -> Result<Option<Vec<u8>>, DsmError> {
        let identities = self.identities.read().await;
        Ok(identities.get(id).cloned())
    }
}

// Simple HTTP response
fn json_response(status: u16, body: serde_json::Value) -> String {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\n\r\n{}",
        status_text(status),
        body
    )
}

// Convert status code to text
fn status_text(status: u16) -> String {
    match status {
        200 => "200 OK".to_string(),
        201 => "201 Created".to_string(),
        400 => "400 Bad Request".to_string(),
        404 => "404 Not Found".to_string(),
        500 => "500 Internal Server Error".to_string(),
        _ => format!("{} Status", status),
    }
}

// Simple HTTP request parser
struct HttpRequest {
    method: String,
    path: String,
    body: String,
}

fn parse_http_request(request: &str) -> Option<HttpRequest> {
    let mut lines = request.lines();

    // Parse request line
    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Find empty line that separates headers from body
    let mut body_start = 0;

    for (i, line) in lines.enumerate() {
        if line.is_empty() {
            body_start = i + 1;
            break;
        }
    }

    // Parse body
    let body = request
        .lines()
        .skip(body_start + 1)
        .collect::<Vec<&str>>()
        .join("\n");

    Some(HttpRequest { method, path, body })
}

// Handle HTTP request
async fn handle_request(request: HttpRequest, app_state: &AppState) -> String {
    match (request.method.as_str(), request.path.as_str()) {
        // Health check
        ("GET", "/health") => {
            let response = serde_json::json!({
                "status": "running",
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": chrono::Utc::now().timestamp(),
            });

            json_response(200, response)
        }

        // Identity API
        ("POST", "/api/v1/identities") => {
            let device_id = match serde_json::from_str::<serde_json::Value>(&request.body) {
                Ok(body) => match body.get("device_id") {
                    Some(device_id) => device_id.as_str().unwrap_or("").to_string(),
                    None => uuid::Uuid::new_v4().to_string(),
                },
                Err(_) => uuid::Uuid::new_v4().to_string(),
            };

            match identity_api::create_identity(device_id) {
                Ok(identity) => {
                    // Convert to JSON
                    let identity_json = serde_json::json!({
                        "identity_id": identity.id(),
                        "device_id": identity.device_id(),
                    });

                    // Store in directory
                    let identity_data = serde_json::json!({
                        "id": identity.id(),
                        "device_id": identity.device_id(),
                    });

                    match app_state
                        .directory
                        .store_identity(identity.id(), &serde_json::to_vec(&identity_data).unwrap())
                        .await
                    {
                        Ok(_) => {
                            let response = serde_json::json!({
                                "success": true,
                                "data": identity_json,
                                "error": null
                            });

                            json_response(201, response)
                        }
                        Err(e) => {
                            let response = serde_json::json!({
                                "success": false,
                                "data": null,
                                "error": format!("Failed to store identity: {}", e)
                            });

                            json_response(500, response)
                        }
                    }
                }
                Err(e) => {
                    let response = serde_json::json!({
                        "success": false,
                        "data": null,
                        "error": format!("Failed to create identity: {}", e)
                    });

                    json_response(400, response)
                }
            }
        }

        // List identities
        ("GET", "/api/v1/identities") => match identity_api::get_identities() {
            Ok(identities) => {
                let identity_json = identities
                    .iter()
                    .map(|identity| {
                        serde_json::json!({
                            "identity_id": identity.id(),
                            "device_id": identity.device_id(),
                        })
                    })
                    .collect::<Vec<_>>();

                let response = serde_json::json!({
                    "success": true,
                    "data": identity_json,
                    "error": null
                });

                json_response(200, response)
            }
            Err(e) => {
                let response = serde_json::json!({
                    "success": false,
                    "data": null,
                    "error": format!("Failed to get identities: {}", e)
                });

                json_response(500, response)
            }
        },

        // Get a specific identity
        ("GET", path) if path.starts_with("/api/v1/identities/") => {
            let id = path.trim_start_matches("/api/v1/identities/");

            match app_state.directory.get_identity(id).await {
                Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(identity_data) => {
                        let response = serde_json::json!({
                            "success": true,
                            "data": identity_data,
                            "error": null
                        });

                        json_response(200, response)
                    }
                    Err(e) => {
                        let response = serde_json::json!({
                            "success": false,
                            "data": null,
                            "error": format!("Failed to parse identity data: {}", e)
                        });

                        json_response(500, response)
                    }
                },
                Ok(None) => {
                    let response = serde_json::json!({
                        "success": false,
                        "data": null,
                        "error": format!("Identity not found: {}", id)
                    });

                    json_response(404, response)
                }
                Err(e) => {
                    let response = serde_json::json!({
                        "success": false,
                        "data": null,
                        "error": format!("Failed to get identity: {}", e)
                    });

                    json_response(500, response)
                }
            }
        }

        // Handle any other request
        _ => {
            let response = serde_json::json!({
                "success": false,
                "data": null,
                "error": format!("Unknown endpoint: {} {}", request.method, request.path)
            });

            json_response(404, response)
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Configure logging
    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();
    tracing::info!("Starting DSM server...");

    // Initialize DSM components
    tracing::debug!("Initializing crypto subsystem...");
    crypto::init_crypto();

    tracing::debug!("Initializing identity subsystem...");
    identity_api::init_identity();

    // Create data directories
    tracing::debug!("Setting up data directories...");
    std::fs::create_dir_all(&cli.data_dir).unwrap_or_else(|e| {
        tracing::error!("Failed to create data directory: {}", e);
        std::process::exit(1);
    });

    // Create subdirectories
    for subdir in &[
        "identities",
        "tokens",
        "commitments",
        "unilateral",
        "vaults",
    ] {
        std::fs::create_dir_all(std::path::Path::new(&cli.data_dir).join(subdir)).unwrap_or_else(
            |e| {
                tracing::error!("Failed to create {} directory: {}", subdir, e);
                std::process::exit(1);
            },
        );
    }

    // Initialize network interface
    tracing::debug!("Starting network interface...");
    if let Err(e) = network_face::start().await {
        tracing::error!("Failed to start network interface: {:?}", e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Network interface error",
        ));
    }

    // Create application state
    let app_state = AppState {
        directory: DirectoryService::new(),
        inbox_manager: Arc::new(RwLock::new(InboxManager::new())),
        vault_manager: Arc::new(RwLock::new(DLVManager::new())),
    };
    tracing::info!("Application state initialized");

    // Load configuration
    tracing::debug!("Loading configuration...");
    let config_path = PathBuf::from(&cli.data_dir).join("config.json");
    let _config = if config_path.exists() {
        match tokio::fs::read_to_string(&config_path).await {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(config) => {
                    tracing::info!("Loaded configuration from {}", config_path.display());
                    Some(config)
                }
                Err(e) => {
                    tracing::warn!("Failed to parse configuration: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to read configuration: {}", e);
                None
            }
        }
    } else {
        // Create default config
        tracing::info!("Creating default configuration...");
        let default_config = serde_json::json!({
            "server": {
                "host": cli.host,
                "port": cli.port,
            },
            "storage": {
                "data_dir": cli.data_dir,
            },
            "network": {
                "enable_p2p": false,
                "bootstrap_nodes": [],
            },
            "vault": {
                "auto_expire_check_interval": 3600,
            },
            "unilateral": {
                "max_transaction_size": 1048576, // 1MB
            }
        });

        // Write default config
        match serde_json::to_string_pretty(&default_config) {
            Ok(json) => match tokio::fs::write(&config_path, json).await {
                Ok(_) => {
                    tracing::info!("Created default configuration at {}", config_path.display());
                    Some(default_config)
                }
                Err(e) => {
                    tracing::warn!("Failed to write default configuration: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to serialize default configuration: {}", e);
                None
            }
        }
    };

    // Start TCP listener
    let socket = SocketAddr::new(
        IpAddr::V4(cli.host.parse().unwrap_or(Ipv4Addr::LOCALHOST)),
        cli.port,
    );

    tracing::info!("Starting TCP listener on {}:{}...", cli.host, cli.port);
    let listener = TcpListener::bind(socket)?;
    println!("Server running at http://{}:{}", cli.host, cli.port);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state = app_state.clone();

                tokio::spawn(async move {
                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(size) => {
                            if size == 0 {
                                tracing::debug!("Received empty request");
                                return;
                            }

                            let request_str = String::from_utf8_lossy(&buffer[0..size]).to_string();
                            tracing::debug!("Received request: {}", request_str);

                            if let Some(request) = parse_http_request(&request_str) {
                                tracing::debug!(
                                    "Handling {} request to {}",
                                    request.method,
                                    request.path
                                );
                                let response = handle_request(request, &state).await;
                                match stream.write_all(response.as_bytes()) {
                                    Ok(_) => tracing::debug!("Response sent successfully"),
                                    Err(e) => tracing::error!("Failed to send response: {}", e),
                                }
                            } else {
                                tracing::warn!("Invalid HTTP request received");
                                let response = json_response(
                                    400,
                                    serde_json::json!({
                                        "success": false,
                                        "data": null,
                                        "error": "Invalid HTTP request"
                                    }),
                                );

                                if let Err(e) = stream.write_all(response.as_bytes()) {
                                    tracing::error!("Failed to send error response: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error reading from stream: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                tracing::error!("Error accepting connection: {}", e);
            }
        }
    }

    // Shutdown network interface
    tracing::info!("Shutting down network interface...");
    if let Err(e) = network_face::stop().await {
        tracing::error!("Failed to stop network interface: {:?}", e);
    }

    tracing::info!("Server shutdown complete");
    Ok(())
}
