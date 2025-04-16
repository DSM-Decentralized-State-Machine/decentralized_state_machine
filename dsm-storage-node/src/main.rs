use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use axum::{
    extract::{Extension, Path as AxumPath},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, delete},
    Json, Router,
};
use clap::{Parser, Subcommand};
use config::{Config, ConfigError, File};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Define command line arguments
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the storage node
    Run,
    /// Start the storage node with staking (amount in tokens)
    Stake {
        #[arg(short, long)]
        amount: u64,
    },
}

// Configuration structs
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct ApiConfig {
    bind_address: String,
    port: u16,
    enable_cors: bool,
    enable_rate_limits: bool,
    max_body_size: usize,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct NodeConfig {
    id: String,
    name: String,
    region: String,
    operator: String,
    version: String,
    description: String,
    public_key: String,
    endpoint: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct StorageConfig {
    engine: String,
    capacity: u64,
    data_dir: String,
    database_path: String,
    assignment_strategy: String,
    replication_strategy: String,
    replica_count: u8,
    min_regions: u8,
    default_ttl: u64,
    enable_pruning: bool,
    pruning_interval: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct NetworkConfig {
    listen_addr: String,
    public_endpoint: String,
    port: u16,
    max_connections: u16,
    connection_timeout: u16,
    bootstrap_nodes: Vec<String>,
    enable_discovery: bool,
    discovery_interval: u64,
    max_peers: u16,
}

#[derive(Debug, Deserialize, Clone)]
struct AppConfig {
    api: ApiConfig,
    node: NodeConfig,
    storage: StorageConfig,
    network: NetworkConfig,
}

impl std::ops::Deref for AppConfig {
    type Target = StorageConfig;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

// Actual storage implementation
enum StorageEngine {
    Memory(MemoryStorage),
    Sqlite(SqliteStorage),
}

impl StorageEngine {
    async fn store(&self, key: String, value: Value) -> Result<(), String> {
        match self {
            StorageEngine::Memory(storage) => storage.store(key, value),
            StorageEngine::Sqlite(storage) => storage.store(key, value).await,
        }
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Value>, String> {
        match self {
            StorageEngine::Memory(storage) => storage.retrieve(key),
            StorageEngine::Sqlite(storage) => storage.retrieve(key).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<bool, String> {
        match self {
            StorageEngine::Memory(storage) => storage.delete(key),
            StorageEngine::Sqlite(storage) => storage.delete(key).await,
        }
    }
}

struct MemoryStorage {
    data: std::sync::RwLock<std::collections::HashMap<String, Value>>,
}

impl MemoryStorage {
    fn new() -> Self {
        Self {
            data: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    fn store(&self, key: String, value: Value) -> Result<(), String> {
        let mut data = self.data.write().unwrap();
        data.insert(key, value);
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Option<Value>, String> {
        let data = self.data.read().unwrap();
        Ok(data.get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.remove(key).is_some())
    }
}

struct SqliteStorage {
    db_path: PathBuf,
}

impl SqliteStorage {
    fn new(db_path: PathBuf) -> Self {
        Self { db_path }
    }

    fn initialize_schema(&self) -> Result<(), String> {
        debug!("Initializing SQLite database schema at {:?}", self.db_path);

        // Create the parent directory if it doesn't exist
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        // Create the data table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS data_entries (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("Failed to create data_entries table: {}", e))?;

        // Create index on timestamp for efficient pruning
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_data_entries_timestamp ON data_entries(timestamp)",
            [],
        )
        .map_err(|e| format!("Failed to create timestamp index: {}", e))?;

        debug!("SQLite database schema initialized successfully");
        Ok(())
    }

    async fn store(&self, key: String, value: Value) -> Result<(), String> {
        // Serialize the value to a JSON string
        let value_str = serde_json::to_string(&value)
            .map_err(|e| format!("Failed to serialize value: {}", e))?;

        // Run the database operation in a blocking task
        let db_path = self.db_path.clone();
        let key_for_logging = key.clone();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            let conn = Connection::open(&db_path)
                .map_err(|e| format!("Failed to open database: {}", e))?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            conn.execute(
                "INSERT OR REPLACE INTO data_entries (key, value, timestamp) VALUES (?, ?, ?)",
                params![key, value_str, timestamp],
            )
            .map_err(|e| format!("Failed to store data: {}", e))?;

            Ok(())
        })
        .await
        .map_err(|e| format!("Task panicked: {}", e))??;

        debug!("Data stored successfully with key: {}", key_for_logging);
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Value>, String> {
        let key_string = key.to_string();
        let db_path = self.db_path.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<Option<Value>, String> {
            let conn = Connection::open(&db_path)
                .map_err(|e| format!("Failed to open database: {}", e))?;

            let mut stmt = conn
                .prepare("SELECT value FROM data_entries WHERE key = ?")
                .map_err(|e| format!("Failed to prepare statement: {}", e))?;

            let mut rows = stmt
                .query(params![key_string])
                .map_err(|e| format!("Failed to execute query: {}", e))?;

            if let Some(row) = rows
                .next()
                .map_err(|e| format!("Failed to retrieve row: {}", e))?
            {
                let value_str: String = row
                    .get(0)
                    .map_err(|e| format!("Failed to get value from row: {}", e))?;

                let value: Value = serde_json::from_str(&value_str)
                    .map_err(|e| format!("Failed to deserialize value: {}", e))?;

                Ok(Some(value))
            } else {
                Ok(None)
            }
        })
        .await
        .map_err(|e| format!("Task panicked: {}", e))??;

        debug!("Data retrieval completed for key: {}", key);
        Ok(result)
    }

    async fn delete(&self, key: &str) -> Result<bool, String> {
        let key_for_logging = key.to_string();
        let key = key.to_string();
        let db_path = self.db_path.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<bool, String> {
            let conn = Connection::open(&db_path)
                .map_err(|e| format!("Failed to open database: {}", e))?;

            let count = conn
                .execute("DELETE FROM data_entries WHERE key = ?", params![key])
                .map_err(|e| format!("Failed to delete data: {}", e))?;

            Ok(count > 0)
        })
        .await
        .map_err(|e| format!("Task panicked: {}", e))??;
        debug!(
            "Data deletion completed for key: {}, deleted: {}",
            key_for_logging, result
        );
        Ok(result)
    }
}

// State representation
struct AppState {
    config: AppConfig,
    staked_amount: Option<u64>,
    storage: StorageEngine,
}

// API response structures
#[derive(Serialize)]
struct StatusResponse {
    node_id: String,
    status: String,
    version: String,
    uptime: u64,
    peers: u16,
    storage_used: u64,
    storage_total: u64,
    staked_amount: Option<u64>,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct ErrorResponse {
    error: String,
}

// Data response structure
#[derive(Serialize, Deserialize)]
struct DataResponse {
    key: String,
    data: Value,
}

// Helper function to load configuration
#[allow(clippy::ptr_arg)]
fn load_config(config_path: &PathBuf) -> Result<AppConfig, ConfigError> {
    let config = Config::builder()
        .add_source(File::from(config_path.clone()))
        .build()?;

    config.try_deserialize::<AppConfig>()
}

// API handlers
async fn status_handler(Extension(state): Extension<Arc<RwLock<AppState>>>) -> impl IntoResponse {
    let state = state.read().await;

    // In a real implementation, you would gather actual metrics
    let status = StatusResponse {
        node_id: state.config.node.id.clone(),
        status: "running".to_string(),
        version: state.config.node.version.clone(),
        uptime: 0,       // Placeholder
        peers: 0,        // Placeholder
        storage_used: 0, // Placeholder
        storage_total: state.config.storage.capacity,
        staked_amount: state.staked_amount,
    };

    (StatusCode::OK, Json(status))
}

async fn store_data_handler(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    AxumPath(key): AxumPath<String>,
    Json(data): Json<Value>,
) -> impl IntoResponse {
    debug!("Storing data with key: {}", key);

    let state = state.read().await;
    match state.storage.store(key, data).await {
        Ok(()) => StatusCode::OK,
        Err(err) => {
            error!("Failed to store data: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn retrieve_data_handler(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    AxumPath(key): AxumPath<String>,
) -> impl IntoResponse {
    debug!("Retrieving data with key: {}", key);

    let state = state.read().await;
    match state.storage.retrieve(&key).await {
        Ok(Some(data)) => (StatusCode::OK, Json(data)),
        Ok(None) => (StatusCode::NOT_FOUND, Json(Value::Null)),
        Err(err) => {
            error!("Failed to retrieve data: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(Value::Null))
        }
    }
}

async fn delete_data_handler(
    Extension(state): Extension<Arc<RwLock<AppState>>>,
    AxumPath(key): AxumPath<String>,
) -> impl IntoResponse {
    debug!("Deleting data with key: {}", key);

    let state = state.read().await;
    match state.storage.delete(&key).await {
        Ok(true) => StatusCode::OK,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(err) => {
            error!("Failed to delete data: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn list_peers_handler(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    // Placeholder implementation
    StatusCode::OK
}

// Setup the API routes
fn create_router(state: Arc<RwLock<AppState>>) -> Router {
    Router::new()
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/data/:key", get(retrieve_data_handler))
        .route("/api/v1/data/:key", post(store_data_handler))
        .route("/api/v1/data/:key", delete(delete_data_handler))
        .route("/api/v1/peers", get(list_peers_handler))
        .layer(Extension(state))
        .layer(TraceLayer::new_for_http())
}

// Initialize storage based on configuration
async fn init_storage(config: &StorageConfig) -> Result<StorageEngine, anyhow::Error> {
    // Create data directory if it doesn't exist
    tokio::fs::create_dir_all(&config.data_dir).await?;

    // Initialize the appropriate storage engine based on the configuration
    match config.engine.as_str() {
        "sqlite" => {
            info!(
                "Initializing SQLite storage engine at {}",
                config.database_path
            );
            let db_path = PathBuf::from(&config.database_path);
            let sqlite_storage = SqliteStorage::new(db_path);
            sqlite_storage
                .initialize_schema()
                .map_err(|e| anyhow::anyhow!("Failed to initialize SQLite schema: {}", e))?;

            Ok(StorageEngine::Sqlite(sqlite_storage))
        }
        "memory" => {
            info!("Initializing in-memory storage engine");
            let memory_storage = MemoryStorage::new();
            Ok(StorageEngine::Memory(memory_storage))
        }
        "epidemic" => {
            info!("Initializing epidemic storage engine");
            // For the epidemic storage, we need to use the DSM module's storage engine
            // The epidemic storage is handled separately in the run_storage_node function
            // This stub allows the epidemic storage type to be recognized
            let memory_storage = MemoryStorage::new(); // Use memory as a fallback for initial testing
            Ok(StorageEngine::Memory(memory_storage))
        }
        _ => {
            error!("Unsupported storage engine: {}", config.engine);
            Err(anyhow::anyhow!("Unsupported storage engine"))
        }
    }
}

// Initialize networking based on configuration
async fn init_networking(config: &NetworkConfig) -> Result<(), anyhow::Error> {
    // This would connect to bootstrap nodes, set up discovery, etc.
    info!(
        "Initializing networking on {}:{}",
        config.listen_addr, config.port
    );

    // For bootstrap nodes
    if !config.bootstrap_nodes.is_empty() {
        info!(
            "Connecting to bootstrap nodes: {:?}",
            config.bootstrap_nodes
        );
        // Actual implementation would connect to these nodes
    }

    Ok(())
}

// Simulate staking process
async fn process_staking(amount: u64) -> Result<(), anyhow::Error> {
    info!("Processing stake of {} tokens", amount);

    // In a real implementation, this would interact with a blockchain
    // to lock tokens as stake for operating a storage node.

    // For now, we just simulate a successful staking
    if amount < 1000 {
        error!("Staking amount too low. Minimum requirement is 1000 tokens.");
        return Err(anyhow::anyhow!("Staking amount too low"));
    }

    info!("Staking successful. Node is eligible for rewards.");
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    // Initialize tracing for logs
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse command line arguments
    let cli = Cli::parse();

    // Load configuration
    let config_path = cli.config;
    info!("Loading configuration from {:?}", config_path);

    let config = match load_config(&config_path) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    info!("Configuration loaded successfully");

    // Process command
    let staked_amount = match cli.command {
        Some(Commands::Stake { amount }) => {
            info!("Staking mode with {} tokens", amount);
            match process_staking(amount).await {
                Ok(_) => Some(amount),
                Err(e) => {
                    error!("Staking failed: {}", e);
                    process::exit(1);
                }
            }
        }
        Some(Commands::Run) | None => {
            info!("Running without explicit stake");
            None
        }
    };

    // Initialize storage
    let storage = match init_storage(&config.storage).await {
        Ok(storage) => storage,
        Err(e) => {
            error!("Failed to initialize storage: {}", e);
            process::exit(1);
        }
    };

    // Create application state
    let state = Arc::new(RwLock::new(AppState {
        config: config.clone(),
        staked_amount,
        storage,
    }));

    // Initialize networking
    if let Err(e) = init_networking(&config.network).await {
        error!("Failed to initialize networking: {}", e);
        process::exit(1);
    }

    // Set up the API server
    let api_addr = format!("{}:{}", config.api.bind_address, config.api.port)
        .parse::<SocketAddr>()
        .expect("Invalid API address");

    let router = create_router(state);

    info!("Starting API server on {}", api_addr);
    let server = axum::Server::bind(&api_addr).serve(router.into_make_service());

    info!("DSM Storage Node running. Press Ctrl+C to stop.");

    // Run the server with graceful shutdown
    if let Err(e) = server.await {
        error!("Server error: {}", e);
        process::exit(1);
    }

    Ok(())
}
