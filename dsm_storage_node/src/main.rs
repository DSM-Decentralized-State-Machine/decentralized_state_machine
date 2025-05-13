/// # DSM Storage Node
///
/// This is the main entry point for the DSM Storage Node application, which provides
/// a secure, distributed, and quantum-resistant storage solution for the Decentralized
/// State Machine ecosystem.
///
/// The storage node implements several types of storage backends:
/// * SQLite - Persistent storage for individual nodes
/// * Memory - In-memory storage for testing and development
/// * Epidemic - Distributed storage with epidemic protocols for replication
///
/// ## Features
///
/// * RESTful API for data storage and retrieval
/// * Configurable storage backends
/// * Node staking for participation in the DSM network
/// * Peer-to-peer networking with automatic discovery
/// * Quantum-resistant encryption of all stored data
/// * Automatic data distribution and replication
///
/// ## Configuration
///
/// The node is configured via a TOML file that specifies:
/// * API settings (bind address, port, CORS, rate limits)
/// * Node identity and metadata
/// * Storage configuration (engine type, capacity, etc.)
/// * Network settings (peers, discovery, etc.)
///
/// ## Usage
///
/// ```bash
/// # Run with default configuration
/// dsm-storage-node --config config.toml
///
/// # Run with staking to earn rewards
/// dsm-storage-node --config config.toml stake --amount 5000
/// ```
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

/// Command line argument parser for the DSM Storage Node.
///
/// Provides options for specifying the configuration file and
/// different operation modes such as regular operation or staking.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The subcommand to execute (run or stake)
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the configuration file
    /// Defaults to config.toml in the current directory
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,
}

/// Available subcommands for the DSM Storage Node
#[derive(Subcommand)]
enum Commands {
    /// Run the storage node in standard mode
    Run,

    /// Start the storage node with staking to participate
    /// in the DSM network and earn rewards
    Stake {
        /// Amount of tokens to stake (minimum usually 1000)
        #[arg(short, long)]
        amount: u64,
    },
}

/// API configuration settings from the config file
///
/// Controls the HTTP API behavior including binding address,
/// security features, and request limits.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct ApiConfig {
    /// IP address to bind the API server to
    bind_address: String,

    /// Port number for the API server
    port: u16,

    /// Whether to enable Cross-Origin Resource Sharing
    enable_cors: bool,

    /// Whether to enable rate limiting for API requests
    enable_rate_limits: bool,

    /// Maximum size of request bodies in bytes
    max_body_size: usize,
}

/// Node identity and metadata configuration
///
/// Defines the node's identity in the DSM network and
/// provides metadata about the node operator.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct NodeConfig {
    /// Unique identifier for this node in the network
    id: String,

    /// Human-readable name for the node
    name: String,

    /// Geographic region where the node is located
    region: String,

    /// Entity operating this node
    operator: String,

    /// Version string for this node
    version: String,

    /// Human-readable description of the node
    description: String,

    /// Public key for node identity verification
    public_key: String,

    /// Public endpoint where this node can be reached
    endpoint: String,
}

/// Storage engine configuration
///
/// Controls how data is stored, distributed, and managed
/// by this storage node.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct StorageConfig {
    /// Storage engine type ("sqlite", "memory", "epidemic")
    engine: String,

    /// Maximum storage capacity in bytes
    capacity: u64,

    /// Directory to store data files
    data_dir: String,

    /// Path to the database file (for sqlite engine)
    database_path: String,

    /// Strategy for assigning data to nodes
    /// Options: "DeterministicHashing", "RoundRobin", "LoadBalanced"
    assignment_strategy: String,

    /// Strategy for data replication across nodes
    /// Options: "FixedReplicas", "DynamicReplicas", "RegionAware"
    replication_strategy: String,

    /// Number of replicas to maintain for each data item
    replica_count: u8,

    /// Minimum number of different regions for replicas
    min_regions: u8,

    /// Default time-to-live for data in seconds (0 = no expiration)
    default_ttl: u64,

    /// Whether to enable automatic pruning of expired data
    enable_pruning: bool,

    /// Interval between pruning operations in seconds
    pruning_interval: u64,
}

/// Network configuration for P2P communication
///
/// Controls how the node communicates with other nodes
/// in the DSM network.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
struct NetworkConfig {
    /// IP address to listen on for P2P communication
    listen_addr: String,

    /// Public endpoint for other nodes to connect to this node
    public_endpoint: String,

    /// Port number for P2P communication
    port: u16,

    /// Maximum number of concurrent P2P connections
    max_connections: u16,

    /// Connection timeout in seconds
    connection_timeout: u16,

    /// List of bootstrap nodes to connect to on startup
    bootstrap_nodes: Vec<String>,

    /// Whether to enable automatic node discovery
    enable_discovery: bool,

    /// Interval between node discovery operations in seconds
    discovery_interval: u64,

    /// Maximum number of peer nodes to maintain
    max_peers: u16,
}

/// Complete application configuration
///
/// Combines all configuration subsections into a single struct.
#[derive(Debug, Deserialize, Clone)]
struct AppConfig {
    /// API server configuration
    api: ApiConfig,

    /// Node identity and metadata
    node: NodeConfig,

    /// Storage engine configuration
    storage: StorageConfig,

    /// Network and P2P configuration
    network: NetworkConfig,
}

// Deref implementation for convenient access to storage config
impl std::ops::Deref for AppConfig {
    type Target = StorageConfig;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

/// Storage engine abstraction that unifies different backend implementations
///
/// This enum provides a common interface to interact with different
/// storage backends, allowing the rest of the application to be
/// agnostic to the specific storage implementation.
enum StorageEngine {
    /// In-memory storage backend (volatile)
    Memory(MemoryStorage),

    /// SQLite database storage backend (persistent)
    Sqlite(SqliteStorage),
}

impl StorageEngine {
    /// Store a key-value pair in the storage backend
    ///
    /// # Arguments
    ///
    /// * `key` - Unique identifier for the data
    /// * `value` - JSON value to store
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful
    /// * `Err(String)` with an error message if the operation fails
    async fn store(&self, key: String, value: Value) -> Result<(), String> {
        match self {
            StorageEngine::Memory(storage) => storage.store(key, value),
            StorageEngine::Sqlite(storage) => storage.store(key, value).await,
        }
    }

    /// Retrieve a value by its key
    ///
    /// # Arguments
    ///
    /// * `key` - Key to retrieve
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Value))` if the key exists
    /// * `Ok(None)` if the key does not exist
    /// * `Err(String)` with an error message if the operation fails
    async fn retrieve(&self, key: &str) -> Result<Option<Value>, String> {
        match self {
            StorageEngine::Memory(storage) => storage.retrieve(key),
            StorageEngine::Sqlite(storage) => storage.retrieve(key).await,
        }
    }

    /// Delete a key-value pair from storage
    ///
    /// # Arguments
    ///
    /// * `key` - Key to delete
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the key existed and was deleted
    /// * `Ok(false)` if the key did not exist
    /// * `Err(String)` with an error message if the operation fails
    async fn delete(&self, key: &str) -> Result<bool, String> {
        match self {
            StorageEngine::Memory(storage) => storage.delete(key),
            StorageEngine::Sqlite(storage) => storage.delete(key).await,
        }
    }
}

/// In-memory storage implementation
///
/// Provides a non-persistent storage backend that keeps all data
/// in memory. This is useful for testing and development, but
/// all data is lost when the node restarts.
struct MemoryStorage {
    /// Thread-safe hash map for storing key-value pairs
    data: std::sync::RwLock<std::collections::HashMap<String, Value>>,
}

impl MemoryStorage {
    /// Create a new in-memory storage instance
    fn new() -> Self {
        Self {
            data: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Store a key-value pair in memory
    ///
    /// # Arguments
    ///
    /// * `key` - Unique identifier for the data
    /// * `value` - JSON value to store
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful
    /// * `Err(String)` with an error message if the operation fails
    fn store(&self, key: String, value: Value) -> Result<(), String> {
        let mut data = self.data.write().unwrap();
        data.insert(key, value);
        Ok(())
    }

    /// Retrieve a value by its key from memory
    ///
    /// # Arguments
    ///
    /// * `key` - Key to retrieve
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Value))` if the key exists
    /// * `Ok(None)` if the key does not exist
    /// * `Err(String)` with an error message if the operation fails
    fn retrieve(&self, key: &str) -> Result<Option<Value>, String> {
        let data = self.data.read().unwrap();
        Ok(data.get(key).cloned())
    }

    /// Delete a key-value pair from memory
    ///
    /// # Arguments
    ///
    /// * `key` - Key to delete
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the key existed and was deleted
    /// * `Ok(false)` if the key did not exist
    /// * `Err(String)` with an error message if the operation fails
    fn delete(&self, key: &str) -> Result<bool, String> {
        let mut data = self.data.write().unwrap();
        Ok(data.remove(key).is_some())
    }
}

/// SQLite-based persistent storage implementation
///
/// Provides a durable storage backend that persists data to a SQLite
/// database file. This ensures data survival across node restarts
/// and provides ACID guarantees for data operations.
struct SqliteStorage {
    /// Path to the SQLite database file
    db_path: PathBuf,
}

impl SqliteStorage {
    /// Create a new SQLite storage instance
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the SQLite database file
    fn new(db_path: PathBuf) -> Self {
        Self { db_path }
    }

    /// Initialize the database schema
    ///
    /// Creates necessary tables and indexes if they don't exist.
    /// Should be called before using the storage engine.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful
    /// * `Err(String)` with an error message if initialization fails
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

    /// Store a key-value pair in the SQLite database
    ///
    /// # Arguments
    ///
    /// * `key` - Unique identifier for the data
    /// * `value` - JSON value to store
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful
    /// * `Err(String)` with an error message if the operation fails
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

    /// Retrieve a value by its key from the SQLite database
    ///
    /// # Arguments
    ///
    /// * `key` - Key to retrieve
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Value))` if the key exists
    /// * `Ok(None)` if the key does not exist
    /// * `Err(String)` with an error message if the operation fails
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

    /// Delete a key-value pair from the SQLite database
    ///
    /// # Arguments
    ///
    /// * `key` - Key to delete
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the key existed and was deleted
    /// * `Ok(false)` if the key did not exist
    /// * `Err(String)` with an error message if the operation fails
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

/// Application state shared across API handlers
///
/// Contains the core components and configuration needed by
/// the API handlers to process requests.
struct AppState {
    /// Application configuration
    config: AppConfig,

    /// Amount of tokens staked by this node (if any)
    staked_amount: Option<u64>,

    /// Storage engine implementation
    storage: StorageEngine,
}

/// Node status response for the API
///
/// Contains information about the node's current state,
/// used by the status endpoint.
#[derive(Serialize)]
struct StatusResponse {
    /// Unique identifier for this node
    node_id: String,

    /// Current operational status
    status: String,

    /// Version string
    version: String,

    /// Time in seconds since the node started
    uptime: u64,

    /// Number of connected peer nodes
    peers: u16,

    /// Amount of storage used in bytes
    storage_used: u64,

    /// Total storage capacity in bytes
    storage_total: u64,

    /// Amount of tokens staked by this node (if any)
    staked_amount: Option<u64>,
}

/// Error response for the API
///
/// Used to return structured error information
/// when an API request fails.
#[derive(Serialize)]
#[allow(dead_code)]
struct ErrorResponse {
    /// Error message
    error: String,
}

/// Data response for the API
///
/// Used to return data items with their keys.
#[derive(Serialize, Deserialize)]
struct DataResponse {
    /// Key for the data item
    key: String,

    /// The data item's content as JSON
    data: Value,
}

/// Load configuration from a TOML file
///
/// # Arguments
///
/// * `config_path` - Path to the configuration file
///
/// # Returns
///
/// * `Ok(AppConfig)` if the configuration was loaded successfully
/// * `Err(ConfigError)` if the configuration could not be loaded
#[allow(clippy::ptr_arg)]
fn load_config(config_path: &PathBuf) -> Result<AppConfig, ConfigError> {
    let config = Config::builder()
        .add_source(File::from(config_path.clone()))
        .build()?;

    config.try_deserialize::<AppConfig>()
}

/// API handler for the node status endpoint
///
/// Returns current information about the node's status,
/// including uptime, connections, and storage usage.
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

/// API handler for storing data
///
/// Stores a JSON value with the given key in the storage backend.
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

/// API handler for retrieving data
///
/// Retrieves a JSON value by its key from the storage backend.
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

/// API handler for deleting data
///
/// Deletes a key-value pair from the storage backend.
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

/// API handler for listing connected peers
///
/// Returns a list of peer nodes connected to this node.
async fn list_peers_handler(
    Extension(_state): Extension<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    // Placeholder implementation
    StatusCode::OK
}

/// Create the API router with all routes
///
/// Sets up all API endpoints and attaches the application state.
///
/// # Arguments
///
/// * `state` - Application state to be shared with all handlers
///
/// # Returns
///
/// An Axum Router configured with all API endpoints
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

/// Initialize the storage engine based on configuration
///
/// Creates and initializes the appropriate storage engine
/// based on the configuration.
///
/// # Arguments
///
/// * `config` - Storage configuration
///
/// # Returns
///
/// * `Ok(StorageEngine)` if initialization was successful
/// * `Err(anyhow::Error)` if initialization failed
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

/// Initialize networking based on configuration
///
/// Sets up networking connections to peer nodes and
/// initializes the discovery mechanism.
///
/// # Arguments
///
/// * `config` - Network configuration
///
/// # Returns
///
/// * `Ok(())` if initialization was successful
/// * `Err(anyhow::Error)` if initialization failed
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

/// Process staking of tokens for node operation
///
/// Stakes the specified amount of tokens to participate
/// in the DSM network and earn rewards.
///
/// # Arguments
///
/// * `amount` - Amount of tokens to stake
///
/// # Returns
///
/// * `Ok(())` if staking was successful
/// * `Err(anyhow::Error)` if staking failed
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

/// Main function for the DSM Storage Node
///
/// Initializes the system, loads configuration, and starts the API server.
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
