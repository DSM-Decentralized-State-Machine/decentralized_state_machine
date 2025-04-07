use clap::Parser;
use dsm::initialize as init_dsm;
use dsm_storage_node::{
    api::ApiServer,
    config::Config,
    storage::{memory_storage::MemoryStorage, sql_storage::SqlStorage, StorageProvider},
    types::StorageNode,
};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Use in-memory storage (for testing)
    #[arg(short, long, default_value_t = false)]
    memory: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    // Parse command line arguments
    let args = Args::parse();

    // Load configuration
    info!("Loading configuration from {}", args.config);
    let config = Config::from_file(&args.config)?;

    // Initialize DSM library
    info!("Initializing DSM library");
    init_dsm();

    // Create storage engine based on command line arguments
    let storage_engine: Arc<dyn dsm_storage_node::storage::StorageEngine + Send + Sync> =
        if args.memory {
            info!("Using in-memory storage engine");
            Arc::new(MemoryStorage::new())
        } else {
            info!(
                "Using SQL storage engine with path: {}",
                config.storage.data_dir.to_string_lossy()
            );
            Arc::new(SqlStorage::new(&config.storage.data_dir)?)
        };

    // Create node information
    let node = StorageNode {
        id: "default-id".to_string(),     // Set default or get from environment
        name: "default-name".to_string(), // Set default or get from environment
        region: "default-region".to_string(), // Set default or get from environment
        public_key: "default-key".to_string(), // Set default or get from environment
        endpoint: config.network.external_address.clone().unwrap_or_default(),
    };

    // Create storage provider
    let _storage_provider = StorageProvider::new(
        storage_engine.clone(),
        None, // No backup storage for now
        node,
        3600, // Default TTL in seconds
        "default-region".to_string(),
    );

    // Create API server
    let api_server = ApiServer::new(
        storage_engine.clone(), // Use storage_engine directly
        config.api.bind_address.clone(),
    );

    // Start API server
    info!("Starting API server on {}", config.api.bind_address);
    api_server.start().await?;

    Ok(())
}
