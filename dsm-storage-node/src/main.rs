use clap::Parser;
use dsm::initialize as init_dsm;
use dsm_storage_node::{
    api::ApiServer,
    config::Config,
    storage::{memory_storage::MemoryStorage, sql_storage::SqlStorage, StorageProvider, StorageFactory},
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

    /// Storage type: memory, sql, epidemic, distributed
    #[arg(short, long, default_value = "sql")]
    storage_type: String,
    
    /// Node ID (used for epidemic storage)
    #[arg(short, long)]
    node_id: Option<String>,
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

    // Create node information
    let node_id = args.node_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    let node = StorageNode {
        id: node_id.clone(),
        name: format!("node-{}", node_id),
        region: config.storage.region.clone().unwrap_or_else(|| "default".to_string()),
        public_key: "default-key".to_string(), // Would be generated or loaded in production
        endpoint: config.network.external_address.clone().unwrap_or_default(),
    };
    
    // Create storage factory
    let storage_factory = StorageFactory::new(config.storage.clone());
    
    // Create storage engine based on command line arguments
    let storage_engine: Arc<dyn dsm_storage_node::storage::StorageEngine + Send + Sync> = match args.storage_type.as_str() {
        "memory" => {
            info!("Using in-memory storage engine");
            storage_factory.create_memory_storage()?
        },
        "sql" => {
            info!(
                "Using SQL storage engine with path: {}",
                config.storage.database_path
            );
            storage_factory.create_sql_storage()?
        },
        "epidemic" => {
            info!("Using epidemic storage engine with small-world topology");
            
            // Create backing storage (SQL)
            let backing_storage = storage_factory.create_sql_storage()?;
            
            // Parse bootstrap nodes from config
            let bootstrap_nodes = config.network.bootstrap_nodes.clone()
                .unwrap_or_default()
                .iter()
                .map(|addr| StorageNode {
                    id: format!("bootstrap-{}", uuid::Uuid::new_v4()),
                    name: format!("Bootstrap {}", addr),
                    region: "default".to_string(),
                    public_key: "".to_string(),
                    endpoint: addr.clone(),
                })
                .collect::<Vec<_>>();
            
            // Create and start the epidemic storage
            storage_factory.create_epidemic_storage(
                node_id.clone(),
                node.clone(),
                bootstrap_nodes,
                Some(backing_storage),
            ).await?
        },
        "distributed" => {
            info!("Using distributed storage engine");
            
            // Create local storage (SQL)
            let local_storage = storage_factory.create_sql_storage()?;
            
            // Parse storage nodes from config
            let storage_nodes = config.network.storage_nodes.clone()
                .unwrap_or_default()
                .iter()
                .map(|addr| StorageNode {
                    id: format!("storage-{}", uuid::Uuid::new_v4()),
                    name: format!("Storage {}", addr),
                    region: "default".to_string(),
                    public_key: "".to_string(),
                    endpoint: addr.clone(),
                })
                .collect::<Vec<_>>();
            
            storage_factory.create_distributed_storage(
                local_storage,
                node_id.clone(),
                storage_nodes,
                config.storage.replication_factor.unwrap_or(3) as usize,
                config.storage.max_hops.unwrap_or(3) as usize,
            )?
        },
        _ => {
            info!("Unknown storage type: {}. Using SQL storage.", args.storage_type);
            storage_factory.create_sql_storage()?
        }
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
