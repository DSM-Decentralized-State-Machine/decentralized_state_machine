use actix_web::{web, App, HttpServer};
use dsm_ethereum_bridge::dsm_anchor_handler::submit_anchor;
use dsm_ethereum_bridge::state_management::PersistentStateManager;
use dsm_storage_node::types::StorageNode;
use std::env;
use std::sync::Arc;
use tracing::log::{error, info};
use tracing_subscriber::FmtSubscriber;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set default subscriber");

    // Get DB path from environment or use default
    let db_path =
        env::var("DSM_DB_PATH").unwrap_or_else(|_| "./data/dsm-eth-bridge.db".to_string());
    info!("Using database path: {}", db_path);

    // Read storage node endpoints from environment (comma separated)
    // Format: "id1:http://node1:8080,id2:http://node2:8080"
    let storage_nodes_str = env::var("DSM_STORAGE_NODES").unwrap_or_else(|_| "".to_string());
    let storage_nodes = if !storage_nodes_str.is_empty() {
        storage_nodes_str
            .split(',')
            .filter_map(|node_str| {
                let parts: Vec<&str> = node_str.split(':').collect();
                if parts.len() >= 2 {
                    Some(StorageNode {
                        id: parts[0].to_string(),
                        name: parts[0].to_string(), // Use ID as name
                        region: "global".to_string(),
                        public_key: "".to_string(), // Will be populated later if needed
                        endpoint: format!("{}:{}", parts[1], parts.get(2).unwrap_or(&"8080")),
                    })
                } else {
                    error!("Invalid storage node format: {}", node_str);
                    None
                }
            })
            .collect::<Vec<StorageNode>>()
    } else {
        Vec::new()
    };

    let state_manager = if !storage_nodes.is_empty() {
        info!(
            "Initializing state manager with {} storage nodes",
            storage_nodes.len()
        );
        for node in &storage_nodes {
            info!("  Node: {} at {}", node.id, node.endpoint);
        }

        // Create state manager with distributed storage
        match PersistentStateManager::with_distributed_storage(
            &db_path,
            storage_nodes,
            3, // Replication factor
        )
        .await
        {
            Ok(manager) => {
                info!("Successfully initialized state manager with distributed storage");
                Arc::new(manager)
            }
            Err(e) => {
                error!("Failed to initialize distributed storage: {:?}", e);
                // Fallback to local storage
                match PersistentStateManager::new(&db_path).await {
                    Ok(manager) => Arc::new(manager),
                    Err(e) => {
                        error!("Failed to initialize local storage: {:?}", e);
                        panic!("Could not initialize any storage backend");
                    }
                }
            }
        }
    } else {
        info!("No storage nodes configured, using local storage only");
        match PersistentStateManager::new(&db_path).await {
            Ok(manager) => Arc::new(manager),
            Err(e) => {
                error!("Failed to initialize local storage: {:?}", e);
                panic!("Could not initialize storage");
            }
        }
    };

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    println!("Starting DSM anchor server on port {}...", port);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state_manager.clone())) // Share state manager across handlers
            .service(submit_anchor) // POST /submit-anchor
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
