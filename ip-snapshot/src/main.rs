mod config;
mod error;
mod geolocation;
mod ip_collector;
mod persistence;
mod types;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use std::sync::Arc;
use crate::config::SnapshotConfig;
use crate::persistence::snapshot_store::SnapshotStore;
use crate::types::SnapshotMetadata;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start IP scanning and collection
    Scan {
        /// Path to configuration file
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Path to GeoIP database
        #[arg(short, long, value_name = "FILE")]
        geoip: Option<PathBuf>,
        
        /// Number of concurrent scans
        #[arg(short, long, default_value = "250")]
        concurrency: Option<usize>,
        
        /// Output directory for collected data
        #[arg(short, long, value_name = "DIR", default_value = "data")]
        output: PathBuf,
    },

    /// Export collected IP data
    Export {
        /// Path to snapshot data directory
        #[arg(short, long, value_name = "DIR")]
        data: PathBuf,

        /// Output format (json, csv, blake3)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            config,
            geoip,
            concurrency,
            output,
        } => {
            info!("Starting IP scanning");

            // Load config
            let config_path = config.unwrap_or_else(|| PathBuf::from("config.json"));
            let mut config = match SnapshotConfig::from_file(&config_path).await {
                Ok(cfg) => cfg,
                Err(e) => {
                    info!(
                        "Config file not found or invalid: {}. Using default configuration.",
                        e
                    );
                    SnapshotConfig::default()
                }
            };
            
            // Set GeoIP database path from command line if provided
            if let Some(path) = geoip {
                config.geoip_path = Some(path);
            }
            
            // Set output directory
            config.data_dir = output;

            // Initialize snapshot store
            let store = SnapshotStore::new(&config.data_dir)
                .await
                .expect("Failed to initialize snapshot store");
                
            // Create a local task set for the collector
            let local = tokio::task::LocalSet::new();
            
            // Initialize IP collector
            let collector = ip_collector::IpCollector::new(config.clone(), Arc::new(store.clone())).await
                .expect("Failed to initialize IP collector");
                
            // Get command sender
            let collector_tx = collector.command_sender();
            
            // Run the collector in the background
            local.spawn_local(async move {
                collector.run().await;
            });
            
            // Send commands to start collection and scanning
            collector_tx.send(ip_collector::CollectorCommand::StartCollection).await
                .expect("Failed to start collection");
                
            collector_tx.send(ip_collector::CollectorCommand::StartScanning { 
                concurrency 
            }).await
                .expect("Failed to start scanning");
                
            info!("IP scanning started. Collecting residential IPs with even global distribution.");
            info!("Press Ctrl+C to stop scanning and save results.");
            
            // Create a signal handler for graceful shutdown
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
            
            // Handle Ctrl+C
            let tx = shutdown_tx.clone();
            tokio::spawn(async move {
                match tokio::signal::ctrl_c().await {
                    Ok(()) => {
                        info!("Received Ctrl+C, stopping IP scan...");
                        let _ = tx.send(()).await;
                    },
                    Err(e) => error!("Error setting up Ctrl+C handler: {}", e),
                }
            });
            
            // Wait for shutdown signal
            local.run_until(async move {
                shutdown_rx.recv().await;
                
                // Stop scanning
                if let Err(e) = collector_tx.send(ip_collector::CollectorCommand::StopScanning).await {
                    error!("Failed to stop scanning: {}", e);
                }
                
                // Create snapshot
                if let Err(e) = collector_tx.send(ip_collector::CollectorCommand::CreateSnapshot {
                    id: format!("snapshot-{}", chrono::Utc::now().timestamp()),
                    description: Some("Automatic scan of residential IPs with global distribution".to_string()),
                }).await {
                    error!("Failed to create snapshot: {}", e);
                }

                // Stop collection
                if let Err(e) = collector_tx.send(ip_collector::CollectorCommand::StopCollection).await {
                    error!("Failed to stop collection: {}", e);
                }

                // Allow collector time to persist the snapshot
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                info!("IP scan completed. Results saved to {}", config.data_dir.display());
                Ok::<(), Box<dyn std::error::Error>>(())
            }).await?;
        }

        Commands::Export {
            data,
            format,
            output,
        } => {
            info!(
                "Exporting IP data from {:?} to {:?} in {} format",
                data, output, format
            );

            // Load snapshot store
            let store = SnapshotStore::new(&data)
                .await
                .expect("Failed to load snapshot store");
                
            // If no snapshots exist but we have IPs in memory, create one
            let snapshots = store.list_snapshots();
            let ip_count = store.get_ip_count();
            
            if snapshots.is_empty() && ip_count > 0 {
                info!("No snapshots found but {} IPs in memory. Creating snapshot.", ip_count);
                
                // Create a snapshot with current timestamp
                let snapshot_id = format!("snapshot_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
                
                // Build metadata
                let metadata = SnapshotMetadata {
                    id: snapshot_id.clone(),
                    description: "Auto-generated snapshot during export".to_string(),
                    created_at: chrono::Utc::now(),
                    ip_count: 0, // Will be updated by the store
                    country_count: 0, // Will be updated by the store
                    start_time: chrono::Utc::now().checked_sub_signed(chrono::Duration::minutes(10)).unwrap_or(chrono::Utc::now()),
                    end_time: Some(chrono::Utc::now()),
                    flagged_ip_count: 0,
                    top_countries: std::collections::HashMap::new(),
                    collection_params: "Auto-export collection".to_string(),
                    data_hash: uuid::Uuid::new_v4().to_string(),
                };
                
                // Create the snapshot
                match store.create_snapshot(&snapshot_id, metadata).await {
                    Ok(count) => {
                        info!("Created snapshot {} with {} IPs", snapshot_id, count);
                    }
                    Err(e) => {
                        error!("Failed to create snapshot: {}", e);
                    }
                }
            }

            // Export data
            match format.as_str() {
                "json" => persistence::exporter::export_json(&store, &output).await?,
                "csv" => persistence::exporter::export_csv(&store, &output).await?,
                _ => {
                    error!("Unsupported export format: {}", format);
                    return Err("Unsupported export format".into());
                }
            }

            info!("Export completed successfully");
        }


    }

    Ok(())
}
