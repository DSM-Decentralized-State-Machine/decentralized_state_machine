mod ip_collector;
mod fraud_detection;
mod geolocation;
mod persistence;
mod cryptography;
mod config;
mod api;
mod types;
mod error;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::SnapshotConfig;
use crate::api::start_api_server;
use crate::persistence::snapshot_store::SnapshotStore;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start IP collection server
    Collect {
        /// Path to configuration file
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
        
        /// Path to GeoIP database
        #[arg(short, long, value_name = "FILE")]
        _geoip: Option<PathBuf>,
        
        /// Listen address:port
        #[arg(short, long, default_value = "0.0.0.0:3000")]
        listen: String,
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
    
    /// Verify dataset integrity
    Verify {
        /// Path to snapshot file
        #[arg(short, long, value_name = "FILE")]
        snapshot: PathBuf,
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
        Commands::Collect { config, _geoip, listen } => {
            info!("Starting IP collection server on {}", listen);
            
            // Load config
            let config_path = config.unwrap_or_else(|| PathBuf::from("config.json"));
            let config = match SnapshotConfig::from_file(&config_path).await {
                Ok(cfg) => cfg,
                Err(e) => {
                    info!("Config file not found or invalid: {}. Using default configuration.", e);
                    SnapshotConfig::default()
                }
            };
            
            // Initialize snapshot store
            let store = SnapshotStore::new(&config.data_dir)
                .await
                .expect("Failed to initialize snapshot store");
            
            // Start API server
            start_api_server(listen, store, config).await?;
        },
        
        Commands::Export { data, format, output } => {
            info!("Exporting IP data from {:?} to {:?} in {} format", data, output, format);
            
            // Load snapshot store
            let store = SnapshotStore::new(&data)
                .await
                .expect("Failed to load snapshot store");
            
            // Export data
            match format.as_str() {
                "json" => persistence::exporter::export_json(&store, &output).await?,
                "csv" => persistence::exporter::export_csv(&store, &output).await?,
                "blake3" => persistence::exporter::export_hash(&store, &output).await?,
                _ => {
                    error!("Unsupported export format: {}", format);
                    return Err("Unsupported export format".into());
                }
            }
            
            info!("Export completed successfully");
        },
        
        Commands::Verify { snapshot } => {
            info!("Verifying snapshot integrity: {:?}", snapshot);
            
            // Verify snapshot
            let result = persistence::verification::verify_snapshot(&snapshot).await?;
            
            if result.is_valid {
                info!("✅ Snapshot verification successful");
                info!("  Snapshot timestamp: {}", result.timestamp);
                info!("  IP addresses: {}", result.ip_count);
                info!("  Countries: {}", result.country_count);
                info!("  Flagged IPs: {}", result.flagged_ips);
                info!("  BLAKE3 Hash: {}", result.hash);
            } else {
                error!("❌ Snapshot verification failed: {}", result.error.unwrap_or_default());
            }
        }
    }
    
    Ok(())
}
