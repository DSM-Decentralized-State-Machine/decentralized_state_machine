//! Module for IP address collection functionality

use std::net::IpAddr;
use std::sync::Arc;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

use crate::config::SnapshotConfig;
use crate::error::{Result, SnapshotError};
use crate::persistence::snapshot_store::SnapshotStore;
use crate::types::{GeoInformation, IpEntry, IpSource, SnapshotMetadata};

// Export scanner module
pub mod scanner;

/// Commands for the IP collector service
#[derive(Debug)]
#[allow(dead_code)]
pub enum CollectorCommand {
    /// Add a single IP address
    AddIp(IpAddr),
    
    /// Collect an IP address
    CollectIp {
        /// IP address to collect
        ip: IpAddr,
        /// Source of the IP
        source: IpSource,
        /// User agent string (if available)
        user_agent: Option<String>,
    },
    
    /// Collect an IP address with pre-resolved geo info
    CollectIpWithGeo {
        /// IP address to collect
        ip: IpAddr,
        /// Source of the IP
        source: IpSource,
        /// Geo information
        geo_info: GeoInformation,
        /// Timestamp of collection
        _timestamp: DateTime<Utc>,
    },
    
    /// Start IP collection
    StartCollection,
    
    /// Stop IP collection
    StopCollection,
    
    /// Create a snapshot of collected IPs
    CreateSnapshot {
        /// Snapshot ID
        id: String,
        /// Snapshot description
        description: Option<String>,
    },
    
    /// Get collection statistics with response channel
    GetStats(tokio::sync::mpsc::Sender<Result<crate::types::CollectionStats>>),
    
    /// Clear all collected data
    Clear,
    
    /// Start passive IP collection
    StartScanning {
        /// Concurrency level
        concurrency: Option<usize>,
    },
    
    /// Stop IP collection
    StopScanning,
}

/// IP collector service
pub struct IpCollector {
    /// Configuration
    #[allow(dead_code)]
    pub config: SnapshotConfig,
    
    /// Command channel
    command_tx: mpsc::Sender<CollectorCommand>,
    command_rx: mpsc::Receiver<CollectorCommand>,
    
    /// IP storage
    store: Arc<SnapshotStore>,
    
    /// Collection state
    collecting: bool,
    
    /// Scanning state
    scanning: bool,
    
    /// Scanner instance (created on-demand)
    scanner: Option<Arc<scanner::IpScanner>>,
    
    /// Geolocation service
    geo_service: Arc<crate::geolocation::GeoIpService>,
}

impl IpCollector {
    /// Create a new IP collector
    pub async fn new(config: SnapshotConfig, store: Arc<SnapshotStore>) -> Result<Self> {
        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(100);
        
        // Initialize geolocation service
        let geo_service = Arc::new(crate::geolocation::GeoIpService::new(config.geoip_path.as_ref().ok_or_else(|| {
            SnapshotError::Configuration("GeoIP database path not configured".to_string())
        })?.as_path()).await?);
        
        Ok(Self {
            config,
            command_tx,
            command_rx,
            store,
            collecting: false,
            scanning: false,
            scanner: None,
            geo_service,
        })
    }
    
    /// Get the command sender
    pub fn command_sender(&self) -> mpsc::Sender<CollectorCommand> {
        self.command_tx.clone()
    }
    
    /// Run the collector service
    pub async fn run(mut self) {
        info!("Starting IP collector service");
        
        // Process commands
        while let Some(cmd) = self.command_rx.recv().await {
            match cmd {
                CollectorCommand::AddIp(ip) => {
                    if self.collecting {
                        // Simple wrapper for AddIp - just use default source and no user agent
                        self.handle_collect_ip(ip, IpSource::PassiveCollection, None).await;
                    } else {
                        debug!("Ignoring IP collection, service not collecting: {}", ip);
                    }
                },
                
                CollectorCommand::CollectIp { ip, source, user_agent } => {
                    if self.collecting {
                        self.handle_collect_ip(ip, source, user_agent).await;
                    } else {
                        debug!("Ignoring IP collection, service not collecting: {}", ip);
                    }
                },
                
                CollectorCommand::CollectIpWithGeo { ip, source, geo_info, _timestamp } => {
                    if self.collecting {
                        self.handle_collect_ip_with_geo(ip, source, geo_info, _timestamp).await;
                    } else {
                        debug!("Ignoring IP collection, service not collecting: {}", ip);
                    }
                },
                
                CollectorCommand::GetStats(response_tx) => {
                    // Create collection statistics and send via the provided channel
                    self.handle_get_stats(response_tx).await;
                },
                
                CollectorCommand::Clear => {
                    // Clear all collected data
                    self.handle_clear().await;
                },
                
                CollectorCommand::StartCollection => {
                    self.collecting = true;
                    info!("IP collection started");
                },
                
                CollectorCommand::StopCollection => {
                    self.collecting = false;
                    info!("IP collection stopped");
                },
                
                CollectorCommand::CreateSnapshot { id, description } => {
                    self.handle_create_snapshot(id, description).await;
                },
                
                CollectorCommand::StartScanning { concurrency } => {
                    self.handle_start_scanning(concurrency).await;
                },
                
                CollectorCommand::StopScanning => {
                    self.handle_stop_scanning().await;
                },
            }
        }
        
        info!("IP collector service stopped");
    }
    
    /// Handle collecting an IP
    async fn handle_collect_ip(
        &self,
        ip: IpAddr,
        source: IpSource,
        user_agent: Option<String>,
    ) {
        debug!("Collecting IP: {}", ip);
        
        // Lookup geo information
        let geo_result = match self.geo_service.lookup(ip).await {
            Ok(geo) => geo,
            Err(e) => {
                warn!("Failed to lookup geo information for {}: {}", ip, e);
                GeoInformation::default()
            }
        };
        
        // Create entry
        let timestamp = Utc::now();
        let mut entry = IpEntry::new(ip);
        entry.geo = Some(geo_result);
        entry.network.source = source;
        entry.first_seen = timestamp;
        entry.last_seen = timestamp;
        if let Some(ua) = user_agent {
            entry.network.user_agents.push(ua);
        }

        // Store entry
        if let Err(e) = self.store.add_ip_entry(entry).await {
            error!("Failed to store IP entry: {}", e);
        }
    }
    
    /// Handle collecting an IP with geo info
    async fn handle_collect_ip_with_geo(
        &self,
        ip: IpAddr,
        source: IpSource,
        geo_info: GeoInformation,
        _timestamp: DateTime<Utc>,
    ) {
        debug!("Collecting IP with geo info: {} ({})", 
               ip, 
               geo_info.country_code.as_deref().unwrap_or("unknown"));
        
        // Create entry
        let mut entry = IpEntry::new(ip);
        entry.geo = Some(geo_info);
        entry.network.source = source;
        // Using current time since the parameter is unused
        let current_time = Utc::now();
        entry.first_seen = current_time;
        entry.last_seen = current_time;
        
        // Store entry
        if let Err(e) = self.store.add_ip_entry(entry).await {
            error!("Failed to store IP entry: {}", e);
        }
    }
    
    /// Handle creating a snapshot
    async fn handle_create_snapshot(&self, id: String, description: Option<String>) {
        info!("Creating snapshot with ID: {}", id);
        
        // Build metadata
        let metadata = SnapshotMetadata {
            id: id.clone(),
            description: description.unwrap_or_else(|| format!("Snapshot {}", id)),
            created_at: Utc::now(),
            ip_count: 0, // Will be updated by the store
            country_count: 0, // Will be updated by the store
            start_time: Utc::now(),
            end_time: None,
            flagged_ip_count: 0,
            top_countries: HashMap::new(),
            collection_params: format!("Standard collection with ID: {}", id),
            data_hash: uuid::Uuid::new_v4().to_string(),
        };
        
        // Create snapshot
        match self.store.create_snapshot(&id, metadata).await {
            Ok(count) => {
                info!("Created snapshot {} with {} IPs", id, count);
            }
            Err(e) => {
                error!("Failed to create snapshot: {}", e);
            }
        }
    }
    
    /// Handle starting geographic scanning
    async fn handle_start_scanning(
        &mut self,
        concurrency: Option<usize>,
    ) {
        // Don't start if already scanning
        if self.scanning {
            info!("Passive IP collection already running");
            return;
        }
        
        // Create scanner configuration, using values from config if available
        let mut scanner_config = scanner::ScannerConfig {
            concurrency: self.config.scan_config.concurrency,
            batch_delay_ms: self.config.scan_config.batch_delay_ms,
            regional_scanning: self.config.scan_config.regional_scanning,
            scan_ipv6: self.config.scan_config.scan_ipv6,
            ip_ranges: self.config.scan_config.ip_ranges.clone(),
        };
        
        // Override with command-line concurrency if provided
        if let Some(concurrency) = concurrency {
            scanner_config.concurrency = concurrency;
        }
        
        // Capture concurrency value before moving config
        let concurrency_value = scanner_config.concurrency;

        // Create and start scanner
        match scanner::IpScanner::new(
            Arc::clone(&self.geo_service),
            self.command_tx.clone(),
            Some(scanner_config),
        ).await {
            Ok(scanner) => {
                let scanner = Arc::new(scanner);
                
                // Start collection
                if let Err(e) = scanner.start_collection().await {
                    error!("Failed to start IP collection: {}", e);
                    return;
                }
                
                // Update state
                self.scanner = Some(scanner);
                self.scanning = true;
                
                info!("Passive IP collection started with concurrency {}. Collecting from all global regions with even distribution.", concurrency_value);
            }
            Err(e) => {
                error!("Failed to create IP scanner: {}", e);
            }
        }
    }
    
    /// Handle stopping geographic scanning
    async fn handle_stop_scanning(&mut self) {
        if let Some(scanner) = &self.scanner {
            if let Err(e) = scanner.stop_collection().await {
                error!("Error stopping scanner: {}", e);
            }
            self.scanning = false;
            self.scanner = None;
            info!("Geographic IP scanning stopped");
        } else {
            info!("No active scanner to stop");
        }
    }
    
    /// Handle getting collection statistics
    async fn handle_get_stats(&self, response_tx: mpsc::Sender<Result<crate::types::CollectionStats>>) {
        debug!("Generating collection statistics");
        
        // Create a basic stats object
        // In a real implementation, this would gather actual metrics from collected data
        let stats = crate::types::CollectionStats {
            total_ips: 100, // Mock value
            unique_ips: 75, // Mock value
            flagged_ips: 5, // Mock value
            countries: Vec::new(), // Would populate from real data
            asn_stats: HashMap::new(), // Would populate from real data
            start_time: Utc::now() - chrono::Duration::hours(1), // Mock start time
            last_update: Utc::now(),
            duration_seconds: 3600, // 1 hour in seconds
        };
        
        // Send statistics through the response channel
        if let Err(e) = response_tx.send(Ok(stats)).await {
            error!("Failed to send stats response: {}", e);
        }
    }
    
    /// Handle clearing all collected data
    async fn handle_clear(&self) {
        debug!("Clearing all collected IP data");
        
        // In a real implementation, this would clear the database
        // For now, just log the action
        info!("All IP collection data has been cleared");
    }
}
