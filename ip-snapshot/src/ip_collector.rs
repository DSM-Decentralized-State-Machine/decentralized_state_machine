use std::net::IpAddr;
use std::sync::Arc;
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};
use std::collections::HashMap;
use blake3::Hasher;
use rand::{thread_rng, Rng};
use hex::encode;
use uuid::Uuid;

use crate::types::{IpEntry, CollectorState, SnapshotMetadata, CollectionStats, CountryStats};
use crate::error::{Result, SnapshotError};
use crate::config::SnapshotConfig;
use crate::persistence::snapshot_store::SnapshotStore;
use crate::geolocation::GeoIpService;
use crate::fraud_detection::FraudDetector;

/// Core IP collector service
pub struct IpCollector {
    /// Collector state
    state: Arc<CollectorState>,
    
    /// Snapshot store
    store: Arc<SnapshotStore>,
    
    /// Configuration
    config: SnapshotConfig,
    
    /// Geolocation service
    geo_service: Option<Arc<GeoIpService>>,
    
    /// Fraud detector
    fraud_detector: Arc<FraudDetector>,
    
    /// Command channel
    command_tx: mpsc::Sender<CollectorCommand>,
    
    /// Command receiver
    command_rx: mpsc::Receiver<CollectorCommand>,
}

/// Collector commands
pub enum CollectorCommand {
    /// Add a new IP
    AddIp(IpAddr),
    
    /// Create a snapshot
    CreateSnapshot,
    
    /// Stop collection
    StopCollection,
    
    /// Start collection
    StartCollection,
    
    /// Get statistics
    GetStats(mpsc::Sender<Result<CollectionStats>>),
    
    /// Clear all data
    Clear,
    
    /// Flush data to disk
    Flush,
    
    /// Shutdown the collector
    Shutdown,
}

impl IpCollector {
    /// Create a new IP collector
    pub async fn new(
        config: SnapshotConfig,
        store: Arc<SnapshotStore>,
    ) -> Result<Self> {
        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(1000);
        
        // Generate verification nonce
        let mut rng = thread_rng();
        let mut nonce_bytes = [0u8; 32];
        rng.fill(&mut nonce_bytes);
        let verification_nonce = encode(nonce_bytes);
        
        // Create metadata
        let metadata = SnapshotMetadata {
            id: Uuid::new_v4().to_string(),
            start_time: Utc::now(),
            end_time: None,
            ip_count: 0,
            country_count: 0,
            flagged_ip_count: 0,
            top_countries: HashMap::new(),
            collection_params: serde_json::to_string(&config).unwrap_or_default(),
            data_hash: String::new(),
            verification_nonce,
        };
        
        // Create state
        let state = Arc::new(CollectorState {
            ip_entries: Arc::new(DashMap::new()),
            known_proxies: Arc::new(DashMap::new()),
            metadata: Arc::new(RwLock::new(metadata)),
            is_collecting: Arc::new(RwLock::new(false)),
        });
        
        // Initialize geo service if configured
        let geo_service = if let Some(geoip_path) = &config.geoip_path {
            match GeoIpService::new(geoip_path).await {
                Ok(service) => Some(Arc::new(service)),
                Err(e) => {
                    warn!("Failed to initialize geo service: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        // Initialize fraud detector
        let fraud_detector = Arc::new(FraudDetector::new(&config));
        
        Ok(Self {
            state,
            store,
            config,
            geo_service,
            fraud_detector,
            command_tx,
            command_rx,
        })
    }
    
    /// Get a command sender
    pub fn command_sender(&self) -> mpsc::Sender<CollectorCommand> {
        self.command_tx.clone()
    }
    
    /// Add an IP address to the collection
    pub async fn add_ip(&self, ip: IpAddr) -> Result<()> {
        // Check if collection is active
        if !*self.state.is_collecting.read() {
            return Err(SnapshotError::Validation("Collection is not active".to_string()));
        }
        
        // Check for max IPs limit
        if let Some(max_ips) = self.config.max_ips {
            if self.state.ip_entries.len() >= max_ips {
                return Err(SnapshotError::Validation("Maximum IP limit reached".to_string()));
            }
        }
        
        // Check if IP already exists
        if let Some(mut entry) = self.state.ip_entries.get_mut(&ip) {
            // Update existing entry
            entry.record_connection();
            
            // Early return
            return Ok(());
        }
        
        // Create new entry
        let mut entry = IpEntry::new(ip);
        
        // Geolocate IP if service is available
        if let Some(geo_service) = &self.geo_service {
            match geo_service.lookup(ip).await {
                Ok(geo_info) => {
                    entry.set_geo(geo_info);
                    
                    // Update country count in metadata
                    if let Some(country_code) = &entry.geo.as_ref().and_then(|g| g.country_code.clone()) {
                        let mut metadata = self.state.metadata.write();
                        
                        // Update top countries
                        metadata.top_countries.entry(country_code.clone())
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                        
                        // Recalculate country count
                        metadata.country_count = metadata.top_countries.len();
                    }
                },
                Err(e) => {
                    warn!("Failed to geolocate IP {}: {}", ip, e);
                }
            }
        }
        
        // Check for proxy/VPN if enabled
        if self.config.detect_proxies {
            match self.fraud_detector.check_ip(ip).await {
                Ok(score) => {
                    entry.set_legitimacy_score(score);
                    
                    // Update flagged IP count in metadata if score is low
                    if score < 50 {
                        let mut metadata = self.state.metadata.write();
                        metadata.flagged_ip_count += 1;
                    }
                },
                Err(e) => {
                    warn!("Failed to check IP {} for fraud: {}", ip, e);
                }
            }
        }
        
        // Collect network metrics if enabled
        if self.config.collect_network_metrics {
            // In a real implementation, this would perform network measurements
            // For now, we'll simulate it with placeholder values
            let mut network = entry.network.clone();
            network.asn = Some(12345); // Placeholder ASN
            entry.set_network(network);
        }
        
        // Update verification hash
        entry.update_verification_hash();
        
        // Add to collection
        self.state.ip_entries.insert(ip, entry);
        
        // Update metadata
        {
            let mut metadata = self.state.metadata.write();
            metadata.ip_count = self.state.ip_entries.len();
        }
        
        Ok(())
    }
    
    /// Start IP collection
    pub async fn start_collection(&self) -> Result<()> {
        // Check if already collecting
        if *self.state.is_collecting.read() {
            return Err(SnapshotError::Validation("Collection is already active".to_string()));
        }
        
        // Reset metadata
        {
            let mut metadata = self.state.metadata.write();
            metadata.start_time = Utc::now();
            metadata.end_time = None;
            metadata.ip_count = 0;
            metadata.country_count = 0;
            metadata.flagged_ip_count = 0;
            metadata.top_countries.clear();
            metadata.data_hash = String::new();
        }
        
        // Clear existing entries if starting fresh
        self.state.ip_entries.clear();
        
        // Set collection state to active
        *self.state.is_collecting.write() = true;
        
        info!("IP collection started");
        
        Ok(())
    }
    
    /// Stop IP collection
    pub async fn stop_collection(&self) -> Result<()> {
        // Check if collecting
        if !*self.state.is_collecting.read() {
            return Err(SnapshotError::Validation("Collection is not active".to_string()));
        }
        
        // Set collection state to inactive
        *self.state.is_collecting.write() = false;
        
        // Update metadata
        {
            let mut metadata = self.state.metadata.write();
            metadata.end_time = Some(Utc::now());
            
            // Calculate data hash
            let hash = self.calculate_data_hash().await?;
            metadata.data_hash = hash;
        }
        
        info!("IP collection stopped");
        
        Ok(())
    }
    
    /// Create a snapshot of the current collection
    pub async fn create_snapshot(&self) -> Result<String> {
        // Check if collection has data
        if self.state.ip_entries.is_empty() {
            return Err(SnapshotError::Validation("No IP addresses collected".to_string()));
        }
        
        // Stop collection if active
        if *self.state.is_collecting.read() {
            self.stop_collection().await?;
        }
        
        // Generate snapshot ID
        let snapshot_id = Uuid::new_v4().to_string();
        
        // Clone metadata
        let metadata = self.state.metadata.read().clone();
        
        // Collect all entries
        let entries: Vec<IpEntry> = self.state.ip_entries.iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        // Store snapshot
        self.store.save_snapshot(&snapshot_id, entries, metadata).await?;
        
        info!("Created snapshot {} with {} IPs", snapshot_id, self.state.ip_entries.len());
        
        Ok(snapshot_id)
    }
    
    /// Calculate the BLAKE3 hash of all data
    async fn calculate_data_hash(&self) -> Result<String> {
        let mut hasher = Hasher::new();
        
        // Add all entries to the hash in a deterministic order
        let mut ips: Vec<IpAddr> = self.state.ip_entries.iter()
            .map(|entry| *entry.key())
            .collect();
        
        // Sort IPs for deterministic ordering
        ips.sort_unstable();
        
        for ip in ips {
            if let Some(entry) = self.state.ip_entries.get(&ip) {
                // Add verification hash of each entry
                hasher.update(entry.verification_hash.as_bytes());
            }
        }
        
        // Add verification nonce - release lock before any await
        let nonce;
        {
            let metadata = self.state.metadata.read();
            nonce = metadata.verification_nonce.clone();
        }
        hasher.update(nonce.as_bytes());
        
        // Return hash as hex string
        Ok(encode(hasher.finalize().as_bytes()))
    }
    
    /// Get collection statistics
    pub async fn get_stats(&self) -> Result<CollectionStats> {
        let metadata = self.state.metadata.read();
        
        // Calculate country statistics
        let mut country_map: HashMap<String, (String, usize, usize)> = HashMap::new();
        
        for entry in self.state.ip_entries.iter() {
            if let Some(geo) = &entry.geo {
                if let Some(country_code) = &geo.country_code {
                    let country_name = geo.country_name.clone().unwrap_or_else(|| country_code.clone());
                    let is_flagged = entry.legitimacy_score < 50;
                    
                    country_map.entry(country_code.clone())
                        .and_modify(|(_, count, flagged)| {
                            *count += 1;
                            if is_flagged {
                                *flagged += 1;
                            }
                        })
                        .or_insert((country_name, 1, if is_flagged { 1 } else { 0 }));
                }
            }
        }
        
        // Convert to country stats vector
        let mut countries: Vec<CountryStats> = country_map.iter()
            .map(|(code, (name, count, flagged))| {
                CountryStats {
                    country_code: code.clone(),
                    country_name: name.clone(),
                    ip_count: *count,
                    flagged_ip_count: *flagged,
                    percentage: *count as f64 / self.state.ip_entries.len() as f64 * 100.0,
                }
            })
            .collect();
        
        // Sort by IP count
        countries.sort_by(|a, b| b.ip_count.cmp(&a.ip_count));
        
        // Collect ASN statistics
        let mut asn_stats: HashMap<u32, usize> = HashMap::new();
        
        for entry in self.state.ip_entries.iter() {
            if let Some(asn) = entry.network.asn {
                *asn_stats.entry(asn).or_insert(0) += 1;
            }
        }
        
        // Calculate duration
        let last_update = metadata.end_time.unwrap_or_else(Utc::now);
        let duration = last_update.signed_duration_since(metadata.start_time);
        
        Ok(CollectionStats {
            total_ips: self.state.ip_entries.len(),
            unique_ips: self.state.ip_entries.len(),
            flagged_ips: metadata.flagged_ip_count,
            countries,
            asn_stats,
            start_time: metadata.start_time,
            last_update,
            duration_seconds: duration.num_seconds() as u64,
        })
    }
    
    /// Clear all collected data
    pub async fn clear(&self) -> Result<()> {
        // Check if collecting
        if *self.state.is_collecting.read() {
            return Err(SnapshotError::Validation("Cannot clear data while collection is active".to_string()));
        }
        
        // Clear all entries
        self.state.ip_entries.clear();
        self.state.known_proxies.clear();
        
        // Reset metadata
        {
            let mut metadata = self.state.metadata.write();
            metadata.ip_count = 0;
            metadata.country_count = 0;
            metadata.flagged_ip_count = 0;
            metadata.top_countries.clear();
            metadata.data_hash = String::new();
        }
        
        info!("Cleared all collected data");
        
        Ok(())
    }
    
    /// Flush data to disk
    pub async fn flush(&self) -> Result<()> {
        // This would normally persist intermediate state
        // For now, just create a snapshot
        if !self.state.ip_entries.is_empty() {
            let snapshot_id = self.create_snapshot().await?;
            info!("Flushed data to snapshot {}", snapshot_id);
        }
        
        Ok(())
    }
    
    /// Run the collector service
    pub async fn run(mut self) {
        info!("IP collector service started");
        
        // Start collection if auto-start is enabled
        if self.config.auto_start_collection {
            if let Err(e) = self.start_collection().await {
                error!("Failed to auto-start collection: {}", e);
            }
        }
        
        // Create a scheduled snapshot task if interval is non-zero
        let snapshot_interval = self.config.snapshot_interval_seconds;
        let snapshot_tx = self.command_tx.clone();
        
        let _snapshot_task = if snapshot_interval > 0 {
            tokio::spawn(async move {
                let interval = tokio::time::Duration::from_secs(snapshot_interval);
                let mut ticker = tokio::time::interval(interval);
                
                loop {
                    ticker.tick().await;
                    
                    // Send snapshot command
                    if let Err(e) = snapshot_tx.send(CollectorCommand::CreateSnapshot).await {
                        error!("Failed to send snapshot command: {}", e);
                        break;
                    }
                }
            })
        } else {
            tokio::spawn(async {})
        };
        
        // Main command loop
        while let Some(cmd) = self.command_rx.recv().await {
            match cmd {
                CollectorCommand::AddIp(ip) => {
                    if let Err(e) = self.add_ip(ip).await {
                        warn!("Failed to add IP {}: {}", ip, e);
                    }
                },
                CollectorCommand::CreateSnapshot => {
                    match self.create_snapshot().await {
                        Ok(id) => debug!("Created snapshot {}", id),
                        Err(e) => error!("Failed to create snapshot: {}", e),
                    }
                },
                CollectorCommand::StopCollection => {
                    if let Err(e) = self.stop_collection().await {
                        error!("Failed to stop collection: {}", e);
                    }
                },
                CollectorCommand::StartCollection => {
                    if let Err(e) = self.start_collection().await {
                        error!("Failed to start collection: {}", e);
                    }
                },
                CollectorCommand::GetStats(tx) => {
                    let result = self.get_stats().await;
                    if let Err(e) = tx.send(result).await {
                        error!("Failed to send stats: {}", e);
                    }
                },
                CollectorCommand::Clear => {
                    if let Err(e) = self.clear().await {
                        error!("Failed to clear data: {}", e);
                    }
                },
                CollectorCommand::Flush => {
                    if let Err(e) = self.flush().await {
                        error!("Failed to flush data: {}", e);
                    }
                },
                CollectorCommand::Shutdown => {
                    info!("Shutting down IP collector service");
                    
                    // Stop collection if active
                    if *self.state.is_collecting.read() {
                        if let Err(e) = self.stop_collection().await {
                            error!("Failed to stop collection during shutdown: {}", e);
                        }
                    }
                    
                    // Flush data
                    if let Err(e) = self.flush().await {
                        error!("Failed to flush data during shutdown: {}", e);
                    }
                    
                    break;
                }
            }
        }
        
        info!("IP collector service stopped");
    }
}
