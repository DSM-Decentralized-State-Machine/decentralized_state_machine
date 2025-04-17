use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio::sync::mpsc;
use tracing::{info, debug, error, warn};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use ip_network::Ipv4Network;
use cidr::Ipv4Cidr;
use futures::stream::{self, StreamExt};

use crate::error::Result;
use crate::geolocation::GeoIpService;
use crate::ip_collector::CollectorCommand;
use crate::types::{GeoInformation, IpSource};

/// IP Scanner configuration
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    /// IP ranges to scan
    pub ip_ranges: Vec<String>,
    
    /// Whether to scan IPv6 addresses
    pub scan_ipv6: bool,
    
    /// Whether to use regional-based scanning
    pub regional_scanning: bool,
    /// Maximum number of concurrent collection operations
    pub concurrency: usize,
    
    /// Processing delay between batches (in milliseconds)
    pub batch_delay_ms: u64,
}

// Common residential IP prefixes for different regions
lazy_static::lazy_static! {
    static ref REGIONAL_IP_RANGES: Vec<(String, &'static str)> = vec![
        // North America
        ("24.0.0.0/8".to_string(), "NA"),      // Comcast, Time Warner
        ("65.0.0.0/8".to_string(), "NA"),     // AT&T, Verizon
        ("75.0.0.0/8".to_string(), "NA"),     // Comcast
        ("174.0.0.0/8".to_string(), "NA"),    // Cogent, various ISPs
        
        // Europe
        ("78.0.0.0/8".to_string(), "EU"),     // European residential
        ("81.0.0.0/8".to_string(), "EU"),     // European ISPs
        ("82.0.0.0/8".to_string(), "EU"),     // UK, Germany, others
        ("90.0.0.0/8".to_string(), "EU"),     // France, Italy
        
        // Asia
        ("114.0.0.0/8".to_string(), "AS"),    // Japan, China
        ("116.0.0.0/8".to_string(), "AS"),    // Korea, Japan
        ("118.0.0.0/8".to_string(), "AS"),    // China, Malaysia, other Asia
        ("122.0.0.0/8".to_string(), "AS"),    // Various Asia-Pacific
        
        // South America
        ("177.0.0.0/8".to_string(), "SA"),    // Brazil
        ("186.0.0.0/8".to_string(), "SA"),    // Argentina, Colombia
        ("189.0.0.0/8".to_string(), "SA"),    // Brazil, others
        
        // Africa
        ("154.0.0.0/8".to_string(), "AF"),    // South Africa, various
        ("197.0.0.0/8".to_string(), "AF"),    // Various African regions
        
        // Oceania
        ("58.0.0.0/8".to_string(), "OC"),     // Australia, NZ
        ("59.0.0.0/8".to_string(), "OC"),     // Australia, NZ
        ("60.0.0.0/8".to_string(), "OC")      // Australia
    ];
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            ip_ranges: REGIONAL_IP_RANGES.iter()
                .map(|(range, _)| range.clone())
                .collect(),
            scan_ipv6: false,
            regional_scanning: true,
            concurrency: 250,
            batch_delay_ms: 2000,
        }
    }
}

/// IP Scanner for collecting IPs from specific geographical regions
pub struct IpScanner {
    /// GeoIP service for reverse lookups
    geoip: Arc<GeoIpService>,
    
    /// Command sender for the collector
    collector_tx: tokio::sync::mpsc::Sender<CollectorCommand>,
    
    /// Scanner configuration
    config: ScannerConfig,
    
    /// Collection rate limiter
    scan_semaphore: Arc<Semaphore>,

    /// Stop signal channel
    stop_tx: mpsc::Sender<bool>,
}

impl IpScanner {
    /// Create a new IP scanner
    pub async fn new(
        geoip: Arc<GeoIpService>,
        collector_tx: tokio::sync::mpsc::Sender<CollectorCommand>,
        config: Option<ScannerConfig>,
    ) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        // Initialize semaphore for scan rate limiting
        let scan_semaphore = Arc::new(Semaphore::new(config.concurrency));
        
        // Create a stop signal channel
        let (stop_tx, _stop_rx) = mpsc::channel::<bool>(1);

        Ok(Self {
            geoip,
            collector_tx,
            config,
            scan_semaphore,
            stop_tx,
        })
    }
    
    /// Start passive IP collection
    pub async fn start_collection(&self) -> Result<()> {
        info!("Starting passive IP collection with concurrency: {}", self.config.concurrency);
        
        // Clone needed values for the task
        let semaphore = Arc::clone(&self.scan_semaphore);
        let collector_tx = self.collector_tx.clone();
        let geoip: Arc<GeoIpService> = Arc::clone(&self.geoip);
        let config = self.config.clone();
        
        // Create a thread-safe counter for successful collections
        let successful_collection_counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = successful_collection_counter.clone();
        
        // Create broadcasters for stop signals - a more sophisticated approach than simple channels
        // that allows multiple receivers to listen to the same signals
        let (main_stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        
        // Create a stop channel that will be used by the scanner task
        let mut scanner_rx = main_stop_tx.subscribe();
        
        // Store stop sender for later use in stop_collection method
        let stop_self_tx = self.stop_tx.clone();
        
        // Set up initial watcher task to relay stop signals from self.stop_tx to the main broadcast
        let main_stop_tx_clone = main_stop_tx.clone();
        tokio::spawn(async move {
            if (stop_self_tx.send(true).await).is_ok() {
                // Relay stop signal to all listeners
                let _ = main_stop_tx_clone.send(());
            }
        });
        
        // Spawn the main scanning task
        let _scan_handle = tokio::task::spawn(async move {
            // Create a thread-safe random number generator with secure seed
            let rng = StdRng::from_entropy();
            // Use Arc to safely share the RNG across tasks
            let rng = Arc::new(tokio::sync::Mutex::new(rng));
            let mut batch_count = 0;
            
            loop {
                // Check if we should stop - try_recv() doesn't take mut self
                if scanner_rx.try_recv().is_ok() {
                    info!("Stopping IP scanning");
                    break;
                }
                
                batch_count += 1;
                let mut tasks = Vec::new();
                
                // Process IP ranges with regional distribution
                let ranges = if config.regional_scanning {
                    // Select IPs from different regions for balanced global coverage
                    let mut selected_ranges = Vec::new();
                    let regions = ["NA", "EU", "AS", "SA", "AF", "OC"];
                    
                    // Select at least one range from each region
                    for region in regions.iter() {
                        let region_ranges: Vec<_> = REGIONAL_IP_RANGES.iter()
                            .filter(|(_, r)| r == region)
                            .collect();
                        
                        if !region_ranges.is_empty() {
                            let idx = {
                                let mut rng_lock = rng.lock().await;
                                rng_lock.gen_range(0..region_ranges.len())
                            };
                            selected_ranges.push(region_ranges[idx].0.clone());
                        }
                    }
                    
                    selected_ranges
                } else {
                    // Use the configured ranges directly
                    config.ip_ranges.clone()
                };
                
                // For each range, generate random IPs within that range
                for range in ranges {
                    match range.parse::<Ipv4Cidr>() {
                        Ok(cidr) => {
                            let network = Ipv4Network::new(cidr.first_address(), cidr.network_length())
                                .expect("Invalid IP network");
                            
                            // Generate random IPs within this range
                            let ip_count = 20; // Number of IPs to scan per range per batch
                            for _ in 0..ip_count {
                                // Skip the first and last IPs (network and broadcast)
                                let host_bits = network.netmask().leading_ones();
                                
                                // Handle large networks safely to avoid overflow
                                // For /8 networks and similar, this calculation would overflow
                                let max_range: u32 = if host_bits <= 24 {
                                    // Just use a reasonable range for large networks
                                    1_000_000
                                } else {
                                    // For smaller networks, calculate actual size
                                    let shift = 32 - host_bits;
                                    if shift >= 31 { 1_000_000 } else { (1u32 << shift) - 2 }
                                };
                                
                                if max_range <= 2 {
                                    continue; // Skip tiny networks
                                }
                                
                                let random_host = {
                                    let mut rng_lock = rng.lock().await;
                                    rng_lock.gen_range(1..max_range.min(1000000))
                                };
                                let network_addr_u32: u32 = network.network_address().into();
                                let ip_int: u32 = network_addr_u32 + random_host;
                                let ip = IpAddr::V4(Ipv4Addr::from(ip_int));
                                
                                let sem_permit = semaphore.clone().acquire_owned().await;
                                let geoip_clone = geoip.clone();
                                let tx_clone = collector_tx.clone();
                                let counter = successful_collection_counter.clone();
                                
                                // Process this IP
                                let task = tokio::spawn(async move {
                                    let _permit = sem_permit;
                                    
                                    // Get GeoIP information without failing on lookup errors
                                    let geo_info = match geoip_clone.lookup(ip).await {
                                        Ok(geo_info) => geo_info,
                                        Err(e) => {
                                            // Log but continue with default geo info
                                            warn!("GeoIP lookup silently recovered for {}: {}", ip, e);
                                            GeoInformation {
                                                country_code: Some("XX".to_string()),
                                                country_name: Some("Unknown".to_string()),
                                                city: None,
                                                coordinates: None,
                                                continent_code: None,
                                                time_zone: None,
                                            }
                                        }
                                    };
                                    
                                    // Only collect residential or unknown IPs
                                    let is_residential = Self::is_likely_residential(&geo_info);
                                    if is_residential {
                                        // Extract country code before moving geo_info
                                        let country_code = geo_info.country_code.as_deref().unwrap_or("unknown").to_string();
                                        
                                        // Use CollectIpWithGeo for explicit geo info
                                        if let Err(e) = tx_clone.send(CollectorCommand::CollectIpWithGeo {
                                            ip,
                                            source: IpSource::PassiveCollection,
                                            geo_info,
                                            _timestamp: chrono::Utc::now(),
                                        }).await {
                                            error!("Failed to send IP to collector: {}", e);
                                        } else {
                                            counter.fetch_add(1, Ordering::SeqCst);
                                            debug!("Added residential IP: {} ({})", ip, country_code);
                                        }
                                    }
                                });
                                
                                tasks.push(task);
                            }
                        },
                        Err(e) => {
                            error!("Invalid IP range: {} - {}", range, e);
                        }
                    }
                }
                
                // Process IPv6 if enabled
                if config.scan_ipv6 {
                    // Generate some random IPv6 addresses in common residential ranges
                    let ipv6_ranges = [
                        "2001::/32",  // Teredo tunneling
                        "2002::/16",  // 6to4
                        "2600::/16",  // Comcast
                        "2001:4860::/32", // Google Fiber
                        "2a00::/16"   // European providers
                    ];
                    
                    for _ in 0..10 { // Fewer IPv6 addresses since they're less common
                        let mut ipv6_segments = [0u16; 8];
                        {
                            let mut rng_lock = rng.lock().await;
                            for segment in &mut ipv6_segments {
                                *segment = rng_lock.gen();
                            }
                        }
                        
                        // Ensure it looks like a residential prefix
                        let range_idx = {
                            let mut rng_lock = rng.lock().await;
                            rng_lock.gen_range(0..ipv6_ranges.len())
                        };
                        let prefix = ipv6_ranges[range_idx];
                        if prefix.starts_with("2001:4860") {
                            ipv6_segments[0] = 0x2001;
                            ipv6_segments[1] = 0x4860;
                        } else if prefix.starts_with("2600") {
                            ipv6_segments[0] = 0x2600;
                        } else if prefix.starts_with("2a00") {
                            ipv6_segments[0] = 0x2a00;
                        } else if prefix.starts_with("2002") {
                            ipv6_segments[0] = 0x2002;
                        } else {
                            ipv6_segments[0] = 0x2001;
                        }
                        
                        let ip = IpAddr::V6(Ipv6Addr::new(
                            ipv6_segments[0], ipv6_segments[1], ipv6_segments[2], ipv6_segments[3],
                            ipv6_segments[4], ipv6_segments[5], ipv6_segments[6], ipv6_segments[7]
                        ));
                        
                        let sem_permit = semaphore.clone().acquire_owned().await;
                        let geoip_clone = geoip.clone();
                        let tx_clone = collector_tx.clone();
                        let counter = successful_collection_counter.clone();
                        
                        let task = tokio::spawn(async move {
                            let _permit = sem_permit;
                            // Get GeoIP information without failing on lookup errors
                            let geo_info = match geoip_clone.lookup(ip).await {
                                Ok(geo_info) => geo_info,
                                Err(e) => {
                                    // Log but continue with default geo info
                                    debug!("GeoIP lookup silently recovered for IPv6 {}: {}", ip, e);
                                    GeoInformation {
                                        country_code: Some("XX".to_string()),
                                        country_name: Some("Unknown".to_string()),
                                        city: None,
                                        coordinates: None,
                                        continent_code: None,
                                        time_zone: None,
                                    }
                                }
                            };
                            
                            // Extract country code before moving geo_info
                            let country_code = geo_info.country_code.as_deref().unwrap_or("unknown").to_string();
                            
                            // Collect all IPv6 addresses regardless of geo lookup result
                            if let Err(e) = tx_clone.send(CollectorCommand::CollectIpWithGeo {
                                ip,
                                source: IpSource::PassiveCollection,
                                geo_info,
                                _timestamp: chrono::Utc::now(),
                            }).await {
                                error!("Failed to send IPv6 to collector: {}", e);
                            } else {
                                counter.fetch_add(1, Ordering::SeqCst);
                                debug!("Added IPv6: {} ({})", ip, country_code);
                            }
                        });
                        
                        tasks.push(task);
                    }
                }
                
                // Wait for all tasks to complete (with bounded concurrency through semaphore)
                stream::iter(tasks)
                    .for_each_concurrent(config.concurrency, |t| async {
                        let _ = t.await;
                    })
                    .await;
                
                // Log progress every batch
                let collection_count = successful_collection_counter.load(Ordering::SeqCst);
                info!("Batch #{}: {} total successful lookups so far", 
                      batch_count, collection_count);
                
                // Wait before next batch
                sleep(Duration::from_millis(config.batch_delay_ms)).await;
            }
        });
        
        // Create a separate monitor subscription for the monitoring task
        let mut monitor_rx = main_stop_tx.subscribe();
        
        // Spawn a monitoring task that periodically logs progress
        tokio::spawn(async move {
            let log_interval = Duration::from_secs(60);
            loop {
                // Use tokio::select! to either wait for the interval or for stop signal
                tokio::select! {
                    _ = sleep(log_interval) => {
                        let count = counter_clone.load(Ordering::SeqCst);
                        info!("Collection progress: {} IPs collected", count);
                    }
                    _ = monitor_rx.recv() => {
                        debug!("Monitoring task received stop signal");
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Stop scanning
    pub async fn stop_collection(&self) -> Result<()> {
        info!("Stopping IP scanner");
        // Send stop signal
        let _ = self.stop_tx.send(true).await;
        Ok(())
    }

    /// Add an observed IP address to the collection
    #[allow(dead_code)]
    pub async fn add_observed_ip(&self, ip: IpAddr) -> Result<()> {
        // Acquire permit for processing this IP
        let _permit = self.scan_semaphore.acquire().await?;
        // Get GeoIP information
        if let Ok(geo_info) = self.geoip.lookup(ip).await {
            // Only collect residential IPs
            if Self::is_likely_residential(&geo_info) {
                self.collector_tx.send(CollectorCommand::AddIp(ip)).await?;
            }
        }
        Ok(())
    }

    /// Generate random IPs for scanning
    #[allow(dead_code)]
    pub fn generate_random_ips(count: usize) -> Vec<IpAddr> {
        let mut rng = StdRng::from_entropy();
        let mut ips = Vec::with_capacity(count);
        
        for _ in 0..count {
            // Generate mostly IPv4 with some IPv6
            if rng.gen_bool(0.9) {
                let ip = Ipv4Addr::new(
                    rng.gen_range(1..224),  // Avoid reserved ranges
                    rng.gen(),
                    rng.gen(),
                    rng.gen_range(1..255), // Avoid network/broadcast addresses
                );
                ips.push(IpAddr::V4(ip));
            } else {
                let ip = Ipv6Addr::new(
                    rng.gen_range(0x2000..0x3000), // Focus on common global unicast ranges
                    rng.gen(),
                    rng.gen(),
                    rng.gen(),
                    rng.gen(),
                    rng.gen(),
                    rng.gen(),
                    rng.gen_range(1..0xfffe), // Avoid reserved addresses
                );
                ips.push(IpAddr::V6(ip));
            }
        }
        
        ips
    }
    
    /// Check if an IP address is likely residential based on GeoIP data
    pub fn is_likely_residential(geo_info: &GeoInformation) -> bool {
        // If geo info is missing or has default "XX" country, treat as residential for collection
        if geo_info.country_code.as_deref() == Some("XX") {
            return true;
        }
        
        // If we have a city but no coordinates, likely residential
        let has_city_no_exact_coords = geo_info.city.is_some() && geo_info.coordinates.is_none();
        
        // Prefer IPs from smaller ISPs/non-major tech hubs
        let residential_bias = matches!(&geo_info.country_code, Some(cc) if !["US", "CN", "IN", "RU", "DE", "FR", "GB"].contains(&cc.as_str()));
        
        // If we have timezone data it's more likely residential
        let has_timezone = geo_info.time_zone.is_some();
        
        // Return true if this IP is likely residential
        has_city_no_exact_coords || residential_bias || has_timezone
    }
}
