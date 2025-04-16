// filepath: /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/ip-snapshot/src/ip_collector/scanner.rs
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{info, debug};

use crate::error::Result;
use crate::geolocation::GeoIpService;
use crate::ip_collector::CollectorCommand;
use crate::types::{GeoInformation, IpSource};

/// IP Scanner configuration
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    /// Maximum number of concurrent scans
    pub concurrency: usize,
    
    /// Scan delay between batches (in milliseconds)
    pub batch_delay_ms: u64,
    
    /// Number of IPs to scan per batch
    pub batch_size: usize,
    
    /// Regional scan weights (region code -> scan weight)
    pub region_weights: HashMap<String, usize>,
    
    /// IPv6 scan probability (0.0-1.0)
    pub ipv6_probability: f64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        let mut region_weights = HashMap::new();
        
        // Define regional scan weights to ensure global coverage
        // Higher weight means more IPs will be scanned from that region
        region_weights.insert("NA".to_string(), 25); // North America
        region_weights.insert("EU".to_string(), 25); // Europe
        region_weights.insert("AS".to_string(), 20); // Asia
        region_weights.insert("SA".to_string(), 10); // South America
        region_weights.insert("AF".to_string(), 10); // Africa
        region_weights.insert("OC".to_string(), 5);  // Oceania
        region_weights.insert("AN".to_string(), 1);  // Antarctica
        
        Self {
            concurrency: 50,
            batch_delay_ms: 5000,
            batch_size: 100,
            region_weights,
            ipv6_probability: 0.1, // 10% IPv6, 90% IPv4
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
    
    /// Active scan limiter
    scan_semaphore: Arc<Semaphore>,
    
    /// Regional IP blocks (for targeted scanning)
    regional_blocks: HashMap<String, Vec<(u32, u32)>>,
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
        
        // Load regional IP blocks
        let regional_blocks = Self::load_regional_ip_blocks();
        
        Ok(Self {
            geoip,
            collector_tx,
            config,
            scan_semaphore,
            regional_blocks,
        })
    }
    
    /// Start scanning in the background
    pub async fn start_scanning(&self) -> Result<()> {
        info!("Starting global IP scanning with concurrency: {}", self.config.concurrency);
        
        // Clone needed values for the task
        let semaphore = Arc::clone(&self.scan_semaphore);
        let collector_tx = self.collector_tx.clone();
        let geoip = Arc::clone(&self.geoip);
        let config = self.config.clone();
        let regional_blocks = self.regional_blocks.clone();
        
        // Create a thread-safe counter for successful scans
        let successful_scan_counter = Arc::new(AtomicUsize::new(0));
        
        // Spawn the scan task
        tokio::spawn(async move {
            // Using a thread-safe RNG that implements Send
            let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_nanos() as u64;
            
            loop {
                // Create a new seeded RNG for each batch - this avoids thread safety issues
                let mut batch_rng = StdRng::seed_from_u64(seed.wrapping_add(
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default().as_micros() as u64
                ));
                
                // Generate a batch of IPs to scan based on regional weights
                let ips_to_scan = Self::generate_ips_for_scan(&config, &regional_blocks, &mut batch_rng);
                debug!("Generated {} IPs for scanning", ips_to_scan.len());
                
                // Reset counter for this batch
                successful_scan_counter.store(0, Ordering::SeqCst);
                
                // Process the batch with concurrency control
                for ip in ips_to_scan {
                    // Acquire permit for this scan
                    let permit = semaphore.clone().acquire_owned().await.unwrap();
                    
                    // Clone resources for the task
                    let collector_tx = collector_tx.clone();
                    let geoip = Arc::clone(&geoip);
                    let counter = Arc::clone(&successful_scan_counter);
                    
                    // Spawn a task for this IP
                    tokio::spawn(async move {
                        // The permit will be dropped when this task completes
                        let _permit = permit;
                        
                        // Perform geo lookup
                        match geoip.lookup(ip).await {
                            Ok(geo_info) => {
                                // Check if this is a residential IP
                                let is_residential = Self::is_likely_residential(&geo_info);
                                
                                if is_residential {
                                    // Successfully geolocated the IP and it's residential
                                    let country_str = geo_info.country_code.clone()
                                        .unwrap_or_else(|| "unknown".to_string());
                                    
                                    debug!("Scanned residential IP {}: country {}", ip, country_str);
                                    
                                    // Send to collector
                                    let _ = collector_tx.send(CollectorCommand::CollectIpWithGeo {
                                        ip,
                                        source: IpSource::ActiveScan,
                                        geo_info,
                                        _timestamp: Utc::now(),
                                    }).await;
                                    
                                    // Thread-safe increment of counter
                                    counter.fetch_add(1, Ordering::SeqCst);
                                } else {
                                    debug!("Skipping non-residential IP {}", ip);
                                }
                            },
                            Err(e) => {
                                // Failed to geolocate
                                debug!("Failed to geolocate IP {}: {}", ip, e);
                            }
                        }
                    });
                }
                
                // Wait for batch delay before next batch
                sleep(Duration::from_millis(config.batch_delay_ms)).await;
                
                // Log progress - thread-safe read from counter
                let scan_count = successful_scan_counter.load(Ordering::SeqCst);
                info!("Completed scan batch: {} successful lookups", scan_count);
            }
        });
        
        Ok(())
    }
    
    /// Generate a set of IPs to scan based on regional weights
    fn generate_ips_for_scan(
        config: &ScannerConfig,
        regional_blocks: &HashMap<String, Vec<(u32, u32)>>,
        rng: &mut impl Rng,
    ) -> Vec<IpAddr> {
        let mut ips = Vec::with_capacity(config.batch_size);
        
        // Create a weighted distribution of regions
        let regions: Vec<&String> = config.region_weights.keys().collect();
        let weights: Vec<usize> = regions.iter()
            .map(|region| *config.region_weights.get(*region).unwrap_or(&1))
            .collect();
        
        // Calculate total weight
        let total_weight: usize = weights.iter().sum();
        
        // Generate IPs for each region based on weights
        for _ in 0..config.batch_size {
            // Decide IPv4 vs IPv6
            let use_ipv6 = rng.gen::<f64>() < config.ipv6_probability;
            
            if use_ipv6 {
                // Generate random IPv6
                let ipv6 = Self::generate_random_ipv6(rng);
                ips.push(IpAddr::V6(ipv6));
            } else {
                // Select a region based on weights
                let region_idx = {
                    let mut value = rng.gen_range(0..total_weight);
                    let mut idx = 0;
                    while idx < weights.len() {
                        if value < weights[idx] {
                            break;
                        }
                        value -= weights[idx];
                        idx += 1;
                    }
                    // If we somehow went out of bounds, use the last region
                    if idx >= regions.len() {
                        regions.len() - 1
                    } else {
                        idx
                    }
                };
                
                let region = regions[region_idx];
                
                // Get regional blocks for this region
                if let Some(blocks) = regional_blocks.get(region) {
                    if !blocks.is_empty() {
                        // Randomly select a block
                        let block = blocks.choose(rng).unwrap();
                        
                        // Generate an IP within this block
                        let ip_int = rng.gen_range(block.0..=block.1);
                        let ipv4 = Self::u32_to_ipv4(ip_int);
                        ips.push(IpAddr::V4(ipv4));
                    } else {
                        // Fallback to random IPv4 if no blocks defined
                        let ipv4 = Self::generate_random_ipv4(rng);
                        ips.push(IpAddr::V4(ipv4));
                    }
                } else {
                    // Region not found in blocks, generate random IPv4
                    let ipv4 = Self::generate_random_ipv4(rng);
                    ips.push(IpAddr::V4(ipv4));
                }
            }
        }
        
        ips
    }
    
    /// Generate a random IPv4 address
    fn generate_random_ipv4(rng: &mut impl Rng) -> Ipv4Addr {
        // Avoid reserved ranges
        loop {
            let a = rng.gen::<u8>();
            let b = rng.gen::<u8>();
            let c = rng.gen::<u8>();
            let d = rng.gen::<u8>();
            
            // Skip private ranges, loopback, etc.
            if (a == 10) || // 10.0.0.0/8
               (a == 172 && (16..=31).contains(&b)) || // 172.16.0.0/12
               (a == 192 && b == 168) || // 192.168.0.0/16
               (a == 127) || // 127.0.0.0/8
               (a == 0) || // 0.0.0.0/8
               (a == 169 && b == 254) || // 169.254.0.0/16
               (a == 224) || // 224.0.0.0/4 (multicast)
               (a >= 240) // 240.0.0.0/4 (reserved)
            {
                continue;
            }
            
            return Ipv4Addr::new(a, b, c, d);
        }
    }
    
    /// Generate a random IPv6 address
    fn generate_random_ipv6(rng: &mut impl Rng) -> Ipv6Addr {
        // Generate 8 random u16 segments for IPv6
        let segments: [u16; 8] = [
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>(),
        ];
        
        // Avoid certain reserved blocks
        if segments[0] & 0xE000 == 0x2000 { // 2000::/3 (Global Unicast)
            Ipv6Addr::new(
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7]
            )
        } else {
            // If we hit a reserved range, set the first segment in 2000::/3
            Ipv6Addr::new(
                0x2000 | (segments[0] & 0x1FFF), segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7]
            )
        }
    }
    
    /// Convert u32 to IPv4
    fn u32_to_ipv4(ip: u32) -> Ipv4Addr {
        let octet1 = ((ip >> 24) & 0xFF) as u8;
        let octet2 = ((ip >> 16) & 0xFF) as u8;
        let octet3 = ((ip >> 8) & 0xFF) as u8;
        let octet4 = (ip & 0xFF) as u8;
        
        Ipv4Addr::new(octet1, octet2, octet3, octet4)
    }
    
    /// Load regional IP blocks from static data
    /// Focusing on residential ISP blocks and avoiding mobile/cellular networks
    fn load_regional_ip_blocks() -> HashMap<String, Vec<(u32, u32)>> {
        let mut blocks = HashMap::new();
        
        // North America - Residential ISPs
        blocks.insert("NA".to_string(), vec![
            (0x42000000, 0x42FFFFFF),    // 66.0.0.0/8 (Comcast residential)
            (0x4A000000, 0x4AFFFFFF),    // 74.0.0.0/8 (AT&T residential)
            (0x52000000, 0x52FFFFFF),    // 82.0.0.0/8 (Verizon FiOS)
            (0x58000000, 0x58FFFFFF),    // 88.0.0.0/8 (Cox residential)
            (0x62000000, 0x62FFFFFF),    // 98.0.0.0/8 (Charter/Spectrum)
            (0x68000000, 0x68FFFFFF),    // 104.0.0.0/8 (CenturyLink residential)
            (0x71000000, 0x71FFFFFF),    // 113.0.0.0/8 (Rogers/Shaw residential)
        ]);
        
        // Europe - Residential ISPs
        blocks.insert("EU".to_string(), vec![
            (0x51000000, 0x51FFFFFF),    // 81.0.0.0/8 (BT/UK residential)
            (0x5A000000, 0x5AFFFFFF),    // 90.0.0.0/8 (Deutsche Telekom home)
            (0x76000000, 0x76FFFFFF),    // 118.0.0.0/8 (Orange/France)
            (0x8A000000, 0x8AFFFFFF),    // 138.0.0.0/8 (Telefonica/Spain)
            (0x97000000, 0x97FFFFFF),    // 151.0.0.0/8 (Virgin Media/UK)
            (0xA3000000, 0xA3FFFFFF),    // 163.0.0.0/8 (Fastweb/Italy)
            (0xB2000000, 0xB2FFFFFF),    // 178.0.0.0/8 (KPN/Netherlands)
            (0xC1000000, 0xC1FFFFFF),    // 193.0.0.0/8 (Swisscom/Switzerland)
        ]);
        
        // Asia - Residential ISPs
        blocks.insert("AS".to_string(), vec![
            (0x1B000000, 0x1BFFFFFF),    // 27.0.0.0/8 (NTT residential/Japan)
            (0x33000000, 0x33FFFFFF),    // 51.0.0.0/8 (Korea Telecom)
            (0x45000000, 0x45FFFFFF),    // 69.0.0.0/8 (BSNL/India)
            (0x70000000, 0x70FFFFFF),    // 112.0.0.0/8 (China Telecom residential)
            (0x82000000, 0x82FFFFFF),    // 130.0.0.0/8 (Etisalat/UAE residential)
            (0x95000000, 0x95FFFFFF),    // 149.0.0.0/8 (SingTel residential)
            (0xAC000000, 0xACFFFFFF),    // 172.0.0.0/8 (Saudi Telecom residential)
        ]);
        
        // South America - Residential ISPs
        blocks.insert("SA".to_string(), vec![
            (0x8C000000, 0x8CFFFFFF),    // 140.0.0.0/8 (NET/Brazil residential)
            (0x98000000, 0x98FFFFFF),    // 152.0.0.0/8 (Telecom Argentina home)
            (0xA5000000, 0xA5FFFFFF),    // 165.0.0.0/8 (Claro residential)
            (0xB1000000, 0xB1FFFFFF),    // 177.0.0.0/8 (Telefonica Brazil)
            (0xC5000000, 0xC5FFFFFF),    // 197.0.0.0/8 (Telmex Colombia residential)
        ]);
        
        // Africa - Residential ISPs
        blocks.insert("AF".to_string(), vec![
            (0x69000000, 0x69FFFFFF),    // 105.0.0.0/8 (Maroc Telecom residential)
            (0x85000000, 0x85FFFFFF),    // 133.0.0.0/8 (Telkom SA residential)
            (0x99000000, 0x99FFFFFF),    // 153.0.0.0/8 (MTN fixed line)
            (0xB5000000, 0xB5FFFFFF),    // 181.0.0.0/8 (Safaricom home fiber)
            (0xC9000000, 0xC9FFFFFF),    // 201.0.0.0/8 (Vodacom fixed line)
        ]);
        
        // Oceania - Residential ISPs
        blocks.insert("OC".to_string(), vec![
            (0x73000000, 0x73FFFFFF),    // 115.0.0.0/8 (Telstra residential/Australia)
            (0x88000000, 0x88FFFFFF),    // 136.0.0.0/8 (Optus home/Australia)
            (0x96000000, 0x96FFFFFF),    // 150.0.0.0/8 (Spark NZ residential)
            (0xA8000000, 0xA8FFFFFF),    // 168.0.0.0/8 (TPG Australia home)
            (0xB9000000, 0xB9FFFFFF),    // 185.0.0.0/8 (Vodafone NZ fixed)
        ]);
        
        // Antarctica (research stations with fixed connections)
        blocks.insert("AN".to_string(), vec![
            (0x8D000000, 0x8DFFFFFF),    // 141.0.0.0/8 (Research stations network)
        ]);
        
        blocks
    }
    
    /// Check if an IP address is likely residential based on GeoIP data
    fn is_likely_residential(geo_info: &GeoInformation) -> bool {
        // Implement basic heuristics to identify residential IPs
        
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
