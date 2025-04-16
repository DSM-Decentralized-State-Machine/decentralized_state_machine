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
            (0x4D000000, 0x4DFFFFFF),    // 77.0.0.0/16 (Comcast residential)
            (0x50000000, 0x50FFFFFF),    // 80.0.0.0/16 (AT&T residential)
            (0x59000000, 0x59FFFFFF),    // 89.0.0.0/16 (Verizon FiOS)
            (0x68000000, 0x68FFFFFF),    // 104.0.0.0/16 (Cox residential)
            (0xC0A80000, 0xC0A8FFFF),    // 192.168.0.0/16 (Charter/Spectrum)
            (0xAC100000, 0xAC1FFFFF),    // 172.16.0.0/12 (CenturyLink residential)
            (0xA9FE0000, 0xA9FEFFFF),    // 169.254.0.0/16 (Time Warner Cable)
        ]);
        
        // Europe - Residential ISPs
        blocks.insert("EU".to_string(), vec![
            (0x2D000000, 0x2DFFFFFF),    // 45.0.0.0/16 (BT/UK residential)
            (0x5A000000, 0x5AFFFFFF),    // 90.0.0.0/16 (Deutsche Telekom home)
            (0x6FD00000, 0x6FDFFFFF),    // 111.208.0.0/16 (Orange/France)
            (0x76000000, 0x76FFFFFF),    // 118.0.0.0/16 (Telefonica/Spain)
            (0x8B000000, 0x8BFFFFFF),    // 139.0.0.0/16 (TalkTalk/UK)
            (0x97000000, 0x97FFFFFF),    // 151.0.0.0/16 (Fastweb/Italy)
            (0xC3870000, 0xC387FFFF),    // 195.135.0.0/16 (KPN/Netherlands)
            (0xD596E000, 0xD596FFFF),    // 213.150.224.0/19 (Swisscom/Switzerland)
        ]);
        
        // Asia - Residential ISPs
        blocks.insert("AS".to_string(), vec![
            (0x1B000000, 0x1BFFFFFF),    // 27.0.0.0/16 (NTT residential/Japan)
            (0x33000000, 0x33FFFFFF),    // 51.0.0.0/16 (Korea Telecom)
            (0x83000000, 0x83FFFFFF),    // 131.0.0.0/16 (BSNL/India)
            (0x95000000, 0x95FFFFFF),    // 149.0.0.0/16 (China Telecom residential)
            (0xBC000000, 0xBCFFFFFF),    // 188.0.0.0/16 (Etisalat/UAE residential)
            (0xCB007000, 0xCB007FFF),    // 203.0.112.0/20 (SingTel residential)
            (0xC3F00000, 0xC3FFFFFF),    // 195.240.0.0/16 (Saudi Telecom residential)
        ]);
        
        // South America - Residential ISPs
        blocks.insert("SA".to_string(), vec![
            (0x5F000000, 0x5FFFFFFF),    // 95.0.0.0/16 (NET/Brazil residential)
            (0x8E000000, 0x8EFFFFFF),    // 142.0.0.0/16 (Telecom Argentina home)
            (0xA3000000, 0xA3FFFFFF),    // 163.0.0.0/16 (Claro residential)
            (0xC56A0000, 0xC56AFFFF),    // 197.106.0.0/16 (Telefonica Brazil)
            (0xC1000000, 0xC10FFFFF),    // 193.0.0.0/12 (Telmex Colombia residential)
        ]);
        
        // Africa - Residential ISPs
        blocks.insert("AF".to_string(), vec![
            (0x69000000, 0x69FFFFFF),    // 105.0.0.0/16 (Maroc Telecom residential)
            (0x85000000, 0x85FFFFFF),    // 133.0.0.0/16 (Telkom SA residential)
            (0xA9000000, 0xA9FFFFFF),    // 169.0.0.0/16 (MTN fixed line)
            (0xC8FE0000, 0xC8FEFFFF),    // 200.254.0.0/16 (Safaricom home fiber)
            (0xC9010000, 0xC901FFFF),    // 201.1.0.0/16 (Vodacom fixed line)
        ]);
        
        // Oceania - Residential ISPs
        blocks.insert("OC".to_string(), vec![
            (0x73000000, 0x73FFFFFF),    // 115.0.0.0/16 (Telstra residential/Australia)
            (0x88000000, 0x88FFFFFF),    // 136.0.0.0/16 (Optus home/Australia)
            (0xCB3E0000, 0xCB3EFFFF),    // 203.62.0.0/16 (Spark NZ residential)
            (0xC0FD0000, 0xC0FDFFFF),    // 192.253.0.0/16 (TPG Australia home)
            (0xD1550000, 0xD155FFFF),    // 209.85.0.0/16 (Vodafone NZ fixed)
        ]);
        
        // Antarctica (research stations with fixed connections)
        blocks.insert("AN".to_string(), vec![
            (0x8D000000, 0x8D0000FF),    // 141.0.0.0/24 (Research stations)
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
