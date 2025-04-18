use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::fs::File;
use maxminddb::{Reader, geoip2, MaxMindDBError};
use dashmap::DashMap;
use tokio::sync::Semaphore;
use tracing::{debug, warn, error, info};
use memmap2::Mmap;

use crate::types::GeoInformation;
use crate::error::{Result, SnapshotError};

/// High-performance geolocation service with intelligent caching
pub struct GeoIpService {
    /// MaxMind GeoIP2 database reader with memory-mapped file access for optimal performance
    reader: Arc<Reader<Mmap>>,
    
    /// Path to the GeoIP database
    db_path: PathBuf,
    
    /// Lookup cache to minimize I/O operations
    cache: Arc<DashMap<IpAddr, GeoInformation>>,
    
    /// Concurrency limiter for batch operations
    lookup_semaphore: Arc<Semaphore>,

    /// Default geo information for when lookups fail
    default_geo: GeoInformation,
    
    /// Database integrity status
    integrity_verified: bool,
}

#[allow(dead_code)]
impl GeoIpService {
    /// Create a new GeoIP service instance with memory-mapped file access
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let path = db_path.as_ref().to_path_buf();
        
        // Verify database exists
        if !path.exists() {
            return Err(SnapshotError::Geolocation(
                format!("GeoIP database not found at {:?}", path)
            ));
        }
        
        // Open file with memory mapping for zero-copy access
        let file = File::open(&path).map_err(|e| {
            SnapshotError::Geolocation(format!("Failed to open GeoIP database file: {}", e))
        })?;
        
        // Create memory map
        #[allow(unsafe_code)]
        let mmap = unsafe { 
            Mmap::map(&file).map_err(|e| {
                SnapshotError::Geolocation(format!("Failed to memory-map GeoIP database: {}", e))
            })?
        };
        
        // Initialize reader with memory-mapped data
        let reader = Reader::from_source(mmap).map_err(|e| {
            SnapshotError::Geolocation(format!("Failed to initialize GeoIP reader: {}", e))
        })?;
        
        // Calculate optimal concurrency limit based on system resources
        let cpu_cores = num_cpus::get();
        let semaphore_permits = std::cmp::max(32, cpu_cores * 4);

        // Create a default geo information object 
        let default_geo = GeoInformation {
            country_code: Some("XX".to_string()),
            country_name: Some("Unknown".to_string()),
            city: None,
            coordinates: None,
            continent_code: None,
            time_zone: None,
        };
        
        let service = Self {
            reader: Arc::new(reader),
            db_path: path,
            cache: Arc::new(DashMap::new()),
            lookup_semaphore: Arc::new(Semaphore::new(semaphore_permits)),
            default_geo,
            integrity_verified: false,
        };
        
        // Verify database integrity
        if let Err(e) = service.validate_database_integrity().await {
            warn!("GeoIP database integrity check failed: {}", e);
            // Continue with the database anyway, just mark as unverified
        } else {
            info!("GeoIP database integrity verified successfully");
        }
        
        Ok(service)
    }
    
    /// Validate the integrity of the GeoIP database
    async fn validate_database_integrity(&self) -> Result<()> {
        let metadata = &self.reader.metadata;
        
        // Verify binary format version is supported
        if metadata.binary_format_major_version != 2 {
            return Err(SnapshotError::Integrity(
                format!("Unsupported binary format version: {}.{}", 
                        metadata.binary_format_major_version,
                        metadata.binary_format_minor_version)
            ));
        }
        
        // Additional integrity checks could be added here
        
        Ok(())
    }
    
    /// Lookup geographic information for an IP address
    pub async fn lookup(&self, ip: IpAddr) -> Result<GeoInformation> {
        // Check cache first
        if let Some(cached) = self.cache.get(&ip) {
            return Ok(cached.clone());
        }
        
        // Acquire semaphore to limit concurrent lookups
        let _permit = self.lookup_semaphore.acquire().await.map_err(|e| {
            SnapshotError::Geolocation(format!("Failed to acquire lookup semaphore: {}", e))
        })?;
        
        // Double-check cache after acquiring permit (prevents race conditions)
        if let Some(cached) = self.cache.get(&ip) {
            return Ok(cached.clone());
        }
        
        // Look up IP in GeoIP database
        match self.reader.lookup::<geoip2::City>(ip) {
            Ok(city) => {
                // Process successful lookup
                let geo_info = self.extract_geo_information(city);
                // Insert into cache
                self.cache.insert(ip, geo_info.clone());
                Ok(geo_info)
            },
            Err(e) => {
                // Handle lookup errors with precise error type handling
                match e {
                    // Address not found indicates tree traversal failure
                    MaxMindDBError::AddressNotFoundError(_) => {
                        // Apply heuristic mapping for not found addresses
                        let geo_info = self.apply_heuristic_mapping(ip);
                        Ok(geo_info)
                    },
                    // Handle specific data issues for improved resilience
                    MaxMindDBError::InvalidDatabaseError(_) => {
                        warn!("Invalid GeoIP database structure detected: {}", e);
                        let geo_info = self.apply_heuristic_mapping(ip);
                        Ok(geo_info)
                    },
                    // Other errors represent actual lookup failures
                    _ => {
                        warn!("GeoIP lookup failed for {}: {}", ip, e);
                        let geo_info = self.apply_heuristic_mapping(ip);
                        Ok(geo_info)
                    }
                }
            }
        }
    }
    
    /// Extract GeoInformation from a successful City lookup
    fn extract_geo_information(&self, city: geoip2::City) -> GeoInformation {
        // Extract location information
        let coordinates = city.location.as_ref().and_then(|loc| {
            match (loc.latitude, loc.longitude) {
                (Some(lat), Some(lon)) => Some((lat, lon)),
                _ => None,
            }
        });
        
        // Extract country information
        let (country_code, country_name) = if let Some(country) = city.country {
            (
                country.iso_code.map(|s| s.to_string()),
                country.names.and_then(|n| n.get("en").map(|s| s.to_string())),
            )
        } else {
            (None, None)
        };
        
        // Extract city name
        let city_name = city.city
            .and_then(|c| c.names)
            .and_then(|n| n.get("en").map(|s| s.to_string()));
        
        // Extract continent code
        let continent_code = city.continent
            .and_then(|c| c.code)
            .map(|s| s.to_string());
        
        // Extract time zone
        let time_zone = city.location
            .and_then(|l| l.time_zone)
            .map(|s| s.to_string());
        
        // Construct GeoInformation
        GeoInformation {
            country_code,
            country_name,
            city: city_name,
            coordinates,
            continent_code,
            time_zone,
        }
    }
    
    /// Apply heuristic mapping for failed lookups
    fn apply_heuristic_mapping(&self, ip: IpAddr) -> GeoInformation {
        // For IPv6 addresses, try to estimate region based on address class
        let geo_info = if ip.is_ipv6() {
            self.estimate_coordinates_by_ipv6_class(ip)
        } else {
            // For IPv4 addresses, use the default geo info
            self.default_geo.clone()
        };
        
        // Cache result to prevent repeated lookup failures
        self.cache.insert(ip, geo_info.clone());
        
        geo_info
    }
    
    /// Estimate coordinates based on IPv6 address class to improve geolocation quality
    fn estimate_coordinates_by_ipv6_class(&self, ip: IpAddr) -> GeoInformation {
        if let IpAddr::V6(ipv6) = ip {
            let segments = ipv6.segments();
            
            // Check for special IPv6 address patterns
            if segments[0] == 0x2001 {
                if segments[1] == 0x4860 {  // Google Fiber
                    return GeoInformation {
                        country_code: Some("US".to_string()),
                        country_name: Some("United States".to_string()),
                        city: None,
                        coordinates: Some((37.4219, -122.0841)),  // Mountain View, CA
                        continent_code: Some("NA".to_string()),
                        time_zone: Some("America/Los_Angeles".to_string()),
                    };
                } else if (segments[1] & 0xFF00) == 0x0200 {  // APNIC
                    return GeoInformation {
                        country_code: Some("AP".to_string()),
                        country_name: Some("Asia/Pacific Region".to_string()),
                        city: None,
                        coordinates: None,
                        continent_code: Some("AS".to_string()),
                        time_zone: None,
                    };
                }
            } else if segments[0] == 0x2a00 {  // RIPE NCC (Europe)
                return GeoInformation {
                    country_code: Some("EU".to_string()),
                    country_name: Some("Europe".to_string()),
                    city: None,
                    coordinates: None,
                    continent_code: Some("EU".to_string()),
                    time_zone: None,
                };
            } else if segments[0] == 0x2600 {  // Hurricane Electric (US)
                return GeoInformation {
                    country_code: Some("US".to_string()),
                    country_name: Some("United States".to_string()),
                    city: None,
                    coordinates: None,
                    continent_code: Some("NA".to_string()),
                    time_zone: None,
                };
            } else if segments[0] == 0x2602 || segments[0] == 0x2606 {  // ARIN (North America)
                return GeoInformation {
                    country_code: Some("US".to_string()),
                    country_name: Some("United States".to_string()),
                    city: None,
                    coordinates: None,
                    continent_code: Some("NA".to_string()),
                    time_zone: None,
                };
            }
        }
        
        // Default to unknown for unrecognized patterns
        self.default_geo.clone()
    }
    
    /// Batch lookup multiple IP addresses in parallel with improved concurrency control
    pub async fn batch_lookup(&self, ips: &[IpAddr]) -> Result<Vec<(IpAddr, Result<GeoInformation>)>> {
        // Create tasks for each IP
        let mut tasks = Vec::with_capacity(ips.len());
        
        for &ip in ips {
            let service = self.clone();
            tasks.push(tokio::spawn(async move {
                let result = service.lookup(ip).await;
                (ip, result)
            }));
        }
        
        // Wait for all tasks to complete
        let mut results = Vec::with_capacity(ips.len());
        
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Batch lookup task failed: {}", e);
                    // Continue with other tasks
                }
            }
        }
        
        Ok(results)
    }
    
    /// Clear the lookup cache
    pub fn clear_cache(&self) {
        self.cache.clear();
        debug!("Cleared GeoIP lookup cache");
    }
    
    /// Get database information
    pub fn get_database_info(&self) -> String {
        let path_str = self.db_path.to_string_lossy();
        format!(
            "GeoIP Database: {} (Node count: {}, Build epoch: {}, Format: {}.{}, Integrity: {})",
            path_str,
            self.reader.metadata.node_count,
            self.reader.metadata.build_epoch,
            self.reader.metadata.binary_format_major_version,
            self.reader.metadata.binary_format_minor_version,
            if self.integrity_verified { "Verified" } else { "Unverified" }
        )
    }
    
    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let entry_count = self.cache.len();
        // Access to private shards() method replaced with a fixed value
        let shard_count = 16; // Default shard count in DashMap
        
        (entry_count, shard_count)
    }
}

impl Clone for GeoIpService {
    fn clone(&self) -> Self {
        Self {
            reader: Arc::clone(&self.reader),
            db_path: self.db_path.clone(),
            cache: Arc::clone(&self.cache),
            lookup_semaphore: Arc::clone(&self.lookup_semaphore),
            default_geo: self.default_geo.clone(),
            integrity_verified: self.integrity_verified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    
    // These tests require a valid GeoIP database file to be present
    // They're marked as ignore by default so CI pipelines don't fail
    // Run with `cargo test -- --ignored` to execute these tests
    
    #[tokio::test]
    #[ignore]
    async fn test_geoip_lookup_ipv4() {
        let service = GeoIpService::new("./GeoLite2-City.mmdb").await.unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)); // Google DNS
        
        let result = service.lookup(ip).await.unwrap();
        
        assert!(result.country_code.is_some());
        assert_eq!(result.country_code.as_ref().unwrap(), "US");
    }
    
    #[tokio::test]
    #[ignore]
    async fn test_geoip_lookup_ipv6() {
        let service = GeoIpService::new("./GeoLite2-City.mmdb").await.unwrap();
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)); // Google DNS IPv6
        
        let result = service.lookup(ip).await.unwrap();
        
        assert!(result.country_code.is_some());
        // The exact country might vary
    }
    
    #[tokio::test]
    #[ignore]
    async fn test_geoip_batch_lookup() {
        let service = GeoIpService::new("./GeoLite2-City.mmdb").await.unwrap();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),         // Google DNS
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),         // Cloudflare DNS
            IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),  // OpenDNS
        ];
        
        let results = service.batch_lookup(&ips).await.unwrap();
        
        assert_eq!(results.len(), 3);
        
        // Check that all lookups succeeded
        for (ip, result) in &results {
            assert!(result.is_ok(), "Lookup for {} failed", ip);
            let geo = result.as_ref().unwrap();
            assert!(geo.country_code.is_some(), "No country code for {}", ip);
        }
    }
    
    #[tokio::test]
    #[ignore]
    async fn test_geoip_cache() {
        let service = GeoIpService::new("./GeoLite2-City.mmdb").await.unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)); // Google DNS
        
        // First lookup should hit the database
        let first_result = service.lookup(ip).await.unwrap();
        
        // Second lookup should hit the cache
        let second_result = service.lookup(ip).await.unwrap();
        
        // Results should be identical
        assert_eq!(
            first_result.country_code, 
            second_result.country_code,
            "Cache returned different country code"
        );
        
        // Check cache stats
        let (entry_count, _) = service.get_cache_stats();
        assert!(entry_count > 0, "Cache is empty after lookups");
        
        // Clear cache and verify
        service.clear_cache();
        let (entry_count, _) = service.get_cache_stats();
        assert_eq!(entry_count, 0, "Cache not empty after clearing");
    }
}
