use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use maxminddb::{Reader, geoip2};
use dashmap::DashMap;
use tokio::sync::Semaphore;
use tracing::{debug, warn, error};

use crate::types::GeoInformation;
use crate::error::{Result, SnapshotError};

/// High-performance geolocation service with intelligent caching
pub struct GeoIpService {
    /// MaxMind GeoIP2 database reader
    reader: Arc<Reader<Vec<u8>>>,

    /// Path to the GeoIP database
    db_path: PathBuf,

    /// Lookup cache to minimize I/O operations
    cache: Arc<DashMap<IpAddr, GeoInformation>>,

    /// Concurrency limiter for batch operations
    lookup_semaphore: Arc<Semaphore>,
}

#[allow(dead_code)]
impl GeoIpService {
    /// Create a new GeoIP service instance
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let path = db_path.as_ref().to_path_buf();

        // Verify database exists
        if !path.exists() {
            return Err(SnapshotError::Geolocation(format!(
                "GeoIP database not found at {:?}",
                path
            )));
        }

        // Initialize reader
        let reader = Reader::open_readfile(&path).map_err(|e| {
            SnapshotError::Geolocation(format!("Failed to open GeoIP database: {}", e))
        })?;

        // Calculate optimal concurrency limit based on system resources
        let cpu_cores = num_cpus::get();
        let semaphore_permits = std::cmp::max(32, cpu_cores * 4);

        Ok(Self {
            reader: Arc::new(reader),
            db_path: path,
            cache: Arc::new(DashMap::new()),
            lookup_semaphore: Arc::new(Semaphore::new(semaphore_permits)),
        })
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

        // Look up IP in GeoIP database
        let city_result = match self.reader.lookup::<geoip2::City>(ip) {
            Ok(city) => city,
            Err(e) => {
                warn!("GeoIP lookup failed for {}: {}", ip, e);
                return Err(SnapshotError::Geolocation(format!(
                    "GeoIP lookup failed: {}",
                    e
                )));
            }
        };

        // Extract location information
        let coordinates =
            city_result
                .location
                .as_ref()
                .and_then(|loc| match (loc.latitude, loc.longitude) {
                    (Some(lat), Some(lon)) => Some((lat, lon)),
                    _ => None,
                });

        // Extract country information
        let (country_code, country_name) = if let Some(country) = city_result.country {
            (
                country.iso_code.map(|s| s.to_string()),
                country
                    .names
                    .and_then(|n| n.get("en").map(|s| s.to_string())),
            )
        } else {
            (None, None)
        };

        // Extract city name
        let city = city_result
            .city
            .and_then(|c| c.names)
            .and_then(|n| n.get("en").map(|s| s.to_string()));

        // Extract continent code
        let continent_code = city_result
            .continent
            .and_then(|c| c.code)
            .map(|s| s.to_string());

        // Extract time zone
        let time_zone = city_result
            .location
            .and_then(|l| l.time_zone)
            .map(|s| s.to_string());

        // Construct GeoInformation
        let geo_info = GeoInformation {
            country_code,
            country_name,
            city,
            coordinates,
            continent_code,
            time_zone,
        };

        // Cache result
        self.cache.insert(ip, geo_info.clone());

        Ok(geo_info)
    }

    /// Batch lookup multiple IP addresses in parallel
    pub async fn batch_lookup(
        &self,
        ips: &[IpAddr],
    ) -> Result<Vec<(IpAddr, Result<GeoInformation>)>> {
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
            "GeoIP Database: {} (Node count: {}, Build epoch: {})",
            path_str, self.reader.metadata.node_count, self.reader.metadata.build_epoch,
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
        assert_eq!(result.country_code.unwrap(), "US");
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
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),        // Google DNS
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),        // Cloudflare DNS
            IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), // OpenDNS
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
            first_result.country_code, second_result.country_code,
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
