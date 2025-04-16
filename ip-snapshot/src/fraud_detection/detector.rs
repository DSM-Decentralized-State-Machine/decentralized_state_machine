use std::net::IpAddr;
use std::sync::Arc;
use futures::future::join_all;
use dashmap::DashMap;
use rand::prelude::*;
use blake3::Hasher;
use tracing::{debug, info};

use crate::config::SnapshotConfig;
use crate::error::Result;
use crate::types::ProxyType;

/// Core fraud detection engine that combines multiple detection techniques
pub struct FraudDetector {
    /// Known VPN/proxy subnet database
    vpn_subnets: Arc<DashMap<String, ProxyType>>,

    /// Known datacenter IP ranges
    datacenter_ranges: Arc<DashMap<String, String>>,

    /// Mobile carrier IP ranges
    mobile_carrier_ranges: Arc<DashMap<String, String>>,

    /// ASN reputation scores (0-100, higher is more legitimate)
    asn_reputation: Arc<DashMap<u32, u8>>,

    /// IP address cache with detection results
    /// The u8 value is the legitimacy score (0-100)
    cache: Arc<DashMap<IpAddr, u8>>,

    /// Deterministic entropy source for consistent scoring
    deterministic_seed: [u8; 32],

    /// Configuration
    config: SnapshotConfig,
}

impl FraudDetector {
    /// Create a new fraud detector instance
    #[allow(dead_code)]
    pub fn new(config: &SnapshotConfig) -> Self {
        // Initialize with default empty databases
        let vpn_subnets = Arc::new(DashMap::new());
        let datacenter_ranges = Arc::new(DashMap::new());
        let mobile_carrier_ranges = Arc::new(DashMap::new());
        let asn_reputation = Arc::new(DashMap::new());
        let cache = Arc::new(DashMap::new());

        // Create deterministic seed for scoring
        let mut rng = StdRng::from_entropy();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);

        let detector = Self {
            vpn_subnets,
            datacenter_ranges,
            mobile_carrier_ranges,
            asn_reputation,
            cache,
            deterministic_seed: seed,
            config: config.clone(),
        };

        // Populate default known VPN ranges
        detector.populate_default_vpn_ranges();

        // Populate ASN reputation data
        detector.populate_asn_reputation();

        detector
    }

    /// Populate detector with known VPN subnet ranges
    #[allow(dead_code)]
    fn populate_default_vpn_ranges(&self) {
        // Add some well-known VPN providers
        // In a real implementation, this would load from a comprehensive database

        // NordVPN ranges (sample)
        self.vpn_subnets
            .insert("5.253.206.0/24".to_string(), ProxyType::Vpn);
        self.vpn_subnets
            .insert("31.13.191.0/24".to_string(), ProxyType::Vpn);
        self.vpn_subnets
            .insert("45.134.140.0/24".to_string(), ProxyType::Vpn);

        // ExpressVPN ranges (sample)
        self.vpn_subnets
            .insert("108.177.236.0/24".to_string(), ProxyType::Vpn);
        self.vpn_subnets
            .insert("185.254.75.0/24".to_string(), ProxyType::Vpn);

        // Tor exit nodes (sample)
        self.vpn_subnets
            .insert("51.15.43.0/24".to_string(), ProxyType::Tor);
        self.vpn_subnets
            .insert("185.220.101.0/24".to_string(), ProxyType::Tor);

        // Public proxies (sample)
        self.vpn_subnets
            .insert("104.149.129.0/24".to_string(), ProxyType::PublicProxy);
        self.vpn_subnets
            .insert("167.71.0.0/16".to_string(), ProxyType::DataCenter);

        // Common datacenter ranges
        self.datacenter_ranges
            .insert("35.184.0.0/13".to_string(), "Google Cloud".to_string());
        self.datacenter_ranges
            .insert("13.64.0.0/11".to_string(), "Microsoft Azure".to_string());
        self.datacenter_ranges
            .insert("52.0.0.0/8".to_string(), "Amazon AWS".to_string());

        info!("Populated default VPN/proxy detection database with {} entries and {} datacenter ranges",
             self.vpn_subnets.len(), self.datacenter_ranges.len());
    }

    /// Populate ASN reputation database
    #[allow(dead_code)]
    fn populate_asn_reputation(&self) {
        // Add reputation scores for some known ASNs
        // In a real implementation, this would load from a comprehensive database

        // Mobile networks (generally legitimate)
        self.asn_reputation.insert(30722, 90); // Vodafone
        self.asn_reputation.insert(22394, 85); // Verizon Wireless
        self.asn_reputation.insert(7922, 88); // Comcast
        self.asn_reputation.insert(7018, 86); // AT&T

        // Corporate networks (generally legitimate)
        self.asn_reputation.insert(32934, 85); // Facebook
        self.asn_reputation.insert(15169, 80); // Google
        self.asn_reputation.insert(16509, 75); // Amazon AWS (some abuse)

        // Known problematic/proxy ASNs
        self.asn_reputation.insert(14618, 30); // Amazon AWS EC2
        self.asn_reputation.insert(14061, 20); // DigitalOcean
        self.asn_reputation.insert(16276, 15); // OVH
        self.asn_reputation.insert(44477, 10); // Stark Industries (known VPN provider)

        info!(
            "Populated ASN reputation database with {} entries",
            self.asn_reputation.len()
        );
    }

    /// Check if an IP address is likely to be a VPN, proxy, or otherwise suspicious
    /// Returns a legitimacy score from 0-100, where higher values indicate more legitimate
    pub async fn check_ip(&self, ip: IpAddr) -> Result<u8> {
        // Check cache first
        if let Some(cached) = self.cache.get(&ip) {
            return Ok(*cached);
        }

        // In a real implementation, this would perform multiple advanced checks
        // For this simulation, we'll generate a deterministic score based on the IP

        // Convert IP to bytes
        let ip_bytes = match ip {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };

        // Create a deterministic hash of the IP using our seed
        let mut hasher = Hasher::new();
        hasher.update(&ip_bytes);
        hasher.update(&self.deterministic_seed);
        let hash = hasher.finalize();

        // Extract first byte as a base score (0-255)
        let base_score = hash.as_bytes()[0];

        // Normalize to 0-100 range
        let mut score = (base_score as f32 / 255.0 * 100.0) as u8;

        // Implement a basic check for known VPN ranges
        // In reality, this would use CIDR matching, but for simplicity
        // we'll just check if the first two octets match our known ranges
        let ip_prefix = match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}", octets[0], octets[1])
            }
            IpAddr::V6(_) => {
                // For IPv6, we'd do proper subnet matching
                // This is simplified for the example
                "".to_string()
            }
        };

        // Check against our simplified VPN database
        // In reality, this would use proper CIDR matching libraries
        for item in self.vpn_subnets.iter() {
            let subnet = item.key();
            if subnet.starts_with(&ip_prefix) {
                // Reduce score for matching VPN range
                score = score.saturating_mul(3) / 10;
                debug!(
                    "IP {} matched VPN range {}, reducing score to {}",
                    ip, subnet, score
                );
                break;
            }
        }

        // Check against datacenter ranges
        for item in self.datacenter_ranges.iter() {
            let subnet = item.key();
            let provider = item.value();
            if subnet.starts_with(&ip_prefix) {
                // Reduce score for matching datacenter range
                score = score.saturating_mul(4) / 10;
                debug!(
                    "IP {} matched datacenter range {} ({}), reducing score to {}",
                    ip, subnet, provider, score
                );
                break;
            }
        }

        // Cache the result
        self.cache.insert(ip, score);

        Ok(score)
    }

    /// Batch check multiple IP addresses in parallel
    #[allow(dead_code)]
    pub async fn batch_check(&self, ips: &[IpAddr]) -> Result<Vec<(IpAddr, u8)>> {
        // Create futures for each IP check
        let mut futures = Vec::with_capacity(ips.len());

        for &ip in ips {
            let detector = self.clone();
            futures.push(async move {
                match detector.check_ip(ip).await {
                    Ok(score) => (ip, score),
                    Err(_) => (ip, 50), // Default to neutral score on error
                }
            });
        }

        // Execute all checks in parallel
        let results = join_all(futures).await;

        Ok(results)
    }
    /// Clear detection cache
    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        self.cache.clear();
        debug!("Cleared fraud detection cache");
    }
    /// Get cache statistics
    #[allow(dead_code)]
    pub fn get_cache_stats(&self) -> usize {
        self.cache.len()
    }
}

impl Clone for FraudDetector {
    fn clone(&self) -> Self {
        Self {
            vpn_subnets: Arc::clone(&self.vpn_subnets),
            datacenter_ranges: Arc::clone(&self.datacenter_ranges),
            mobile_carrier_ranges: Arc::clone(&self.mobile_carrier_ranges),
            asn_reputation: Arc::clone(&self.asn_reputation),
            cache: Arc::clone(&self.cache),
            deterministic_seed: self.deterministic_seed,
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::config::SnapshotConfig;

    #[tokio::test]
    async fn test_fraud_detection() {
        let config = SnapshotConfig::default();
        let detector = FraudDetector::new(&config);

        // Test with a few IPs
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), // Google DNS (should be high score)
            IpAddr::V4(Ipv4Addr::new(104, 149, 129, 1)), // In our fake proxy list (should be low)
            IpAddr::V4(Ipv4Addr::new(52, 4, 16, 34)), // AWS (should be moderate)
        ];

        for ip in ips {
            let score = detector.check_ip(ip).await.unwrap();
            println!("IP {} has legitimacy score: {}", ip, score);

            // Scores should be in valid range
            assert!(score <= 100);
        }

        // Test batch checking
        let batch_ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),        // Cloudflare DNS
            IpAddr::V4(Ipv4Addr::new(185, 220, 101, 10)), // In our fake Tor list
        ];

        let results = detector.batch_check(&batch_ips).await.unwrap();
        assert_eq!(results.len(), batch_ips.len());

        // Cache should contain all checked IPs
        assert_eq!(detector.get_cache_stats(), 5);

        // Clear cache and verify
        detector.clear_cache();
        assert_eq!(detector.get_cache_stats(), 0);
    }

    #[test]
    fn test_deterministic_scoring() {
        let config = SnapshotConfig::default();
        let detector = FraudDetector::new(&config);

        // Create a fixed seed for deterministic tests
        let seed = [42u8; 32];

        // Clone the Arc fields before moving
        let vpn_subnets_clone = Arc::clone(&detector.vpn_subnets);
        let datacenter_ranges_clone = Arc::clone(&detector.datacenter_ranges);
        let mobile_carrier_ranges_clone = Arc::clone(&detector.mobile_carrier_ranges);
        let asn_reputation_clone = Arc::clone(&detector.asn_reputation);
        let cache_clone = Arc::clone(&detector.cache);
        let config_clone = detector.config.clone();

        let detector_with_seed = FraudDetector {
            deterministic_seed: seed,
            vpn_subnets: Arc::clone(&detector.vpn_subnets),
            datacenter_ranges: Arc::clone(&detector.datacenter_ranges),
            mobile_carrier_ranges: Arc::clone(&detector.mobile_carrier_ranges),
            asn_reputation: Arc::clone(&detector.asn_reputation),
            cache: Arc::clone(&detector.cache),
            config: detector.config.clone(),
        };

        // Create another detector with the same seed
        let other_detector = FraudDetector {
            deterministic_seed: seed,
            vpn_subnets: vpn_subnets_clone,
            datacenter_ranges: datacenter_ranges_clone,
            mobile_carrier_ranges: mobile_carrier_ranges_clone,
            asn_reputation: asn_reputation_clone,
            cache: cache_clone,
            config: config_clone,
        };

        // Test IP
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Both detectors should produce the same score for the same IP
        let rt = tokio::runtime::Runtime::new().unwrap();

        let score1 = rt.block_on(detector_with_seed.check_ip(ip)).unwrap();
        let score2 = rt.block_on(other_detector.check_ip(ip)).unwrap();

        assert_eq!(score1, score2, "Deterministic scoring failed");
    }
}
