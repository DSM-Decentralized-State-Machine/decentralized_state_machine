use std::net::IpAddr;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use tracing::{debug, warn};
use lazy_static::lazy_static;

// Known ASN ranges for major datacenters and VPN providers
lazy_static! {
    static ref DATACENTER_ASNS: HashSet<u32> = {
        let mut set = HashSet::new();
        // AWS
        set.extend(14618..=14619); // Amazon
        set.extend(16509..=16550); // Amazon AWS
        // Google Cloud
        set.extend(15169..=15170); // Google
        set.extend(396982..=396983); // Google Cloud
        // Azure  
        set.extend(8075..=8076); // Microsoft
        set.extend(35357..=35379); // Microsoft Azure
        set
    };

    static ref VPN_PROVIDER_ASNS: HashSet<u32> = {
        let mut set = HashSet::new();
        set.extend([
            4785,  // ExpressVPN
            9009,  // M247 (Used by many VPNs)
            51167, // Contabo
            9370,  // Proton VPN
            23959, // NordVPN
            20860, // Surfshark
            51531, // Private Internet Access
        ]);
        set
    };
}

/// Network analysis tools for detecting suspicious patterns
#[derive(Default)]
pub struct NetworkAnalyzer;

impl NetworkAnalyzer {
    /// Analyze network patterns to detect potential VPN/proxy usage
    pub fn analyze_network_behavior(ip: &IpAddr) -> NetworkAnalysisResult {
        let mut result = NetworkAnalysisResult::default();
        
        // Get ASN info
        if let Some(asn) = Self::get_asn_info(ip) {
            // ASN Reputation Check
            let asn_score = if DATACENTER_ASNS.contains(&asn.number) {
                95 // Very likely datacenter IP
            } else if VPN_PROVIDER_ASNS.contains(&asn.number) {
                90 // Known VPN provider
            } else {
                match &asn.organization.to_lowercase() {
                    org if org.contains("hosting") || org.contains("datacenter") => 85,
                    org if org.contains("cloud") || org.contains("server") => 80,
                    org if org.contains("vpn") || org.contains("proxy") => 90,
                    _ => 20, // Likely residential ISP
                }
            };
            
            result.scores.insert("asn_reputation".to_string(), asn_score);
            result.aggregate_score += asn_score as f32 * 0.4; // 40% weight
        }

        // Geographic Analysis
        if let Some((rtt, location)) = Self::get_network_metrics(ip) {
            let geo_score = Self::analyze_geo_consistency(rtt, &location);
            result.scores.insert("geographic_consistency".to_string(), geo_score);
            result.aggregate_score += geo_score as f32 * 0.3; // 30% weight
        }

        // Connection Pattern Analysis
        if let Some(conn_score) = Self::analyze_connection_patterns(ip) {
            result.scores.insert("connection_patterns".to_string(), conn_score);
            result.aggregate_score += conn_score as f32 * 0.3; // 30% weight
        }

        // Normalize final score
        result.aggregate_score = result.aggregate_score.clamp(0.0, 100.0);
        
        debug!(
            "Network analysis for {}: score={}, factors={:?}",
            ip, result.aggregate_score, result.scores
        );

        result
    }

    /// Get ASN info for an IP
    fn get_asn_info(ip: &IpAddr) -> Option<AsnInfo> {
        // In production this would use MaxMind GeoIP2 or similar
        // For now return test data based on IP
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                Some(AsnInfo {
                    number: ((octets[0] as u32) << 16) | ((octets[1] as u32) << 8) | (octets[2] as u32),
                    organization: format!("AS{} Test Org", octets[0]),
                })
            }
            IpAddr::V6(_) => None
        }
    }

    /// Analyze geographic consistency based on RTT and location
    fn analyze_geo_consistency(rtt: f32, location: &str) -> u8 {
        // Expected RTT ranges by region (in ms)
        let expected_rtts: HashMap<&str, (f32, f32)> = [
            ("NA", (10.0, 100.0)),   // North America
            ("EU", (80.0, 200.0)),   // Europe
            ("AS", (150.0, 300.0)),  // Asia
            ("SA", (120.0, 250.0)),  // South America 
            ("AF", (200.0, 350.0)),  // Africa
            ("OC", (180.0, 300.0)),  // Oceania
        ].iter().cloned().collect();

        if let Some((min_rtt, max_rtt)) = expected_rtts.get(location) {
            if rtt < *min_rtt {
                // RTT suspiciously low for region
                90
            } else if rtt > *max_rtt {
                // RTT higher than expected
                70  
            } else {
                // RTT in expected range
                20
            }
        } else {
            50 // Unknown region
        }
    }

    /// Get network metrics for an IP
    fn get_network_metrics(ip: &IpAddr) -> Option<(f32, String)> {
        // In production this would do active measurements
        // For now return test data
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                let rtt = (octets[3] as f32) * 2.0;
                let region = match octets[0] {
                    0..=63 => "NA",
                    64..=127 => "EU", 
                    128..=191 => "AS",
                    192..=223 => "SA",
                    224..=239 => "AF",
                    _ => "OC"
                };
                Some((rtt, region.to_string()))
            }
            IpAddr::V6(_) => None
        }
    }

    /// Analyze connection patterns
    fn analyze_connection_patterns(ip: &IpAddr) -> Option<u8> {
        // In production this would analyze:
        // - Connection frequency
        // - Protocol distribution
        // - Port usage patterns
        // - Traffic volume
        
        // For now use simplified test logic
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                let conn_per_min = octets[3] as u32 * 10;
                
                Some(match conn_per_min {
                    0..=100 => 20,     // Normal residential
                    101..=500 => 50,   // Moderate usage
                    501..=2000 => 75,  // Heavy usage
                    _ => 90            // Suspicious volume
                })
            }
            IpAddr::V6(_) => None
        }
    }
}

#[derive(Debug)]
struct AsnInfo {
    number: u32,
    organization: String,
}

/// Result of network analysis
#[derive(Debug, Clone)]
pub struct NetworkAnalysisResult {
    /// Individual scores from different analyses
    pub scores: HashMap<String, u8>,

    /// Aggregated final score (0-100)
    /// Higher values indicate higher probability of being a VPN/proxy
    pub aggregate_score: f32,
}

impl Default for NetworkAnalysisResult {
    fn default() -> Self {
        Self {
            scores: HashMap::new(),
            aggregate_score: 50.0, // Start with neutral score
        }
    }
}
