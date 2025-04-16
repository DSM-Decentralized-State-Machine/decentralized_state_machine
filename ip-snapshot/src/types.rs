use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use dashmap::DashMap;

/// Represents a single IP address collection entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpEntry {
    /// The IP address
    pub ip: IpAddr,

    /// Timestamp when this IP was first observed
    pub first_seen: DateTime<Utc>,

    /// Timestamp when this IP was last observed
    pub last_seen: DateTime<Utc>,

    /// Number of times this IP has connected
    pub connection_count: u32,

    /// Geolocation information
    pub geo: Option<GeoInformation>,

    /// Network attributes
    pub network: NetworkInformation,

    /// Fraud detection score (0-100)
    /// Higher score indicates higher probability of being legitimate
    pub legitimacy_score: u8,

    /// BLAKE3 verification hash of this entry
    /// Comprises all fields above deterministically serialized and hashed
    pub verification_hash: String,
}

impl IpEntry {
    /// Create a new IP entry with minimal information
    pub fn new(ip: IpAddr) -> Self {
        let now = Utc::now();

        let mut entry = Self {
            ip,
            first_seen: now,
            last_seen: now,
            connection_count: 1,
            geo: None,
            network: NetworkInformation::default(),
            legitimacy_score: 50, // Neutral initial score
            verification_hash: String::new(),
        };

        // Generate verification hash
        entry.update_verification_hash();

        entry
    }

    /// Update the entry with a new connection
    #[allow(dead_code)]
    pub fn record_connection(&mut self) {
        self.last_seen = Utc::now();
        self.connection_count += 1;
        self.update_verification_hash();
    }

    /// Set geolocation information
    #[allow(dead_code)]
    pub fn set_geo(&mut self, geo: GeoInformation) {
        self.geo = Some(geo);
        self.update_verification_hash();
    }

    /// Update network information
    #[allow(dead_code)]
    pub fn set_network(&mut self, network: NetworkInformation) {
        self.network = network;
        self.update_verification_hash();
    }

    /// Set legitimacy score
    #[allow(dead_code)]
    pub fn set_legitimacy_score(&mut self, score: u8) {
        self.legitimacy_score = score;
        self.update_verification_hash();
    }

    /// Update verification hash
    pub fn update_verification_hash(&mut self) {
        let serialized = serde_json::json!({
            "ip": self.ip.to_string(),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "connection_count": self.connection_count,
            "geo": self.geo,
            "network": self.network,
            "legitimacy_score": self.legitimacy_score,
        });

        let mut hasher = blake3::Hasher::new();
        hasher.update(serialized.to_string().as_bytes());
        self.verification_hash = hex::encode(hasher.finalize().as_bytes());
    }

    /// Verify integrity of this entry
    pub fn verify_integrity(&self) -> bool {
        let serialized = serde_json::json!({
            "ip": self.ip.to_string(),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "connection_count": self.connection_count,
            "geo": self.geo,
            "network": self.network,
            "legitimacy_score": self.legitimacy_score,
        });

        let mut hasher = blake3::Hasher::new();
        hasher.update(serialized.to_string().as_bytes());
        let computed_hash = hex::encode(hasher.finalize().as_bytes());

        computed_hash == self.verification_hash
    }

    /// Canonicalize the entry into a consistent byte representation for hashing
    #[allow(dead_code)]
    pub fn canonicalize(&self) -> Result<Vec<u8>, serde_json::Error> {
        // Create a simplified representation without the verification_hash
        let canonical = serde_json::json!({
            "ip": self.ip.to_string(),
            "first_seen": self.first_seen.to_rfc3339(),
            "last_seen": self.last_seen.to_rfc3339(),
            "connection_count": self.connection_count,
            "geo": self.geo,
            "network": self.network,
            "legitimacy_score": self.legitimacy_score
        });

        // Convert to sorted key representation to ensure consistency
        serde_json::to_vec(&canonical)
    }
}

/// Geolocation information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoInformation {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: Option<String>,

    /// Country name
    pub country_name: Option<String>,

    /// City name
    pub city: Option<String>,

    /// Coordinates (latitude, longitude)
    pub coordinates: Option<(f64, f64)>,

    /// Continent code
    pub continent_code: Option<String>,

    /// Time zone
    pub time_zone: Option<String>,
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInformation {
    /// Autonomous System Number
    pub asn: Option<u32>,

    /// Autonomous System Organization
    pub asn_org: Option<String>,

    /// RTT latency measurements from different vantage points (ms)
    /// Key is the vantage point identifier, value is the RTT in milliseconds
    pub latency: HashMap<String, u32>,

    /// TCP fingerprint
    pub tcp_fingerprint: Option<String>,

    /// User agent strings observed
    pub user_agents: Vec<String>,

    /// Headers that might indicate proxy usage
    pub proxy_headers: HashMap<String, String>,

    /// Network range this IP belongs to
    pub network_range: Option<String>,
    
    /// Source of the IP
    pub source: IpSource,
}

impl Default for NetworkInformation {
    fn default() -> Self {
        Self {
            asn: None,
            asn_org: None,
            latency: HashMap::new(),
            tcp_fingerprint: None,
            user_agents: Vec::new(),
            proxy_headers: HashMap::new(),
            network_range: None,
            source: IpSource::PassiveCollection,
        }
    }
}

/// Snapshot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Unique identifier for this snapshot
    pub id: String,
    
    /// Snapshot description
    pub description: String,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Timestamp when the snapshot was started
    pub start_time: DateTime<Utc>,

    /// Timestamp when the snapshot was finalized
    pub end_time: Option<DateTime<Utc>>,

    /// Total number of IP addresses collected
    pub ip_count: usize,

    /// Number of countries represented
    pub country_count: usize,

    /// Number of flagged/suspicious IPs
    pub flagged_ip_count: usize,

    /// Top 10 countries by IP count
    pub top_countries: HashMap<String, usize>,

    /// Configuration parameters used for collection
    pub collection_params: String,

    /// BLAKE3 hash of all IP entries
    pub data_hash: String,

    /// Verification nonce for this snapshot
    pub verification_nonce: String,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the verification was successful
    pub is_valid: bool,

    /// Error message if verification failed
    pub error: Option<String>,

    /// Snapshot timestamp
    pub timestamp: DateTime<Utc>,

    /// Number of IP addresses
    pub ip_count: usize,

    /// Number of countries
    pub country_count: usize,

    /// Number of flagged IPs
    pub flagged_ips: usize,

    /// BLAKE3 hash of the snapshot
    pub hash: String,
}

/// IP collector state
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CollectorState {
    /// Collection of IP entries
    pub ip_entries: Arc<DashMap<IpAddr, IpEntry>>,

    /// Collection of known proxies/VPNs
    pub known_proxies: Arc<DashMap<IpAddr, ProxyEntry>>,

    /// Snapshot metadata
    pub metadata: Arc<parking_lot::RwLock<SnapshotMetadata>>,

    /// Whether collection is active
    pub is_collecting: Arc<parking_lot::RwLock<bool>>,
}

/// Proxy/VPN entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    /// The IP address
    pub ip: IpAddr,

    /// Type of proxy
    pub proxy_type: ProxyType,

    /// Confidence score (0-100)
    pub confidence: u8,

    /// Source of this classification
    pub source: String,

    /// First detection time
    pub detected_at: DateTime<Utc>,
}

/// Types of proxies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProxyType {
    Vpn,
    DataCenter,
    Tor,
    PublicProxy,
    WebProxy,
    ResidentialProxy,
    UnknownProxy,
}

/// Country statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountryStats {
    /// Country code
    pub country_code: String,

    /// Country name
    pub country_name: String,

    /// Number of unique IPs
    pub ip_count: usize,

    /// Number of flagged IPs
    pub flagged_ip_count: usize,

    /// Percentage of total IPs
    pub percentage: f64,
}

/// Collection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionStats {
    /// Total IPs collected
    pub total_ips: usize,

    /// Unique IPs
    pub unique_ips: usize,

    /// IPs flagged as proxies/VPNs
    pub flagged_ips: usize,

    /// Country statistics
    pub countries: Vec<CountryStats>,

    /// ASN statistics (number of IPs per ASN)
    pub asn_stats: HashMap<u32, usize>,

    /// Collection start time
    pub start_time: DateTime<Utc>,

    /// Last update time
    pub last_update: DateTime<Utc>,

    /// Collection duration in seconds
    pub duration_seconds: u64,
}

/// Sources of IP addresses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpSource {
    /// API endpoints
    ApiEndpoint,
    /// Active scanning
    ActiveScan,
    /// Passive collection
    PassiveCollection,
    /// Manually added
    Manual,
    /// External source
    External(String),
}

/// API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Success status
    pub success: bool,

    /// Response data
    pub data: Option<T>,

    /// Error message if success is false
    pub error: Option<String>,

    /// Response timestamp
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    /// Create a successful response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    /// Create an error response
    pub fn error(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.into()),
            timestamp: Utc::now(),
        }
    }
}
