
use std::net::IpAddr;
use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::RwLock;


/// Database of known VPN, proxy, and data center IP addresses
pub struct VpnDatabase {
    /// Set of known VPN/proxy IPs
    known_vpns: Arc<DashMap<IpAddr, VpnEntry>>,
    
    /// Last update timestamp
    last_update: Arc<RwLock<u64>>,
}

/// Entry in the VPN database
#[derive(Debug, Clone)]
pub struct VpnEntry {
    /// IP address
    pub ip: IpAddr,
    
    /// Type of service (VPN, proxy, tor exit, etc.)
    pub service_type: ServiceType,
    
    /// Confidence score (0-100)
    pub confidence: u8,
    
    /// Source of this information
    pub source: String,
    
    /// Last verification timestamp
    pub last_verified: u64,
}

/// Type of privacy service
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceType {
    /// Virtual Private Network
    Vpn,
    
    /// Proxy server
    Proxy,
    
    /// Tor exit node
    TorExit,
    
    /// Data center IP
    DataCenter,
    
    /// Residential proxy
    ResidentialProxy,
}

impl VpnDatabase {
    /// Create a new VPN database
    pub fn new() -> Self {
        Self {
            known_vpns: Arc::new(DashMap::new()),
            last_update: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Check if an IP is a known VPN/proxy
    pub fn is_vpn(&self, ip: &IpAddr) -> bool {
        self.known_vpns.contains_key(ip)
    }
    
    /// Get information about a VPN IP
    pub fn get_vpn_info(&self, ip: &IpAddr) -> Option<VpnEntry> {
        self.known_vpns.get(ip).map(|entry| entry.clone())
    }
    
    /// Add a new VPN IP to the database
    pub fn add_vpn(&self, entry: VpnEntry) {
        self.known_vpns.insert(entry.ip, entry);
    }
    
    /// Get the number of entries in the database
    pub fn size(&self) -> usize {
        self.known_vpns.len()
    }
}

impl Default for VpnDatabase {
    fn default() -> Self {
        Self::new()
    }
}
