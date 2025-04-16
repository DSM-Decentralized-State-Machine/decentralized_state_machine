pub mod crypto_net;
pub mod directory;
pub mod init;
pub mod manager;
pub mod nfc;
pub mod p2p;
pub mod protocol;
pub mod storage_cache;
pub mod transport;

use crate::types::error::DsmError;
use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

pub const DEFAULT_PORT: u16 = 4433;
pub const DEFAULT_UDP_PORT: u16 = 4434;
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB limit

/// Transport type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// TLS over TCP
    Tls,
    /// Secure UDP with DTLS
    SecureUdp,
    /// Bluetooth transport
    #[cfg(feature = "bluetooth")]
    Bluetooth,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Tls => write!(f, "TLS"),
            TransportType::SecureUdp => write!(f, "SecureUDP"),
            #[cfg(feature = "bluetooth")]
            TransportType::Bluetooth => write!(f, "Bluetooth"),
        }
    }
}

/// Protocol options for connection establishment
#[derive(Debug, Clone)]
pub struct ConnectionOptions {
    /// Preferred transport types in order of preference
    pub preferred_transports: Vec<TransportType>,
    /// Whether to enforce quantum resistance
    pub require_quantum_resistance: bool,
    /// Whether offline capability is required
    pub require_offline_capability: bool,
    /// Maximum message size
    pub max_message_size: usize,
    /// Connection timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            preferred_transports: vec![
                TransportType::Tls,
                TransportType::SecureUdp,
                #[cfg(feature = "bluetooth")]
                TransportType::Bluetooth,
            ],
            require_quantum_resistance: true,
            require_offline_capability: false,
            max_message_size: 1024 * 1024,
            timeout_ms: 30000, // 30 seconds
        }
    }
}

/// Trait defining network interface operations
#[async_trait]
pub trait NetworkInterface: Send + Sync {
    async fn connect(&self, peer_id: &str, addr: SocketAddr) -> Result<(), DsmError>;
    async fn disconnect(&self, peer_id: &str) -> Result<(), DsmError>;
    async fn send_data(&self, peer_id: &str, data: &[u8]) -> Result<(), DsmError>;
    async fn receive_data(&self, peer_id: &str) -> Result<Option<Bytes>, DsmError>;
}

use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, IsCa};

/// Generate a self-signed certificate for TLS communication
pub fn generate_self_signed_cert() -> Result<Certificate, rcgen::Error> {
    // Create certificate parameters
    let mut params = CertificateParams::new(vec!["dsm.local".to_string()]);

    // Set up distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "DSM Node");
    dn.push(DnType::OrganizationName, "DSM Network");
    params.distinguished_name = dn;

    // Add localhost and local IP addresses to the SAN field
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("localhost".to_string()));
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));

    // Set appropriate key usage
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];

    // Set extended key usage for server and client auth
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // Generate the self-signed certificate
    Certificate::from_params(params)
}

/// Generate a CA certificate for signing other certificates
/// Generate a CA certificate for signing other certificates
pub fn generate_ca_cert() -> Result<Certificate, rcgen::Error> {
    let mut params = CertificateParams::new(vec!["DSM Root CA".to_string()]);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "DSM Root CA");
    dn.push(DnType::OrganizationName, "DSM Network");
    params.distinguished_name = dn;

    // Mark as CA certificate
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    // Set key usage for CA
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    // Generate the CA certificate
    Certificate::from_params(params)
}

// Re-export key types
pub use self::manager::{ConnectionManager, NetworkManager};
pub use self::protocol::{Message, Protocol, Session};
pub use self::storage_cache::StorageCache;
pub use self::transport::{Transport, TransportConnection, TransportListener};
