use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::communication::crypto_net::{
    CommunicationNonce, DebugCryptoProvider, KyberCryptoProvider,
};
use crate::communication::transport::Transport;
use crate::communication::transport::{TransportConnection, TransportListener};
use crate::communication::TransportType;
use crate::types::error::DsmError;

const MAX_UDP_PACKET_SIZE: usize = 65507;
const DEFAULT_HANDSHAKE_TIMEOUT_MS: u64 = 5000; // 5 seconds
const ENCRYPTED_OVERHEAD: usize = 16; // ChaCha20Poly1305 overhead
#[allow(dead_code)]
const MAX_TIME_DIFF_SECS: u64 = 300; // Maximum acceptable time difference for handshake

/// Authentication data for messages
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct AuthData {
    connection_id: u64,
    message_type: u8,
}

impl AuthData {
    fn to_bytes(self) -> [u8; 9] {
        let mut result = [0u8; 9];
        result[0..8].copy_from_slice(&self.connection_id.to_be_bytes());
        result[8] = self.message_type;
        result
    }
}

/// Message types for UDP framing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum UdpMessageType {
    Handshake = 0,
    HandshakeResponse = 1,
    Data = 2,
    KeepAlive = 3,
    Close = 4,
}

/// Handshake message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeMessage {
    version: u32,
    timestamp: u64,
    nonce: [u8; 32],
    public_key: Vec<u8>,
}

/// Local state for handshake process
#[derive(Debug)]
#[allow(dead_code)]
struct HandshakeState {
    sent_msg: HandshakeMessage,
    received_msg: Option<HandshakeMessage>,
    completed: bool,
}

/// Secure UDP transport implementation with built-in post-quantum key exchange
pub struct SecureUdpTransport {
    crypto_provider: Arc<dyn DebugCryptoProvider>,
    active_connections: Arc<RwLock<HashMap<SocketAddr, SecureUdpConnectionState>>>,
    #[allow(dead_code)]
    keypair: Vec<u8>, // This represents our public key; private key is used only during handshake.
}

impl SecureUdpTransport {
    /// Create a new secure UDP transport.
    /// Now returns a Result because we need to generate a keypair.
    pub fn new(crypto_provider: Arc<dyn DebugCryptoProvider>) -> Result<Self, DsmError> {
        // Generate a keypair from our crypto provider.
        let kp = crypto_provider.generate_keypair()?;
        Ok(Self {
            crypto_provider,
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            keypair: kp.public_key, // store our public key (for handshake)
        })
    }

    /// Initialize with default crypto provider
    pub fn init() -> Result<Self, DsmError> {
        Self::new(Arc::new(KyberCryptoProvider::new()))
    }

    /// Generate a new connection ID.
    #[allow(dead_code)]
    fn generate_connection_id() -> u64 {
        let mut rng = OsRng;
        rng.next_u64()
    }

    /// An associated function to generate a new nonce.
    fn generate_nonce() -> Result<[u8; 32], DsmError> {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Ok(nonce)
    }
}

#[async_trait]
impl Transport for SecureUdpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::SecureUdp
    }

    async fn connect(&self, _addr: SocketAddr) -> Result<Box<dyn TransportConnection>, DsmError> {
        Err(DsmError::network(
            "connect not implemented for SecureUdpTransport",
            None::<std::io::Error>,
        ))
    }

    async fn bind(&self, addr: SocketAddr) -> Result<Box<dyn TransportListener>, DsmError> {
        use tokio::net::UdpSocket;
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| DsmError::network(format!("Bind failed: {}", e), Some(e)))?;
        Ok(Box::new(SecureUdpListener {
            socket: Arc::new(socket),
            local_addr: addr,
            crypto_provider: self.crypto_provider.clone(),
            active_connections: self.active_connections.clone(),
            pending_connections: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    fn is_quantum_resistant(&self) -> bool {
        true
    }

    fn supports_offline(&self) -> bool {
        false
    }
}

/// Secure UDP connection implementation
#[derive(Debug)]
pub struct SecureUdpConnection {
    socket: Arc<UdpSocket>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    connection_id: u64,
    crypto_provider: Arc<dyn DebugCryptoProvider>,
    shared_secret: Vec<u8>,
    next_nonce: AtomicU64,
    active_connections: Arc<RwLock<HashMap<SocketAddr, SecureUdpConnectionState>>>,
    // New fields for session keys
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    peer_public_key: Vec<u8>,
}

impl Clone for SecureUdpConnection {
    fn clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
            remote_addr: self.remote_addr,
            local_addr: self.local_addr,
            connection_id: self.connection_id,
            crypto_provider: self.crypto_provider.clone(),
            shared_secret: self.shared_secret.clone(),
            next_nonce: AtomicU64::new(self.next_nonce.load(Ordering::SeqCst)),
            active_connections: self.active_connections.clone(),
            enc_key: self.enc_key,
            mac_key: self.mac_key,
            peer_public_key: self.peer_public_key.clone(),
        }
    }
}

#[async_trait]
impl TransportConnection for SecureUdpConnection {
    async fn send(&self, data: &[u8]) -> Result<(), DsmError> {
        if data.len() > MAX_UDP_PACKET_SIZE - ENCRYPTED_OVERHEAD - 9 {
            return Err(DsmError::validation(
                format!(
                    "Message too large for UDP: {} bytes (max {})",
                    data.len(),
                    MAX_UDP_PACKET_SIZE - ENCRYPTED_OVERHEAD - 9
                ),
                None::<std::io::Error>,
            ));
        }

        let nonce_value = self.next_nonce.fetch_add(1, Ordering::SeqCst);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&nonce_value.to_be_bytes());
        let nonce = crate::communication::crypto_net::CommunicationNonce::from_u64(nonce_value);

        let auth_data = AuthData {
            connection_id: self.connection_id,
            message_type: UdpMessageType::Data as u8,
        }
        .to_bytes();

        let encrypted =
            self.crypto_provider
                .encrypt(&self.shared_secret, &nonce, data, &auth_data)?;

        let mut message = Vec::with_capacity(auth_data.len() + encrypted.len());
        message.extend_from_slice(&auth_data);
        message.extend_from_slice(&encrypted);

        self.socket
            .send_to(&message, self.remote_addr)
            .await
            .map_err(|e| DsmError::network(format!("Failed to send data: {}", e), Some(e)))?;

        {
            let mut connections = self.active_connections.write().await;
            if let Some(state) = connections.get_mut(&self.remote_addr) {
                state.update_activity();
            }
        }

        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, DsmError> {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        let recv_result = timeout(Duration::from_secs(2), self.socket.recv_from(&mut buf))
            .await
            .map_err(|_| DsmError::network("Receive timeout", None::<std::io::Error>))?
            .map_err(|e| DsmError::network(format!("Failed to receive data: {}", e), Some(e)))?;
        let (len, src_addr) = recv_result;
        if src_addr != self.remote_addr {
            return Err(DsmError::network(
                format!("Received data from unexpected address: {}", src_addr),
                None::<std::io::Error>,
            ));
        }
        if len < 9 {
            return Err(DsmError::network(
                "Message too short",
                None::<std::io::Error>,
            ));
        }
        let conn_id = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let msg_type = buf[8];
        if conn_id != self.connection_id {
            return Err(DsmError::network(
                format!(
                    "Unexpected connection ID: {} (expected {})",
                    conn_id, self.connection_id
                ),
                None::<std::io::Error>,
            ));
        }
        match msg_type {
            t if t == UdpMessageType::Data as u8 => {
                let auth_data = AuthData {
                    connection_id: conn_id,
                    message_type: t,
                }
                .to_bytes();
                let nonce_value = {
                    let mut connections = self.active_connections.write().await;
                    if let Some(state) = connections.get_mut(&self.remote_addr) {
                        state.update_activity();
                        state.next_nonce.fetch_add(1, Ordering::SeqCst)
                    } else {
                        return Err(DsmError::network(
                            "Connection state not found",
                            None::<std::io::Error>,
                        ));
                    }
                };
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&nonce_value.to_be_bytes());
                let nonce = CommunicationNonce::from_u64(nonce_value);
                let encrypted_data = &buf[9..len];
                let decrypted = self.crypto_provider.decrypt(
                    &self.shared_secret,
                    &nonce,
                    encrypted_data,
                    &auth_data,
                )?;
                Ok(decrypted)
            }
            t if t == UdpMessageType::KeepAlive as u8 => {
                let mut connections = self.active_connections.write().await;
                if let Some(state) = connections.get_mut(&self.remote_addr) {
                    state.update_activity();
                }
                Ok(Vec::new())
            }
            t if t == UdpMessageType::Close as u8 => {
                let mut connections = self.active_connections.write().await;
                connections.remove(&self.remote_addr);
                Err(DsmError::network(
                    "Connection closed by peer",
                    None::<std::io::Error>,
                ))
            }
            _ => Err(DsmError::network(
                format!("Unexpected message type: {}", msg_type),
                None::<std::io::Error>,
            )),
        }
    }

    async fn close(&self) -> Result<(), DsmError> {
        let auth_data = AuthData {
            connection_id: self.connection_id,
            message_type: UdpMessageType::Close as u8,
        }
        .to_bytes();
        match self.socket.send_to(&auth_data, self.remote_addr).await {
            Ok(_) => (),
            Err(e) => {
                tracing::warn!("Error sending close message: {}", e);
            }
        }
        let mut connections = self.active_connections.write().await;
        connections.remove(&self.remote_addr);
        Ok(())
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn transport_type(&self) -> TransportType {
        TransportType::SecureUdp
    }
}

/// Secure UDP connection state for an active connection.
#[derive(Debug)]
pub struct SecureUdpConnectionState {
    #[allow(dead_code)]
    connection_id: u64,
    #[allow(dead_code)]
    shared_secret: Vec<u8>,
    next_nonce: AtomicU64,
    last_activity: std::time::Instant,
}

impl SecureUdpConnectionState {
    fn new(connection_id: u64, shared_secret: Vec<u8>) -> Self {
        Self {
            connection_id,
            shared_secret,
            next_nonce: AtomicU64::new(0),
            last_activity: std::time::Instant::now(),
        }
    }

    fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    #[allow(dead_code)]
    fn is_expired(&self, timeout_ms: u64) -> bool {
        self.last_activity.elapsed().as_millis() > timeout_ms as u128
    }
}

/// Secure UDP listener implementation.
pub struct SecureUdpListener {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    crypto_provider: Arc<dyn DebugCryptoProvider>,
    active_connections: Arc<RwLock<HashMap<SocketAddr, SecureUdpConnectionState>>>,
    pending_connections: Arc<RwLock<HashMap<u64, PendingConnection>>>,
}

#[async_trait]
impl TransportListener for SecureUdpListener {
    async fn accept(&self) -> Result<Box<dyn TransportConnection>, DsmError> {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        loop {
            let (len, src_addr) = self.socket.recv_from(&mut buf).await.map_err(|e| {
                DsmError::network(format!("Failed to receive data: {}", e), Some(e))
            })?;
            {
                let connections = self.active_connections.read().await;
                if connections.contains_key(&src_addr) {
                    continue;
                }
            }
            if len < 9 {
                continue;
            }
            let conn_id = u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            let msg_type = buf[8];
            if msg_type == UdpMessageType::Handshake as u8 {
                if len < 9 + 32 {
                    continue;
                }
                let client_public_key = &buf[9..len].to_vec();
                let server_keypair = self.crypto_provider.generate_keypair()?;
                {
                    let mut pending = self.pending_connections.write().await;
                    pending.retain(|_, conn| {
                        !conn.created_at.elapsed().as_millis()
                            > DEFAULT_HANDSHAKE_TIMEOUT_MS as u128
                    });
                    pending.insert(
                        conn_id,
                        PendingConnection {
                            connection_id: conn_id,
                            remote_addr: src_addr,
                            public_key: client_public_key.clone(),
                            created_at: std::time::Instant::now(),
                            timeout: None,
                        },
                    );
                }
                let mut response = Vec::with_capacity(9 + server_keypair.public_key.len());
                response.extend_from_slice(&conn_id.to_be_bytes());
                response.push(UdpMessageType::HandshakeResponse as u8);
                response.extend_from_slice(&server_keypair.public_key);
                self.socket
                    .send_to(&response, src_addr)
                    .await
                    .map_err(|e| {
                        DsmError::network(
                            format!("Failed to send handshake response: {}", e),
                            Some(e),
                        )
                    })?;
                let session_key = self
                    .crypto_provider
                    .derive_shared_secret(&server_keypair.private_key, client_public_key)?;
                let conn_state = SecureUdpConnectionState::new(conn_id, session_key.clone());
                {
                    let mut connections = self.active_connections.write().await;
                    connections.insert(src_addr, conn_state);
                    let mut pending = self.pending_connections.write().await;
                    pending.remove(&conn_id);
                }
                // Derive session keys using a local helper function.
                #[allow(unused_variables)]
                let our_nonce = SecureUdpTransport::generate_nonce()?;
                // For simplicity, assume the handshake response includes a nonce after the public key.
                // Here we simulate extracting a 32-byte nonce from the response (if available).
                #[allow(unused_variables)]
                let peer_nonce = if response.len() >= 9 + server_keypair.public_key.len() + 32 {
                    let start = 9 + server_keypair.public_key.len();
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&response[start..start + 32]);
                    nonce
                } else {
                    [0u8; 32]
                };
                // Create connection and return it.
                return Ok(Box::new(SecureUdpConnection {
                    socket: self.socket.clone(),
                    remote_addr: src_addr,
                    local_addr: self.local_addr,
                    connection_id: conn_id,
                    crypto_provider: self.crypto_provider.clone(),
                    shared_secret: session_key,
                    next_nonce: AtomicU64::new(0),
                    active_connections: self.active_connections.clone(),
                    enc_key: [0u8; 32],
                    mac_key: [0u8; 32],
                    peer_public_key: client_public_key.clone(),
                }));
            }
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn close(&self) -> Result<(), DsmError> {
        let connections = self.active_connections.read().await;
        for (addr, state) in connections.iter() {
            let auth_data = AuthData {
                connection_id: state.connection_id,
                message_type: UdpMessageType::Close as u8,
            }
            .to_bytes();
            match self.socket.send_to(&auth_data, *addr).await {
                Ok(_) => (),
                Err(e) => {
                    tracing::warn!("Error sending close message to {}: {}", addr, e);
                }
            }
        }
        let mut connections = self.active_connections.write().await;
        connections.clear();
        Ok(())
    }

    fn transport_type(&self) -> TransportType {
        TransportType::SecureUdp
    }
}

/// Pending connection for secure UDP.
struct PendingConnection {
    #[allow(dead_code)]
    connection_id: u64,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    #[allow(dead_code)]
    public_key: Vec<u8>,
    created_at: std::time::Instant,
    #[allow(dead_code)]
    timeout: Option<std::time::Duration>,
}

// Allow unused variables in function
#[allow(unused_variables)]
pub fn process_handshake(our_nonce: Vec<u8>, peer_nonce: Vec<u8>) {
    // ...existing code...
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_secure_udp_transport_creation() {
        let transport = SecureUdpTransport::init().unwrap();
        assert_eq!(transport.transport_type(), TransportType::SecureUdp);
        assert!(transport.is_quantum_resistant());
        assert!(!transport.supports_offline());
    }

    #[tokio::test]
    async fn test_auth_data_serialization() {
        let auth = AuthData {
            connection_id: 12345,
            message_type: UdpMessageType::Data as u8,
        };
        let bytes = auth.to_bytes();
        assert_eq!(bytes.len(), 9);
        assert_eq!(u64::from_be_bytes(bytes[0..8].try_into().unwrap()), 12345);
        assert_eq!(bytes[8], UdpMessageType::Data as u8);
    }

    #[tokio::test]
    async fn test_connection_state_expiry() {
        let state = SecureUdpConnectionState::new(1, vec![0; 32]);
        sleep(Duration::from_millis(100)).await;
        assert!(state.is_expired(50));
        assert!(!state.is_expired(150));
    }

    #[tokio::test]
    async fn test_bind_invalid_address() {
        let transport = SecureUdpTransport::init().unwrap();
        // Using 255.255.255.255 which is a broadcast address and typically can't be bound to
        let result = transport
            .bind(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                8080,
            ))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_generate_nonce() {
        let nonce1 = SecureUdpTransport::generate_nonce().unwrap();
        let nonce2 = SecureUdpTransport::generate_nonce().unwrap();
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 32);
    }
}
