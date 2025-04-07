// Network interface implementations
use crate::types::error::DsmError;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// DSM Network Message Format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    version: u32,
    #[serde(rename = "type")]
    message_type: MessageType,
    timestamp: String, // ISO8601 format
    payload: String,   // Base64 encoded
    signatures: Vec<SignatureInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    #[serde(rename = "STATE_UPDATE")]
    StateUpdate,
    #[serde(rename = "INVALIDATION")]
    Invalidation,
    #[serde(rename = "GENESIS")]
    Genesis,
    #[serde(rename = "QUERY")]
    Query,
    #[serde(rename = "RESPONSE")]
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    signer: String,    // Public key
    signature: String, // Base64 encoded
    schema: SignatureScheme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureScheme {
    #[serde(rename = "SPHINCS+")]
    SphincsPlus,
}

impl NetworkMessage {
    pub fn new(message_type: MessageType, payload: &[u8], signer: &str, signature: &[u8]) -> Self {
        let timestamp = Utc::now().to_rfc3339();
        let payload_base64 = BASE64.encode(payload);
        let signature_base64 = BASE64.encode(signature);

        Self {
            version: 1,
            message_type,
            timestamp,
            payload: payload_base64,
            signatures: vec![SignatureInfo {
                signer: signer.to_string(),
                signature: signature_base64,
                schema: SignatureScheme::SphincsPlus, // Default to SPHINCS+
            }],
        }
    }

    pub fn get_payload(&self) -> Result<Vec<u8>, DsmError> {
        BASE64.decode(&self.payload).map_err(|e| {
            DsmError::crypto(
                format!("Failed to decode payload: {}", e),
                Some(Box::new(e)),
            )
        })
    }

    pub fn add_signature(&mut self, signer: &str, signature: &[u8], scheme: SignatureScheme) {
        self.signatures.push(SignatureInfo {
            signer: signer.to_string(),
            signature: BASE64.encode(signature),
            schema: scheme,
        });
    }
}

/// Network communication interface
#[async_trait]
pub trait NetworkInterface {
    /// Connect to the network
    async fn connect(&mut self) -> Result<(), DsmError>;

    /// Disconnect from the network
    async fn disconnect(&mut self) -> Result<(), DsmError>;

    /// Send data to a peer
    async fn send(&self, peer_id: &str, data: &[u8]) -> Result<(), DsmError>;

    /// Send a structured network message to a peer
    async fn send_message(&self, peer_id: &str, message: &NetworkMessage) -> Result<(), DsmError> {
        let serialized = serde_json::to_vec(message).map_err(|e| {
            DsmError::serialization(format!("Failed to serialize message: {}", e), Some(e))
        })?;
        self.send(peer_id, &serialized).await
    }

    /// Receive data from a peer
    async fn receive(&self) -> Result<(String, Vec<u8>), DsmError>;

    /// Receive a structured network message
    async fn receive_message(&self) -> Result<(String, NetworkMessage), DsmError> {
        let (peer_id, data) = self.receive().await?;
        let message = serde_json::from_slice(&data).map_err(|e| {
            DsmError::serialization(format!("Failed to deserialize message: {}", e), Some(e))
        })?;
        Ok((peer_id, message))
    }

    /// Publish data to the directory service
    async fn publish(&self, key: &str, data: &[u8]) -> Result<(), DsmError>;

    /// Retrieve data from the directory service
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>, DsmError>;

    /// Check if peer is online
    async fn is_peer_online(&self, peer_id: &str) -> Result<bool, DsmError>;
}

/// Network manager for handling different transport protocols
pub struct NetworkManager {
    #[cfg(feature = "bluetooth")]
    bluetooth_network: Option<BluetoothNetwork>,
    preferred_transport: TransportProtocol,
    connected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Bluetooth,
    Internet,
}

impl NetworkManager {
    /// Create a new network manager with default configuration
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "bluetooth")]
            bluetooth_network: None,
            preferred_transport: TransportProtocol::Internet,
            connected: false,
        }
    }

    /// Get current connection state
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Configure Bluetooth transport
    #[cfg(feature = "bluetooth")]
    pub fn with_bluetooth(mut self, device_id: String) -> Self {
        self.bluetooth_network = Some(BluetoothNetwork::new(device_id));
        self
    }

    /// Set preferred transport protocol
    pub fn set_preferred_transport(&mut self, protocol: TransportProtocol) {
        if self.preferred_transport != protocol {
            // Reset connection state when transport changes
            self.connected = false;
            self.preferred_transport = protocol;
        }
    }

    /// Connect to the network using preferred transport
    pub async fn connect(&mut self) -> Result<(), DsmError> {
        match self.preferred_transport {
            #[cfg(feature = "bluetooth")]
            TransportProtocol::Bluetooth => {
                if let Some(network) = self.bluetooth_network.as_mut() {
                    network.connect().await?;
                    self.connected = true;
                    Ok(())
                } else {
                    Err(DsmError::Network {
                        context: "Bluetooth transport not configured".into(),
                        source: None,
                    })
                }
            }
            TransportProtocol::Internet => {
                // Fallback to HTTPS implementation
                Err(DsmError::Network {
                    context: "HTTPS transport not yet implemented".into(),
                    source: None,
                })
            }
            #[allow(unreachable_patterns)]
            _ => {
                self.connected = false;
                Err(DsmError::Network {
                    context: "Unsupported transport protocol".into(),
                    source: None,
                })
            }
        }
    }

    /// Disconnect from the network
    pub async fn disconnect(&mut self) -> Result<(), DsmError> {
        let result = match self.preferred_transport {
            #[cfg(feature = "bluetooth")]
            TransportProtocol::Bluetooth => {
                if let Some(network) = self.bluetooth_network.as_mut() {
                    network.disconnect().await
                } else {
                    Ok(())
                }
            }
            TransportProtocol::Internet => Ok(()),
            #[allow(unreachable_patterns)]
            _ => Ok(()),
        };

        // Update connection state regardless of specific transport result
        self.connected = false;
        result
    }
}

// Add Default implementation for NetworkManager
impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn start() -> Result<(), &'static str> {
    println!("Network interface starting");
    // Initialize network manager and default transports
    let _manager = NetworkManager::new();
    Ok(())
}

pub async fn stop() -> Result<(), &'static str> {
    println!("Network interface stopping");
    Ok(())
}

// Directory service implementation
#[derive(Default)]
pub struct DirectoryService {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl DirectoryService {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn store(&self, key: &str, data: &[u8]) -> Result<(), DsmError> {
        let mut store = self.store.lock().map_err(|_| DsmError::LockError)?;
        store.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    pub fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, DsmError> {
        let store = self.store.lock().map_err(|_| DsmError::LockError)?;
        Ok(store.get(key).cloned())
    }

    pub fn remove(&self, key: &str) -> Result<(), DsmError> {
        let mut store = self.store.lock().map_err(|_| DsmError::LockError)?;
        store.remove(key);
        Ok(())
    }
}

#[cfg(feature = "bluetooth")]
pub struct BluetoothNetwork {
    device_id: String,
    connected: bool,
    directory: DirectoryService,
    peers: HashMap<String, String>, // Peer ID to Bluetooth address mapping
}

#[cfg(feature = "bluetooth")]
impl BluetoothNetwork {
    pub fn new(device_id: String) -> Self {
        Self {
            device_id,
            connected: false,
            directory: DirectoryService::new(),
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, peer_id: &str, bt_address: &str) {
        self.peers
            .insert(peer_id.to_string(), bt_address.to_string());
    }
}

#[cfg(feature = "bluetooth")]
#[async_trait]
impl NetworkInterface for BluetoothNetwork {
    async fn connect(&mut self) -> Result<(), DsmError> {
        // Simulate Bluetooth connection
        println!(
            "Connecting to Bluetooth network with device ID: {}",
            self.device_id
        );
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), DsmError> {
        println!("Disconnecting from Bluetooth network");
        self.connected = false;
        Ok(())
    }

    async fn send(&self, peer_id: &str, data: &[u8]) -> Result<(), DsmError> {
        if !self.connected {
            return Err(DsmError::Network {
                context: "Not connected to Bluetooth network".into(),
                source: None,
            });
        }

        if !self.peers.contains_key(peer_id) {
            return Err(DsmError::Network {
                context: format!("Unknown Bluetooth peer: {}", peer_id),
                source: None,
            });
        }

        println!(
            "Sending {} bytes via Bluetooth to peer {}",
            data.len(),
            peer_id
        );
        Ok(())
    }

    async fn receive(&self) -> Result<(String, Vec<u8>), DsmError> {
        if !self.connected {
            return Err(DsmError::Network {
                context: "Not connected to Bluetooth network".into(),
                source: None,
            });
        }

        // Simulate receiving from the first peer in our list
        if let Some((peer_id, _)) = self.peers.iter().next() {
            return Ok((peer_id.clone(), b"Bluetooth received data".to_vec()));
        }

        Err(DsmError::Network {
            context: "No Bluetooth peers available".into(),
            source: None,
        })
    }

    async fn publish(&self, key: &str, data: &[u8]) -> Result<(), DsmError> {
        // Store in local directory service (for offline usage)
        self.directory.store(key, data)
    }

    async fn retrieve(&self, key: &str) -> Result<Vec<u8>, DsmError> {
        let result = self.directory.retrieve(key)?;
        result.ok_or_else(|| DsmError::not_found("key", Some(key.to_string())))
    }

    async fn is_peer_online(&self, peer_id: &str) -> Result<bool, DsmError> {
        Ok(self.connected && self.peers.contains_key(peer_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_message_creation() {
        let message_type = MessageType::StateUpdate;
        let payload = b"test payload";
        let signer = "test_signer";
        let signature = b"test_signature";

        let message = NetworkMessage::new(message_type, payload, signer, signature);

        assert_eq!(message.version, 1);
        assert!(matches!(message.message_type, MessageType::StateUpdate));
        assert_eq!(message.signatures.len(), 1);
        assert_eq!(message.signatures[0].signer, "test_signer");
    }

    #[tokio::test]
    async fn test_directory_service() {
        let directory = DirectoryService::new();
        let key = "test_key";
        let data = b"test_data";

        directory.store(key, data).expect("Failed to store data");

        let retrieved = directory.retrieve(key).expect("Failed to retrieve data");
        assert_eq!(retrieved, Some(data.to_vec()));

        directory.remove(key).expect("Failed to remove data");
        let empty_result = directory
            .retrieve(key)
            .expect("Failed to check after removal");
        assert_eq!(empty_result, None);
    }

    #[tokio::test]
    async fn test_network_manager() {
        let mut manager = NetworkManager::new();

        assert!(!manager.connected);

        // Set preferred transport
        manager.set_preferred_transport(TransportProtocol::Internet);

        // Attempt connection
        let result = manager.connect().await;
        assert!(result.is_err());
        assert!(!manager.connected);
    }
}
