// P2P communication implementation for DSM

use crate::types::error::DsmError;
use crate::types::state_types::State;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

lazy_static! {
    static ref STOP_P2P_LOOP: AtomicBool = AtomicBool::new(false);
}

/// Custom message type for P2P communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    StateSync { state_id: u64, data: Vec<u8> },
    // Add more message types as needed
}

/// P2P network manager
#[derive(Debug)]
pub struct P2PNetwork {
    /// Connected peers
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    /// Channel for incoming messages
    message_rx: mpsc::Receiver<(String, Vec<u8>)>,
    /// Channel for outgoing messages
    message_tx: mpsc::Sender<(String, Vec<u8>)>,
    /// Maximum message size
    max_message_size: usize,
}

/// Represents a connection to a peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: String,
    pub last_state_number: u64,
    pub public_key: Option<Vec<u8>>,
}

impl P2PNetwork {
    /// Create a new P2P network manager
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<(String, Vec<u8>)>(100);
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_rx: rx,
            message_tx: tx,
            max_message_size: 16384, // 16KB limit
        }
    }

    /// Start the P2P network
    pub async fn start(&self, listen_addr: &str) -> Result<(), DsmError> {
        // In a real implementation, this would start listeners and connection managers
        println!("Starting P2P network on {}", listen_addr);

        // Start a background task to handle incoming connections
        let peers = self.peers.clone();
        let tx = self.message_tx.clone();
        tokio::spawn(async move {
            // This would actually accept incoming connections
            // For now, just simulate a peer connecting every 5 seconds
            loop {
                if STOP_P2P_LOOP.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                // Simulate an incoming connection
                let peer_id = format!("peer-{}", rand::random::<u16>());

                let mut peers_write = peers.write().await;
                peers_write.insert(
                    peer_id.clone(),
                    PeerInfo {
                        address: format!("192.168.1.{}", rand::random::<u8>()),
                        last_state_number: 0,
                        public_key: None,
                    },
                );

                // Notify about new connection
                println!("New peer connected: {}", peer_id);

                // Simulate receiving a message from this peer
                let message = b"Hello from new peer".to_vec();
                let _ = tx.send((peer_id.clone(), message)).await;
            }
        });

        Ok(())
    }

    /// Connect to a peer
    pub async fn connect(&self, peer_id: &str, address: &str) -> Result<(), DsmError> {
        // In a real implementation, this would establish a connection
        println!("Connecting to peer {} at {}", peer_id, address);

        let mut peers = self.peers.write().await;

        peers.insert(
            peer_id.to_string(),
            PeerInfo {
                address: address.to_string(),
                last_state_number: 0,
                public_key: None,
            },
        );

        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &str) -> Result<(), DsmError> {
        let mut peers = self.peers.write().await;
        if peers.remove(peer_id).is_none() {
            return Err(DsmError::not_found(
                "Peer",
                Some(format!("{} not found", peer_id)),
            ));
        }

        println!("Disconnected from peer {}", peer_id);
        Ok(())
    }

    /// Send a message to a peer
    pub async fn send_message(&self, peer_id: &str, message: &Message) -> Result<(), DsmError> {
        // Check if we're connected to this peer
        let peers = self.peers.read().await;
        if !peers.contains_key(peer_id) {
            return Err(DsmError::not_found(
                "Peer",
                Some(format!("{} not found", peer_id)),
            ));
        }

        // Serialize the message
        let _serialized = bincode::serialize(message)
            .map_err(|e| DsmError::serialization(e.to_string(), Some(e)))?;

        // In a real implementation, this would send over the network
        println!("Sending message to peer {}: {:?}", peer_id, message);

        // Simulate successful send
        Ok(())
    }

    /// Receive the next message
    pub async fn receive_message(&mut self) -> Option<(String, Message)> {
        // Try to receive a raw message from the channel
        if let Some((peer_id, data)) = self.message_rx.recv().await {
            // Deserialize the message
            match bincode::deserialize(&data) {
                Ok(message) => {
                    return Some((peer_id, message));
                }
                Err(e) => {
                    println!("Failed to deserialize message: {}", e);
                    return None;
                }
            }
        }

        None
    }

    /// Send state to a peer
    pub async fn send_state(&self, peer_id: &str, state: &State) -> Result<(), DsmError> {
        // Check if the peer exists
        let peers = self.peers.read().await;
        if !peers.contains_key(peer_id) {
            return Err(DsmError::not_found(
                "Peer",
                Some(format!("Peer {} not found", peer_id)),
            ));
        }

        // Check message size limit
        let serialized = bincode::serialize(state)
            .map_err(|e| DsmError::serialization(e.to_string(), Some(e)))?;

        if serialized.len() > self.max_message_size {
            return Err(DsmError::validation(
                format!(
                    "State size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    serialized.len(),
                    self.max_message_size
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // In a real implementation, this would send the state
        println!("Sending state {} to peer {}", state.id, peer_id);

        Ok(())
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast(&self, message: &Message) -> Result<(), DsmError> {
        let peers = self.peers.read().await;

        for peer_id in peers.keys() {
            // In a real implementation, we would actually send to each peer
            println!("Broadcasting message to peer {}: {:?}", peer_id, message);
        }

        Ok(())
    }

    /// Broadcast a state to all connected peers
    pub async fn broadcast_state(&self, state: &State) -> Result<(), DsmError> {
        let peers = self.peers.read().await;

        for peer_id in peers.keys() {
            // In a real implementation, we would actually send to each peer
            println!("Broadcasting state {} to peer {}", state.id, peer_id);
        }

        Ok(())
    }

    /// Get the number of connected peers
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Shutdown the P2P network
    pub async fn shutdown(&self) {
        STOP_P2P_LOOP.store(true, Ordering::Relaxed);
        println!("P2P network shutting down");
    }
}

impl Default for P2PNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_p2p_network() {
        let p2p = P2PNetwork::new();
        p2p.start("127.0.0.1:9000")
            .await
            .expect("Failed to start P2P");

        // Connect to a test peer
        p2p.connect("test-peer-1", "192.168.1.100")
            .await
            .expect("Failed to connect to peer");

        // Wait a moment for the background task to run
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        p2p.shutdown().await;
    }
}
