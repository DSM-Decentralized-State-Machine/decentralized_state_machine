// Network module for DSM Storage Node
//
// This module provides networking capabilities for communicating between storage nodes.

/// Factory for creating network clients
pub struct NetworkClientFactory;

impl NetworkClientFactory {
    /// Create a new network client from a storage node
    pub fn create_client(
        node: crate::types::StorageNode,
    ) -> Result<Arc<dyn NetworkClient + Send + Sync>> {
        // Create the network client implementation
        let client = HttpNetworkClient::new(node.id.clone(), 30000); // Default 30s timeout

        // Register the node itself
        let node_client = Arc::new(client);

        // Return the client
        Ok(node_client)
    }
}

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::error::{Result, StorageNodeError};
use crate::types::StorageNode;

/// Network client trait for communicating with other nodes
#[async_trait]
pub trait NetworkClient: Send + Sync {
    /// Send entries to another node
    async fn send_entries(&self, node_id: String, entries: Vec<StateEntry>) -> Result<()>;

    /// Request entries from another node
    async fn request_entries(&self, node_id: String, keys: Vec<String>) -> Result<()>;

    /// Forward a PUT operation to another node
    async fn forward_put(&self, node_id: String, key: String, value: Vec<u8>) -> Result<()>;

    /// Forward a GET operation to another node
    async fn forward_get(&self, node_id: String, key: String) -> Result<Option<Vec<u8>>>;

    /// Forward a DELETE operation to another node
    async fn forward_delete(&self, node_id: String, key: String) -> Result<()>;

    /// Get the status of another node
    async fn get_node_status(&self, node_id: &str) -> Result<NodeStatus>;

    /// Join a cluster by contacting bootstrap nodes
    async fn join_cluster(&self, bootstrap_nodes: Vec<String>) -> Result<Vec<StorageNode>>;

    /// Send a message to another node for topology propagation
    fn send_message(
        &self,
        address: std::net::SocketAddr,
        message_id: [u8; 32],
        data: Vec<u8>,
        ttl: u8,
    ) -> Result<()>;

    /// Find nodes close to the target ID
    fn find_nodes(&self, target: &crate::storage::topology::NodeId) -> Result<()>;

    /// Find nodes in a specific geographic region
    fn find_nodes_in_region(&self, region: u8) -> Result<()>;
}

/// Implementation of NetworkClient using HTTP/REST
pub struct HttpNetworkClient {
    /// Local node ID
    node_id: String,
    /// HTTP client
    client: reqwest::Client,
    /// Node registry mapping node IDs to endpoints
    node_registry: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    /// Default timeout for network operations
    timeout: Duration,
}

impl HttpNetworkClient {
    /// Create a new HTTP network client
    pub fn new(node_id: String, timeout_ms: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .unwrap_or_default();

        Self {
            node_id,
            client,
            node_registry: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Register a node endpoint
    pub async fn register_node(&self, node_id: String, endpoint: String) {
        let mut registry = self.node_registry.write().await;
        registry.insert(node_id, endpoint);
    }

    /// Get the endpoint for a node
    async fn get_endpoint(&self, node_id: &str) -> Result<String> {
        let registry = self.node_registry.read().await;
        registry
            .get(node_id)
            .cloned()
            .ok_or_else(|| StorageNodeError::NodeManagement(format!("Unknown node: {}", node_id)))
    }
}

#[async_trait]
impl NetworkClient for HttpNetworkClient {
    async fn send_entries(&self, node_id: String, entries: Vec<StateEntry>) -> Result<()> {
        let endpoint = self.get_endpoint(&node_id).await?;
        let url = format!("{}/entries", endpoint);

        debug!("Sending {} entries to node {}", entries.len(), node_id);

        let result = timeout(self.timeout, self.client.post(&url).json(&entries).send())
            .await
            .map_err(|_| StorageNodeError::Timeout)?;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(StorageNodeError::Network(format!(
                        "Failed to send entries to {}: HTTP {}",
                        node_id,
                        response.status()
                    )))
                }
            }
            Err(_e) => Err(StorageNodeError::Network(format!(
                "Failed to send entries to {}: {}",
                node_id, _e
            ))),
        }
    }

    async fn request_entries(&self, node_id: String, keys: Vec<String>) -> Result<()> {
        let endpoint = self.get_endpoint(&node_id).await?;
        let url = format!("{}/entries/request", endpoint);

        debug!("Requesting {} entries from node {}", keys.len(), node_id);

        let result = timeout(self.timeout, self.client.post(&url).json(&keys).send())
            .await
            .map_err(|_| StorageNodeError::Timeout)?;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(StorageNodeError::Network(format!(
                        "Failed to request entries from {}: HTTP {}",
                        node_id,
                        response.status()
                    )))
                }
            }
            Err(_e) => Err(StorageNodeError::Network(format!(
                "Failed to request entries from {}: {}",
                node_id, _e
            ))),
        }
    }

    async fn forward_put(&self, node_id: String, key: String, value: Vec<u8>) -> Result<()> {
        let endpoint = self.get_endpoint(&node_id).await?;
        let url = format!("{}/data/{}", endpoint, key);

        debug!("Forwarding PUT for key {} to node {}", key, node_id);

        let result = timeout(self.timeout, self.client.put(&url).body(value).send())
            .await
            .map_err(|_| StorageNodeError::Timeout)?;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(StorageNodeError::Network(format!(
                        "Failed to forward PUT to {}: HTTP {}",
                        node_id,
                        response.status()
                    )))
                }
            }
            Err(_e) => Err(StorageNodeError::Network(format!(
                "Failed to forward PUT to {}: {}",
                node_id, _e
            ))),
        }
    }

    async fn forward_get(&self, node_id: String, key: String) -> Result<Option<Vec<u8>>> {
        let endpoint = self.get_endpoint(&node_id).await?;
        let url = format!("{}/data/{}", endpoint, key);

        debug!("Forwarding GET for key {} to node {}", key, node_id);

        let result = timeout(self.timeout, self.client.get(&url).send())
            .await
            .map_err(|_| StorageNodeError::Timeout)?;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    let bytes = response.bytes().await.map_err(|_e| {
                        StorageNodeError::Network(format!("Failed to read response body: {}", _e))
                    })?;
                    Ok(Some(bytes.to_vec()))
                } else if response.status() == reqwest::StatusCode::NOT_FOUND {
                    Ok(None)
                } else {
                    Err(StorageNodeError::Network(format!(
                        "Failed to forward GET to {}: HTTP {}",
                        node_id,
                        response.status()
                    )))
                }
            }
            Err(_e) => Err(StorageNodeError::Network(format!(
                "Failed to forward GET to {}: {}",
                node_id, _e
            ))),
        }
    }

    async fn forward_delete(&self, node_id: String, key: String) -> Result<()> {
        let endpoint = self.get_endpoint(&node_id).await?;
        let url = format!("{}/data/{}", endpoint, key);

        debug!("Forwarding DELETE for key {} to node {}", key, node_id);

        let result = timeout(self.timeout, self.client.delete(&url).send())
            .await
            .map_err(|_| StorageNodeError::Timeout)?;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(StorageNodeError::Network(format!(
                        "Failed to forward DELETE to {}: HTTP {}",
                        node_id,
                        response.status()
                    )))
                }
            }
            Err(_e) => Err(StorageNodeError::Network(format!(
                "Failed to forward DELETE to {}: {}",
                node_id, _e
            ))),
        }
    }

    async fn get_node_status(&self, node_id: &str) -> Result<NodeStatus> {
        let endpoint = self.get_endpoint(node_id).await?;
        let url = format!("{}/status", endpoint);

        debug!("Getting status from node {}", node_id);

        let result = timeout(self.timeout, self.client.get(&url).send())
            .await
            .map_err(|_| StorageNodeError::Timeout)?;

        match result {
            Ok(response) => {
                if response.status().is_success() {
                    let status = response.json::<NodeStatus>().await.map_err(|_e| {
                        StorageNodeError::Serialization(format!(
                            "Failed to parse node status: {}",
                            _e
                        ))
                    })?;
                    Ok(status)
                } else {
                    Err(StorageNodeError::Network(format!(
                        "Failed to get status from {}: HTTP {}",
                        node_id,
                        response.status()
                    )))
                }
            }
            Err(_e) => Err(StorageNodeError::Network(format!(
                "Failed to get status from {}: {}",
                node_id, _e
            ))),
        }
    }

    async fn join_cluster(&self, bootstrap_nodes: Vec<String>) -> Result<Vec<StorageNode>> {
        info!("Joining cluster via bootstrap nodes: {:?}", bootstrap_nodes);
        let mut nodes = Vec::new();

        for node_addr in bootstrap_nodes {
            let url = format!("http://{}/join", node_addr);
            debug!("Sending join request to {}", url);

            match timeout(
                self.timeout,
                self.client
                    .post(&url)
                    .json(&JoinRequest {
                        node_id: self.node_id.clone(),
                    })
                    .send(),
            )
            .await
            {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        match response.json::<JoinResponse>().await {
                            Ok(join_response) => {
                                info!(
                                    "Successfully joined cluster via {} - received {} nodes",
                                    node_addr,
                                    join_response.nodes.len()
                                );
                                nodes = join_response.nodes;
                                break;
                            }
                            Err(_e) => {
                                warn!("Failed to parse join response from {}: {}", node_addr, _e);
                                continue;
                            }
                        }
                    } else {
                        warn!(
                            "Failed to join via {}: HTTP {}",
                            node_addr,
                            response.status()
                        );
                        continue;
                    }
                }
                Ok(Err(_)) => {
                    warn!("Failed to connect to bootstrap node {}", node_addr);
                    continue;
                }
                Err(_) => {
                    warn!("Timeout connecting to bootstrap node {}", node_addr);
                    continue;
                }
            }
        }

        if nodes.is_empty() {
            Err(StorageNodeError::NodeManagement(
                "Failed to join cluster via any bootstrap node".to_string(),
            ))
        } else {
            // Register nodes in the registry
            let mut registry = self.node_registry.write().await;
            for node in &nodes {
                registry.insert(node.id.clone(), node.endpoint.clone());
            }
            Ok(nodes)
        }
    }

    fn send_message(
        &self,
        address: std::net::SocketAddr,
        message_id: [u8; 32],
        data: Vec<u8>,
        ttl: u8,
    ) -> Result<()> {
        // Create a future for the async send_message operation
        let future = async {
            let url = format!("http://{}/message", address);
            debug!("Sending message {} to {}", hex::encode(message_id), address);

            // Prepare the message payload
            let payload = MessagePayload {
                message_id,
                sender_id: self.node_id.clone(),
                data,
                ttl,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };

            // Send the message with timeout
            let result = timeout(self.timeout, self.client.post(&url).json(&payload).send()).await;

            match result {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        Ok(())
                    } else {
                        Err(StorageNodeError::Network(format!(
                            "Failed to send message to {}: HTTP {}",
                            address,
                            response.status()
                        )))
                    }
                }
                Ok(Err(_e)) => Err(StorageNodeError::Network(format!(
                    "Failed to send message to {}: {}",
                    address, _e
                ))),
                Err(_) => Err(StorageNodeError::Timeout),
            }
        };

        // Execute the future in a synchronous context
        // This is a workaround since the trait method is not async
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(future),
            Err(_) => {
                // Create a new runtime if we're not in a tokio context
                let rt = tokio::runtime::Runtime::new().map_err(|_e| StorageNodeError::Internal)?;
                rt.block_on(future)
            }
        }
    }

    fn find_nodes(&self, target: &crate::storage::topology::NodeId) -> Result<()> {
        // Create a future for the async find_nodes operation
        let target_clone = target.clone();
        let future = async move {
            debug!("Finding nodes close to target ID: {}", target_clone);

            // Get immediate neighbors to query
            let registry = self.node_registry.read().await;
            let neighbors: Vec<(String, String)> = registry.clone().into_iter().take(3).collect();

            if neighbors.is_empty() {
                return Err(StorageNodeError::NodeManagement(
                    "No known nodes to query".to_string(),
                ));
            }

            // Query each neighbor for nodes close to the target
            for (node_id, endpoint) in neighbors {
                let url = format!("{}/find_nodes/{}", endpoint, target_clone);

                match timeout(self.timeout, self.client.get(&url).send()).await {
                    Ok(Ok(response)) => {
                        if response.status().is_success() {
                            // Process response
                            debug!("Received response from node {} for find_nodes", node_id);
                        } else {
                            warn!(
                                "Failed find_nodes query to {}: HTTP {}",
                                node_id,
                                response.status()
                            );
                        }
                    }
                    Ok(Err(_)) => {
                        warn!("Failed to send find_nodes query to {}", node_id);
                    }
                    Err(_) => {
                        warn!("Timeout querying node {} for find_nodes", node_id);
                    }
                }
            }

            Ok(())
        };

        // Execute the future in a synchronous context
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(future),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new().map_err(|_| StorageNodeError::Internal)?;
                rt.block_on(future)
            }
        }
    }

    fn find_nodes_in_region(&self, region: u8) -> Result<()> {
        // Create a future for the async find_nodes_in_region operation
        let future = async move {
            debug!("Finding nodes in region: {}", region);

            // Get some known nodes to query
            let registry = self.node_registry.read().await;
            let nodes: Vec<(String, String)> = registry.clone().into_iter().take(5).collect();

            if nodes.is_empty() {
                return Err(StorageNodeError::NodeManagement(
                    "No known nodes to query".to_string(),
                ));
            }

            // Query each node for nodes in the specified region
            for (node_id, endpoint) in nodes {
                let url = format!("{}/find_nodes_in_region/{}", endpoint, region);

                match timeout(self.timeout, self.client.get(&url).send()).await {
                    Ok(Ok(response)) => {
                        if response.status().is_success() {
                            debug!("Received response from node {} for region query", node_id);
                        } else {
                            warn!(
                                "Failed region query to {}: HTTP {}",
                                node_id,
                                response.status()
                            );
                        }
                    }
                    Ok(Err(_)) => {
                        warn!("Failed to send region query to {}", node_id);
                    }
                    Err(_) => {
                        warn!("Timeout querying node {} for region", node_id);
                    }
                }
            }

            Ok(())
        };

        // Execute the future in a synchronous context
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(future),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new().map_err(|_| StorageNodeError::Internal)?;
                rt.block_on(future)
            }
        }
    }
}

// Simplified mock implementation for testing
#[cfg(test)]
pub struct MockNetworkClient {
    node_id: String,
    responses: std::sync::Mutex<HashMap<String, Vec<u8>>>,
}

#[cfg(test)]
impl Default for MockNetworkClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl MockNetworkClient {
    pub fn new() -> Self {
        Self {
            node_id: "mock-node".to_string(),
            responses: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn with_node_id(node_id: String) -> Self {
        Self {
            node_id,
            responses: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn add_response(&self, key: String, value: Vec<u8>) {
        let mut responses = self.responses.lock().unwrap();
        responses.insert(key, value);
    }
}

#[cfg(test)]
#[async_trait]
impl NetworkClient for MockNetworkClient {
    async fn send_entries(&self, _node_id: String, _entries: Vec<StateEntry>) -> Result<()> {
        Ok(())
    }

    async fn request_entries(&self, _node_id: String, _keys: Vec<String>) -> Result<()> {
        Ok(())
    }

    async fn forward_put(&self, _node_id: String, key: String, value: Vec<u8>) -> Result<()> {
        let mut responses = self.responses.lock().unwrap();
        responses.insert(key, value);
        Ok(())
    }

    async fn forward_get(&self, _node_id: String, key: String) -> Result<Option<Vec<u8>>> {
        let responses = self.responses.lock().unwrap();
        Ok(responses.get(&key).cloned())
    }

    async fn forward_delete(&self, _node_id: String, key: String) -> Result<()> {
        let mut responses = self.responses.lock().unwrap();
        responses.remove(&key);
        Ok(())
    }

    async fn get_node_status(&self, _node_id: &str) -> Result<NodeStatus> {
        Ok(NodeStatus {
            node_id: self.node_id.clone(),
            status: "ok".to_string(),
            uptime: 0,
            version: "0.1.0".to_string(),
            metrics: HashMap::new(),
        })
    }

    async fn join_cluster(&self, _bootstrap_nodes: Vec<String>) -> Result<Vec<StorageNode>> {
        Ok(vec![StorageNode {
            id: "mock-node-1".to_string(),
            name: "Mock Node 1".to_string(),
            region: "mock-region".to_string(),
            public_key: "mock-key".to_string(),
            endpoint: "http://localhost:8000".to_string(),
        }])
    }

    fn send_message(
        &self,
        _address: std::net::SocketAddr,
        _message_id: [u8; 32],
        _data: Vec<u8>,
        _ttl: u8,
    ) -> Result<()> {
        Ok(())
    }

    fn find_nodes(&self, _target: &crate::storage::topology::NodeId) -> Result<()> {
        Ok(())
    }

    fn find_nodes_in_region(&self, _region: u8) -> Result<()> {
        Ok(())
    }
}

/// Entry for state synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEntry {
    /// Unique key for the entry
    pub key: String,
    /// Value data
    pub value: Vec<u8>,
    /// Vector clock for conflict resolution
    pub vector_clock: VectorClock,
    /// Timestamp of the entry
    pub timestamp: u64,
    /// Origin node ID
    pub origin_node: String,
}

/// Join request sent when joining a cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    /// ID of the node trying to join
    pub node_id: String,
}

/// Response to a join request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    /// List of nodes in the cluster
    pub nodes: Vec<StorageNode>,
}

/// Node status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Node ID
    pub node_id: String,
    /// Status string (e.g., "ok", "degraded")
    pub status: String,
    /// Uptime in seconds
    pub uptime: u64,
    /// Version string
    pub version: String,
    /// Additional metrics
    pub metrics: HashMap<String, String>,
}

// Message payload for network propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    /// Unique message identifier
    pub message_id: [u8; 32],
    /// Node ID of the sender
    pub sender_id: String,
    /// Message data
    pub data: Vec<u8>,
    /// Time-to-live counter
    pub ttl: u8,
    /// Timestamp
    pub timestamp: u64,
}

// Re-export vector clock for convenience
use crate::storage::vector_clock::VectorClock;
