// filepath: /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/dsm-storage-node/src/client/mod.rs
// DSM Storage Node Client Module
//
// This module provides client-side functionality for interfacing with
// storage nodes in the DSM network.

use crate::error::{Result, StorageNodeError};
use base64::Engine;
use serde::{Deserialize, Serialize};

use tokio::sync::RwLock;
use std::collections::HashMap;
use url::Url;

#[cfg(feature = "reqwest")]
use std::time::Duration;

/// Default timeout value for storage node requests (30 seconds)
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

/// Storage node client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageNodeClientConfig {
    /// Storage node base URL
    pub base_url: String,
    
    /// API token (if required)
    pub api_token: Option<String>,
    
    /// Request timeout in seconds
    pub timeout_seconds: u64,
}

impl Default for StorageNodeClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080".to_string(),
            api_token: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }
}

/// Storage node client with full HTTP capabilities
#[cfg(feature = "reqwest")]
pub struct StorageNodeClient {
    /// HTTP client for network operations
    http_client: reqwest::Client,
    
    /// Base URL of the storage node
    base_url: Url,
    
    /// API token for authentication
    api_token: Option<String>,
    
    /// Cache for recently accessed data
    cache: RwLock<HashMap<String, Vec<u8>>>,
}

/// Storage node client with minimal functionality when reqwest is disabled
#[cfg(not(feature = "reqwest"))]
pub struct StorageNodeClient {
    /// Base URL of the storage node
    base_url: Url,
    
    /// API token for authentication
    api_token: Option<String>,
    
    /// Cache for recently accessed data
    cache: RwLock<HashMap<String, Vec<u8>>>,
}

#[cfg(feature = "reqwest")]
impl StorageNodeClient {
    /// Create a new storage node client with default configuration
    ///
    /// # Arguments
    /// * `config` - Client configuration including base URL and authentication
    ///
    /// # Returns
    /// * `Result<Self, StorageNodeError>` - The initialized client or an error
    pub fn new(config: StorageNodeClientConfig) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds.max(1)))
            .build()
            .map_err(|e| StorageNodeError::Network(format!("Failed to create HTTP client: {}", e)))?;

        let base_url = Url::parse(&config.base_url)
            .map_err(|e| StorageNodeError::Config(format!("Invalid base URL: {}", e)))?;

        Ok(Self {
            http_client,
            base_url,
            api_token: config.api_token,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Check if the storage node is healthy by pinging its health endpoint
    ///
    /// # Returns
    /// * `Result<bool>` - Whether the storage node is healthy
    pub async fn check_health(&self) -> Result<bool> {
        let url = self
            .base_url
            .join("health")
            .map_err(|e| StorageNodeError::Network(format!("Failed to create URL: {}", e)))?;

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| StorageNodeError::Network(format!("Failed to send request: {}", e)))?;

        Ok(response.status().is_success())
    }

    /// Store data in the storage node
    ///
    /// # Arguments
    /// * `key` - Unique identifier for the data
    /// * `data` - Binary data to store
    /// * `ttl` - Optional time-to-live in seconds
    ///
    /// # Returns
    /// * `Result<()>` - Success or an error
    pub async fn store_data(&self, key: &str, data: &[u8], ttl: Option<u64>) -> Result<()> {
        let url = self
            .base_url
            .join("data")
            .map_err(|e| StorageNodeError::Network(format!("Failed to create URL: {}", e)))?;

        let mut builder = self.http_client.post(url);

        if let Some(token) = &self.api_token {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }

        // Construct the payload
        let mut payload = HashMap::<&str, String>::new();
        payload.insert("key", key.to_string());
        let encoded_data = base64::engine::general_purpose::STANDARD.encode(data);
        payload.insert("data", encoded_data);
        
        if let Some(ttl_value) = ttl {
            payload.insert("ttl", ttl_value.to_string());
        }

        let response = builder
            .json(&payload)
            .send()
            .await
            .map_err(|e| StorageNodeError::Network(format!("Failed to send request: {}", e)))?;
            
        if !response.status().is_success() {
            return Err(StorageNodeError::Network(format!(
                "Storage node returned error: {}",
                response.status()
            )));
        }
        
        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), data.to_vec());
        
        Ok(())
    }

    /// Retrieve data from the storage node
    ///
    /// # Arguments
    /// * `key` - Unique identifier for the data
    ///
    /// # Returns
    /// * `Result<Option<Vec<u8>>>` - The data if found
    pub async fn retrieve_data(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(data) = cache.get(key) {
                return Ok(Some(data.clone()));
            }
        }

        // Fetch from storage node
        let url = self
            .base_url
            .join(&format!("data/{}", key))
            .map_err(|e| StorageNodeError::Network(format!("Failed to create URL: {}", e)))?;

        let mut builder = self.http_client.get(url);

        if let Some(token) = &self.api_token {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }

        let response = builder
            .send()
            .await
            .map_err(|e| StorageNodeError::Network(format!("Failed to send request: {}", e)))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(StorageNodeError::Network(format!(
                "Storage node returned error: {}",
                response.status()
            )));
        }

        // Parse response
        let data = response
            .bytes()
            .await
            .map_err(|e| StorageNodeError::Network(format!("Failed to read response: {}", e)))?
            .to_vec();

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), data.clone());

        Ok(Some(data))
    }

    /// Delete data from the storage node
    ///
    /// # Arguments
    /// * `key` - Unique identifier for the data
    ///
    /// # Returns
    /// * `Result<bool>` - Whether the data was deleted
    pub async fn delete_data(&self, key: &str) -> Result<bool> {
        let url = self
            .base_url
            .join(&format!("data/{}", key))
            .map_err(|e| StorageNodeError::Network(format!("Failed to create URL: {}", e)))?;

        let mut builder = self.http_client.delete(url);

        if let Some(token) = &self.api_token {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }

        let response = builder
            .send()
            .await
            .map_err(|e| StorageNodeError::Network(format!("Failed to send request: {}", e)))?;

        // 404 means it didn't exist, which isn't an error for delete
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if !response.status().is_success() {
            return Err(StorageNodeError::Network(format!(
                "Storage node returned error: {}",
                response.status()
            )));
        }

        // Update cache
        let mut cache = self.cache.write().await;
        cache.remove(key);

        Ok(true)
    }

    /// Check if data exists in the storage node
    ///
    /// # Arguments
    /// * `key` - Unique identifier for the data
    ///
    /// # Returns
    /// * `Result<bool>` - Whether the data exists
    pub async fn exists_data(&self, key: &str) -> Result<bool> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if cache.contains_key(key) {
                return Ok(true);
            }
        }

        // Check storage node
        let url = self
            .base_url
            .join(&format!("data/{}/exists", key))
            .map_err(|e| StorageNodeError::Network(format!("Failed to create URL: {}", e)))?;

        let mut builder = self.http_client.get(url);

        if let Some(token) = &self.api_token {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }

        let response = builder
            .send()
            .await
            .map_err(|e| StorageNodeError::Network(format!("Failed to send request: {}", e)))?;

        Ok(response.status().is_success())
    }
}

#[cfg(not(feature = "reqwest"))]
impl StorageNodeClient {
    /// Create a new storage node client with minimal capabilities
    pub fn new(config: StorageNodeClientConfig) -> Result<Self> {
        let base_url = Url::parse(&config.base_url)
            .map_err(|e| StorageNodeError::Config(format!("Invalid base URL: {}", e)))?;

        Ok(Self {
            base_url,
            api_token: config.api_token,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Functions below return errors when reqwest is disabled
    
    pub async fn check_health(&self) -> Result<bool> {
        Err(StorageNodeError::Internal)
    }

    pub async fn store_data(&self, _key: &str, _data: &[u8], _ttl: Option<u64>) -> Result<()> {
        Err(StorageNodeError::Internal)
    }

    pub async fn retrieve_data(&self, _key: &str) -> Result<Option<Vec<u8>>> {
        Err(StorageNodeError::Internal)
    }

    pub async fn delete_data(&self, _key: &str) -> Result<bool> {
        Err(StorageNodeError::Internal)
    }

    pub async fn exists_data(&self, _key: &str) -> Result<bool> {
        Err(StorageNodeError::Internal)
    }
}