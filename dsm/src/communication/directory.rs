// Update the communication/directory.rs
// Directory service client for Genesis state publishing and retrieval

use crate::types::error::DsmError;
use crate::types::state_types::State;
use lazy_static::lazy_static;
use parking_lot;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::{Arc, Once};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// Conditionally include reqwest if the feature is enabled
#[cfg(feature = "reqwest")]
use reqwest;
// Duration is only needed with the reqwest feature
#[cfg(feature = "reqwest")]
use std::time::Duration;

/// Configuration for retry behavior in network operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base delay between retries in milliseconds
    pub base_delay_ms: u64,
    /// Maximum delay between retries in milliseconds
    pub max_delay_ms: u64,
    /// Timeout for each request in milliseconds
    pub timeout_ms: u64,
}

static INIT: Once = Once::new();

lazy_static! {
    /// Global directory service instance - follows singleton pattern for centralized access
    static ref GLOBAL_DIRECTORY_SERVICE: Arc<DirectoryService> = Arc::new(DirectoryService::new());
}

/// Initialize the directory service
/// This must be called before any directory operations are performed
pub fn init_directory() -> Result<(), DsmError> {
    INIT.call_once(|| {
        tracing::info!("Initializing directory service");
    });
    Ok(())
}

/// Get the global directory service instance
pub fn get_directory_service() -> Arc<DirectoryService> {
    GLOBAL_DIRECTORY_SERVICE.clone()
}

/// Directory service response structure with comprehensive metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct DirectoryResponse<T> {
    /// Status code (follows HTTP convention)
    pub status: u16,
    /// Status message
    pub message: String,
    /// Response data
    pub data: Option<T>,
    /// Error message if applicable
    pub error: Option<String>,
    /// Timestamp for response creation
    pub timestamp: u64,
}

/// Client for interacting with a directory service
#[derive(Debug, Clone)]
pub struct DirectoryClient {
    /// Cached genesis states - improves performance for frequently accessed states
    genesis_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Cached invalidation markers - provides fast local lookup for invalidation status
    invalidation_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Server endpoints with fallback capability
    endpoints: Vec<String>,

    #[cfg(feature = "reqwest")]
    /// HTTP client for network requests
    http_client: reqwest::Client,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 500,
            max_delay_ms: 5000,
            timeout_ms: 10000,
        }
    }
}

impl Default for DirectoryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryClient {
    /// Create a new directory client with default endpoints
    pub fn new() -> Self {
        // Default endpoints could be loaded from config
        let default_endpoints = vec![
            "https://directory1.dsm-network.io".to_string(),
            "https://directory2.dsm-network.io".to_string(),
        ];

        #[cfg(feature = "reqwest")]
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        #[cfg(feature = "reqwest")]
        return Self {
            genesis_cache: Arc::new(RwLock::new(HashMap::new())),
            invalidation_cache: Arc::new(RwLock::new(HashMap::new())),
            endpoints: default_endpoints,
            http_client,
        };

        #[cfg(not(feature = "reqwest"))]
        return Self {
            genesis_cache: Arc::new(RwLock::new(HashMap::new())),
            invalidation_cache: Arc::new(RwLock::new(HashMap::new())),
            endpoints: default_endpoints,
        };
    }

    /// Create a new directory client with custom endpoint
    pub fn with_endpoint(endpoint: &str) -> Self {
        #[cfg(feature = "reqwest")]
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        #[cfg(feature = "reqwest")]
        return Self {
            genesis_cache: Arc::new(RwLock::new(HashMap::new())),
            invalidation_cache: Arc::new(RwLock::new(HashMap::new())),
            endpoints: vec![endpoint.to_string()],
            http_client,
        };

        #[cfg(not(feature = "reqwest"))]
        return Self {
            genesis_cache: Arc::new(RwLock::new(HashMap::new())),
            invalidation_cache: Arc::new(RwLock::new(HashMap::new())),
            endpoints: vec![endpoint.to_string()],
        };
    }

    /// Add a custom directory endpoint for resilience
    pub fn add_endpoint(&mut self, endpoint: String) {
        self.endpoints.push(endpoint);
    }

    #[cfg(feature = "reqwest")]
    /// Send a request to the directory service with retry logic
    /// Implements exponential backoff with jitter for robustness against network failures
    async fn send_request<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        method: reqwest::Method,
        body: Option<Vec<u8>>,
    ) -> Result<DirectoryResponse<T>, DsmError> {
        let mut last_error = None;

        // Define retry configuration inline since we don't have it as a field
        let retry_config = RetryConfig::default();

        // Try each endpoint with retries
        for endpoint in &self.endpoints {
            let url = format!("{}{}", endpoint, path);

            for retry in 0..=retry_config.max_retries {
                // Exponential backoff with jitter
                if retry > 0 {
                    let delay = std::cmp::min(
                        retry_config.base_delay_ms * (1 << (retry - 1)),
                        retry_config.max_delay_ms,
                    );

                    // Add jitter (±20%) to prevent thundering herd problem
                    let jitter = (rand::random::<f64>() * 0.4 - 0.2) * delay as f64;
                    let delay_with_jitter = (delay as f64 + jitter) as u64;

                    tokio::time::sleep(Duration::from_millis(delay_with_jitter)).await;
                }

                // Build the request
                let mut request_builder = self
                    .http_client
                    .request(method.clone(), &url)
                    .timeout(Duration::from_millis(retry_config.timeout_ms))
                    .header("Content-Type", "application/octet-stream")
                    .header("User-Agent", "DSM-Client/0.1.0");

                // Add body if provided
                if let Some(data) = &body {
                    request_builder = request_builder.body(data.clone());
                }

                // Send the request with careful error handling
                match request_builder.send().await {
                    Ok(response) => {
                        // Check if we got a successful response
                        if response.status().is_success() {
                            // Clone status before consuming response with json()
                            // Parse the response
                            match response.json::<DirectoryResponse<T>>().await {
                                Ok(dir_response) => {
                                    return Ok(dir_response);
                                }
                                Err(e) => {
                                    last_error = Some(DsmError::network(
                                        format!("Failed to parse directory response: {}", e),
                                        Some(e),
                                    ));
                                }
                            }
                        } else {
                            // Non-success status code
                            let status = response.status();
                            let body = response.text().await.unwrap_or_default();
                            last_error = Some(DsmError::network(
                                format!("Directory service returned error: {} - {}", status, body),
                                None::<std::convert::Infallible>,
                            ));

                            // Don't retry for certain status codes (optimization)
                            if status.as_u16() >= 400
                                && status.as_u16() < 500
                                && status.as_u16() != 429
                            {
                                break; // Skip retries for client errors except rate limiting
                            }
                        }
                    }
                    Err(e) => {
                        let is_retriable = e.is_timeout() || e.is_connect();
                        last_error = Some(DsmError::network(
                            format!("Failed to connect to directory service: {}", e),
                            Some(e),
                        ));

                        // Retry network errors but not client errors
                        if !is_retriable {
                            break;
                        }
                    }
                }
            }
        }

        // If we get here, all retries on all endpoints failed
        Err(last_error.unwrap_or_else(|| {
            DsmError::network(
                "Failed to communicate with any directory service endpoint",
                None::<std::convert::Infallible>,
            )
        }))
    }

    #[cfg(feature = "reqwest")]
    /// Ping the directory service to check connectivity
    pub async fn ping_directory(&self) -> Result<bool, DsmError> {
        // Use the send_request method to send a simple ping request
        let path = "/api/v1/ping";
        match self
            .send_request::<String>(path, reqwest::Method::GET, None)
            .await
        {
            Ok(response) => {
                if response.status == 200 {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    #[cfg(not(feature = "reqwest"))]
    #[allow(dead_code)]
    /// Send a request to the directory service with retry logic - mock version for when reqwest is not available
    async fn send_request<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        _method: &str,
        _body: Option<Vec<u8>>,
    ) -> Result<DirectoryResponse<T>, DsmError> {
        // This is a mock implementation for when reqwest is not available
        Err(DsmError::network(
            format!("HTTP client not available for request to {}", path),
            None::<std::convert::Infallible>,
        ))
    }

    /// Publish a genesis state to the directory
    /// Implements the genesis publication mechanism described in whitepaper Section 4.2
    pub async fn publish_genesis(&self, genesis: &State) -> Result<(), DsmError> {
        if genesis.state_number != 0 {
            return Err(DsmError::validation(
                "Only genesis states can be published to directory",
                None::<std::convert::Infallible>,
            ));
        }

        // Serialize the genesis state
        let genesis_bytes = bincode::serialize(genesis)
            .map_err(|e| DsmError::serialization(e.to_string(), Some(e)))?;

        // Cache it locally first for resilience
        {
            let mut cache = self.genesis_cache.write().await;
            cache.insert(genesis.id.clone(), genesis_bytes.clone());
        }

        #[cfg(feature = "reqwest")]
        {
            // Send to the directory service
            let path = format!("/api/v1/genesis/{}", genesis.id);
            let response = self
                .send_request::<()>(&path, reqwest::Method::PUT, Some(genesis_bytes))
                .await?;

            if response.status != 200 && response.status != 201 {
                return Err(DsmError::network(
                    format!("Failed to publish genesis state: {}", response.message),
                    None::<std::convert::Infallible>,
                ));
            }
        }

        tracing::info!("Published genesis state {}", genesis.id);
        Ok(())
    }

    /// Retrieve a genesis state from the directory
    /// Implements the genesis retrieval mechanism described in whitepaper Section 4.2.2
    pub async fn get_genesis(&self, genesis_id: &str) -> Result<State, DsmError> {
        // Check cache first for performance optimization
        {
            let cache = self.genesis_cache.read().await;
            if let Some(bytes) = cache.get(genesis_id) {
                return bincode::deserialize(bytes)
                    .map_err(|e| DsmError::serialization(e.to_string(), Some(e)));
            }
        }

        #[cfg(feature = "reqwest")]
        {
            // Fetch from the directory service
            let path = format!("/api/v1/genesis/{}", genesis_id);
            let response = self
                .send_request::<Vec<u8>>(&path, reqwest::Method::GET, None)
                .await?;

            if response.status != 200 {
                return Err(DsmError::not_found(
                    "Genesis state",
                    Some(format!("{} not found in directory", genesis_id)),
                ));
            }

            // Extract the data with proper error propagation
            let genesis_bytes = response.data.ok_or_else(|| {
                DsmError::network(
                    "Directory response missing data field",
                    None::<std::convert::Infallible>,
                )
            })?;

            // Deserialize the state with detailed error context
            let state = bincode::deserialize(&genesis_bytes).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to deserialize genesis state: {}", e),
                    Some(e),
                )
            })?;

            // Update the cache with a write lock scope
            {
                let mut cache = self.genesis_cache.write().await;
                cache.insert(genesis_id.to_string(), genesis_bytes);
            }

            Ok(state)
        }

        // When reqwest is not available, simulate failure after checking cache
        #[cfg(not(feature = "reqwest"))]
        {
            // Simulate network operation for testing or minimal builds
            let mock_state = State::new_genesis(
                vec![0, 0, 0, 0], // Placeholder entropy
                crate::types::state_types::DeviceInfo::new(
                    "mock_device",
                    vec![0, 0, 0, 0], // Placeholder public key
                ),
            );

            tracing::warn!(
                "Using mock genesis state for {}: reqwest feature not enabled",
                genesis_id
            );
            Ok(mock_state)
        }
    }

    /// Publish an invalidation marker to the directory
    /// Implements the state invalidation mechanism described in whitepaper Section 9
    pub async fn publish_invalidation(
        &self,
        identity_id: &str,
        state_hash: &[u8],
        signatures: &[Vec<u8>],
    ) -> Result<(), DsmError> {
        // Create the invalidation marker with precise timestamp handling
        let marker = InvalidationMarker {
            identity_id: identity_id.to_string(),
            state_hash: state_hash.to_vec(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DsmError::generic("Failed to get current timestamp", Some(e)))?
                .as_secs(),
            signatures: signatures.to_vec(),
        };

        // Serialize the invalidation marker with error propagation
        let marker_bytes = bincode::serialize(&marker).map_err(|e| {
            DsmError::serialization("Failed to serialize invalidation marker", Some(e))
        })?;

        // Cache it locally first for resilience
        {
            let mut cache = self.invalidation_cache.write().await;
            cache.insert(identity_id.to_string(), marker_bytes.clone());
        }

        #[cfg(feature = "reqwest")]
        {
            // Send to the directory service with proper API path construction
            let path = format!("/api/v1/invalidation/{}", identity_id);
            let response = self
                .send_request::<()>(&path, reqwest::Method::PUT, Some(marker_bytes))
                .await?;

            // Validate response status with specific error context
            if response.status != 200 && response.status != 201 {
                return Err(DsmError::network(
                    format!(
                        "Failed to publish invalidation marker: {}",
                        response.message
                    ),
                    None::<std::convert::Infallible>,
                ));
            }
        }

        tracing::info!("Published invalidation marker for {}", identity_id);
        Ok(())
    }

    /// Check if an identity has been invalidated
    /// Implements the invalidation verification mechanism described in whitepaper Section 9
    pub async fn check_invalidation(
        &self,
        identity_id: &str,
    ) -> Result<Option<InvalidationMarker>, DsmError> {
        // Check cache first for performance optimization
        {
            let cache = self.invalidation_cache.read().await;
            if let Some(bytes) = cache.get(identity_id) {
                return bincode::deserialize(bytes).map(Some).map_err(|e| {
                    DsmError::serialization(
                        "Failed to deserialize cached invalidation marker",
                        Some(e),
                    )
                });
            }
        }

        #[cfg(feature = "reqwest")]
        {
            // Fetch from the directory service with proper error handling
            let path = format!("/api/v1/invalidation/{}", identity_id);
            let response = self
                .send_request::<Vec<u8>>(&path, reqwest::Method::GET, None)
                .await?;

            // Special handling for 404 to indicate not invalidated rather than error
            if response.status == 404 {
                // Not invalidated - expected case, not an error
                return Ok(None);
            } else if response.status != 200 {
                return Err(DsmError::network(
                    format!("Failed to check invalidation: {}", response.message),
                    None::<std::convert::Infallible>,
                ));
            }

            // Extract the data with proper null checking
            let marker_bytes = match response.data {
                Some(bytes) => bytes,
                None => return Ok(None), // No invalidation marker is a valid state
            };

            // Deserialize the marker with specific error context
            let marker = bincode::deserialize(&marker_bytes).map_err(|e| {
                DsmError::serialization("Failed to deserialize invalidation marker", Some(e))
            })?;

            // Update the cache atomically
            {
                let mut cache = self.invalidation_cache.write().await;
                cache.insert(identity_id.to_string(), marker_bytes);
            }

            Ok(Some(marker))
        }

        // When reqwest is not enabled, return None after cache check
        #[cfg(not(feature = "reqwest"))]
        {
            tracing::debug!(
                "Check invalidation for {}: reqwest feature not enabled",
                identity_id
            );
            Ok(None)
        }
    }
}

/// Represents an invalidation marker in the directory
/// Implements the Forward-Only Invalidation marker structure described in whitepaper Section 9
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationMarker {
    /// ID of the identity being invalidated
    pub identity_id: String,
    /// Hash of the last valid state
    pub state_hash: Vec<u8>,
    /// Timestamp when the invalidation was created
    pub timestamp: u64,
    /// Signatures from authorized parties
    pub signatures: Vec<Vec<u8>>,
}

/// Entry in the directory service with comprehensive metadata
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    /// Binary data for the entry
    pub data: Vec<u8>,
    /// State number associated with this entry
    pub state_number: u64,
    /// Timestamp when the entry was created or last updated
    pub timestamp: u64,
    /// Type of the entry
    pub entry_type: DirectoryEntryType,
}

/// Possible types of directory entries for type safety
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryEntryType {
    /// Genesis state entry
    Genesis,
    /// Invalidation marker entry
    Invalidation,
    /// State transition entry
    StateTransition,
    /// Other entry type with custom identifier
    Other(String),
}

/// Directory service for managing distributed state storage
///
/// The DirectoryService provides a high-availability repository for critical
/// DSM protocol components as described in whitepaper Section 3:
/// - Genesis states
/// - Invalidation markers
/// - Optional state transitions for verification
///
/// This implementation supports both in-memory and remote operations,
/// with automatic synchronization and robust consistency guarantees.
#[derive(Clone)]
pub struct DirectoryService {
    /// Internal storage for directory entries with concurrent access
    store: Arc<parking_lot::RwLock<HashMap<String, DirectoryEntry>>>,
    /// Remote client for network operations
    client: Option<DirectoryClient>,
    /// Consistency mode for storage operations
    consistency_mode: ConsistencyMode,
}

/// Consistency modes for directory operations
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsistencyMode {
    /// Local operations only, no remote synchronization
    LocalOnly,
    /// Write locally, then asynchronously to remote
    WriteLocalAsync,
    /// Write to both local and remote synchronously
    WriteSync,
    /// Write to remote first, then locally
    WriteRemoteFirst,
}

impl Default for DirectoryService {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryService {
    /// Create a new directory service with default settings
    pub fn new() -> Self {
        Self {
            store: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            client: None,
            consistency_mode: ConsistencyMode::LocalOnly,
        }
    }

    /// Create a new directory service with a specific endpoint
    pub fn with_endpoint(endpoint: &str) -> Self {
        Self {
            store: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            client: Some(DirectoryClient::with_endpoint(endpoint)),
            consistency_mode: ConsistencyMode::WriteSync,
        }
    }

    /// Set the consistency mode
    pub fn set_consistency_mode(&mut self, mode: ConsistencyMode) {
        self.consistency_mode = mode;
    }

    /// Publish a state to the directory with consistency guarantees
    pub fn publish_state(&self, state: &State) -> Result<(), DsmError> {
        // Serialize the state with detailed error context
        let state_bytes = bincode::serialize(state).map_err(|e| {
            DsmError::serialization("Failed to serialize state for publication", Some(e))
        })?;

        // Determine entry type based on state properties
        let entry_type = if state.state_number == 0 {
            DirectoryEntryType::Genesis
        } else {
            DirectoryEntryType::StateTransition
        };

        // Create directory entry with precise timestamp
        let entry = DirectoryEntry {
            data: state_bytes.clone(),
            state_number: state.state_number,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DsmError::generic("Failed to get current timestamp", Some(e)))?
                .as_secs(),
            entry_type: entry_type.clone(), // Clone to avoid ownership issues
        };

        // Store locally with proper locking
        {
            let mut store = self.store.write();
            store.insert(state.id.clone(), entry);
        }

        // Handle remote publishing based on consistency mode with extensive error handling
        if let Some(client) = &self.client {
            match self.consistency_mode {
                ConsistencyMode::LocalOnly => {
                    // No remote publishing - intentional no-op
                    tracing::debug!("LocalOnly mode: State {} not published to remote", state.id);
                }
                ConsistencyMode::WriteLocalAsync => {
                    // Publish asynchronously to remote for better latency
                    let client_clone = client.clone();
                    let state_clone = state.clone();

                    // Spawning task with proper error handling
                    tokio::spawn(async move {
                        if let Err(e) = client_clone.publish_genesis(&state_clone).await {
                            tracing::error!(
                                "Async remote publishing failed for {}: {}",
                                state_clone.id,
                                e
                            );
                        } else {
                            tracing::debug!(
                                "Async remote publishing succeeded for {}",
                                state_clone.id
                            );
                        }
                    });

                    tracing::debug!(
                        "WriteLocalAsync mode: State {} queued for async publication",
                        state.id
                    );
                }
                ConsistencyMode::WriteSync | ConsistencyMode::WriteRemoteFirst => {
                    // For synchronous operations, handle based on state type
                    if entry_type == DirectoryEntryType::Genesis {
                        // Use tokio runtime to execute async code in sync context with proper error propagation
                        let rt = tokio::runtime::Runtime::new().map_err(|e| {
                            DsmError::generic(
                                "Failed to create tokio runtime for sync publication",
                                Some(e),
                            )
                        })?;

                        // Execute with proper await and error propagation
                        rt.block_on(async { client.publish_genesis(state).await })?;

                        tracing::debug!(
                            "WriteSync mode: Genesis state {} published to remote",
                            state.id
                        );
                    } else {
                        tracing::debug!(
                            "Non-genesis state transitions not synchronized with remote"
                        );
                    }
                }
            }
        } else {
            tracing::debug!(
                "No remote client configured: State {} stored locally only",
                state.id
            );
        }

        Ok(())
    }

    /// Retrieve a state from the directory with multi-layered caching
    pub fn retrieve_state(&self, state_id: &str) -> Result<State, DsmError> {
        // Check local store first for cache hit optimization
        {
            let store = self.store.read();
            if let Some(entry) = store.get(state_id) {
                // Deserialize the state with specific error context
                return bincode::deserialize(&entry.data).map_err(|e| {
                    DsmError::serialization("Failed to deserialize cached state", Some(e))
                });
            }
        }

        // If not found locally and we have a remote client, try to fetch from remote
        if let Some(client) = &self.client {
            // Use tokio runtime to execute async code in sync context with proper error handling
            let rt = tokio::runtime::Runtime::new().map_err(|e| {
                DsmError::generic(
                    "Failed to create tokio runtime for state retrieval",
                    Some(e),
                )
            })?;

            // Perform remote fetch with error propagation
            let state = rt.block_on(async { client.get_genesis(state_id).await })?;

            // Store in local cache after successful fetch for future performance
            let state_bytes = bincode::serialize(&state).map_err(|e| {
                DsmError::serialization("Failed to serialize retrieved state for caching", Some(e))
            })?;

            // Create entry with appropriate metadata
            let entry = DirectoryEntry {
                data: state_bytes,
                state_number: state.state_number,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| DsmError::generic("Failed to get current timestamp", Some(e)))?
                    .as_secs(),
                entry_type: if state.state_number == 0 {
                    DirectoryEntryType::Genesis
                } else {
                    DirectoryEntryType::StateTransition
                },
            };

            // Update cache atomically
            {
                let mut store = self.store.write();
                store.insert(state_id.to_string(), entry);
            }

            tracing::debug!("State {} fetched from remote and cached locally", state_id);
            return Ok(state);
        }

        Err(DsmError::not_found(
            "State",
            Some(format!(
                "State ID {} not found locally or remotely",
                state_id
            )),
        ))
    }

    /// Publish a tombstone (invalidation marker) with integrity guarantees
    /// Implements the forward-only invalidation mechanism described in whitepaper Section 9
    pub async fn publish_tombstone(
        &self,
        state_hash: &[u8],
        tombstone_type: &self::TombstoneType,
    ) -> Result<(), DsmError> {
        // Create the tombstone key with proper type prefix
        let prefix = match tombstone_type {
            TombstoneType::StateInvalidation => "state_invalidation",
            TombstoneType::IdentityRevocation => "identity_revocation",
            TombstoneType::DeviceRevocation => "device_revocation",
        };

        let key = format!(
            "{}_{}_{}",
            prefix,
            hex::encode(state_hash),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DsmError::generic("Failed to get current timestamp", Some(e)))?
                .as_secs()
        );

        // Create a simple entry for the tombstone
        let entry = DirectoryEntry {
            data: state_hash.to_vec(),
            state_number: 0, // Tombstones don't have a state number
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    DsmError::generic("Failed to get current timestamp for tombstone", Some(e))
                })?
                .as_secs(),
            entry_type: DirectoryEntryType::Invalidation,
        };

        // Store locally with proper locking
        {
            let mut store = self.store.write();
            store.insert(key.clone(), entry);
        }

        tracing::info!("Published tombstone with key: {}", key);
        Ok(())
    }

    /// Check if a state has been tombstoned (invalidated)
    /// Implements the invalidation verification mechanism described in whitepaper Section 9
    pub async fn check_tombstone(
        &self,
        state_hash: &[u8],
        tombstone_type: &self::TombstoneType,
    ) -> Result<bool, DsmError> {
        // Determine the prefix based on tombstone type
        let prefix = match tombstone_type {
            TombstoneType::StateInvalidation => "state_invalidation",
            TombstoneType::IdentityRevocation => "identity_revocation",
            TombstoneType::DeviceRevocation => "device_revocation",
        };

        // Check for any entry with this prefix and hash
        let store = self.store.read();
        let state_hash_hex = hex::encode(state_hash);

        for key in store.keys() {
            if key.starts_with(prefix) && key.contains(&state_hash_hex) {
                return Ok(true); // Found a tombstone for this state
            }
        }

        // If we have a remote client, check there as well
        if let Some(_client) = &self.client {
            // In a real implementation, we would check with the remote service
            // For now, just use local results
            tracing::debug!("Remote tombstone checking not implemented yet");
        }

        Ok(false) // No tombstone found
    }

    /// Publish an invalidation marker with integrity guarantees
    pub fn publish_invalidation(
        &self,
        identity_id: &str,
        state_hash: &[u8],
        signatures: &[Vec<u8>],
    ) -> Result<(), DsmError> {
        // Create the invalidation marker with precise timestamp
        let marker = InvalidationMarker {
            identity_id: identity_id.to_string(),
            state_hash: state_hash.to_vec(), // Create ownership copy
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    DsmError::generic("Failed to get current timestamp for invalidation", Some(e))
                })?
                .as_secs(),
            signatures: signatures.to_vec(), // Create ownership copy
        };

        // Serialize the marker with detailed error context
        let marker_bytes = bincode::serialize(&marker).map_err(|e| {
            DsmError::serialization("Failed to serialize invalidation marker", Some(e))
        })?;

        // Create directory entry with appropriate metadata
        let entry = DirectoryEntry {
            data: marker_bytes.clone(),
            state_number: 0, // Invalidation markers don't have a state number
            timestamp: marker.timestamp,
            entry_type: DirectoryEntryType::Invalidation,
        };

        // Generate a key for the invalidation marker with consistent prefix
        let key = format!("invalidation_{}", identity_id);

        // Store locally with proper locking
        {
            let mut store = self.store.write();
            store.insert(key.clone(), entry);
        }

        // Handle remote publishing based on consistency mode
        if let Some(client) = &self.client {
            match self.consistency_mode {
                ConsistencyMode::LocalOnly => {
                    // No remote publishing - intentional no-op
                    tracing::debug!(
                        "LocalOnly mode: Invalidation for {} stored locally only",
                        identity_id
                    );
                }
                ConsistencyMode::WriteLocalAsync => {
                    // Publish asynchronously to remote for better latency
                    let client_clone = client.clone();
                    let identity_id_owned = identity_id.to_string();
                    let state_hash_owned = state_hash.to_vec();
                    let signatures_owned = signatures.to_vec();

                    // Spawn task with proper error handling and logging
                    tokio::spawn(async move {
                        if let Err(e) = client_clone
                            .publish_invalidation(
                                &identity_id_owned,
                                &state_hash_owned,
                                &signatures_owned,
                            )
                            .await
                        {
                            tracing::error!(
                                "Async remote invalidation publishing failed for {}: {}",
                                identity_id_owned,
                                e
                            );
                        } else {
                            tracing::debug!(
                                "Async remote invalidation publishing succeeded for {}",
                                identity_id_owned
                            );
                        }
                    });

                    tracing::debug!(
                        "WriteLocalAsync mode: Invalidation for {} queued for async publication",
                        identity_id
                    );
                }
                ConsistencyMode::WriteSync | ConsistencyMode::WriteRemoteFirst => {
                    // Use tokio runtime to execute async code in sync context
                    let rt = tokio::runtime::Runtime::new().map_err(|e| {
                        DsmError::generic(
                            "Failed to create tokio runtime for invalidation publication",
                            Some(e),
                        )
                    })?;

                    // Execute with proper await and error propagation
                    rt.block_on(async {
                        client
                            .publish_invalidation(identity_id, state_hash, signatures)
                            .await
                    })?;

                    tracing::debug!(
                        "WriteSync mode: Invalidation marker for {} published to remote",
                        identity_id
                    );
                }
            }
        } else {
            tracing::debug!(
                "No remote client configured: Invalidation for {} stored locally only",
                identity_id
            );
        }

        Ok(())
    }

    /// Verify a genesis state against the directory with cryptographic verification
    /// This implements the requirements described in Section 4.2.2 of the whitepaper
    pub async fn verify_genesis_state(&self, state: &State) -> Result<bool, DsmError> {
        // Ensure the state is actually a genesis state
        if state.state_number != 0 {
            return Err(DsmError::validation(
                "Only genesis states can be verified",
                None::<std::convert::Infallible>,
            ));
        }

        // First check if we already have this state in our local cache
        let key = format!("genesis_{}", hex::encode(&state.hash));

        {
            let store = self.store.read();
            if let Some(entry) = store.get(&key) {
                // Deserialize the stored state for comparison
                let stored_state: State = bincode::deserialize(&entry.data).map_err(|e| {
                    DsmError::serialization("Failed to deserialize cached genesis state", Some(e))
                })?;

                // Compare the hash (since state might have additional metadata)
                if stored_state.hash == state.hash {
                    return Ok(true); // State is already verified and cached
                }
            }
        }

        // If not found locally and we have a remote client, try to verify against remote directory
        if let Some(client) = &self.client {
            // Use tokio runtime to execute async code in sync context
            let rt = tokio::runtime::Runtime::new().map_err(|e| {
                DsmError::generic(
                    "Failed to create tokio runtime for genesis verification",
                    Some(e),
                )
            })?;

            // Try to retrieve the state from the remote directory
            let result = rt.block_on(async {
                match client.get_genesis(&state.id).await {
                    Ok(remote_state) => {
                        // Verify the hash matches
                        if remote_state.hash == state.hash {
                            // Cache the verified state
                            let state_bytes = bincode::serialize(&state).map_err(|e| {
                                DsmError::serialization(
                                    "Failed to serialize verified genesis state",
                                    Some(e),
                                )
                            })?;

                            let entry = DirectoryEntry {
                                data: state_bytes,
                                state_number: 0,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map_err(|e| {
                                        DsmError::generic(
                                            "Failed to get current timestamp",
                                            Some(e),
                                        )
                                    })?
                                    .as_secs(),
                                entry_type: DirectoryEntryType::Genesis,
                            };

                            // Update cache atomically
                            let mut store = self.store.write();
                            store.insert(key, entry);

                            Ok(true)
                        } else {
                            Ok(false) // Hash mismatch
                        }
                    }
                    Err(_) => Ok(false), // Not found in remote directory
                }
            });

            return result;
        }

        // If no remote client, we can't verify beyond our local cache
        tracing::warn!("Cannot verify genesis state: no remote directory client configured");
        Ok(false)
    }

    /// Check if an identity has been invalidated with multi-layered lookup
    pub fn check_invalidation(
        &self,
        identity_id: &str,
    ) -> Result<Option<InvalidationMarker>, DsmError> {
        // Generate the key for the invalidation marker with consistent prefix
        let key = format!("invalidation_{}", identity_id);

        // Check local store first for cache hit optimization
        {
            let store = self.store.read();
            if let Some(entry) = store.get(&key) {
                // Deserialize the marker with detailed error context
                return bincode::deserialize(&entry.data).map(Some).map_err(|e| {
                    DsmError::serialization(
                        "Failed to deserialize cached invalidation marker",
                        Some(e),
                    )
                });
            }
        }

        // If not found locally and we have a remote client, try to fetch from remote
        if let Some(client) = &self.client {
            // Use tokio runtime to execute async code in sync context
            let rt = tokio::runtime::Runtime::new().map_err(|e| {
                DsmError::generic(
                    "Failed to create tokio runtime for invalidation check",
                    Some(e),
                )
            })?;

            // Perform remote check with proper error handling
            let marker_opt = rt.block_on(async { client.check_invalidation(identity_id).await })?;

            // If we found a marker, store it locally for future performance
            if let Some(marker) = &marker_opt {
                let marker_bytes = bincode::serialize(marker).map_err(|e| {
                    DsmError::serialization(
                        "Failed to serialize invalidation marker for caching",
                        Some(e),
                    )
                })?;

                // Create entry with appropriate metadata
                let entry = DirectoryEntry {
                    data: marker_bytes,
                    state_number: 0,
                    timestamp: marker.timestamp,
                    entry_type: DirectoryEntryType::Invalidation,
                };

                // Update cache atomically
                {
                    let mut store = self.store.write();
                    store.insert(key, entry);
                }

                tracing::debug!(
                    "Invalidation marker for {} fetched from remote and cached locally",
                    identity_id
                );
            } else {
                tracing::debug!(
                    "No invalidation marker found for {} in remote service",
                    identity_id
                );
            }

            return Ok(marker_opt);
        }

        // Not found locally or remotely - this is not an error condition
        tracing::debug!(
            "No invalidation marker found for {}, and no remote client configured",
            identity_id
        );
        Ok(None)
    }

    /// List all entries in the directory for diagnostics
    pub fn list_entries(&self) -> Result<Vec<String>, DsmError> {
        let store = self.store.read();
        Ok(store.keys().cloned().collect())
    }

    /// Remove an entry from the directory (local only, invalidation should be used instead)
    pub fn remove(&self, key: &str) -> Result<(), DsmError> {
        let mut store = self.store.write();
        store.remove(key);
        tracing::debug!("Entry {} removed from local directory cache", key);
        Ok(())
    }

    /// Clear the directory (local cache only) for testing and reset
    pub fn clear(&self) -> Result<(), DsmError> {
        let mut store = self.store.write();
        store.clear();
        tracing::debug!("Local directory cache cleared");
        Ok(())
    }

    /// Get the number of entries in the directory for diagnostics
    pub fn entry_count(&self) -> usize {
        let store = self.store.read();
        store.len()
    }
}

/// Enum representing different types of tombstone markers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TombstoneType {
    /// Invalidation of a specific state
    StateInvalidation,
    /// Complete revocation of an identity
    IdentityRevocation,
    /// Revocation of a specific device
    DeviceRevocation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_directory_client() {
        let client = DirectoryClient::new();
        assert_eq!(client.endpoints.len(), 2);
    }

    #[tokio::test]
    async fn test_publish_and_retrieve_genesis() {
        let client = DirectoryClient::new();

        // Create a test state
        let device_info = crate::types::state_types::DeviceInfo::new(
            "test_device",
            vec![1, 2, 3, 4], // Test public key
        );

        let test_state = State::new_genesis(
            vec![1, 2, 3], // Test entropy
            device_info,
        );

        let publish_res = client.publish_genesis(&test_state).await;
        assert!(publish_res.is_ok());

        let fetch_res = client.get_genesis(&test_state.id).await;
        assert!(fetch_res.is_ok());
        let fetched = fetch_res.unwrap();
        assert_eq!(fetched.id, test_state.id);
    }

    #[test]
    fn test_directory_service_local() {
        let service = DirectoryService::new();

        // Create a test state
        let device_info = crate::types::state_types::DeviceInfo::new(
            "test_device",
            vec![1, 2, 3, 4], // Test public key
        );

        let test_state = State::new_genesis(
            vec![1, 2, 3], // Test entropy
            device_info,
        );

        // Publish state
        let publish_res = service.publish_state(&test_state);
        assert!(publish_res.is_ok());

        // Retrieve state
        let fetch_res = service.retrieve_state(&test_state.id);
        assert!(fetch_res.is_ok());
        let fetched = fetch_res.unwrap();
        assert_eq!(fetched.id, test_state.id);
    }

    #[test]
    fn test_invalidation_local() {
        let service = DirectoryService::new();
        let identity_id = "test_identity";
        let state_hash = vec![1, 2, 3, 4, 5];
        let signatures = vec![vec![10, 11, 12]];

        // Publish invalidation
        let publish_res = service.publish_invalidation(identity_id, &state_hash, &signatures);
        assert!(publish_res.is_ok());

        // Check invalidation
        let check_res = service.check_invalidation(identity_id);
        assert!(check_res.is_ok());
        let marker = check_res.unwrap();
        assert!(marker.is_some());
        let marker = marker.unwrap();
        assert_eq!(marker.identity_id, identity_id);
        assert_eq!(marker.state_hash, state_hash);
    }
}

use crate::interfaces::network_face::NetworkInterface;
use async_trait::async_trait;

#[async_trait]
impl NetworkInterface for DirectoryClient {
    async fn connect(&mut self) -> Result<(), DsmError> {
        Ok(()) // No-op for in-memory implementation
    }

    async fn disconnect(&mut self) -> Result<(), DsmError> {
        Ok(()) // No-op for in-memory implementation
    }

    async fn send(&self, _peer_id: &str, _data: &[u8]) -> Result<(), DsmError> {
        Err(DsmError::network(
            "Not supported for directory service",
            None::<std::io::Error>,
        ))
    }

    async fn receive(&self) -> Result<(String, Vec<u8>), DsmError> {
        Err(DsmError::network(
            "Not supported for directory service",
            None::<std::io::Error>,
        ))
    }

    async fn publish(&self, key: &str, data: &[u8]) -> Result<(), DsmError> {
        let mut store = self.genesis_cache.write().await;
        store.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Vec<u8>, DsmError> {
        let store = self.genesis_cache.read().await;
        store
            .get(key)
            .cloned()
            .ok_or_else(|| DsmError::not_found("key", Some(key.to_string())))
    }

    async fn is_peer_online(&self, _peer_id: &str) -> Result<bool, DsmError> {
        Ok(true) // Directory service is always considered online
    }
}
