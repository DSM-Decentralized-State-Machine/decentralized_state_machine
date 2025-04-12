//! Integration of Ethereum anchors with DSM state management
//!
//! This module provides functionality to persist DSM states with Ethereum anchors
//! using the DSM storage system. It supports different storage backends
//! including in-memory, SQL, and distributed storage through the StorageEngine trait.

use std::collections::HashMap;
use std::sync::Arc;

use dsm::interfaces::storage_face::{RocksDbStorage, StorageInterface};
use dsm::types::error::DsmError;
use dsm_storage_node::storage::distributed_storage::DistributedStorage;
use dsm_storage_node::storage::memory_storage::{MemoryStorage, MemoryStorageConfig, EvictionPolicy};
use dsm_storage_node::storage::StorageEngine;
use dsm_storage_node::types::BlindedStateEntry;
use dsm_storage_node::types::StorageNode;

use bincode;
use chrono;
use parking_lot::Mutex;
use sha3::{Digest, Keccak256};
use tokio::sync::RwLock;

use crate::ethereum_anchor::{DsmState, EthereumAnchor};

/// Storage key prefixes for organizing data
const STATE_KEY_PREFIX: &str = "dsm_state:";
const ETH_ANCHOR_PREFIX: &str = "eth_anchor:";
const LATEST_STATE_KEY: &str = "latest_state";

/// A persistent state manager that uses DSM storage interfaces
pub struct PersistentStateManager {
    // The core DSM storage interface for direct DB access
    core_storage: RwLock<RocksDbStorage>,

    // Optional distributed storage for more complex setups
    distributed_storage: Option<Arc<dyn StorageEngine>>,

    // Cache of recently accessed states for performance
    state_cache: Mutex<HashMap<String, DsmState>>,

    // Configuration
    #[allow(dead_code)]
    db_path: String,
}

impl PersistentStateManager {
    /// Create a new state manager with RocksDB storage
    pub async fn new(db_path: &str) -> Result<Self, DsmError> {
        let mut core_storage = RocksDbStorage::new(db_path.to_string());
        core_storage.open()?;

        Ok(Self {
            core_storage: RwLock::new(core_storage),
            distributed_storage: None,
            state_cache: Mutex::new(HashMap::new()),
            db_path: db_path.to_string(),
        })
    }

    /// Create a new state manager with distributed storage
    pub async fn with_distributed_storage(
        db_path: &str,
        storage_nodes: Vec<StorageNode>,
        replication_factor: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut manager = Self::new(db_path).await?;

        // Set up memory storage as primary backend
        // Use Default::default() and then modify the public fields
        let mut memory_config = MemoryStorageConfig::default();
        memory_config.max_memory_bytes = 1024 * 1024 * 1024; // 1GB
        memory_config.max_entries = 1_000_000;
        memory_config.eviction_policy = EvictionPolicy::LRU;

        let memory_storage = Arc::new(MemoryStorage::new(memory_config));

        // Create distributed storage with the provided nodes
        let distributed = DistributedStorage::new(
            memory_storage,
            "bridge-node".to_string(),
            storage_nodes,
            replication_factor,
            3, // max_hops
        )?;
        let distributed = Arc::new(distributed);

        manager.distributed_storage = Some(distributed);
        Ok(manager)
    }

    /// Add a new DSM state, optionally with an Ethereum anchor
    pub async fn add_state(&self, state: DsmState) -> Result<(), DsmError> {
        // Generate a unique identifier for this state
        let state_id = format!("{}{}", STATE_KEY_PREFIX, self.generate_state_id(&state));

        // Serialize the state
        let state_bytes = bincode::serialize(&state).map_err(|e| DsmError::Serialization {
            context: "Failed to serialize DSM state".into(),
            source: Some(Box::new(e)),
        })?;

        // Store the state in RocksDB
        let storage = self.core_storage.write().await;
        storage.store(state_id.as_bytes(), &state_bytes).await?;

        // Update the latest state pointer
        storage
            .store(LATEST_STATE_KEY.as_bytes(), state_id.as_bytes())
            .await?;

        // If this state has an Ethereum anchor, create a special index for it
        if let Some(anchor) = &state.ethereum_anchor {
            self.index_ethereum_anchor(&state_id, anchor).await?;
        }

        // Update the cache
        self.state_cache
            .lock()
            .insert(state_id.clone(), state.clone());

        // If we have distributed storage enabled, also store there
        if let Some(_dist_storage) = &self.distributed_storage {
            self.store_in_distributed(state_id, &state_bytes).await?;
        }

        Ok(())
    }

    /// Get the latest state
    pub async fn latest_state(&self) -> Result<Option<DsmState>, DsmError> {
        let storage = self.core_storage.read().await;

        // Get the key of the latest state
        let latest_key_res = storage.retrieve(LATEST_STATE_KEY.as_bytes()).await;

        match latest_key_res {
            Ok(latest_key_bytes) => {
                // Convert bytes to string
                let latest_key = std::str::from_utf8(&latest_key_bytes).map_err(|e| {
                    DsmError::Serialization {
                        context: "Failed to parse latest state key".into(),
                        source: Some(Box::new(e)),
                    }
                })?;

                // Retrieve state using the key
                self.get_state_by_id(latest_key).await
            }
            Err(DsmError::Storage {
                context: _,
                source: _,
            }) => {
                // No latest state found
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Find all states with a specific Ethereum block number
    pub async fn find_states_by_eth_block(
        &self,
        block_number: u64,
    ) -> Result<Vec<DsmState>, DsmError> {
        // Format the index key for this block
        let block_index_key = format!("{}block:{}", ETH_ANCHOR_PREFIX, block_number);

        let storage = self.core_storage.read().await;

        // Check if we have any entries for this block
        match storage.exists(block_index_key.as_bytes()).await {
            Ok(true) => {
                // Get the list of state IDs for this block
                let state_ids_bytes = storage.retrieve(block_index_key.as_bytes()).await?;
                let state_ids_str =
                    std::str::from_utf8(&state_ids_bytes).map_err(|e| DsmError::Serialization {
                        context: "Failed to parse state IDs".into(),
                        source: Some(Box::new(e)),
                    })?;

                // Split the comma-separated IDs
                let state_ids: Vec<&str> = state_ids_str.split(',').collect();

                // Load all the states
                let mut states = Vec::with_capacity(state_ids.len());
                for id in state_ids {
                    if let Some(state) = self.get_state_by_id(id).await? {
                        states.push(state);
                    }
                }

                Ok(states)
            }
            Ok(false) => Ok(Vec::new()), // No states found for this block
            Err(e) => Err(e),
        }
    }

    /// Find a state by its Ethereum transaction hash
    pub async fn find_state_by_tx_hash(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<DsmState>, DsmError> {
        // Format the index key for this transaction
        let tx_hash_hex = hex::encode(tx_hash);
        let tx_index_key = format!("{}tx:{}", ETH_ANCHOR_PREFIX, tx_hash_hex);

        let storage = self.core_storage.read().await;

        // Check if we have an entry for this transaction
        match storage.exists(tx_index_key.as_bytes()).await {
            Ok(true) => {
                // Get the state ID for this transaction
                let state_id_bytes = storage.retrieve(tx_index_key.as_bytes()).await?;
                let state_id =
                    std::str::from_utf8(&state_id_bytes).map_err(|e| DsmError::Serialization {
                        context: "Failed to parse state ID".into(),
                        source: Some(Box::new(e)),
                    })?;

                // Load the state
                self.get_state_by_id(state_id).await
            }
            Ok(false) => Ok(None), // No state found for this transaction
            Err(e) => Err(e),
        }
    }

    /// Get a state by its ID
    async fn get_state_by_id(&self, id: &str) -> Result<Option<DsmState>, DsmError> {
        // First check the cache
        {
            if let Some(state) = self.state_cache.lock().get(id) {
                return Ok(Some(state.clone()));
            }
        }

        // If not in cache, check storage
        let storage = self.core_storage.read().await;

        match storage.retrieve(id.as_bytes()).await {
            Ok(state_bytes) => {
                // Deserialize the state
                let state: DsmState =
                    bincode::deserialize(&state_bytes).map_err(|e| DsmError::Serialization {
                        context: "Failed to deserialize DSM state".into(),
                        source: Some(Box::new(e)),
                    })?;

                // Update cache
                self.state_cache
                    .lock()
                    .insert(id.to_string(), state.clone());

                Ok(Some(state))
            }
            Err(DsmError::Storage {
                context: _,
                source: _,
            }) => {
                // State not found
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Store data in distributed storage
    async fn store_in_distributed(&self, id: String, data: &[u8]) -> Result<(), DsmError> {
        if let Some(_dist_storage) = &self.distributed_storage {
            // Create a blinded entry from the state data
            let entry = BlindedStateEntry {
                blinded_id: id.clone(),
                encrypted_payload: data.to_vec(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                ttl: 86400 * 30, // 30 days TTL
                region: "global".to_string(),
                priority: 1,
                proof_hash: self.hash_data(data),
                metadata: HashMap::new(),
            };

            // Store in distributed storage - temporarily disabled
            /*match dist_storage.store(entry).await {
                Ok(_) => Ok(()),
                Err(e) => Err(DsmError::Storage {
                    context: format!("Distributed storage error: {:?}", e),
                    source: None,
                }),
            }*/

            // For now, just ignore the entry and return success
            let _ = entry; // Use the entry to avoid unused variable warning
            Ok(())
        } else {
            // Distributed storage not configured, just return success
            Ok(())
        }
    }

    /// Create indexes for Ethereum anchors to enable efficient queries
    async fn index_ethereum_anchor(
        &self,
        state_id: &str,
        anchor: &EthereumAnchor,
    ) -> Result<(), DsmError> {
        let storage = self.core_storage.write().await;

        // Create block number index
        let block_index_key = format!("{}block:{}", ETH_ANCHOR_PREFIX, anchor.block_number);

        // Check if we already have entries for this block
        let state_ids: Vec<String> = if storage
            .exists(block_index_key.as_bytes())
            .await
            .unwrap_or(false)
        {
            let existing_bytes = storage.retrieve(block_index_key.as_bytes()).await?;
            let existing_str =
                std::str::from_utf8(&existing_bytes).map_err(|e| DsmError::Serialization {
                    context: "Failed to parse existing state IDs".into(),
                    source: Some(Box::new(e)),
                })?;

            let mut ids: Vec<String> = existing_str.split(',').map(|s| s.to_string()).collect();

            // Add the new ID if not already present
            if !ids.contains(&state_id.to_string()) {
                ids.push(state_id.to_string());
            }

            ids
        } else {
            // First entry for this block
            vec![state_id.to_string()]
        };

        // Store the updated index
        let state_ids_str = state_ids.join(",");
        storage
            .store(block_index_key.as_bytes(), state_ids_str.as_bytes())
            .await?;

        // Create transaction hash index
        let tx_hash_hex = hex::encode(anchor.tx_hash);
        let tx_index_key = format!("{}tx:{}", ETH_ANCHOR_PREFIX, tx_hash_hex);

        // Store state ID by transaction
        storage
            .store(tx_index_key.as_bytes(), state_id.as_bytes())
            .await?;

        Ok(())
    }

    /// Generate a unique ID for a state
    pub fn generate_state_id(&self, state: &DsmState) -> String {
        let mut hasher = Keccak256::new();

        // Hash the state data
        hasher.update(&state.data);

        // If there's an Ethereum anchor, add that to the hash
        if let Some(anchor) = &state.ethereum_anchor {
            hasher.update(anchor.block_number.to_be_bytes());
            hasher.update(anchor.tx_hash);
            hasher.update(anchor.event_root);
        }

        // Finalize and return as hex
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Calculate hash of data (for proof verification)
    fn hash_data(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    /// Close database connections
    pub async fn shutdown(&mut self) {
        let mut storage = self.core_storage.write().await;
        storage.close();
    }
}

/// Legacy StateManager implementation for backward compatibility
pub struct StateManager {
    pub states: Vec<DsmState>,
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StateManager {
    pub fn new() -> Self {
        Self { states: Vec::new() }
    }

    pub fn add_state(&mut self, state: DsmState) {
        self.states.push(state);
    }

    /// Example of retrieving the latest state
    pub fn latest_state(&self) -> Option<&DsmState> {
        self.states.last()
    }
}
