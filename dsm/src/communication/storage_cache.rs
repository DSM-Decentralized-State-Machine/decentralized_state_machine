//! Storage Cache Module
//!
//! This module provides caching functionality for DSM storage nodes,
//! enabling clients to cache genesis states, tokens, checkpoints, and
//! other critical data for offline operations.

use crate::core::identity::GenesisState;
use crate::recovery::invalidation::InvalidationMarker;
use crate::types::error::DsmError;
use crate::types::state_types::State;
use crate::types::token_types::Token;

use std::collections::HashMap;
// use std::sync::Arc - Removed unused import
use blake3;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry<T> {
    /// Cached item
    data: T,

    /// Last access timestamp
    last_accessed: SystemTime,

    /// Creation timestamp
    created_at: SystemTime,

    /// Time-to-live in seconds (0 = no expiration)
    ttl: u64,

    /// Hash of the item for integrity validation
    hash: [u8; 32],

    /// Whether this item has been cryptographically verified
    verified: bool,
}

impl<T: Serialize + Clone> CacheEntry<T> {
    /// Create a new cache entry
    fn new(data: T, ttl: u64, verified: bool) -> Result<Self, DsmError> {
        let now = SystemTime::now();

        // Calculate hash for integrity checking
        let serialized = bincode::serialize(&data)
            .map_err(|e| DsmError::serialization("Failed to serialize cache entry", Some(e)))?;

        let hash = blake3::hash(&serialized).into();

        Ok(Self {
            data,
            last_accessed: now,
            created_at: now,
            ttl,
            hash,
            verified,
        })
    }

    /// Check if entry has expired
    fn is_expired(&self) -> bool {
        if self.ttl == 0 {
            return false; // Never expires
        }

        match self.created_at.elapsed() {
            Ok(elapsed) => elapsed > Duration::from_secs(self.ttl),
            Err(_) => false, // System time went backwards, consider not expired
        }
    }

    /// Update last access time
    fn update_accessed(&mut self) {
        self.last_accessed = SystemTime::now();
    }

    /// Verify data integrity
    fn verify_integrity(&self) -> Result<bool, DsmError> {
        // Re-serialize and hash to compare with stored hash
        let serialized = bincode::serialize(&self.data).map_err(|e| {
            DsmError::serialization("Failed to serialize cache entry for verification", Some(e))
        })?;

        let computed_hash: [u8; 32] = *blake3::hash(&serialized).as_bytes();

        Ok(self.hash == computed_hash)
    }
}

/// Storage cache to enable offline operations
#[derive(Debug)]
pub struct StorageCache {
    /// Genesis state cache
    genesis_cache: RwLock<HashMap<String, CacheEntry<GenesisState>>>,

    /// Token cache
    token_cache: RwLock<HashMap<String, CacheEntry<Token>>>,

    /// Checkpoint cache
    checkpoint_cache: RwLock<HashMap<String, CacheEntry<State>>>,

    /// Invalidation marker cache
    invalidation_cache: RwLock<HashMap<String, CacheEntry<InvalidationMarker>>>,

    /// Maximum size of each cache
    max_entries: usize,

    /// Default TTL for cache entries in seconds
    default_ttl: u64,
}

impl StorageCache {
    /// Create a new storage cache with default settings
    pub fn new() -> Self {
        Self {
            genesis_cache: RwLock::new(HashMap::new()),
            token_cache: RwLock::new(HashMap::new()),
            checkpoint_cache: RwLock::new(HashMap::new()),
            invalidation_cache: RwLock::new(HashMap::new()),
            max_entries: 1000,
            default_ttl: 86400 * 30, // 30 days by default
        }
    }

    /// Create a storage cache with custom settings
    pub fn with_settings(max_entries: usize, default_ttl: u64) -> Self {
        Self {
            genesis_cache: RwLock::new(HashMap::new()),
            token_cache: RwLock::new(HashMap::new()),
            checkpoint_cache: RwLock::new(HashMap::new()),
            invalidation_cache: RwLock::new(HashMap::new()),
            max_entries,
            default_ttl,
        }
    }

    /// Calculate cache key from genesis hash
    fn genesis_key(genesis_hash: &[u8]) -> String {
        hex::encode(genesis_hash)
    }

    /// Cache a genesis state
    pub async fn cache_genesis(
        &self,
        genesis: GenesisState,
        verified: bool,
        ttl: Option<u64>,
    ) -> Result<(), DsmError> {
        let mut cache = self.genesis_cache.write().await;

        // Check if cache is full
        if cache.len() >= self.max_entries {
            // Remove oldest entry
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }

        // Calculate key
        let serialized = bincode::serialize(&genesis)?;
        let hash = *blake3::hash(&serialized).as_bytes();
        let key = Self::genesis_key(&hash);

        // Create cache entry
        let entry = CacheEntry::new(genesis, ttl.unwrap_or(self.default_ttl), verified)?;

        // Store in cache
        cache.insert(key, entry);

        Ok(())
    }

    /// Get a cached genesis state
    pub async fn get_genesis(&self, genesis_hash: &[u8]) -> Result<Option<GenesisState>, DsmError> {
        let mut cache = self.genesis_cache.write().await;
        let key = Self::genesis_key(genesis_hash);

        if let Some(entry) = cache.get_mut(&key) {
            // Check if expired
            if entry.is_expired() {
                cache.remove(&key);
                return Ok(None);
            }

            // Check integrity
            if !entry.verify_integrity()? {
                cache.remove(&key);
                return Err(DsmError::Integrity {
                    context: "Genesis state cache integrity check failed".into(),
                    source: None,
                });
            }

            // Update last accessed
            entry.update_accessed();

            Ok(Some(entry.data.clone()))
        } else {
            Ok(None)
        }
    }

    /// Check if a genesis state is cached
    pub async fn has_genesis(&self, genesis_hash: &[u8]) -> bool {
        let cache = self.genesis_cache.read().await;
        let key = Self::genesis_key(genesis_hash);

        if let Some(entry) = cache.get(&key) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Cache a token
    pub async fn cache_token(
        &self,
        token_id: &str,
        token: Token,
        verified: bool,
        ttl: Option<u64>,
    ) -> Result<(), DsmError> {
        let mut cache = self.token_cache.write().await;

        // Check if cache is full
        if cache.len() >= self.max_entries {
            // Remove oldest entry
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }

        // Create cache entry
        let entry = CacheEntry::new(token, ttl.unwrap_or(self.default_ttl), verified)?;

        // Store in cache
        cache.insert(token_id.to_string(), entry);

        Ok(())
    }

    /// Get a cached token
    pub async fn get_token(&self, token_id: &str) -> Result<Option<Token>, DsmError> {
        let mut cache = self.token_cache.write().await;

        if let Some(entry) = cache.get_mut(token_id) {
            // Check if expired
            if entry.is_expired() {
                cache.remove(token_id);
                return Ok(None);
            }

            // Check integrity
            if !entry.verify_integrity()? {
                cache.remove(token_id);
                return Err(DsmError::Integrity {
                    context: "Token cache integrity check failed".into(),
                    source: None,
                });
            }

            // Update last accessed
            entry.update_accessed();

            Ok(Some(entry.data.clone()))
        } else {
            Ok(None)
        }
    }

    /// Check if a token is cached
    pub async fn has_token(&self, token_id: &str) -> bool {
        let cache = self.token_cache.read().await;

        if let Some(entry) = cache.get(token_id) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Cache a checkpoint state
    pub async fn cache_checkpoint(
        &self,
        state: State,
        verified: bool,
        ttl: Option<u64>,
    ) -> Result<(), DsmError> {
        let mut cache = self.checkpoint_cache.write().await;

        // Check if cache is full
        if cache.len() >= self.max_entries {
            // Remove oldest entry
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }

        // Calculate key
        let key = format!(
            "checkpoint_{}_{}",
            state.state_number,
            hex::encode(state.hash()?)
        );

        // Create cache entry
        let entry = CacheEntry::new(state, ttl.unwrap_or(self.default_ttl), verified)?;

        // Store in cache
        cache.insert(key, entry);

        Ok(())
    }

    /// Get closest checkpoint before a given state number
    pub async fn get_closest_checkpoint(
        &self,
        state_number: u64,
    ) -> Result<Option<State>, DsmError> {
        let cache = self.checkpoint_cache.read().await;

        let mut closest: Option<(u64, &CacheEntry<State>)> = None;

        for (_, entry) in cache.iter() {
            // Skip expired entries
            if entry.is_expired() {
                continue;
            }

            // Skip entries with integrity issues
            if !entry.verify_integrity()? {
                continue;
            }

            let entry_state_number = entry.data.state_number;

            // Must be less than or equal to target
            if entry_state_number <= state_number {
                if let Some((current_best, _)) = closest {
                    if entry_state_number > current_best {
                        closest = Some((entry_state_number, entry));
                    }
                } else {
                    // First valid entry
                    closest = Some((entry_state_number, entry));
                }
            }
        }

        // Return clone of closest entry if found
        if let Some((_, entry)) = closest {
            let mut entry_clone = entry.clone();
            entry_clone.update_accessed();
            Ok(Some(entry.data.clone()))
        } else {
            Ok(None)
        }
    }

    /// Cache an invalidation marker
    pub async fn cache_invalidation(
        &self,
        marker: InvalidationMarker,
        verified: bool,
        ttl: Option<u64>,
    ) -> Result<(), DsmError> {
        let mut cache = self.invalidation_cache.write().await;

        // Check if cache is full
        if cache.len() >= self.max_entries {
            // Remove oldest entry
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }

        // Calculate key
        let key = hex::encode(&marker.state_hash);

        // Create cache entry
        let entry = CacheEntry::new(marker, ttl.unwrap_or(self.default_ttl), verified)?;

        // Store in cache
        cache.insert(key, entry);

        Ok(())
    }

    /// Check if a state has been invalidated
    pub async fn is_state_invalidated(&self, state_hash: &[u8]) -> Result<bool, DsmError> {
        let cache = self.invalidation_cache.read().await;
        let key = hex::encode(state_hash);

        if let Some(entry) = cache.get(&key) {
            if entry.is_expired() {
                return Ok(false);
            }

            if !entry.verify_integrity()? {
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get an invalidation marker
    pub async fn get_invalidation(
        &self,
        state_hash: &[u8],
    ) -> Result<Option<InvalidationMarker>, DsmError> {
        let mut cache = self.invalidation_cache.write().await;
        let key = hex::encode(state_hash);

        if let Some(entry) = cache.get_mut(&key) {
            // Check if expired
            if entry.is_expired() {
                cache.remove(&key);
                return Ok(None);
            }

            // Check integrity
            if !entry.verify_integrity()? {
                cache.remove(&key);
                return Err(DsmError::Integrity {
                    context: "Invalidation marker cache integrity check failed".into(),
                    source: None,
                });
            }

            // Update last accessed
            entry.update_accessed();

            Ok(Some(entry.data.clone()))
        } else {
            Ok(None)
        }
    }

    /// Get the number of cached entries
    pub async fn get_cache_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();

        stats.insert("genesis".to_string(), self.genesis_cache.read().await.len());
        stats.insert("token".to_string(), self.token_cache.read().await.len());
        stats.insert(
            "checkpoint".to_string(),
            self.checkpoint_cache.read().await.len(),
        );
        stats.insert(
            "invalidation".to_string(),
            self.invalidation_cache.read().await.len(),
        );

        stats
    }

    /// Clear all expired entries
    pub async fn clear_expired(&self) -> usize {
        let mut total_removed = 0;

        // Clean genesis cache
        {
            let mut cache = self.genesis_cache.write().await;
            let before = cache.len();
            cache.retain(|_, entry| !entry.is_expired());
            total_removed += before - cache.len();
        }

        // Clean token cache
        {
            let mut cache = self.token_cache.write().await;
            let before = cache.len();
            cache.retain(|_, entry| !entry.is_expired());
            total_removed += before - cache.len();
        }

        // Clean checkpoint cache
        {
            let mut cache = self.checkpoint_cache.write().await;
            let before = cache.len();
            cache.retain(|_, entry| !entry.is_expired());
            total_removed += before - cache.len();
        }

        // Clean invalidation cache
        {
            let mut cache = self.invalidation_cache.write().await;
            let before = cache.len();
            cache.retain(|_, entry| !entry.is_expired());
            total_removed += before - cache.len();
        }

        total_removed
    }

    /// Clear all caches
    pub async fn clear_all(&self) {
        self.genesis_cache.write().await.clear();
        self.token_cache.write().await.clear();
        self.checkpoint_cache.write().await.clear();
        self.invalidation_cache.write().await.clear();
    }
}

impl Default for StorageCache {
    fn default() -> Self {
        Self::new()
    }
}
