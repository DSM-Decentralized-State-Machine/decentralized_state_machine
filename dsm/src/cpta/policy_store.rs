//! Token Policy Storage
//!
//! This module implements persistent storage and retrieval mechanisms for token policies,
//! allowing CTPAs to be discovered, verified, and cached.
//!
//! The implementation includes a high-performance LRU cache with time-based expiration
//! to optimize frequent policy lookups while ensuring policies are periodically re-verified.

use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::ErrorKind,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::RwLock;
use tokio::{fs::File, io::AsyncWriteExt};

use crate::{
    cpta::policy_verification::verify_policy_anchor,
    types::{
        error::DsmError,
        policy_types::{PolicyAnchor, PolicyFile, TokenPolicy},
    },
};

/// Cache entry with expiration time
#[derive(Debug)]
struct CacheEntry {
    /// The policy being cached
    policy: TokenPolicy,
    /// When this entry was added to the cache
    added: Instant,
    /// Last access time for LRU management
    last_access: Instant,
}

/// Token Policy Store
///
/// Provides storage, retrieval, and verification of token policies.
/// Implements a high-performance LRU cache for frequently accessed policies.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    /// In-memory cache of verified policies with expiration
    cache: Arc<RwLock<HashMap<PolicyAnchor, CacheEntry>>>,

    /// Access order for implementing LRU eviction
    access_order: Arc<RwLock<VecDeque<PolicyAnchor>>>,

    /// Maximum cache size
    max_cache_size: usize,

    /// Cache entry expiration time
    cache_ttl: Duration,

    /// Base directory for policy file storage
    base_dir: PathBuf,
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyStore {
    /// Create a new policy store with default settings
    pub fn new() -> Self {
        Self::with_cache_settings(1000, Duration::from_secs(3600)) // 1000 entries, 1 hour TTL
    }

    /// Create a new policy store with specified cache settings
    pub fn with_cache_settings(max_cache_size: usize, cache_ttl: Duration) -> Self {
        let home_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());

        let base_dir = PathBuf::from(home_dir).join(".dsm_config").join("policies");

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&base_dir).unwrap_or_else(|_| {
            eprintln!("Warning: Failed to create policies storage directory");
        });

        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            access_order: Arc::new(RwLock::new(VecDeque::with_capacity(max_cache_size))),
            max_cache_size,
            cache_ttl,
            base_dir,
        }
    }

    /// Get the path to a policy file
    fn get_policy_path(&self, anchor: &PolicyAnchor) -> PathBuf {
        self.base_dir.join(format!("{}.json", anchor.to_hex()))
    }

    /// Store a policy file
    pub async fn store_policy(&self, policy: &PolicyFile) -> Result<PolicyAnchor, DsmError> {
        // Generate anchor
        let anchor = policy.generate_anchor()?;

        // Serialize policy
        let policy_json = serde_json::to_string_pretty(policy).map_err(|e| {
            DsmError::serialization(format!("Failed to serialize policy: {}", e), Some(e))
        })?;

        // Write policy file
        let policy_path = self.get_policy_path(&anchor);

        let mut file = File::create(&policy_path).await.map_err(|e| {
            DsmError::storage(format!("Failed to create policy file: {}", e), Some(e))
        })?;

        file.write_all(policy_json.as_bytes()).await.map_err(|e| {
            DsmError::storage(format!("Failed to write policy file: {}", e), Some(e))
        })?;

        // Create TokenPolicy for cache
        let token_policy = TokenPolicy {
            file: policy.clone(),
            anchor: anchor.clone(),
            verified: true,
            last_verified: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Add to cache
        let mut cache = self.cache.write();
        cache.insert(
            anchor.clone(),
            CacheEntry {
                policy: token_policy,
                added: Instant::now(),
                last_access: Instant::now(),
            },
        );

        Ok(anchor)
    }

    /// Retrieve a policy by its anchor
    pub async fn get_policy(&self, anchor: &PolicyAnchor) -> Result<TokenPolicy, DsmError> {
        // Check cache first and handle expiration/LRU
        {
            let mut cache = self.cache.write();
            let mut access_order = self.access_order.write();

            if let Some(entry) = cache.get_mut(anchor) {
                let now = Instant::now();

                // Check if entry has expired
                if now.duration_since(entry.added) > self.cache_ttl {
                    // Remove from cache and continue to disk load
                    cache.remove(anchor);
                    if let Some(pos) = access_order.iter().position(|a| a == anchor) {
                        access_order.remove(pos);
                    }
                } else {
                    // Update access time and order
                    entry.last_access = now;

                    // Update LRU order
                    if let Some(pos) = access_order.iter().position(|a| a == anchor) {
                        access_order.remove(pos);
                    }
                    access_order.push_back(anchor.clone());

                    return Ok(entry.policy.clone());
                }
            }
        }

        // Load from file
        let policy_path = self.get_policy_path(anchor);

        let policy_json = match fs::read_to_string(&policy_path) {
            Ok(content) => content,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(DsmError::not_found(
                    "Policy",
                    Some(format!("Policy with anchor {} not found", anchor.to_hex())),
                ));
            }
            Err(e) => {
                return Err(DsmError::storage(
                    format!("Failed to read policy file: {}", e),
                    Some(e),
                ));
            }
        };

        // Deserialize policy
        let policy_file: PolicyFile = serde_json::from_str(&policy_json).map_err(|e| {
            DsmError::serialization(format!("Failed to deserialize policy: {}", e), Some(e))
        })?;

        // Validate anchor
        let calculated_anchor = policy_file.generate_anchor()?;
        if calculated_anchor != *anchor {
            return Err(DsmError::validation(
                format!(
                    "Policy anchor mismatch: expected {}, got {}",
                    anchor.to_hex(),
                    calculated_anchor.to_hex()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Create TokenPolicy for cache
        let token_policy = TokenPolicy {
            file: policy_file,
            anchor: anchor.clone(),
            verified: true,
            last_verified: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Add to cache with LRU management
        self.add_to_cache(anchor.clone(), token_policy.clone());

        Ok(token_policy)
    }

    /// Verify and retrieve a policy by its anchor
    pub async fn verify_and_get_policy(
        &self,
        anchor: &PolicyAnchor,
        policy_data: Option<&[u8]>,
    ) -> Result<TokenPolicy, DsmError> {
        // If policy data is provided, verify it against the anchor
        if let Some(data) = policy_data {
            // Check if the provided policy data matches the anchor
            verify_policy_anchor(anchor)?;

            // Deserialize and store the provided policy
            let policy_file: PolicyFile = serde_json::from_slice(data).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to deserialize policy data: {}", e),
                    Some(e),
                )
            })?;

            // Store policy for future reference
            let _ = self.store_policy(&policy_file).await?;
        }

        // Get policy by anchor
        self.get_policy(anchor).await
    }

    /// List all stored policy anchors
    pub fn list_policy_anchors(&self) -> Result<Vec<PolicyAnchor>, DsmError> {
        let mut anchors = Vec::new();

        // Read directory entries
        for entry in fs::read_dir(&self.base_dir).map_err(|e| {
            DsmError::storage(format!("Failed to read policies directory: {}", e), Some(e))
        })? {
            let entry = entry.map_err(|e| {
                DsmError::storage(format!("Failed to read directory entry: {}", e), Some(e))
            })?;

            let path = entry.path();

            // Skip non-JSON files
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            // Extract anchor from filename
            if let Some(filename) = path.file_stem().and_then(|stem| stem.to_str()) {
                match PolicyAnchor::from_hex(filename) {
                    Ok(anchor) => anchors.push(anchor),
                    Err(_) => {} // Skip invalid filenames
                }
            }
        }

        Ok(anchors)
    }

    /// Delete a policy
    pub async fn delete_policy(&self, anchor: &PolicyAnchor) -> Result<(), DsmError> {
        // Remove from cache
        {
            let mut cache = self.cache.write();
            let mut access_order = self.access_order.write();

            cache.remove(anchor);
            if let Some(pos) = access_order.iter().position(|a| a == anchor) {
                access_order.remove(pos);
            }
        }

        // Delete file
        let policy_path = self.get_policy_path(anchor);

        if policy_path.exists() {
            tokio::fs::remove_file(&policy_path).await.map_err(|e| {
                DsmError::storage(format!("Failed to delete policy file: {}", e), Some(e))
            })?;
        }

        Ok(())
    }

    /// Clear the policy cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        let mut access_order = self.access_order.write();

        cache.clear();
        access_order.clear();
    }

    /// Get policy from cache if available and not expired
    pub fn get_from_cache(&self, anchor: &PolicyAnchor) -> Option<TokenPolicy> {
        let mut cache = self.cache.write();
        let mut access_order = self.access_order.write();

        if let Some(entry) = cache.get_mut(anchor) {
            let now = Instant::now();

            // Check if entry has expired
            if now.duration_since(entry.added) > self.cache_ttl {
                // Remove from cache
                cache.remove(anchor);
                if let Some(pos) = access_order.iter().position(|a| a == anchor) {
                    access_order.remove(pos);
                }
                return None;
            }

            // Update access time and LRU order
            entry.last_access = now;
            if let Some(pos) = access_order.iter().position(|a| a == anchor) {
                access_order.remove(pos);
            }
            access_order.push_back(anchor.clone());

            return Some(entry.policy.clone());
        }

        None
    }

    /// Add a policy to the cache with LRU eviction
    fn add_to_cache(&self, anchor: PolicyAnchor, policy: TokenPolicy) {
        let mut cache = self.cache.write();
        let mut access_order = self.access_order.write();

        // Check if we need to evict entries
        if cache.len() >= self.max_cache_size && !cache.contains_key(&anchor) {
            // Evict least recently used
            if let Some(lru_anchor) = access_order.pop_front() {
                cache.remove(&lru_anchor);
            }
        }

        // Add new entry
        let now = Instant::now();
        let entry = CacheEntry {
            policy,
            added: now,
            last_access: now,
        };

        // Update LRU tracking
        if let Some(pos) = access_order.iter().position(|a| a == &anchor) {
            access_order.remove(pos);
        }
        access_order.push_back(anchor.clone());

        // Insert in cache
        cache.insert(anchor, entry);
    }

    /// Evict expired entries from cache
    pub fn evict_expired(&self) {
        let mut cache = self.cache.write();
        let mut access_order = self.access_order.write();
        let now = Instant::now();

        // Find expired entries
        let expired: Vec<PolicyAnchor> = cache
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.added) > self.cache_ttl)
            .map(|(anchor, _)| anchor.clone())
            .collect();

        // Remove expired entries
        for anchor in &expired {
            cache.remove(anchor);
            if let Some(pos) = access_order.iter().position(|a| a == anchor) {
                access_order.remove(pos);
            }
        }
    }
}
