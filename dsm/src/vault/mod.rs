// Path: /Users/cryptskii/Desktop/claude_workspace/self_evolving_cryptographic_identification/dsm_project/dsm/src/vault/mod.rs

//! Deterministic Limbo Vault Module
//!
//! This module implements the Deterministic Limbo Vault (DLV) functionality, which allows
//! storing data with time-based or event-based conditions for future release.

use crate::types::error::DsmError;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::fs;
use uuid::Uuid;

/// Vault condition for determining when data can be released
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaultCondition {
    /// Time-based condition (Unix timestamp)
    Time(u64),

    /// Event-based condition (arbitrary data that must match)
    Event(Vec<u8>),
}

/// Status of a vault
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VaultStatus {
    /// Vault is active and locked
    Active,

    /// Vault has been claimed by the recipient
    Claimed,

    /// Vault has been revoked by the creator
    Revoked,

    /// Vault has expired
    Expired,
}

/// Deterministic Limbo Vault for storing conditional data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterministicLimboVault {
    /// Vault ID
    id: String,

    /// Creator's identity ID
    creator_id: String,

    /// Recipient's identity ID
    recipient_id: String,

    /// Vault data
    data: Vec<u8>,

    /// Release condition
    condition: VaultCondition,

    /// Vault status
    status: VaultStatus,

    /// Creation timestamp
    created_at: u64,

    /// Last updated timestamp
    updated_at: u64,

    /// Metadata
    metadata: HashMap<String, String>,
}

impl DeterministicLimboVault {
    /// Create a new vault
    pub fn new(
        creator_id: &str,
        recipient_id: &str,
        data: Vec<u8>,
        condition: VaultCondition,
    ) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;

        Self {
            id: Uuid::new_v4().to_string(),
            creator_id: creator_id.to_string(),
            recipient_id: recipient_id.to_string(),
            data,
            condition,
            status: VaultStatus::Active,
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }

    /// Get the vault ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the creator's identity ID
    pub fn creator_id(&self) -> &str {
        &self.creator_id
    }

    /// Get the recipient's identity ID
    pub fn recipient_id(&self) -> &str {
        &self.recipient_id
    }

    /// Get the vault data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the release condition
    pub fn condition(&self) -> &VaultCondition {
        &self.condition
    }

    /// Get the vault status
    pub fn status(&self) -> &VaultStatus {
        &self.status
    }

    /// Get the creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the last updated timestamp
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Set the vault status
    pub fn set_status(&mut self, status: VaultStatus) {
        self.status = status;
        self.updated_at = chrono::Utc::now().timestamp() as u64;
    }

    /// Check if the vault is claimable
    pub fn is_claimable(&self, recipient_id: &str) -> bool {
        // Must be active
        if self.status != VaultStatus::Active {
            return false;
        }

        // Recipient must match
        if self.recipient_id != recipient_id {
            return false;
        }

        // Check condition
        match &self.condition {
            VaultCondition::Time(timestamp) => {
                let now = chrono::Utc::now().timestamp() as u64;
                now >= *timestamp
            }
            // Event-based conditions must be verified externally
            VaultCondition::Event(_) => false,
        }
    }

    /// Verify an event condition
    pub fn verify_event_condition(&self, event_data: &[u8]) -> bool {
        match &self.condition {
            VaultCondition::Event(expected) => expected == event_data,
            _ => false,
        }
    }
}

/// Interface for vault storage
#[async_trait]
pub trait VaultStorage: Send + Sync {
    /// Store a vault
    async fn store_vault(&self, vault: &DeterministicLimboVault) -> Result<(), DsmError>;

    /// Get a vault by ID
    async fn get_vault(&self, vault_id: &str) -> Result<Option<DeterministicLimboVault>, DsmError>;

    /// Get vaults by creator
    async fn get_vaults_by_creator(
        &self,
        creator_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError>;

    /// Get vaults by recipient
    async fn get_vaults_by_recipient(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError>;

    /// Update a vault
    async fn update_vault(&self, vault: &DeterministicLimboVault) -> Result<(), DsmError>;

    /// Delete a vault
    async fn delete_vault(&self, vault_id: &str) -> Result<(), DsmError>;

    /// Get all vaults
    async fn get_all_vaults(&self) -> Result<Vec<DeterministicLimboVault>, DsmError>;
}

/// File-based vault storage implementation
pub struct FileVaultStorage {
    base_dir: PathBuf,
}

impl Default for FileVaultStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl FileVaultStorage {
    /// Create a new file-based vault storage
    pub fn new() -> Self {
        let home_dir = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());

        let base_dir = PathBuf::from(home_dir).join(".dsm_config").join("vaults");

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&base_dir).unwrap_or_else(|_| {
            eprintln!("Warning: Failed to create vaults storage directory");
        });

        Self { base_dir }
    }

    /// Get the path to a vault file
    fn get_vault_path(&self, vault_id: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", vault_id))
    }

    /// Get the path to a vault index file
    fn get_index_path(&self, index_type: &str, id: &str) -> PathBuf {
        self.base_dir
            .join(format!("index_{}_{}.json", index_type, id))
    }
}

#[async_trait]
impl VaultStorage for FileVaultStorage {
    async fn store_vault(&self, vault: &DeterministicLimboVault) -> Result<(), DsmError> {
        // Serialize vault
        let vault_json = serde_json::to_string_pretty(vault).map_err(|e| {
            DsmError::serialization(format!("Failed to serialize vault: {}", e), Some(e))
        })?;

        // Write vault file
        let vault_path = self.get_vault_path(vault.id());
        fs::write(&vault_path, vault_json).await.map_err(|e| {
            DsmError::storage(format!("Failed to write vault file: {}", e), Some(e))
        })?;

        // Update creator index
        let creator_index_path = self.get_index_path("creator", vault.creator_id());
        let creator_index = if creator_index_path.exists() {
            let content = fs::read_to_string(&creator_index_path).await.map_err(|e| {
                DsmError::storage(format!("Failed to read creator index: {}", e), Some(e))
            })?;

            let mut index: Vec<String> = serde_json::from_str(&content).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to deserialize creator index: {}", e),
                    Some(e),
                )
            })?;

            if !index.contains(&vault.id().to_string()) {
                index.push(vault.id().to_string());
            }

            index
        } else {
            vec![vault.id().to_string()]
        };

        let creator_index_json = serde_json::to_string_pretty(&creator_index).map_err(|e| {
            DsmError::serialization(format!("Failed to serialize creator index: {}", e), Some(e))
        })?;

        fs::write(&creator_index_path, creator_index_json)
            .await
            .map_err(|e| {
                DsmError::storage(format!("Failed to write creator index: {}", e), Some(e))
            })?;

        // Update recipient index
        let recipient_index_path = self.get_index_path("recipient", vault.recipient_id());
        let recipient_index = if recipient_index_path.exists() {
            let content = fs::read_to_string(&recipient_index_path)
                .await
                .map_err(|e| {
                    DsmError::storage(format!("Failed to read recipient index: {}", e), Some(e))
                })?;

            let mut index: Vec<String> = serde_json::from_str(&content).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to deserialize recipient index: {}", e),
                    Some(e),
                )
            })?;

            if !index.contains(&vault.id().to_string()) {
                index.push(vault.id().to_string());
            }

            index
        } else {
            vec![vault.id().to_string()]
        };

        let recipient_index_json = serde_json::to_string_pretty(&recipient_index).map_err(|e| {
            DsmError::serialization(
                format!("Failed to serialize recipient index: {}", e),
                Some(e),
            )
        })?;

        fs::write(&recipient_index_path, recipient_index_json)
            .await
            .map_err(|e| {
                DsmError::storage(format!("Failed to write recipient index: {}", e), Some(e))
            })?;

        Ok(())
    }

    async fn get_vault(&self, vault_id: &str) -> Result<Option<DeterministicLimboVault>, DsmError> {
        let vault_path = self.get_vault_path(vault_id);

        if !vault_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&vault_path)
            .await
            .map_err(|e| DsmError::storage(format!("Failed to read vault file: {}", e), Some(e)))?;

        let vault: DeterministicLimboVault = serde_json::from_str(&content).map_err(|e| {
            DsmError::serialization(format!("Failed to deserialize vault: {}", e), Some(e))
        })?;

        Ok(Some(vault))
    }

    async fn get_vaults_by_creator(
        &self,
        creator_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        let index_path = self.get_index_path("creator", creator_id);

        if !index_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&index_path).await.map_err(|e| {
            DsmError::storage(format!("Failed to read creator index: {}", e), Some(e))
        })?;

        let index: Vec<String> = serde_json::from_str(&content).map_err(|e| {
            DsmError::serialization(
                format!("Failed to deserialize creator index: {}", e),
                Some(e),
            )
        })?;

        let mut vaults = Vec::new();
        for vault_id in index {
            if let Some(vault) = self.get_vault(&vault_id).await? {
                vaults.push(vault);
            }
        }

        Ok(vaults)
    }

    async fn get_vaults_by_recipient(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        let index_path = self.get_index_path("recipient", recipient_id);

        if !index_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&index_path).await.map_err(|e| {
            DsmError::storage(format!("Failed to read recipient index: {}", e), Some(e))
        })?;

        let index: Vec<String> = serde_json::from_str(&content).map_err(|e| {
            DsmError::serialization(
                format!("Failed to deserialize recipient index: {}", e),
                Some(e),
            )
        })?;

        let mut vaults = Vec::new();
        for vault_id in index {
            if let Some(vault) = self.get_vault(&vault_id).await? {
                vaults.push(vault);
            }
        }

        Ok(vaults)
    }

    async fn update_vault(&self, vault: &DeterministicLimboVault) -> Result<(), DsmError> {
        // Simply store the updated vault
        self.store_vault(vault).await
    }

    async fn delete_vault(&self, vault_id: &str) -> Result<(), DsmError> {
        // Get the vault first to update indices
        let vault = match self.get_vault(vault_id).await? {
            Some(v) => v,
            None => {
                return Err(DsmError::not_found(
                    "Vault",
                    Some(format!("Vault with ID {} not found", vault_id)),
                ))
            }
        };

        // Update creator index
        let creator_index_path = self.get_index_path("creator", vault.creator_id());
        if creator_index_path.exists() {
            let content = fs::read_to_string(&creator_index_path).await.map_err(|e| {
                DsmError::storage(format!("Failed to read creator index: {}", e), Some(e))
            })?;

            let mut index: Vec<String> = serde_json::from_str(&content).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to deserialize creator index: {}", e),
                    Some(e),
                )
            })?;

            index.retain(|id| id != vault_id);

            let creator_index_json = serde_json::to_string_pretty(&index).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to serialize creator index: {}", e),
                    Some(e),
                )
            })?;

            fs::write(&creator_index_path, creator_index_json)
                .await
                .map_err(|e| {
                    DsmError::storage(format!("Failed to write creator index: {}", e), Some(e))
                })?;
        }

        // Update recipient index
        let recipient_index_path = self.get_index_path("recipient", vault.recipient_id());
        if recipient_index_path.exists() {
            let content = fs::read_to_string(&recipient_index_path)
                .await
                .map_err(|e| {
                    DsmError::storage(format!("Failed to read recipient index: {}", e), Some(e))
                })?;

            let mut index: Vec<String> = serde_json::from_str(&content).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to deserialize recipient index: {}", e),
                    Some(e),
                )
            })?;

            index.retain(|id| id != vault_id);

            let recipient_index_json = serde_json::to_string_pretty(&index).map_err(|e| {
                DsmError::serialization(
                    format!("Failed to serialize recipient index: {}", e),
                    Some(e),
                )
            })?;

            fs::write(&recipient_index_path, recipient_index_json)
                .await
                .map_err(|e| {
                    DsmError::storage(format!("Failed to write recipient index: {}", e), Some(e))
                })?;
        }

        // Delete vault file
        let vault_path = self.get_vault_path(vault_id);
        fs::remove_file(&vault_path).await.map_err(|e| {
            DsmError::storage(format!("Failed to delete vault file: {}", e), Some(e))
        })?;

        Ok(())
    }

    async fn get_all_vaults(&self) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        let mut vaults = Vec::new();

        let mut dir = fs::read_dir(&self.base_dir).await.map_err(|e| {
            DsmError::storage(format!("Failed to read vaults directory: {}", e), Some(e))
        })?;

        while let Some(entry) = dir.next_entry().await.map_err(|e| {
            DsmError::storage(
                format!("Failed to read vaults directory entry: {}", e),
                Some(e),
            )
        })? {
            let path = entry.path();

            // Skip non-JSON files and index files
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            let filename = path.file_name().unwrap().to_string_lossy();
            if filename.starts_with("index_") {
                continue;
            }

            // Read and parse file
            let content = fs::read_to_string(&path).await.map_err(|e| {
                DsmError::storage(format!("Failed to read vault file: {}", e), Some(e))
            })?;

            let vault: DeterministicLimboVault = serde_json::from_str(&content).map_err(|e| {
                DsmError::serialization(format!("Failed to deserialize vault: {}", e), Some(e))
            })?;

            vaults.push(vault);
        }

        Ok(vaults)
    }
}

/// In-memory vault storage implementation (for testing)
pub struct MemoryVaultStorage {
    vaults: Arc<RwLock<HashMap<String, DeterministicLimboVault>>>,
}

impl Default for MemoryVaultStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryVaultStorage {
    /// Create a new in-memory vault storage
    pub fn new() -> Self {
        Self {
            vaults: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl VaultStorage for MemoryVaultStorage {
    async fn store_vault(&self, vault: &DeterministicLimboVault) -> Result<(), DsmError> {
        let mut vaults = self.vaults.write();
        vaults.insert(vault.id().to_string(), vault.clone());
        Ok(())
    }

    async fn get_vault(&self, vault_id: &str) -> Result<Option<DeterministicLimboVault>, DsmError> {
        let vaults = self.vaults.read();
        Ok(vaults.get(vault_id).cloned())
    }

    async fn get_vaults_by_creator(
        &self,
        creator_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        let vaults = self.vaults.read();
        let filtered = vaults
            .values()
            .filter(|v| v.creator_id() == creator_id)
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn get_vaults_by_recipient(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        let vaults = self.vaults.read();
        let filtered = vaults
            .values()
            .filter(|v| v.recipient_id() == recipient_id)
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn update_vault(&self, vault: &DeterministicLimboVault) -> Result<(), DsmError> {
        let mut vaults = self.vaults.write();
        vaults.insert(vault.id().to_string(), vault.clone());
        Ok(())
    }

    async fn delete_vault(&self, vault_id: &str) -> Result<(), DsmError> {
        let mut vaults = self.vaults.write();
        if vaults.remove(vault_id).is_none() {
            return Err(DsmError::not_found(
                "Vault",
                Some(format!("Vault with ID {} not found", vault_id)),
            ));
        }
        Ok(())
    }

    async fn get_all_vaults(&self) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        let vaults = self.vaults.read();
        let all = vaults.values().cloned().collect();
        Ok(all)
    }
}

/// Deterministic Limbo Vault Manager for handling vault operations
pub struct DLVManager {
    storage: Box<dyn VaultStorage>,
}

impl DLVManager {
    /// Create a new DLV manager with file-based storage
    pub fn new() -> Self {
        Self {
            storage: Box::new(FileVaultStorage::new()),
        }
    }

    /// Create a new DLV manager with in-memory storage (for testing)
    pub fn new_in_memory() -> Self {
        Self {
            storage: Box::new(MemoryVaultStorage::new()),
        }
    }

    /// Create a new vault and store it
    pub async fn create_vault(&self, vault: DeterministicLimboVault) -> Result<String, DsmError> {
        let vault_id = vault.id().to_string();
        self.storage.store_vault(&vault).await?;
        Ok(vault_id)
    }

    /// Get a vault by ID
    pub async fn get_vault(&self, vault_id: &str) -> Result<DeterministicLimboVault, DsmError> {
        match self.storage.get_vault(vault_id).await? {
            Some(vault) => Ok(vault),
            None => Err(DsmError::not_found(
                "Vault",
                Some(format!("Vault with ID {} not found", vault_id)),
            )),
        }
    }

    /// Get vaults by creator
    pub async fn get_vaults_by_creator(
        &self,
        creator_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        self.storage.get_vaults_by_creator(creator_id).await
    }

    /// Get vaults by recipient
    pub async fn get_vaults_by_recipient(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        self.storage.get_vaults_by_recipient(recipient_id).await
    }

    /// Get all vaults
    pub async fn get_all_vaults(&self) -> Result<Vec<DeterministicLimboVault>, DsmError> {
        self.storage.get_all_vaults().await
    }

    /// Claim a vault if conditions are met
    pub async fn claim_vault(&self, vault_id: &str, recipient_id: &str) -> Result<bool, DsmError> {
        let mut vault = self.get_vault(vault_id).await?;

        // Check if the vault is claimable
        if !vault.is_claimable(recipient_id) {
            return Ok(false);
        }

        // Update status
        vault.set_status(VaultStatus::Claimed);
        self.storage.update_vault(&vault).await?;

        Ok(true)
    }

    /// Verify an event condition and claim if valid
    pub async fn verify_event_condition(
        &self,
        vault_id: &str,
        recipient_id: &str,
        event_data: &[u8],
    ) -> Result<bool, DsmError> {
        let mut vault = self.get_vault(vault_id).await?;

        // Check if this is an event condition vault
        match vault.condition() {
            VaultCondition::Event(_) => {
                // Check if vault is active and for the right recipient
                if vault.status() != &VaultStatus::Active || vault.recipient_id() != recipient_id {
                    return Ok(false);
                }

                // Verify the event condition
                if vault.verify_event_condition(event_data) {
                    // Update status
                    vault.set_status(VaultStatus::Claimed);
                    self.storage.update_vault(&vault).await?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false), // Not an event condition vault
        }
    }

    /// Revoke a vault (creator only)
    pub async fn revoke_vault(&self, vault_id: &str, creator_id: &str) -> Result<bool, DsmError> {
        let mut vault = self.get_vault(vault_id).await?;

        // Check if creator matches
        if vault.creator_id() != creator_id {
            return Ok(false);
        }

        // Check if vault is still active
        if vault.status() != &VaultStatus::Active {
            return Ok(false);
        }

        // Update status
        vault.set_status(VaultStatus::Revoked);
        self.storage.update_vault(&vault).await?;

        Ok(true)
    }

    /// Delete a vault (only if it's no longer active)
    pub async fn delete_vault(&self, vault_id: &str) -> Result<bool, DsmError> {
        let vault = self.get_vault(vault_id).await?;

        // Only allow deletion of non-active vaults
        if vault.status() == &VaultStatus::Active {
            return Ok(false);
        }

        self.storage.delete_vault(vault_id).await?;
        Ok(true)
    }
}

impl Default for DLVManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_claim_time_vault() {
        // Create in-memory vault manager for testing
        let manager = DLVManager::new_in_memory();

        // Create vault with time condition in the past
        let now = chrono::Utc::now().timestamp() as u64;
        let past_time = now - 3600; // 1 hour ago

        let vault = DeterministicLimboVault::new(
            "creator123",
            "recipient456",
            b"test vault data".to_vec(),
            VaultCondition::Time(past_time),
        );

        let vault_id = manager.create_vault(vault).await.unwrap();

        // Claim the vault
        let claimed = manager
            .claim_vault(&vault_id, "recipient456")
            .await
            .unwrap();
        assert!(claimed);

        // Verify status is updated
        let vault = manager.get_vault(&vault_id).await.unwrap();
        assert_eq!(vault.status(), &VaultStatus::Claimed);
    }

    #[tokio::test]
    async fn test_create_and_claim_event_vault() {
        // Create in-memory vault manager for testing
        let manager = DLVManager::new_in_memory();

        // Create vault with event condition
        let event_data = b"special_event_123".to_vec();

        let vault = DeterministicLimboVault::new(
            "creator123",
            "recipient456",
            b"test vault data".to_vec(),
            VaultCondition::Event(event_data.clone()),
        );

        let vault_id = manager.create_vault(vault).await.unwrap();

        // Try claiming with wrong event data
        let claimed = manager
            .verify_event_condition(&vault_id, "recipient456", b"wrong_event_data")
            .await
            .unwrap();
        assert!(!claimed);

        // Verify status is still active
        let vault = manager.get_vault(&vault_id).await.unwrap();
        assert_eq!(vault.status(), &VaultStatus::Active);

        // Try claiming with correct event data
        let claimed = manager
            .verify_event_condition(&vault_id, "recipient456", &event_data)
            .await
            .unwrap();
        assert!(claimed);

        // Verify status is updated
        let vault = manager.get_vault(&vault_id).await.unwrap();
        assert_eq!(vault.status(), &VaultStatus::Claimed);
    }

    #[tokio::test]
    async fn test_revoke_vault() {
        // Create in-memory vault manager for testing
        let manager = DLVManager::new_in_memory();

        // Create vault
        let vault = DeterministicLimboVault::new(
            "creator123",
            "recipient456",
            b"test vault data".to_vec(),
            VaultCondition::Time(chrono::Utc::now().timestamp() as u64 + 3600), // 1 hour in future
        );

        let vault_id = manager.create_vault(vault).await.unwrap();

        // Revoke with wrong creator
        let revoked = manager
            .revoke_vault(&vault_id, "wrong_creator")
            .await
            .unwrap();
        assert!(!revoked);

        // Verify status is still active
        let vault = manager.get_vault(&vault_id).await.unwrap();
        assert_eq!(vault.status(), &VaultStatus::Active);

        // Revoke with correct creator
        let revoked = manager.revoke_vault(&vault_id, "creator123").await.unwrap();
        assert!(revoked);

        // Verify status is updated
        let vault = manager.get_vault(&vault_id).await.unwrap();
        assert_eq!(vault.status(), &VaultStatus::Revoked);
    }
}
