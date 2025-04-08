//! DLV Manager Module
//!
//! This module implements the manager for Deterministic Limbo Vaults (DLVs),
//! providing functionality for creating, tracking, and interacting with vaults
//! in a thread-safe manner.

use super::{LimboVault, VaultState, FulfillmentMechanism, FulfillmentProof};
use crate::types::{
    error::DsmError,
    state_types::State,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

/// Manages Limbo Vaults
pub struct DLVManager {
    /// Vaults managed by this instance, keyed by vault ID
    vaults: RwLock<HashMap<String, Arc<Mutex<LimboVault>>>>,
}

impl DLVManager {
    /// Create a new DLV manager
    pub fn new() -> Self {
        Self {
            vaults: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new vault
    pub fn create_vault(
        &self,
        creator_keypair: (&[u8], &[u8]),
        condition: FulfillmentMechanism,
        content: &[u8],
        content_type: &str,
        intended_recipient: Option<Vec<u8>>,
        reference_state: &State,
    ) -> Result<String, DsmError> {
        let vault = LimboVault::new(
            creator_keypair,
            condition,
            content,
            content_type,
            intended_recipient,
            reference_state,
        )?;

        let vault_id = vault.id.clone();
        
        let mut vaults = self.vaults.write().map_err(|_| {
            DsmError::internal("Failed to acquire write lock on vaults", None::<std::convert::Infallible>)
        })?;

        vaults.insert(vault_id.clone(), Arc::new(Mutex::new(vault)));

        Ok(vault_id)
    }

    /// Get a vault by ID
    pub fn get_vault(
        &self,
        vault_id: &str,
    ) -> Result<Arc<Mutex<LimboVault>>, DsmError> {
        let vaults = self.vaults.read().map_err(|_| {
            DsmError::internal("Failed to acquire read lock on vaults", None::<std::convert::Infallible>)
        })?;

        vaults.get(vault_id).cloned().ok_or_else(|| {
            DsmError::not_found("Vault", Some(format!("Vault with ID {} not found", vault_id)))
        })
    }

    /// List all vault IDs
    pub fn list_vaults(&self) -> Result<Vec<String>, DsmError> {
        let vaults = self.vaults.read().map_err(|_| {
            DsmError::internal("Failed to acquire read lock on vaults", None::<std::convert::Infallible>)
        })?;

        Ok(vaults.keys().cloned().collect())
    }

    /// Get vaults by status
    pub fn get_vaults_by_status(&self, status: VaultState) -> Result<Vec<String>, DsmError> {
        let vaults = self.vaults.read().map_err(|_| {
            DsmError::internal("Failed to acquire read lock on vaults", None::<std::convert::Infallible>)
        })?;

        let mut result = Vec::new();
        for (id, vault_lock) in vaults.iter() {
            if let Ok(vault) = vault_lock.lock() {
                if vault.state == status {
                    result.push(id.clone());
                }
            }
        }
        Ok(result)
    }

    /// Attempt to unlock a vault
    pub fn try_unlock_vault(
        &self,
        vault_id: &str,
        proof: FulfillmentProof,
        requester: &[u8],
        reference_state: &State,
    ) -> Result<bool, DsmError> {
        let vault_lock = self.get_vault(vault_id)?;
        let mut vault = vault_lock.lock().map_err(|_| {
            DsmError::internal("Failed to acquire lock on vault", None::<std::convert::Infallible>)
        })?;

        vault.unlock(proof, requester, reference_state)
    }

    /// Claim vault content
    pub fn claim_vault_content(
        &self,
        vault_id: &str,
        claimant: &[u8],
        reference_state: &State,
    ) -> Result<Vec<u8>, DsmError> {
        let vault_lock = self.get_vault(vault_id)?;
        let mut vault = vault_lock.lock().map_err(|_| {
            DsmError::internal("Failed to acquire lock on vault", None::<std::convert::Infallible>)
        })?;

        vault.claim(claimant, reference_state).map(|result| result.content)
    }

    /// Invalidate a vault
    pub fn invalidate_vault(
        &self,
        vault_id: &str,
        reason: &str,
        creator_private_key: &[u8],
        reference_state: &State,
    ) -> Result<(), DsmError> {
        let vault_lock = self.get_vault(vault_id)?;
        let mut vault = vault_lock.lock().map_err(|_| {
            DsmError::internal("Failed to acquire lock on vault", None::<std::convert::Infallible>)
        })?;

        vault.invalidate(reason, creator_private_key, reference_state)
    }

    /// Create a vault post
    pub fn create_vault_post(
        &self,
        vault_id: &str,
        purpose: &str,
        timeout: Option<u64>,
    ) -> Result<Vec<u8>, DsmError> {
        let vault_lock = self.get_vault(vault_id)?;
        let vault = vault_lock.lock().map_err(|_| {
            DsmError::internal("Failed to acquire lock on vault", None::<std::convert::Infallible>)
        })?;

        let post = vault.to_vault_post(purpose, timeout)?;
        bincode::serialize(&post).map_err(|e| DsmError::serialization("Failed to serialize vault post", Some(e)))
    }
}

impl Default for DLVManager {
    fn default() -> Self {
        Self::new()
    }
}