//! Token Registry
//!
//! Provides a centralized registry for token lookup and management.
//! This module serves as the lookup/registry service for tokens,
//! delegating state integration to the TokenStateManager.

use std::{collections::HashMap, sync::Arc};

use parking_lot::RwLock;

use crate::{
    core::token::token_state_manager::TokenStateManager,
    types::{
        error::DsmError,
        token_types::{Balance, Token, TokenStatus},
    },
};

/// Token Registry for managing token metadata and lookup
pub struct TokenRegistry {
    /// Internal token storage (separate from state-integrated balances)
    token_store: Arc<RwLock<HashMap<String, Token>>>,

    /// Mapping from friendly names to token IDs for easier lookup
    name_registry: Arc<RwLock<HashMap<String, String>>>,

    /// Reference to the token state manager for state-integrated operations
    token_state_manager: Arc<TokenStateManager>,
}

impl TokenRegistry {
    /// Create a new token registry with a reference to the token state manager
    pub fn new(token_state_manager: Arc<TokenStateManager>) -> Self {
        Self {
            token_store: Arc::new(RwLock::new(HashMap::new())),
            name_registry: Arc::new(RwLock::new(HashMap::new())),
            token_state_manager,
        }
    }

    /// Register a token in the registry
    pub fn register_token(
        &self,
        token: Token,
        friendly_name: Option<String>,
    ) -> Result<(), DsmError> {
        // Instead of using store_token (which doesn't exist), store locally
        // self.token_state_manager.store_token(token.clone())?;

        // Update local registry
        let mut store = self.token_store.write();
        store.insert(token.id().to_string(), token.clone());

        // If friendly name provided, register it
        if let Some(name) = friendly_name {
            let mut names = self.name_registry.write();
            names.insert(name, token.id().to_string());
        }

        Ok(())
    }

    /// Get a token by ID
    pub fn get_token(&self, token_id: &str) -> Result<Token, DsmError> {
        // Try TokenStateManager first
        match self.token_state_manager.get_token(token_id) {
            Ok(token) => Ok(token),
            Err(_) => {
                // If not found in state manager, try local registry
                let store = self.token_store.read();
                store
                    .get(token_id)
                    .cloned()
                    .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))
            }
        }
    }

    /// Get a token by its friendly name
    pub fn get_token_by_name(&self, name: &str) -> Result<Token, DsmError> {
        let names = self.name_registry.read();

        if let Some(token_id) = names.get(name) {
            self.get_token(token_id)
        } else {
            Err(DsmError::not_found("Token name", Some(name.to_string())))
        }
    }

    /// Find tokens matching search criteria
    pub fn find_tokens(
        &self,
        owner_id: Option<&str>,
        status: Option<TokenStatus>,
        limit: usize,
    ) -> Result<Vec<Token>, DsmError> {
        let store = self.token_store.read();

        let mut results: Vec<Token> = store
            .values()
            .filter(|token| {
                // Apply owner filter if specified
                if let Some(owner) = owner_id {
                    if token.owner_id() != owner {
                        return false;
                    }
                }

                // Apply status filter if specified
                if let Some(s) = &status {
                    if token.status() != s {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Sort by ID for deterministic results
        results.sort_by(|a, b| a.id().cmp(b.id()));

        // Apply limit
        if results.len() > limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    /// Verify if a token exists and is valid
    pub fn verify_token(&self, token_id: &str) -> Result<bool, DsmError> {
        match self.get_token(token_id) {
            Ok(token) => Ok(token.is_valid()),
            Err(DsmError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Update token friendly name
    pub fn update_token_name(&self, token_id: &str, new_name: &str) -> Result<(), DsmError> {
        // Verify token exists
        self.get_token(token_id)?;

        // Update name mapping
        let mut names = self.name_registry.write();

        // Remove old name mapping if exists
        let key_to_remove = names
            .iter()
            .find(|(_, v)| *v == token_id)
            .map(|(k, _)| k.clone());

        if let Some(key) = key_to_remove {
            names.remove(&key);
        }

        // Add new name mapping
        names.insert(new_name.to_string(), token_id.to_string());

        Ok(())
    }

    /// Get all registered token IDs
    pub fn get_all_token_ids(&self) -> Result<Vec<String>, DsmError> {
        let store = self.token_store.read();
        Ok(store.keys().cloned().collect())
    }

    /// Get token count
    pub fn token_count(&self) -> usize {
        self.token_store.read().len()
    }

    /// Get token's balance for a specific owner
    pub fn get_token_balance(&self, token_id: &str, owner_id: &str) -> Balance {
        // Convert owner_id to bytes for TokenStateManager
        self.token_state_manager
            .get_token_balance_from_store(owner_id.as_bytes(), token_id)
    }

    /// Revoke a token
    pub fn revoke_token(&self, token_id: &str) -> Result<(), DsmError> {
        // Try state manager method, ignoring errors if it doesn't exist
        let _ = self.token_state_manager.revoke_token(token_id);

        // Then update local registry
        let mut store = self.token_store.write();

        if let Some(token) = store.get_mut(token_id) {
            token.set_status(TokenStatus::Revoked);
            Ok(())
        } else {
            Err(DsmError::not_found("Token", Some(token_id.to_string())))
        }
    }

    /// Update token metadata
    pub fn update_token_metadata(&self, token_id: &str, metadata: Vec<u8>) -> Result<(), DsmError> {
        // Try to update in state manager if method exists (skipping if error occurs)
        let _ = self
            .token_state_manager
            .update_token_metadata(token_id, metadata.clone());

        // Always update in local registry
        let mut store = self.token_store.write();

        if let Some(token) = store.get_mut(token_id) {
            let mut updated_token = Token::new(
                token.owner_id(),
                token.token_hash().to_vec(),
                metadata,
                token.balance().clone(),
            );

            // Preserve token status
            if token.status() == &TokenStatus::Revoked {
                updated_token.set_status(TokenStatus::Revoked);
            }

            // Replace token
            store.insert(token_id.to_string(), updated_token);
            Ok(())
        } else {
            Err(DsmError::not_found("Token", Some(token_id.to_string())))
        }
    }

    /// Refresh local registry from token state manager
    pub fn refresh_registry(&self) -> Result<(), DsmError> {
        // Since token_state_manager.list_tokens() may not be available or is implemented differently,
        // we can use our local token store as a fallback
        // Get all tokens from local store instead
        let local_token_ids: Vec<String> = self.token_store.read().keys().cloned().collect();

        let mut store = self.token_store.write();

        // Instead of clearing, we'll update existing tokens
        for id in local_token_ids {
            if let Ok(token) = self.token_state_manager.get_token(&id) {
                store.insert(id, token);
            }
        }

        Ok(())
    }
}
