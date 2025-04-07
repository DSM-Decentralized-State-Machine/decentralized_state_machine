//! Token State Manager
//!
//! Implements atomic state updates for tokens as specified in whitepaper Section 9.
//! This module ensures that token operations are integrated directly into state transitions,
//! providing atomic guarantees for token balances and state evolution.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Fix the imports to use the correct policy types
use crate::policy::policy_store::PolicyStore;
use crate::policy::policy_types::PolicyAnchor;
use crate::policy::policy_verification::{verify_policy, PolicyVerificationResult};
use crate::types::error::DsmError;
use crate::types::operations::{Operation, Ops};
use crate::types::state_types::State;
use crate::types::token_types::{Balance, Token, TokenStatus};

use tokio::runtime::Runtime;

// We're removing duplicate token type definitions and using the imported ones instead

// These are token extensions for methods that aren't available in the type definitions
// They are implemented on the imported types

#[derive(Debug)]
pub struct TokenTransfer {
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub amount: u64,
    pub token_id: String,
    pub timestamp: u64,
}

/// Helper for returning an insufficient-balance error
pub fn insufficient_balance(message: impl Into<String>) -> DsmError {
    DsmError::token_error(message.into(), None::<std::io::Error>)
}

/// TokenStateManager implements atomic state updates for tokens as specified in the whitepaper.
/// This integrates token balances directly in state transitions (Section 9).
#[derive(Debug, Default)]
pub struct TokenStateManager {
    /// Underlying token store (optional usage)
    token_store: Arc<RwLock<HashMap<String, Token>>>,

    /// Balance cache for performance optimization
    balance_cache: Arc<RwLock<HashMap<String, Balance>>>,
    
    /// Policy store for token policy verification
    policy_store: Option<Arc<PolicyStore>>,
    
    /// Runtime for async operations
    runtime: Option<Runtime>,
}

impl TokenStateManager {
    /// Create a new TokenStateManager
    pub fn new() -> Self {
        let runtime = Runtime::new().ok();
        
        Self {
            token_store: Arc::new(RwLock::new(HashMap::new())),
            balance_cache: Arc::new(RwLock::new(HashMap::new())),
            policy_store: None,
            runtime,
        }
    }
    
    /// Create a new TokenStateManager with a policy store
    pub fn with_policy_store(policy_store: Arc<PolicyStore>) -> Self {
        let runtime = Runtime::new().ok();
        
        Self {
            token_store: Arc::new(RwLock::new(HashMap::new())),
            balance_cache: Arc::new(RwLock::new(HashMap::new())),
            policy_store: Some(policy_store),
            runtime,
        }
    }

    /// Create a new token state transition that maintains commitment chain integrity
    pub fn create_token_state_transition(
        &self,
        current_state: &State,
        operation: Operation,
        new_entropy: Vec<u8>,
        encapsulated_entropy: Option<Vec<u8>>,
    ) -> Result<State, DsmError> {
        // First validate operation meets basic requirements using the Ops trait
        if let Err(e) = operation.validate() {
            return Err(DsmError::validation(
                format!("Invalid operation for token state transition: {}", e),
                Some(e),
            ));
        }

        // Apply token operation atomically - all balance changes happen together
        let updated_balances = self.apply_token_operation(current_state, &operation)?;

        // Calculate previous state hash for chain integrity
        let prev_state_hash = current_state.hash()?;
        let next_state_number = current_state.state_number + 1;

        // Build sparse index for efficient verification
        let mut indices = Vec::new();
        let mut n = next_state_number;
        while n > 0 {
            if n & 1 == 1 {
                indices.push(n);
            }
            n >>= 1;
        }
        
        // Use the proper SparseIndex type
        let sparse_index = crate::types::state_types::SparseIndex::new(indices);

        // Validate forward commitment adherence if present
        if let Some(pre_commit) = &current_state.forward_commitment {
            // Verify pre-commitment signature and parameters
            if !self.verify_precommitment_parameters(pre_commit, &operation)? {
                return Err(DsmError::policy_violation(
                    "forward commitment".to_string(),
                    "Operation violates forward commitment parameters".to_string(),
                    None::<std::io::Error>,
                ));
            }
        }
        // Create new state with atomic token balance updates
        let state_params = crate::types::state_types::StateParams::new(
            next_state_number,
            new_entropy,
            operation,
            current_state.device_info.clone(),
        );

        // Set additional parameters
        let state_params = state_params
            .with_encapsulated_entropy(encapsulated_entropy.unwrap_or_default())
            .with_prev_state_hash(prev_state_hash)
            .with_sparse_index(sparse_index);

        let mut new_state = State::new(state_params);

        // Set token balances atomically
        new_state.token_balances = updated_balances;

        // Set ID in canonical format
        new_state.id = format!("state_{}", new_state.state_number);

        // Compute final hash including all state components
        let computed_hash = new_state.compute_hash()?;
        new_state.hash = computed_hash;

        Ok(new_state)
    }

    /// Apply token operations atomically while maintaining forward commitment chain
    pub fn apply_token_operation(
        &self,
        current_state: &State,
        operation: &Operation,
    ) -> Result<HashMap<String, Balance>, DsmError> {
        // First, verify the token policy if applicable
        self.verify_token_policy(operation)?;
        
        let mut new_balances = current_state.token_balances.clone();

        match operation {
            Operation::Transfer {
                token_id,
                amount,
                recipient,
                ..
            } => {
                // Get the sender's key from the device info
                let sender_key = current_state.device_info.public_key.clone();

                // Use recipient as a string key directly, not trying to access device_info
                let recipient_key = recipient.clone();

                let sender_balance = new_balances
                    .get(token_id)
                    .ok_or_else(|| DsmError::not_found("Token", Some(token_id.clone())))?;

                // Verify sufficient balance
                if sender_balance.value() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_id.clone(),
                        sender_balance.value() as i64,
                        amount.value() as i64,
                    ));
                }

                // Update balances atomically
                let new_sender_balance = crate::types::token_types::Balance::new(sender_balance.value() - amount.value());
                let recipient_balance = new_balances
                    .get(&recipient_key)
                    .cloned()
                    .unwrap_or_else(|| crate::types::token_types::Balance::new(0));

                let new_recipient_balance =
                    crate::types::token_types::Balance::new(recipient_balance.value() + amount.value());

                // Convert the Vec<u8> to a hex string as key
                let sender_key_string = hex::encode(&sender_key);
                new_balances.insert(sender_key_string, new_sender_balance);
                new_balances.insert(recipient_key, new_recipient_balance);
            }

            Operation::Mint {
                amount,
                token_id,
                authorized_by,
                proof_of_authorization,
                ..
            } => {
                // Verify mint authorization
                if !self.verify_mint_authorization(authorized_by, proof_of_authorization)? {
                    return Err(DsmError::unauthorized(
                        "Invalid mint authorization",
                        None::<std::io::Error>,
                    ));
                }

                let recipient_key = format!("{}:{}", current_state.device_info.device_id, token_id);
                let current_balance = new_balances
                    .get(&recipient_key)
                    .cloned()
                    .unwrap_or_else(|| crate::types::token_types::Balance::new(0));

                new_balances.insert(
                    recipient_key,
                    crate::types::token_types::Balance::new(current_balance.value() + amount.value()),
                );
            }

            Operation::Burn {
                amount,
                token_id,
                proof_of_ownership,
                ..
            } => {
                // Verify ownership proof
                if !self.verify_token_ownership(token_id, proof_of_ownership)? {
                    return Err(DsmError::unauthorized(
                        "Invalid burn authorization",
                        None::<std::io::Error>,
                    ));
                }

                let owner_key = format!("{}:{}", current_state.device_info.device_id, token_id);
                let owner_balance = new_balances
                    .get(&owner_key)
                    .cloned()
                    .unwrap_or_else(|| crate::types::token_types::Balance::new(0));

                if owner_balance.value() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_id.clone(),
                        owner_balance.value() as i64,
                        amount.value() as i64,
                    ));
                }

                new_balances.insert(
                    owner_key,
                    crate::types::token_types::Balance::new(owner_balance.value() - amount.value()),
                );
            }

            _ => {} // Other operations don't affect token balances
        }

        Ok(new_balances)
    }
    
    /// Verify that an operation complies with the pre-commitment parameters
    /// 
    /// This implements the pre-commitment verification described in whitepaper
    /// section 8, ensuring that operations adhere to previously committed parameters.
    /// 
    /// # Arguments
    /// * `pre_commit` - The pre-commitment to verify against
    /// * `operation` - The operation to verify
    /// 
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether the operation complies with the pre-commitment
    fn verify_precommitment_parameters(
        &self,
        pre_commit: &crate::types::state_types::PreCommitment,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        // First, verify operation type matches the pre-commitment
        let matches_type = match operation {
            Operation::Transfer { .. } => pre_commit.operation_type == "transfer",
            Operation::Mint { .. } => pre_commit.operation_type == "mint",
            Operation::Burn { .. } => pre_commit.operation_type == "burn",
            Operation::LockToken { .. } => pre_commit.operation_type == "lock",
            Operation::UnlockToken { .. } => pre_commit.operation_type == "unlock",
            _ => false, // Non-token operations don't match any token pre-commitment
        };

        if !matches_type {
            return Ok(false);
        }

        // Check that operation matches fixed parameters
        let matches_fixed_params = match operation {
            Operation::Transfer { token_id, recipient, .. } => {
                // Check if token_id matches fixed parameter if present
                let token_id_matches = if let Some(expected_token_id) = pre_commit.fixed_parameters.get("token_id") {
                    token_id.as_bytes() == expected_token_id.as_slice()
                } else {
                    true // No constraint on token_id
                };

                // Check if recipient matches fixed parameter if present
                let recipient_matches = if let Some(expected_recipient) = pre_commit.fixed_parameters.get("recipient") {
                    recipient.as_bytes() == expected_recipient.as_slice()
                } else {
                    true // No constraint on recipient
                };

                token_id_matches && recipient_matches
            },
            Operation::Mint { token_id, .. } => {
                // Check if token_id matches fixed parameter if present
                if let Some(expected_token_id) = pre_commit.fixed_parameters.get("token_id") {
                    token_id.as_bytes() == expected_token_id.as_slice()
                } else {
                    true // No constraint on token_id
                }
            },
            Operation::Burn { token_id, .. } => {
                // Check if token_id matches fixed parameter if present
                if let Some(expected_token_id) = pre_commit.fixed_parameters.get("token_id") {
                    token_id.as_bytes() == expected_token_id.as_slice()
                } else {
                    true // No constraint on token_id
                }
            },
            _ => true, // For other operations, no fixed parameters to check
        };

        if !matches_fixed_params {
            return Ok(false);
        }

                // Verify operation only modifies allowed variable parameters
                let variable_params_valid = match operation {
                    Operation::Transfer { amount, .. } => {
                        // For transfers, check if amount is allowed to vary
                        pre_commit.variable_parameters.contains("amount") || 
                        // Or check if fixed amount matches
                        if let Some(expected_amount_bytes) = pre_commit.fixed_parameters.get("amount") {
                            if expected_amount_bytes.len() == 8 {
                                let mut expected_amount_arr = [0u8; 8];
                                expected_amount_arr.copy_from_slice(&expected_amount_bytes[0..8]);
                                let expected_amount = u64::from_le_bytes(expected_amount_arr);
                                amount.value() == expected_amount
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    },
                    Operation::Mint { amount, .. } => {
                        // For mints, check if amount is allowed to vary
                        pre_commit.variable_parameters.contains("amount") || 
                        // Or check if fixed amount matches
                        if let Some(expected_amount_bytes) = pre_commit.fixed_parameters.get("amount") {
                            if expected_amount_bytes.len() == 8 {
                                let mut expected_amount_arr = [0u8; 8];
                                expected_amount_arr.copy_from_slice(&expected_amount_bytes[0..8]);
                                let expected_amount = u64::from_le_bytes(expected_amount_arr);
                                amount.value() == expected_amount
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    },
                    Operation::Burn { amount, .. } => {
                        // For burns, check if amount is allowed to vary
                        pre_commit.variable_parameters.contains("amount") || 
                        // Or check if fixed amount matches
                        if let Some(expected_amount_bytes) = pre_commit.fixed_parameters.get("amount") {
                            if expected_amount_bytes.len() == 8 {
                                let mut expected_amount_arr = [0u8; 8];
                                expected_amount_arr.copy_from_slice(&expected_amount_bytes[0..8]);
                                let expected_amount = u64::from_le_bytes(expected_amount_arr);
                                amount.value() == expected_amount
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    },
                    _ => true, // For other operations, no variable parameters to check
                };

        Ok(matches_type && matches_fixed_params && variable_params_valid)
    }
    
    /// Verify mint authorization proof
    fn verify_mint_authorization(
        &self,
        _authorized_by: &str,
        _proof: &[u8],
    ) -> Result<bool, DsmError> {
        // Implementation would verify cryptographic proof
        Ok(true) // Placeholder
    }

    /// Verify token ownership proof
    fn verify_token_ownership(&self, _token_id: &str, _proof: &[u8]) -> Result<bool, DsmError> {
        // Implementation would verify cryptographic proof
        Ok(true) // Placeholder
    }
    
    /// Verify that the operation complies with the token's CTPA policy
    fn verify_token_policy(&self, operation: &Operation) -> Result<(), DsmError> {
        // Skip verification if policy store is not configured
        let policy_store = match &self.policy_store {
            Some(store) => store,
            None => return Ok(()), // No policy store, skip verification
        };
        
        // Get token ID based on operation type
        let token_id = match operation {
            Operation::Transfer { token_id, .. } => token_id,
            Operation::Mint { token_id, .. } => token_id,
            Operation::Burn { token_id, .. } => token_id,
            Operation::LockToken { token_id, .. } => token_id,
            Operation::UnlockToken { token_id, .. } => token_id,
            _ => return Ok(()), // Not a token operation, skip verification
        };
        
        // Get token to check if it has a policy anchor
        let token = match self.get_token(token_id) {
            Ok(token) => token,
            Err(_) => return Ok(()), // Token not found, skip verification
        };
        
        // Skip verification if token has no policy anchor
        let policy_anchor_bytes = match token.policy_anchor() {
            Some(anchor) => anchor,
            None => return Ok(()), // No policy anchor, skip verification
        };
        
        // Create PolicyAnchor from bytes
        let policy_anchor = PolicyAnchor(*policy_anchor_bytes);
        
        // Get runtime for async operations
        let runtime = match &self.runtime {
            Some(rt) => rt,
            None => return Err(DsmError::internal(
                "No runtime available for policy verification",
                None::<std::io::Error>
            )),
        };
        
        // Retrieve and verify policy
        let policy = match runtime.block_on(policy_store.get_policy(&policy_anchor)) {
            Ok(policy) => policy,
            Err(e) => {
                return Err(DsmError::validation(
                    format!("Failed to retrieve policy for token {}: {}", token_id, e),
                    Some(e),
                ));
            }
        };
        
        // Verify the policy against the operation
        let result = verify_policy(&policy, operation, None, None, None);
        
        match result {
            PolicyVerificationResult::Valid => Ok(()),
            PolicyVerificationResult::Invalid { message, condition: _ } => {
                Err(DsmError::policy_violation(
                    token_id.clone(),
                    format!("Policy violation: {}", message),
                    None::<std::io::Error>,
                ))
            },
            PolicyVerificationResult::Unverifiable { message } => {
                Err(DsmError::validation(
                    format!("Policy verification failed: {}", message),
                    None::<std::io::Error>,
                ))
            }
        }
    }
    // ------------------------------------------------------------------------
    //                           Token Store Methods
    // ------------------------------------------------------------------------

    /// Check if a token with the given `token_id` exists
    pub fn token_exists(&self, token_id: &str) -> Result<bool, DsmError> {
        let store = self.token_store.read().map_err(|_| DsmError::LockError)?;
        Ok(store.contains_key(token_id))
    }

    /// Retrieve a `Token` by ID
    pub fn get_token(&self, token_id: &str) -> Result<Token, DsmError> {
        let store = self.token_store.read().map_err(|_| DsmError::LockError)?;
        store
            .get(token_id)
            .cloned()
            .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))
    }

    /// Returns a token's balance for the given `owner_id`, if the store is used that way,
    /// falling back to zero if not found.  (This is separate from the `State::token_balances` map.)
    pub fn get_token_balance_from_store(&self, token_id: &str, owner_id: &str) -> Balance {
        let key = format!("{}:{}", owner_id, token_id);

        // First try the cache
        if let Ok(cache) = self.balance_cache.read() {
            if let Some(bal) = cache.get(&key) {
                return bal.clone();
            }
        }

        // Then check the store
        if let Ok(store) = self.token_store.read() {
            if let Some(token) = store.get(token_id) {
                // If it's truly single-owner, we compare token.owner_id() to `owner_id`
                if token.owner_id() == owner_id {
                    return token.balance().clone();
                }
            }
        }

        // Default is zero
        crate::types::token_types::Balance::new(0)
    }

    /// Update an existing token's metadata while preserving other properties.
    pub fn update_token_metadata(&self, token_id: &str, metadata: Vec<u8>) -> Result<(), DsmError> {
        let mut store = self.token_store.write().map_err(|_| DsmError::LockError)?;

        if let Some(old_token) = store.get_mut(token_id) {
            let mut new_token = Token::new(
                token_id,
                old_token.owner_id().to_string().into(),
                metadata,
                old_token.balance().clone(),
            );

            // Preserve status if it was revoked or otherwise
            new_token.set_status(old_token.status().clone());

            // Overwrite in the store
            *old_token = new_token;
            Ok(())
        } else {
            Err(DsmError::not_found("Token", Some(token_id.to_string())))
        }
    }

    /// Revoke a token, marking it with `TokenStatus::Revoked`
    pub fn revoke_token(&self, token_id: &str) -> Result<(), DsmError> {
        let mut store = self.token_store.write().map_err(|_| DsmError::LockError)?;
        if let Some(token) = store.get_mut(token_id) {
            token.set_status(TokenStatus::Revoked);
            Ok(())
        } else {
            Err(DsmError::not_found("Token", Some(token_id.to_string())))
        }
    }

    /// Verify that a token exists and is still valid (i.e., not revoked).
    pub fn verify_token(&self, token_id: &str) -> Result<bool, DsmError> {
        let store = self.token_store.read().map_err(|_| DsmError::LockError)?;
        if let Some(token) = store.get(token_id) {
            Ok(token.is_valid())
        } else {
            // Token does not exist
            Ok(false)
        }
    }

    /// List all token IDs in the store
    pub fn list_tokens(&self) -> Result<Vec<String>, DsmError> {
        let store = self.token_store.read().map_err(|_| DsmError::LockError)?;
        Ok(store.keys().cloned().collect())
    }

    /// Return all tokens owned by a specific `owner_id`
    pub fn get_tokens_by_owner(&self, owner_id: &str) -> Result<Vec<Token>, DsmError> {
        let store = self.token_store.read().map_err(|_| DsmError::LockError)?;
        let tokens: Vec<Token> = store
            .values()
            .filter(|tok| tok.owner_id() == owner_id)
            .cloned()
            .collect();
        Ok(tokens)
    }

    /// Create a token transfer
    pub fn create_token_transfer(
        sender_state: &State,
        recipient_state: &State,
        amount: u64,
        token_id: &str,
    ) -> Result<TokenTransfer, DsmError> {
        let sender_key = sender_state.device_info.public_key.clone();
        let recipient_key = recipient_state.device_info.public_key.clone();

        let transfer = TokenTransfer {
            sender: sender_key,
            recipient: recipient_key,
            amount,
            token_id: token_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        Ok(transfer)
    }
}
