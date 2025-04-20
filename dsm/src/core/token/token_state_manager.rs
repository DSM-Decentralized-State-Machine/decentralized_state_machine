//! Token State Manager
//!
//! Implements atomic state updates for tokens as specified in whitepaper Section 9.
//! This module ensures that token operations are integrated directly into state transitions,
//! providing atomic guarantees for token balances and state evolution.

use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::runtime::Runtime;

use crate::cpta::PolicyStore;
use crate::types::{
    error::DsmError,
    state_types::State,
    token_types::{Balance, Token, TokenStatus},
};

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

#[derive(Debug)]
pub struct TokenTransfer {
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub amount: u64,
    pub token_id: String,
    pub timestamp: u64,
    // Add reference to token store and balance cache
    pub(crate) token_store: Option<Arc<RwLock<HashMap<String, Token>>>>,
    pub(crate) balance_cache: Option<Arc<RwLock<HashMap<String, Balance>>>>,
}

impl TokenTransfer {
    pub fn new(sender: Vec<u8>, recipient: Vec<u8>, amount: u64, token_id: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            sender,
            recipient,
            amount,
            token_id,
            timestamp,
            token_store: None,
            balance_cache: None,
        }
    }

    // / Create a new TokenTransfer with token store and balance cache
    pub fn with_stores(
        mut self,
        token_store: Arc<RwLock<HashMap<String, Token>>>,
        balance_cache: Arc<RwLock<HashMap<String, Balance>>>,
    ) -> Self {
        self.token_store = Some(token_store);
        self.balance_cache = Some(balance_cache);
        self
    }
}

/// Helper for returning an insufficient-balance error
pub fn insufficient_balance(message: impl Into<String>) -> DsmError {
    DsmError::token_error(message.into(), None::<std::io::Error>)
}

// Imports
use crate::cpta::policy_verification::{PolicyVerificationResult, verify_policy};
use crate::types::operations::{Ops, Operation};
use crate::types::policy_types::PolicyAnchor;
// Using our native SPHINCS+ implementation
use subtle::ConstantTimeEq;

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

    /// Create a new TokenStateManager with a policy anchor
    pub fn with_policy_anchor(_policy_anchor: &PolicyAnchor) -> Self {
        let runtime = Runtime::new().ok();

        Self {
            token_store: Arc::new(RwLock::new(HashMap::new())),
            balance_cache: Arc::new(RwLock::new(HashMap::new())),
            policy_store: None, // No policy store available
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

        // Clone the current balances so we can modify them
        let mut new_balances = current_state.token_balances.clone();

        match operation {
            Operation::Transfer {
                token_id,
                amount,
                recipient,
                ..
            } => {
                // Convert the sender's public key to a string key
                let sender_pk = &current_state.device_info.public_key;
                let sender_key = Self::make_balance_key(sender_pk, token_id);

                // `recipient` is assumed to be a `String`, so `.as_bytes()` gives us &[u8]
                let recipient_key = Self::make_balance_key(recipient.as_bytes(), token_id);

                // Retrieve the sender's balance
                let sender_balance = new_balances
                    .get(&sender_key)
                    .cloned()
                    .unwrap_or_else(|| Balance::new(0));

                // Verify sufficient balance
                if sender_balance.value() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_id.to_string(),
                        sender_balance.value(),
                        amount.value(),
                    ));
                }

                // Update the sender's balance
                let new_sender_balance =
                    Balance::new(sender_balance.value().saturating_sub(amount.value()));

                // Retrieve the recipient's balance (default 0 if not found)
                let recipient_balance = new_balances
                    .get(&recipient_key)
                    .cloned()
                    .unwrap_or_else(|| Balance::new(0));

                // Update the recipient's balance
                let new_recipient_balance =
                    Balance::new(recipient_balance.value().saturating_add(amount.value()));

                new_balances.insert(sender_key, new_sender_balance);
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

                // We treat the current state's device as the one receiving the minted tokens
                let owner_pk = &current_state.device_info.public_key;
                let owner_key = Self::make_balance_key(owner_pk, token_id);

                let current_balance = new_balances
                    .get(&owner_key)
                    .cloned()
                    .unwrap_or_else(|| Balance::new(0));

                // Increase the owner's balance
                new_balances.insert(
                    owner_key,
                    Balance::new(current_balance.value().saturating_add(amount.value())),
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

                // The token to be burned presumably belongs to the current state's device
                let owner_pk = &current_state.device_info.public_key;
                let owner_key = Self::make_balance_key(owner_pk, token_id);

                let owner_balance = new_balances
                    .get(&owner_key)
                    .cloned()
                    .unwrap_or_else(|| Balance::new(0));

                if owner_balance.value() < amount.value() {
                    return Err(DsmError::insufficient_balance(
                        token_id.to_string(),
                        owner_balance.value(),
                        amount.value(),
                    ));
                }

                // Subtract from the owner's balance
                let new_owner_balance =
                    Balance::new(owner_balance.value().saturating_sub(amount.value()));

                new_balances.insert(owner_key, new_owner_balance);
            }

            // Other operations may not affect token balances
            _ => {}
        }

        self.update_balance_cache(&new_balances)?;
        Ok(new_balances)
    }

    /// Verify that an operation complies with the pre-commitment parameters
    ///
    /// This implements the pre-commitment verification described in whitepaper
    /// section 8, ensuring that operations adhere to previously committed parameters.
    ///
    /// # Arguments
    ///  `pre_commit` - The pre-commitment to verify against
    ///  `operation` - The operation to verify
    ///
    /// # Returns
    ///  `Result<bool, DsmError>` - Whether the operation complies with the pre-commitment
    fn verify_precommitment_parameters(
        &self,
        pre_commit: &crate::types::state_types::PreCommitment,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        let matches_type = match operation {
            Operation::Transfer { .. } => pre_commit.operation_type == "transfer",
            Operation::Mint { .. } => pre_commit.operation_type == "mint",
            Operation::Burn { .. } => pre_commit.operation_type == "burn",
            Operation::LockToken { .. } => pre_commit.operation_type == "lock",
            Operation::UnlockToken { .. } => pre_commit.operation_type == "unlock",
            _ => false,
        };

        if !matches_type {
            return Ok(false);
        }

        // Check that operation matches fixed parameters
        let matches_fixed_params = match operation {
            Operation::Transfer {
                token_id,
                recipient,
                ..
            } => {
                // If the pre-commit stores these fields as Vec<u8>, compare with as_bytes():
                let token_id_matches =
                    if let Some(expected_token_id) = pre_commit.fixed_parameters.get("token_id") {
                        token_id.as_bytes() == &expected_token_id[..]
                    } else {
                        true
                    };

                let recipient_matches = if let Some(expected_recipient) =
                    pre_commit.fixed_parameters.get("recipient")
                {
                    recipient.as_bytes() == &expected_recipient[..]
                } else {
                    true
                };

                token_id_matches && recipient_matches
            }
            Operation::Mint { token_id, .. } => {
                if let Some(expected_token_id) = pre_commit.fixed_parameters.get("token_id") {
                    token_id.as_bytes() == &expected_token_id[..]
                } else {
                    true
                }
            }
            Operation::Burn { token_id, .. } => {
                if let Some(expected_token_id) = pre_commit.fixed_parameters.get("token_id") {
                    token_id.as_bytes() == &expected_token_id[..]
                } else {
                    true
                }
            }
            _ => true,
        };

        if !matches_fixed_params {
            return Ok(false);
        }

        // Verify operation only modifies allowed variable parameters
        let variable_params_valid = match operation {
            Operation::Transfer { amount, .. }
            | Operation::Mint { amount, .. }
            | Operation::Burn { amount, .. } => {
                // Check if "amount" is in variable_parameters or if it's fixed and matches
                if pre_commit.variable_parameters.contains("amount") {
                    true
                } else if let Some(expected_amount_bytes) =
                    pre_commit.fixed_parameters.get("amount")
                {
                    if expected_amount_bytes.len() == 8 {
                        let mut arr = [0u8; 8];
                        arr.copy_from_slice(&expected_amount_bytes[0..8]);
                        let expected_amount = u64::from_le_bytes(arr);
                        amount.value() == expected_amount
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => true,
        };

        Ok(matches_type && matches_fixed_params && variable_params_valid)
    }

    /// Verify mint authorization proof
    #[allow(unused_variables)]
    fn verify_mint_authorization(
        &self,
        authorized_by: &str,
        proof: &[u8],
    ) -> Result<bool, DsmError> {
        // Implementation would verify cryptographic proof
        // using authorized_by (str) and proof (&[u8])
        Ok(true) // Placeholder
    }

    /// Verify token ownership proof
    #[allow(unused_variables)]
    fn verify_token_ownership(&self, token_id: &str, proof: &[u8]) -> Result<bool, DsmError> {
        // Implementation would verify cryptographic proof
        // using token_id (str) and proof (&[u8])
        Ok(true) // Placeholder
    }

    /// Verify that the operation complies with the token's CTPA policy
    fn verify_token_policy(&self, operation: &Operation) -> Result<(), DsmError> {
        // Skip verification if policy store is not configured
        let policy_store = match &self.policy_store {
            Some(store) => store,
            None => return Ok(()),
        };

        // Get token ID based on operation type
        let token_id = match operation {
            Operation::Transfer { token_id, .. } => token_id,
            Operation::Mint { token_id, .. } => token_id,
            Operation::Burn { token_id, .. } => token_id,
            Operation::LockToken { token_id, .. } => token_id,
            Operation::UnlockToken { token_id, .. } => token_id,
            _ => return Ok(()),
        };

        // Get token to check if it has a policy anchor
        let token = match self.get_token(token_id) {
            Ok(token) => token,
            Err(_) => return Ok(()), // Token not found, skip verification
        };

        // Skip verification if token has no policy anchor
        let policy_anchor_bytes = match token.policy_anchor() {
            Some(anchor) => anchor,
            None => return Ok(()),
        };

        // Create PolicyAnchor from bytes
        let policy_anchor = PolicyAnchor(policy_anchor_bytes.clone());

        // Get runtime for async operations
        let runtime = match &self.runtime {
            Some(rt) => rt,
            None => {
                return Err(DsmError::internal(
                    "No runtime available for policy verification",
                    None::<std::io::Error>,
                ))
            }
        };

        // Retrieve policy
        let token_policy =
            match runtime.block_on(async { policy_store.get_policy(&policy_anchor).await }) {
                Ok(policy) => policy,
                Err(e) => {
                    return Err(DsmError::validation(
                        format!("Failed to retrieve policy for token {}: {}", token_id, e),
                        Some(e),
                    ));
                }
            };

        // Check basic policy compliance
        let result: PolicyVerificationResult =
            verify_policy(&token_policy, operation, None, None, None);
        match result {
            PolicyVerificationResult::Valid => Ok(()),
            PolicyVerificationResult::Invalid { message } => Err(DsmError::policy_violation(
                token_id.clone(),
                message,
                None::<std::io::Error>,
            )),
            PolicyVerificationResult::Unverifiable { message } => Err(DsmError::validation(
                format!("Policy verification failed: {}", message),
                None::<std::io::Error>,
            )),
        }
    }

    /// A helper to create a consistent key for our `HashMap<String, Balance>`.
    /// We use the hex-encoded public key (owner) plus the token_id.
    pub fn make_balance_key(owner_pk: &[u8], token_id: &str) -> String {
        format!("{}{}", hex::encode(owner_pk), token_id)
    }

    // ------------------------------------------------------------------------
    //                           Token Store Methods
    // ------------------------------------------------------------------------

    /// Check if a token with the given `token_id` exists
    pub fn token_exists(&self, token_id: &str) -> Result<bool, DsmError> {
        let store = self.token_store.read();
        Ok(store.contains_key(token_id))
    }

    /// Retrieve a `Token` by ID
    pub fn get_token(&self, token_id: &str) -> Result<Token, DsmError> {
        let store = self.token_store.read();
        store
            .get(token_id)
            .cloned()
            .ok_or_else(|| DsmError::not_found("Token", Some(token_id.to_string())))
    }

    /// Returns a token's balance for the given (public_key, token_id),
    /// falling back to zero if not found. (Separate from the `State::token_balances` map.)
    pub fn get_token_balance_from_store(&self, owner_pk: &[u8], token_id: &str) -> Balance {
        let key = Self::make_balance_key(owner_pk, token_id);

        // First try the cache
        let cache = self.balance_cache.read();
        if let Some(bal) = cache.get(&key) {
            return bal.clone();
        }

        // Then check the token_store for single-owner usage or some fallback logic
        // if you have a separate record of "store-level" balances (but typically it's in the state).
        // If you don't store per-owner token data in token_store, you might skip this part.

        // If not found, default to zero
        Balance::new(0)
    }

    /// Update an existing token's metadata while preserving other properties.
    pub fn update_token_metadata(&self, token_id: &str, metadata: Vec<u8>) -> Result<(), DsmError> {
        let mut store = self.token_store.write();
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
        let mut store = self.token_store.write();
        if let Some(token) = store.get_mut(token_id) {
            token.set_status(TokenStatus::Revoked);
            Ok(())
        } else {
            Err(DsmError::not_found("Token", Some(token_id.to_string())))
        }
    }

    /// Verify that a token exists and is still valid (i.e., not revoked).
    pub fn verify_token(&self, token_id: &str) -> Result<bool, DsmError> {
        let store = self.token_store.read();
        if let Some(token) = store.get(token_id) {
            Ok(token.is_valid())
        } else {
            // Token does not exist
            Ok(false)
        }
    }

    /// List all token IDs in the store
    pub fn list_tokens(&self) -> Result<Vec<String>, DsmError> {
        let store = self.token_store.read();
        Ok(store.keys().cloned().collect())
    }

    /// Return all tokens owned by a specific `owner_id`
    pub fn get_tokens_by_owner(&self, owner_id: &str) -> Result<Vec<Token>, DsmError> {
        let store = self.token_store.read();
        let tokens: Vec<Token> = store
            .values()
            .filter(|tok| tok.owner_id() == owner_id)
            .cloned()
            .collect();
        Ok(tokens)
    }

    /// Create a token transfer object (for logging or returning to the caller),
    /// referencing the public keys of the states involved.
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
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            token_store: None,
            balance_cache: None,
        };

        Ok(transfer)
    }

    /// Create a token transfer object with attached stores (for reference)
    pub fn create_token_transfer_with_stores(
        sender_state: &State,
        recipient_state: &State,
        amount: u64,
        token_id: &str,
        token_store: Arc<RwLock<HashMap<String, Token>>>,
        balance_cache: Arc<RwLock<HashMap<String, Balance>>>,
    ) -> Result<TokenTransfer, DsmError> {
        let transfer =
            Self::create_token_transfer(sender_state, recipient_state, amount, token_id)?;
        Ok(transfer.with_stores(token_store, balance_cache))
    }

    /// Optimize balance cache with LRU eviction and bulk loading  
    pub fn optimize_balance_cache(&self) -> Result<(), DsmError> {
        let mut cache = self.balance_cache.write();

        // Set maximum cache size (configurable)
        const MAX_CACHE_SIZE: usize = 10_000;

        // Evict oldest entries if cache exceeds max size
        if cache.len() > MAX_CACHE_SIZE {
            // Sort entries by key (which contains timestamp information)
            let mut entries: Vec<_> = cache.iter().collect();
            entries.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

            // Calculate how many entries to skip
            let entries_len = entries.len();
            let to_skip = entries_len.saturating_sub(MAX_CACHE_SIZE);

            // Keep only the newest MAX_CACHE_SIZE entries
            let entries_to_keep: HashMap<_, _> = entries
                .into_iter()
                .skip(to_skip)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            // Replace cache contents with kept entries
            *cache = entries_to_keep;
        }

        Ok(())
    }

    /// Bulk load balances into cache
    pub fn bulk_load_balances(&self, balances: HashMap<String, Balance>) -> Result<(), DsmError> {
        let mut cache = self.balance_cache.write();
        cache.extend(balances);
        self.optimize_balance_cache()?;
        Ok(())
    }

    /// Update balance cache with atomic operation results
    fn update_balance_cache(
        &self,
        new_balances: &HashMap<String, Balance>,
    ) -> Result<(), DsmError> {
        let mut cache = self.balance_cache.write();
        for (key, balance) in new_balances {
            cache.insert(key.clone(), balance.clone());
        }
        self.optimize_balance_cache()?;
        Ok(())
    }

    /// Validate forward commitment chain integrity
    pub fn validate_commitment_chain(&self, states: &[State]) -> Result<bool, DsmError> {
        // Verify each consecutive pair of states maintains commitment chain
        for window in states.windows(2) {
            let current = &window[0];
            let next = &window[1];

            // Skip if no forward commitment exists
            if let Some(commitment) = &current.forward_commitment {
                // Verify state number requirements
                if next.state_number < commitment.min_state_number {
                    return Ok(false);
                }

                // Verify operation parameters match commitment
                if !self.verify_precommitment_parameters(commitment, &next.operation)? {
                    return Ok(false);
                }

                // Verify the commitment hash matches
                let expected_hash = self.compute_commitment_hash(commitment)?;
                if !bool::from(expected_hash.as_slice().ct_eq(&commitment.hash)) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Verify a single forward commitment transition
    #[allow(dead_code)]
    fn verify_forward_commitment_transition(
        &self,
        commitment: &crate::types::state_types::PreCommitment,
        next_state: &State,
    ) -> Result<bool, DsmError> {
        // Verify basic operation adherence
        if !self.verify_precommitment_parameters(commitment, &next_state.operation)? {
            return Ok(false);
        }

        // Verify commitment signatures if present
        if let Some(entity_sig) = &commitment.entity_signature {
            let entity_pk = &next_state.device_info.public_key;
            if !self.verify_commitment_signature(entity_sig, entity_pk, &commitment.hash)? {
                return Ok(false);
            }
        }

        // Verify state number meets requirements
        if next_state.state_number < commitment.min_state_number {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify a commitment signature
    #[allow(dead_code)]
    fn verify_commitment_signature(
        &self,
        signature: &[u8],
        public_key: &[u8],
        message: &[u8],
    ) -> Result<bool, DsmError> {
        use crate::crypto::sphincs;

        // Use our pure Rust implementation of SPHINCS+
        sphincs::sphincs_verify(public_key, message, signature)
    }

    /// Helper function for constant-time equality comparison using subtle crate
    #[allow(dead_code)]
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        bool::from(a.ct_eq(b))
    }

    /// Compute commitment hash for verification
    fn compute_commitment_hash(
        &self,
        commitment: &crate::types::state_types::PreCommitment,
    ) -> Result<Vec<u8>, DsmError> {
        // Sort parameters for deterministic ordering
        let mut sorted_fixed: Vec<_> = commitment.fixed_parameters.iter().collect();
        sorted_fixed.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

        let mut sorted_var: Vec<_> = commitment.variable_parameters.iter().collect();
        sorted_var.sort();

        // Construct commitment data
        let mut data = Vec::new();

        // Add state hash
        data.extend_from_slice(&commitment.hash);

        // Add fixed parameters in sorted order
        for (key, value) in sorted_fixed {
            data.extend_from_slice(key.as_bytes());
            data.extend_from_slice(value);
        }

        // Add variable parameters in sorted order
        for param in sorted_var {
            data.extend_from_slice(param.as_bytes());
        }

        // Return BLAKE3 hash
        Ok(blake3::hash(&data).as_bytes().to_vec())
    }
}
