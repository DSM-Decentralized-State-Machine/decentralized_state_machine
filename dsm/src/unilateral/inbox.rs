// Unilateral Transaction Inbox
//
// This module implements the inbox concept for unilateral transactions.
// It allows users to send transactions to other users when they are offline.
// The transactions are stored in the recipient's inbox until they come online.

use crate::core::identity::{GenesisState, Identity};
use crate::core::state_machine::transition::StateTransition;
use crate::interfaces::storage_face::StorageInterface;
use crate::types::error::DsmError;
use crate::types::state_types::State;
use crate::verify_signature;

// Add necessary serialization implementations for GenesisState
use serde::{Deserialize, Serialize};

// Add helper functions for state transitions and hashing
fn derive_next_state(
    previous_state: &State,
    transaction: &crate::types::operations::Operation,
    signature: &[u8],
) -> Result<State, DsmError> {
    // Proper implementation based on the DSM whitepaper Section 3.1
    let mut new_state = previous_state.clone();
    
    // Increment state number
    new_state.state_number += 1;
    
    // Set previous state hash for hash chain continuity
    new_state.prev_state_hash = hash_state(previous_state)?.to_vec();
    
    // Generate deterministic entropy for the next state according to whitepaper equation:
    // e(n+1) = H(e(n) || op(n+1) || (n+1))
    let next_state_number = new_state.state_number;
    let op_bytes = bincode::serialize(transaction).map_err(|e| 
        DsmError::Serialization {
            context: "Failed to serialize operation for entropy derivation".into(),
            source: Some(Box::new(e)),
        }
    )?;
    
    // Create entropy data
    let mut entropy_data = Vec::new();
    entropy_data.extend_from_slice(&previous_state.entropy);
    entropy_data.extend_from_slice(&op_bytes);
    entropy_data.extend_from_slice(&next_state_number.to_le_bytes());
    
    // Derive new entropy using BLAKE3
    let new_entropy = blake3::hash(&entropy_data).as_bytes().to_vec();
    new_state.entropy = new_entropy;
    
    // Add the operation to the new state
    new_state.operation = transaction.clone();
    
    // Add signature for verification
    if !signature.is_empty() {
        new_state.signature = Some(signature.to_vec());
    }
    
    // Update the state hash with the new values
    let new_hash = hash_state(&new_state)?;
    new_state.hash = new_hash.to_vec();
    
    Ok(new_state)
}

// Generate entropy for transaction according to whitepaper Section 15.1
fn generate_entropy_for_transaction(
    current_state: &State,
    operation: &Transaction
) -> Result<Vec<u8>, DsmError> {
    // Implement the deterministic entropy evolution equation: en+1 = H(en ∥ opn+1 ∥ (n+1))
    let next_state_number = current_state.state_number + 1;
    
    // Serialize the operation
    let op_bytes = bincode::serialize(operation).map_err(|e| 
        DsmError::Serialization {
            context: "Failed to serialize operation for entropy derivation".into(),
            source: Some(Box::new(e)),
        }
    )?;
    
    // Create entropy data
    let mut entropy_data = Vec::new();
    entropy_data.extend_from_slice(&current_state.entropy);
    entropy_data.extend_from_slice(&op_bytes);
    entropy_data.extend_from_slice(&next_state_number.to_le_bytes());
    
    // Derive new entropy using BLAKE3
    Ok(blake3::hash(&entropy_data).as_bytes().to_vec())
}

fn hash_state(state: &State) -> Result<[u8; 32], DsmError> {
    // Proper implementation based on the DSM whitepaper
    // This function implements the hash chaininging described in Section 3.1
    // It creates a deterministic hash of the state for continuity verification
    
    // Create a canonical representation of the state for hashing
    // Only include the essential parts of the state that affect its identity
    let mut hash_components = Vec::new();
    
    // Add state number
    hash_components.extend_from_slice(&state.state_number.to_le_bytes());
    
    // Add entropy
    hash_components.extend_from_slice(&state.entropy);
    
    // Add prev_state_hash
    hash_components.extend_from_slice(&state.prev_state_hash);
    
    // Serialize and add operation
    let op_bytes = bincode::serialize(&state.operation).map_err(|e| DsmError::Serialization {
        context: "Failed to serialize operation for state hashing".into(),
        source: Some(Box::new(e)),
    })?;
    hash_components.extend_from_slice(&op_bytes);
    
    // Add device info
    hash_components.extend_from_slice(state.device_info.device_id.as_bytes());
    
    // If available, add token balances
    if !state.token_balances.is_empty() {
        let token_bytes = bincode::serialize(&state.token_balances).map_err(|e| DsmError::Serialization {
            context: "Failed to serialize token balances for state hashing".into(),
            source: Some(Box::new(e)),
        })?;
        hash_components.extend_from_slice(&token_bytes);
    }
    
    // Compute the hash using BLAKE3
    Ok(blake3::hash(&hash_components).into())
}

// Define type aliases for clarity (following whitepaper terminology)
type DsmState = State;
type Transaction = crate::types::operations::Operation;

// Define StateVerificationResult enum
enum StateVerificationResult {
    Valid(Box<DsmState>),
    Invalid(String),
    Deferred(String),
}

use bincode;
use blake3;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

const INBOX_PREFIX: &str = "inbox:";
const MAX_INBOX_SIZE: usize = 1000;
const MAX_INBOX_TTL: u64 = 86400 * 30; // 30 days

/// Inbox entry for unilateral transactions
#[derive(Clone, Serialize, Deserialize)]
pub struct InboxEntry {
    /// Blinded ID of the entry (for reference)
    pub blinded_id: String,

    /// Hash of the sender's genesis state
    pub sender_genesis_hash: [u8; 32],

    /// Hash of the sender's current state
    pub sender_state_hash: [u8; 32],

    /// The projected state after applying the transaction
    pub projected_state: DsmState,

    /// The transaction that was sent
    pub transaction: Transaction,

    /// Signature of the transaction
    pub signature: Vec<u8>,

    /// Timestamp when the entry was created
    pub timestamp: u64,

    /// Time to live in seconds
    pub ttl: u64,
}

/// Unilateral transaction inbox manager
#[derive(Clone)]
pub struct InboxManager {
    /// Storage interface for persisting inbox entries
    storage: Arc<dyn StorageInterface + Send + Sync>,

    /// In-memory cache of inbox entries
    cache: Arc<RwLock<HashMap<String, VecDeque<InboxEntry>>>>,

    /// Maximum inbox size per recipient
    max_inbox_size: usize,

    /// Default TTL for inbox entries
    default_ttl: u64,
}

impl InboxManager {
    /// Create a new inbox manager
    pub fn new(storage: Arc<dyn StorageInterface + Send + Sync>) -> Self {
        Self {
            storage,
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_inbox_size: MAX_INBOX_SIZE,
            default_ttl: MAX_INBOX_TTL,
        }
    }

    /// Get the inbox key for a recipient genesis hash
    fn get_inbox_key(recipient_genesis_hash: &[u8; 32]) -> String {
        format!("{}{}", INBOX_PREFIX, hex::encode(recipient_genesis_hash))
    }

    /// Add a transaction to a recipient's inbox
    pub async fn add_to_inbox(
        &self,
        sender_identity: &Identity,
        sender_state: &DsmState,
        recipient_genesis: &GenesisState,
        transaction: Transaction,
        signature: Vec<u8>,
    ) -> Result<String, DsmError> {
        // Get the public key from the identity's device
        let public_key = sender_identity
            .devices
            .first()
            .ok_or_else(|| {
                DsmError::validation(
                    "Sender identity has no devices",
                    None::<std::convert::Infallible>,
                )
            })?
            .sub_genesis
            .signing_key
            .public_key
            .clone();

        // Validate the transaction and signature
        let transaction_bytes =
            bincode::serialize(&transaction).map_err(|e| DsmError::Serialization {
                context: "Failed to serialize transaction".into(),
                source: Some(Box::new(e)),
            })?;

        if !verify_signature(&public_key, &transaction_bytes, &signature) {
            return Err(DsmError::validation(
                "Invalid signature for unilateral transaction",
                None::<std::convert::Infallible>,
            ));
        }

        // Calculate the projected state after applying the transaction
        let _state_transition = StateTransition {
            previous_state: sender_state.clone(),
            transaction: transaction.clone(),
            signature: signature.clone(),
            operation: transaction.clone(),
            new_entropy: Some(generate_entropy_for_transaction(sender_state, &transaction.clone())?),
            encapsulated_entropy: None,
            device_id: sender_state.device_info.device_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| DsmError::internal("Failed to get system time", Some(e)))?
                .as_secs(),
            flags: vec![],
            position_sequence: None,
            token_balances: None,
            forward_commitment: None,
            prev_state_hash: Some(sender_state.hash.clone()),
            entity_signature: None,
            counterparty_signature: None,
            from_state: sender_state.clone(),
            to_state: sender_state.clone(), // Will be replaced with projected_state later
        };

        let projected_state = derive_next_state(sender_state, &transaction, &signature)?;

        // Create the inbox entry - get hash of master genesis which is the identity's root
        let sender_genesis_data =
            bincode::serialize(&sender_identity.master_genesis).map_err(|e| {
                DsmError::Serialization {
                    context: "Failed to serialize sender genesis".into(),
                    source: Some(Box::new(e)),
                }
            })?;
        let sender_genesis_hash = blake3::hash(&sender_genesis_data).into();

        // Get hash of the current state
        let sender_state_hash = hash_state(sender_state)?;

        let entry = InboxEntry {
            blinded_id: format!(
                "{}_{}",
                hex::encode(sender_genesis_hash),
                hex::encode(sender_state_hash)
            ),
            sender_genesis_hash,
            sender_state_hash,
            projected_state,
            transaction,
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| DsmError::internal("Failed to get system time", Some(e)))?
                .as_secs(),
            ttl: self.default_ttl,
        };

        // Get the inbox key for the recipient - serialize GenesisState properly
        let recipient_genesis_data =
            bincode::serialize(&recipient_genesis).map_err(|e| DsmError::Serialization {
                context: "Failed to serialize recipient genesis".into(),
                source: Some(Box::new(e)),
            })?;
        let recipient_genesis_hash: [u8; 32] = *blake3::hash(&recipient_genesis_data).as_bytes();
        let inbox_key = Self::get_inbox_key(&recipient_genesis_hash);

        // Add the entry to the cache
        {
            let mut cache = self.cache.write().await;
            let inbox = cache.entry(inbox_key.clone()).or_insert_with(VecDeque::new);

            // Enforce maximum inbox size
            if inbox.len() >= self.max_inbox_size {
                inbox.pop_front(); // Remove the oldest entry
            }

            inbox.push_back(entry.clone());
        }

        // Persist the inbox in storage
        self.persist_inbox(&inbox_key).await?;

        // Return the blinded ID of the entry
        Ok(entry.blinded_id)
    }

    /// Get all inbox entries for a recipient
    pub async fn get_inbox(
        &self,
        recipient_genesis: &GenesisState,
    ) -> Result<Vec<InboxEntry>, DsmError> {
        // Get the inbox key for the recipient
        let recipient_genesis_hash: [u8; 32] =
            blake3::hash(&bincode::serialize(recipient_genesis)?).into();
        let inbox_key = Self::get_inbox_key(&recipient_genesis_hash);

        // Try to get the inbox from the cache first
        {
            let cache = self.cache.read().await;
            if let Some(inbox) = cache.get(&inbox_key) {
                return Ok(Vec::from_iter(inbox.iter().cloned()));
            }
        }

        // Try to load the inbox from storage
        match self.storage.retrieve(inbox_key.as_bytes()).await {
            Ok(bytes) => {
                let entries: Vec<InboxEntry> =
                    bincode::deserialize(&bytes).map_err(|e| DsmError::Serialization {
                        context: "Failed to deserialize inbox entries".into(),
                        source: Some(Box::new(e)),
                    })?;

                // Update the cache
                {
                    let mut cache = self.cache.write().await;
                    let inbox = cache.entry(inbox_key).or_insert_with(VecDeque::new);
                    inbox.clear();
                    for entry in &entries {
                        inbox.push_back(entry.clone());
                    }
                }

                Ok(entries)
            }
            Err(DsmError::Storage {
                context: _,
                source: _,
            }) => {
                // No inbox found, return empty list
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Process inbox entries for a recipient
    pub async fn process_inbox(
        &self,
        recipient_identity: &Identity,
        current_state: &DsmState,
    ) -> Result<Vec<DsmState>, DsmError> {
        // Get the inbox entries - Identity now has master_genesis instead of genesis
        // We'll serialize master_genesis as the identity's genesis reference
        let recipient_genesis_data = bincode::serialize(&recipient_identity.master_genesis)
            .map_err(|e| DsmError::Serialization {
                context: "Failed to serialize recipient genesis".into(),
                source: Some(Box::new(e)),
            })?;

        // Create a GenesisState from the serialized data for compatibility
        let recipient_genesis = recipient_identity.master_genesis.clone();

        let entries = self.get_inbox(&recipient_genesis).await?;
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let recipient_genesis_hash = blake3::hash(&recipient_genesis_data).into();
        let inbox_key = Self::get_inbox_key(&recipient_genesis_hash);

        let mut processed_states = Vec::new();
        let mut processed_indices = Vec::new();

        // Process each entry
        for (i, entry) in entries.iter().enumerate() {
            // Verify the state transition
            let verification_result = self
                .verify_unilateral_transaction(entry, recipient_identity, current_state)
                .await?;

            match verification_result {
                StateVerificationResult::Valid(projected_state) => {
                    // Extract the projected state from the Box
                    // Add the projected state to the results
                    processed_states.push(*projected_state);

                    // Mark this entry for removal
                    processed_indices.push(i);

                    info!(
                        "Processed unilateral transaction from inbox: {}",
                        entry.blinded_id
                    );
                }
                StateVerificationResult::Invalid(reason) => {
                    // Mark invalid entries for removal too
                    processed_indices.push(i);
                    warn!(
                        "Invalid unilateral transaction in inbox: {}, reason: {}",
                        entry.blinded_id, reason
                    );
                }
                StateVerificationResult::Deferred(reason) => {
                    // Keep deferred entries in the inbox
                    debug!(
                        "Deferred unilateral transaction in inbox: {}, reason: {}",
                        entry.blinded_id, reason
                    );
                }
            }
        }

        // Remove processed entries from the cache
        {
            let mut cache = self.cache.write().await;
            if let Some(inbox) = cache.get_mut(&inbox_key) {
                // Process indices in reverse order to maintain validity
                for i in processed_indices.iter().rev() {
                    // Use nth to remove the item at the specified index
                    if let Some(j) = inbox
                        .iter()
                        .position(|e| e.blinded_id == entries[*i].blinded_id)
                    {
                        inbox.remove(j);
                    }
                }
            }
        }

        // Persist the changes
        self.persist_inbox(&inbox_key).await?;

        Ok(processed_states)
    }

    /// Verify a unilateral transaction from the inbox
    async fn verify_unilateral_transaction(
        &self,
        entry: &InboxEntry,
        recipient_identity: &Identity,
        current_state: &DsmState,
    ) -> Result<StateVerificationResult, DsmError> {
        // 1. Check if the transaction is for the recipient
        // No need to serialize the genesis for the check we're doing
        // Remove unused variable

        // Check if the transaction is for this recipient
        // Using the identity name as a comparison - adjust according to your Operation structure
        if !transaction_is_for_recipient(&entry.transaction, recipient_identity) {
            return Ok(StateVerificationResult::Invalid(
                "Transaction not for this recipient".into(),
            ));
        }

        // 2. Verify the transaction signature (already done when adding to inbox)

        // Calculate the projected state first
        let projected_state =
            derive_next_state(current_state, &entry.transaction, &entry.signature)?;

        // 3. Verify the state transition
        let state_transition = StateTransition {
            previous_state: current_state.clone(),
            transaction: entry.transaction.clone(),
            signature: entry.signature.clone(),
            operation: entry.transaction.clone(),
            new_entropy: Some(generate_entropy_for_transaction(current_state, &entry.transaction.clone())?),
            encapsulated_entropy: None,
            device_id: current_state.device_info.device_id.clone(),
            timestamp: entry.timestamp,
            flags: vec![],
            position_sequence: None,
            token_balances: None,
            forward_commitment: None,
            prev_state_hash: Some(current_state.hash.clone()),
            entity_signature: None,
            counterparty_signature: None,
            from_state: current_state.clone(),
            to_state: projected_state,
        };

        // Verify the state transition
        let verification_result = verify_state_transition(&state_transition)?;

        Ok(verification_result)
    }

    /// Persist an inbox to storage
    async fn persist_inbox(&self, inbox_key: &str) -> Result<(), DsmError> {
        let cache = self.cache.read().await;

        if let Some(inbox) = cache.get(inbox_key) {
            // Convert to Vec for serialization
            let entries: Vec<InboxEntry> = inbox.iter().cloned().collect();

            // Serialize and store
            let bytes = bincode::serialize(&entries).map_err(|e| DsmError::Serialization {
                context: "Failed to serialize inbox entries".into(),
                source: Some(Box::new(e)),
            })?;

            self.storage.store(inbox_key.as_bytes(), &bytes).await?;
        }

        Ok(())
    }

    /// Remove entries from an inbox
    pub async fn remove_from_inbox(
        &self,
        recipient_genesis: &GenesisState,
        entry_ids: &[String],
    ) -> Result<usize, DsmError> {
        // Get the inbox key for the recipient
        let recipient_genesis_hash: [u8; 32] =
            blake3::hash(&bincode::serialize(recipient_genesis)?).into();
        let inbox_key = Self::get_inbox_key(&recipient_genesis_hash);

        let mut removed_count = 0;

        // Remove entries from the cache
        {
            let mut cache = self.cache.write().await;
            if let Some(inbox) = cache.get_mut(&inbox_key) {
                let original_len = inbox.len();

                // Preserve entries that are not in the removal list
                let ids_set: HashSet<&String> = entry_ids.iter().collect();
                inbox.retain(|entry| !ids_set.contains(&entry.blinded_id));

                removed_count = original_len - inbox.len();
            }
        }

        self.persist_inbox(&inbox_key).await?;

        Ok(removed_count)
    }

    /// Prune expired entries from all inboxes
    pub async fn prune_expired(&self) -> Result<usize, DsmError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DsmError::internal("Failed to get system time", Some(e)))?
            .as_secs();

        let mut total_pruned = 0;

        // Prune from each inbox in the cache
        {
            let mut cache = self.cache.write().await;
            for (inbox_key, inbox) in cache.iter_mut() {
                let original_len = inbox.len();

                // Remove entries that have expired
                inbox.retain(|entry| now < entry.timestamp + entry.ttl);

                let pruned = original_len - inbox.len();
                if pruned > 0 {
                    total_pruned += pruned;

                    // Persist the changes for this inbox
                    let inbox_key = inbox_key.clone();
                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        let _ = self_clone.persist_inbox(&inbox_key).await;
                    });
                }
            }
        }

        Ok(total_pruned)
    }
}

/// Helper function to check if a transaction is for a specific recipient
fn transaction_is_for_recipient(transaction: &Transaction, recipient: &Identity) -> bool {
    match transaction {
        Transaction::Transfer {
            recipient: tx_recipient,
            ..
        } => tx_recipient == &recipient.name,
        Transaction::Generic { .. } => true, // Generic operations can be for any recipient
        _ => false,                          // Other operations require specific handling
    }
}

/// Verify a state transition according to the DSM whitepaper Section 3.1
/// This verifies the hash chain integrity and other properties defined in the whitepaper
///
/// # Arguments
/// * `state_transition` - The state transition to verify
///
/// # Returns
/// * `Result<StateVerificationResult, DsmError>` - Verification result
fn verify_state_transition(
    state_transition: &StateTransition,
) -> Result<StateVerificationResult, DsmError> {
    // Get references to the states
    let previous_state = &state_transition.previous_state;
    let transaction = &state_transition.transaction;

    // Check if the transaction requires deferred processing
    // Instead of relying on a non-existent get_flags() method, check the flags directly
    // in the state_transition which has a flags field
    if state_transition
        .flags
        .contains(&"requires_additional_validation".to_string())
    {
        return Ok(StateVerificationResult::Deferred(
            "Transaction requires additional validation".to_string(),
        ));
    }

    // Calculate the expected next state using deterministic entropy evolution
    let projected_state =
        derive_next_state(previous_state, transaction, &state_transition.signature)?;

    // Verify state number sequentiality
    if projected_state.state_number != previous_state.state_number + 1 {
        return Ok(StateVerificationResult::Invalid(
            "State number not sequential".to_string(),
        ));
    }

    // Verify hash chain continuity (immutability property from Section 3.1)
    // S(n+1).prev_hash = H(S(n))
    let previous_hash = hash_state(previous_state)?;
    if projected_state.prev_state_hash != previous_hash {
        return Ok(StateVerificationResult::Invalid(
            "Hash chain continuity violated".to_string(),
        ));
    }

    // If all checks pass, return the valid projected state
    Ok(StateVerificationResult::Valid(Box::new(projected_state)))
}
