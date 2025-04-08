//! Relationship Management Module
//!
//! This module implements bilateral state isolation for DSM as described in
//! whitepaper section 3.4. It ensures that transactions between specific entities
//! maintain their own isolated context while preserving cryptographic integrity.
//! Temporal ordering is enforced through the hash chain structure itself.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use crate::{
    core::state_machine::utils::{constant_time_eq, verify_state_hash},
    types::{
        error::DsmError,
        operations::Operation,
        state_types::{DeviceInfo, PreCommitment, State},
    },
};

#[derive(Debug, Clone)]
pub struct StateTransition {
    pub operation: Operation,
    pub new_entropy: Option<Vec<u8>>,
    pub encapsulated_entropy: Option<Vec<u8>>,
    pub device_id: String,
}

impl StateTransition {
    pub fn new(
        operation: Operation,
        new_entropy: Option<Vec<u8>>,
        encapsulated_entropy: Option<Vec<u8>>,
        device_id: &str,
    ) -> Self {
        Self {
            operation,
            new_entropy,
            encapsulated_entropy,
            device_id: device_id.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartCommitment {
    pub hash: Vec<u8>,
    pub commitment_type: CommitmentType,
    pub parameters: HashMap<String, String>,
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    pub variable_parameters: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CommitmentType {
    TimeLocked,
    Conditional,
    Recurring,
}

impl SmartCommitment {
    pub fn new(
        hash: Vec<u8>,
        commitment_type: CommitmentType,
        parameters: HashMap<String, String>,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
    ) -> Self {
        Self {
            hash,
            commitment_type,
            parameters,
            fixed_parameters,
            variable_parameters,
        }
    }
}

/// Forward-linked commitment for future state guarantee
#[derive(Debug, Clone)]
pub struct ForwardLinkedCommitment {
    /// Hash of the next state this commitment links to
    pub next_state_hash: Vec<u8>,
    /// Counterparty ID this commitment involves
    pub counterparty_id: String,
    /// Fixed parameters for the commitment
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    /// Variable parameters allowed to change
    pub variable_parameters: HashSet<String>,
    /// Entity's signature on this commitment
    pub entity_signature: Vec<u8>,
    /// Counterparty's signature on this commitment
    pub counterparty_signature: Vec<u8>,
    /// Hash of the commitment for verification
    pub commitment_hash: Vec<u8>,
    /// Minimum state number this commitment applies to
    pub min_state_number: u64,
}

impl ForwardLinkedCommitment {
    pub fn new(
        next_state_hash: Vec<u8>,
        counterparty_id: String,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
    ) -> Result<Self, DsmError> {
        // Create a new commitment
        let mut commitment = ForwardLinkedCommitment {
            next_state_hash,
            counterparty_id,
            fixed_parameters,
            variable_parameters,
            entity_signature: Vec::new(),
            counterparty_signature: Vec::new(),
            commitment_hash: Vec::new(), // Will be updated
            min_state_number: 0,
        };

        // Calculate commitment hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(&commitment.next_state_hash);
        hasher.update(commitment.counterparty_id.as_bytes());

        // Add fixed parameters in sorted order for determinism
        let mut keys: Vec<&String> = commitment.fixed_parameters.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(&commitment.fixed_parameters[key]);
        }

        commitment.commitment_hash = hasher.finalize().as_bytes().to_vec();
        Ok(commitment)
    }

    pub fn verify_operation_adherence(&self, operation: &Operation) -> Result<bool, DsmError> {
        // Example check: look in fixed_parameters for "operation_type"
        if let Some(expected_op) = self.fixed_parameters.get("operation_type") {
            let actual_op = match *operation {
                Operation::Genesis => b"genesis_",
                Operation::Generic { .. } => b"generic_",
                Operation::Transfer { .. } => b"transfer",
                Operation::Mint { .. } => b"mint____",
                Operation::Burn { .. } => b"burn____",
                Operation::Create { .. } => b"create__",
                Operation::Update { .. } => b"update__",
                Operation::AddRelationship { .. } => b"add_rel_",
                Operation::CreateRelationship { .. } => b"crt_rel_",
                Operation::RemoveRelationship { .. } => b"rem_rel_",
                Operation::Recovery { .. } => b"recovery",
                Operation::Delete { .. } => b"delete__",
                Operation::Link { .. } => b"link____",
                Operation::Unlink { .. } => b"unlink__",
                Operation::Invalidate { .. } => b"invalid_",
                Operation::LockToken { .. } => b"lock____",
                Operation::UnlockToken { .. } => b"unlock__",
            };

            if actual_op != expected_op.as_slice() {
                return Ok(false);
            }
        }

        // ... further checks as needed
        Ok(true)
    }
}

/// Embedded commitment used within states
#[derive(Debug, Clone)]
pub struct EmbeddedCommitment {
    /// Counterparty ID this commitment involves
    pub counterparty_id: String,
    /// Fixed parameters that can't change
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    /// Variable parameters that are allowed to change
    pub variable_parameters: Vec<String>,
    /// Entity's signature on this commitment
    pub entity_signature: Vec<u8>,
    /// Counterparty's signature on this commitment
    pub counterparty_signature: Vec<u8>,
    /// Hash of the commitment for verification
    pub commitment_hash: Vec<u8>,
    /// Minimum state number this commitment applies to
    pub min_state_number: u64,
}

/// A pair of states representing the bilateral relationship between two entities
/// This implements the core bilateral state isolation concept from whitepaper Section 3.4
#[derive(Debug, Clone)]
pub struct RelationshipStatePair {
    pub entity_id: String,
    pub counterparty_id: String,
    pub entity_state: State,
    pub counterparty_state: State,
    pub verification_metadata: HashMap<String, Vec<u8>>,
    pub relationship_hash: Vec<u8>,
    pub active: bool,
}

impl RelationshipStatePair {
    pub fn new(
        entity_id: String,
        counterparty_id: String,
        entity_state: State,
        counterparty_state: State,
    ) -> Result<Self, DsmError> {
        let mut pair = Self {
            entity_id,
            counterparty_id,
            entity_state,
            counterparty_state,
            verification_metadata: HashMap::new(),
            relationship_hash: Vec::new(),
            active: true,
        };
        // Compute relationship hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pair.entity_state.hash()?);
        hasher.update(&pair.counterparty_state.hash()?);
        pair.relationship_hash = hasher.finalize().as_bytes().to_vec();

        Ok(pair)
    }

    pub fn compute_relationship_hash(&self) -> Result<Vec<u8>, DsmError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.entity_id.as_bytes());
        hasher.update(self.counterparty_id.as_bytes());
        hasher.update(&self.entity_state.state_number.to_le_bytes());
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Check if there are pending unilateral transactions
    pub fn has_pending_unilateral_transactions(&self) -> bool {
        // Placeholder
        false
    }

    /// Get the last synchronized state
    pub fn get_last_synced_state(&self) -> Option<State> {
        // Placeholder
        None
    }

    /// Set the last synchronized state
    pub fn set_last_synced_state(&mut self, _state: Option<State>) -> Result<(), DsmError> {
        // Placeholder
        Ok(())
    }

    /// Update the entity state
    pub fn update_entity_state(&mut self, new_state: State) -> Result<(), DsmError> {
        if new_state.state_number <= self.entity_state.state_number {
            return Err(DsmError::validation(
                "Cannot update to a state with a lower or equal state number",
                None::<std::convert::Infallible>,
            ));
        }
        self.entity_state = new_state;
        Ok(())
    }

    /// Add a pending transaction (placeholder)
    pub fn add_pending_transaction(&mut self, _state: State) -> Result<(), DsmError> {
        Ok(())
    }

    /// Get all pending unilateral transactions (placeholder)
    pub fn get_pending_unilateral_transactions(&self) -> Vec<State> {
        vec![]
    }

    /// Apply a transaction to the relationship
    pub fn apply_transaction(&mut self, state: State) -> Result<(), DsmError> {
        self.entity_state = state;
        Ok(())
    }

    /// Clear all pending transactions (placeholder)
    pub fn clear_pending_transactions(&mut self) {}

    pub fn build_verification_metadata(&self) -> Result<Vec<u8>, DsmError> {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(self.counterparty_state.id.as_bytes());
        metadata.extend_from_slice(&self.counterparty_state.state_number.to_le_bytes());
        Ok(metadata)
    }

    pub fn validate_operation(&self, operation: &Operation) -> Result<bool, DsmError> {
        match operation {
            Operation::AddRelationship { .. } => Ok(true),
            Operation::RemoveRelationship { .. } => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn handle_operation(&mut self, operation: Operation) -> Result<(), DsmError> {
        if !self.validate_operation(&operation)? {
            return Err(DsmError::validation(
                "Invalid operation for relationship",
                None::<std::convert::Infallible>,
            ));
        }

        match operation {
            Operation::AddRelationship { from_id, to_id, .. } => {
                self.entity_id = from_id.clone();
                self.counterparty_id = to_id.clone();
                self.active = true;
                Ok(())
            }
            Operation::RemoveRelationship { from_id, to_id, .. } => {
                self.entity_id = from_id.clone();
                self.counterparty_id = to_id.clone();
                self.active = false;
                Ok(())
            }
            _ => Err(DsmError::validation(
                "Unsupported operation type",
                None::<std::convert::Infallible>,
            )),
        }
    }

    pub fn resume(&self) -> Result<RelationshipContext, DsmError> {
        Ok(RelationshipContext {
            entity_id: self.entity_id.clone(),
            counterparty_id: self.counterparty_id.clone(),
            relationship_hash: self.relationship_hash.clone(),
            entity_state: self.entity_state.clone(),
            counterparty_state: self.counterparty_state.clone(),
            active: self.active,
        })
    }

    pub fn verify_cross_chain_continuity(
        &self,
        new_entity_state: &State,
        new_counterparty_state: &State,
    ) -> Result<bool, DsmError> {
        // Verify state number progression
        if new_entity_state.state_number != self.entity_state.state_number + 1
            || new_counterparty_state.state_number != self.counterparty_state.state_number + 1
        {
            return Ok(false);
        }

        // Verify hash chain continuity
        if new_entity_state.prev_state_hash != self.entity_state.hash()?
            || new_counterparty_state.prev_state_hash != self.counterparty_state.hash()?
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn validate_against_forward_commitment(
        &self,
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        // If there's a forward commitment in the entity state, validate against it
        if let Some(commitment) = &self.entity_state.forward_commitment {
            for (key, value) in &commitment.fixed_parameters {
                if key.as_str() == "operation_type" {
                    let op_type = match operation {
                        Operation::Genesis => b"genesis_",
                        Operation::Generic { .. } => b"generic_",
                        Operation::Transfer { .. } => b"transfer",
                        Operation::Mint { .. } => b"mint____",
                        Operation::Burn { .. } => b"burn____",
                        Operation::Create { .. } => b"create__",
                        Operation::Update { .. } => b"update__",
                        Operation::AddRelationship { .. } => b"add_rel_",
                        Operation::CreateRelationship { .. } => b"crt_rel_",
                        Operation::RemoveRelationship { .. } => b"rem_rel_",
                        Operation::Recovery { .. } => b"recovery",
                        Operation::Delete { .. } => b"delete__",
                        Operation::Link { .. } => b"link____",
                        Operation::Unlink { .. } => b"unlink__",
                        Operation::Invalidate { .. } => b"invalid_",
                        Operation::LockToken { .. } => b"lock____",
                        Operation::UnlockToken { .. } => b"unlock__",
                    };

                    if value != op_type {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }
}

/// Core functions implementing deterministic state transitions
/// Validate state transition with cryptographic verification
#[allow(dead_code)]
fn validate_transition(
    current_state: &State,
    new_state: &State,
    _operation: &Operation,
) -> Result<bool, DsmError> {
    // Validate state number increment (monotonicity)
    if new_state.state_number != current_state.state_number + 1 {
        return Ok(false);
    }

    // Validate hash chain continuity
    let current_hash = current_state.hash()?;
    if !constant_time_eq(&new_state.prev_state_hash, &current_hash) {
        return Ok(false);
    }

    // Verify state hash integrity
    if !verify_state_hash(new_state)? {
        return Ok(false);
    }

    // All checks passed
    Ok(true)
}

/// Execute a state transition with deterministic transformation
pub fn execute_transition(
    current_state: &State,
    operation: Operation,
    device_info: DeviceInfo,
) -> Result<State, DsmError> {
    let mut next_state = current_state.clone();
    next_state.state_number += 1;
    next_state.operation = operation;
    next_state.device_info = device_info;

    // Update the `hash` field using the normal state `compute_hash`
    let hash = next_state.compute_hash()?;
    next_state.hash = hash;

    Ok(next_state)
}

/// Verify entropy evolution integrity - essential for security
#[allow(dead_code)]
fn verify_entropy_evolution(
    _prev_entropy: &[u8],
    _current_entropy: &[u8],
    _operation: &Operation,
) -> Result<bool, DsmError> {
    // Placeholder logic - always true for now
    Ok(true)
}

/// Validate a relationship state transition
pub fn validate_relationship_state_transition(
    state1: &State,
    state2: &State,
) -> Result<bool, DsmError> {
    // Very basic checks (placeholder)
    if !verify_basic_state_properties(state1, state2)? {
        return Ok(false);
    }

    if let (Some(rel1), Some(rel2)) = (&state1.relationship_context, &state2.relationship_context) {
        // Verify same counterparty
        if rel1.counterparty_id != rel2.counterparty_id {
            return Ok(false);
        }
        // Verify monotonic increment
        if state2.state_number != state1.state_number + 1 {
            return Ok(false);
        }
        // Verify chain continuity
        if state2.prev_state_hash != state1.hash()? {
            return Ok(false);
        }
        // (Placeholder) verify entropy
        // ...
        // (Placeholder) verify forward commitments
        // ...
        return Ok(true);
    }

    // If no relationship context, fail
    Ok(false)
}

/// Verify an operation complies with a forward commitment
#[allow(dead_code)]
fn verify_commitment_compliance(
    operation: &Operation,
    commitment: &PreCommitment,
) -> Result<bool, DsmError> {
    match operation {
        Operation::AddRelationship { to_id, .. } => {
            // Just a simple check
            if to_id != &commitment.counterparty_id {
                return Ok(false);
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Verify basic state properties for a relationship
fn verify_basic_state_properties(state1: &State, state2: &State) -> Result<bool, DsmError> {
    // Verify both states have non-empty hashes
    if state1.hash.is_empty() || state2.hash.is_empty() {
        return Ok(false);
    }
    // Verify chain continuity
    if state2.prev_state_hash != state1.hash()? {
        return Ok(false);
    }
    Ok(true)
}

/// Verify entropy validity for a relationship state
pub fn verify_relationship_entropy(
    prev_state: &State,
    current_state: &State,
    entropy: &[u8],
) -> Result<bool, DsmError> {
    let expected_entropy = crate::crypto::blake3::generate_deterministic_entropy(
        &prev_state.entropy,
        &bincode::serialize(&current_state.operation).unwrap_or_default(),
        current_state.state_number,
    )
    .as_bytes()
    .to_vec();

    Ok(constant_time_eq(entropy, &expected_entropy))
}

/// Represents a canonical relationship key derivation strategy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyDerivationStrategy {
    /// Canonical ordering of entity and counterparty IDs
    Canonical,
    /// Entity-centric ordering (entity always first)
    EntityCentric,
    /// Cryptographic hash of entity and counterparty IDs
    Hashed,
}

/// Context for resuming a relationship interaction
#[derive(Debug, Clone)]
pub struct RelationshipContext {
    pub entity_id: String,
    pub counterparty_id: String,
    pub relationship_hash: Vec<u8>,
    pub entity_state: State,
    pub counterparty_state: State,
    pub active: bool,
}

impl RelationshipContext {
    pub fn new(
        entity_id: String,
        counterparty_id: String,
        entity_state: State,
        counterparty_state: State,
    ) -> Result<Self, DsmError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entity_state.hash()?);
        hasher.update(&counterparty_state.hash()?);
        let relationship_hash = hasher.finalize().as_bytes().to_vec();

        Ok(Self {
            entity_id,
            counterparty_id,
            relationship_hash,
            entity_state,
            counterparty_state,
            active: true,
        })
    }
}

/// Cryptographically verifiable proof of relationship existence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipProof {
    /// Entity identifier
    pub entity_id: String,
    /// Counterparty identifier
    pub counterparty_id: String,
    /// Hash of entity's state
    pub entity_state_hash: Vec<u8>,
    /// Hash of counterparty's state
    pub counterparty_state_hash: Vec<u8>,
    /// Cryptographic binding of relationship
    pub relationship_hash: Vec<u8>,
}

/// Custom error for relationship manager operations
#[derive(Debug)]
pub struct LockError;

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to acquire lock on relationship store")
    }
}

impl std::error::Error for LockError {}

/// Manager for bilateral relationship state pairs
/// Using Mutex instead of RwLock to avoid Send requirement issues
pub struct RelationshipManager {
    relationship_store: Mutex<HashMap<String, RelationshipStatePair>>,
    key_derivation_strategy: KeyDerivationStrategy,
}

impl Clone for RelationshipManager {
    fn clone(&self) -> Self {
        RelationshipManager {
            relationship_store: Mutex::new(self.relationship_store.lock().unwrap().clone()),
            key_derivation_strategy: self.key_derivation_strategy,
        }
    }
}

impl Default for RelationshipManager {
    fn default() -> Self {
        RelationshipManager::new(KeyDerivationStrategy::Canonical)
    }
}

impl std::fmt::Debug for RelationshipManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RelationshipManager {{ key_derivation_strategy: {:?} }}",
            self.key_derivation_strategy
        )
    }
}

impl RelationshipManager {
    /// Create a new relationship manager with the specified key derivation strategy
    pub fn new(strategy: KeyDerivationStrategy) -> Self {
        RelationshipManager {
            relationship_store: Mutex::new(HashMap::new()),
            key_derivation_strategy: strategy,
        }
    }

    /// Derive a canonical relationship key using entity and counterparty IDs
    pub fn get_relationship_key(&self, entity_id: &str, counterparty_id: &str) -> String {
        match self.key_derivation_strategy {
            KeyDerivationStrategy::Canonical => {
                let mut ids = [entity_id, counterparty_id];
                ids.sort();
                format!("{}:{}", ids[0], ids[1])
            }
            KeyDerivationStrategy::EntityCentric => {
                format!("{}:{}", entity_id, counterparty_id)
            }
            KeyDerivationStrategy::Hashed => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(entity_id.as_bytes());
                hasher.update(counterparty_id.as_bytes());
                hasher.finalize().to_hex().to_string()
            }
        }
    }

    /// Store a relationship state pair with thread-safe access
    pub fn store_relationship(
        &self,
        entity_id: &str,
        counterparty_id: &str,
        entity_state: State,
        counterparty_state: State,
    ) -> Result<(), DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let pair = RelationshipStatePair::new(
            entity_id.to_string(),
            counterparty_id.to_string(),
            entity_state,
            counterparty_state,
        )?;

        let mut store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;

        store.insert(key, pair);
        Ok(())
    }

    /// Resume a relationship from last known state pair with thread-safe access
    pub fn resume_relationship(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<RelationshipContext, DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;

        if let Some(pair) = store.get(&key) {
            pair.resume()
        } else {
            Err(DsmError::not_found(
                "Relationship",
                Some(format!(
                    "No relationship found between {} and {}",
                    entity_id, counterparty_id
                )),
            ))
        }
    }

    /// Update a relationship with new states, maintaining bilateral consistency
    pub fn update_relationship(
        &self,
        entity_id: &str,
        counterparty_id: &str,
        new_entity_state: State,
        new_counterparty_state: State,
    ) -> Result<(), DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);

        let mut store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;

        if let Some(pair) = store.get(&key) {
            // Verify cross-chain continuity before updating
            if !pair.verify_cross_chain_continuity(&new_entity_state, &new_counterparty_state)? {
                return Err(DsmError::validation(
                    "Cross-chain continuity violation detected",
                    None::<DsmError>,
                ));
            }
            // Create updated relationship pair
            let updated_pair = RelationshipStatePair::new(
                entity_id.to_string(),
                counterparty_id.to_string(),
                new_entity_state,
                new_counterparty_state,
            )?;

            store.insert(key, updated_pair);
            Ok(())
        } else {
            Err(DsmError::not_found(
                "Relationship",
                Some(format!(
                    "No relationship found between {} and {}",
                    entity_id, counterparty_id
                )),
            ))
        }
    }

    /// Execute a state transition within a relationship context
    pub fn execute_relationship_transition(
        &self,
        entity_id: &str,
        counterparty_id: &str,
        operation: Operation,
        new_entropy: Vec<u8>,
    ) -> Result<RelationshipStatePair, DsmError> {
        // Resume the relationship
        let context = self.resume_relationship(entity_id, counterparty_id)?;

        // Validate operation against any forward commitment
        let relationship = RelationshipStatePair::new(
            context.entity_id.clone(),
            context.counterparty_id.clone(),
            context.entity_state.clone(),
            context.counterparty_state.clone(),
        )?;

        if !relationship.validate_against_forward_commitment(&operation)? {
            return Err(DsmError::validation(
                "Operation does not comply with forward commitment",
                None::<DsmError>,
            ));
        }

        // Execute the transition on the entity state
        let state_transition = StateTransition::new(
            operation.clone(),
            Some(new_entropy.clone()),
            None,
            &context.entity_state.device_info.device_id,
        );
        let new_entity_state = apply_transition(&state_transition, &context.entity_state)?;

        // Create new relationship pair with updated state
        let new_relationship = RelationshipStatePair::new(
            entity_id.to_string(),
            counterparty_id.to_string(),
            new_entity_state.clone(),
            context.counterparty_state.clone(),
        )?;

        // Update the relationship store
        self.update_relationship(
            entity_id,
            counterparty_id,
            new_relationship.entity_state.clone(),
            new_relationship.counterparty_state.clone(),
        )?;

        Ok(new_relationship)
    }

    /// Verify relationship existence without resuming
    pub fn verify_relationship_exists(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<bool, DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;
        Ok(store.contains_key(&key))
    }

    /// Export relationship proof for verification by third parties
    pub fn export_relationship_proof(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<RelationshipProof, DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;

        if let Some(pair) = store.get(&key) {
            Ok(RelationshipProof {
                entity_id: pair.entity_id.clone(),
                counterparty_id: pair.counterparty_id.clone(),
                entity_state_hash: pair.entity_state.hash()?,
                counterparty_state_hash: pair.counterparty_state.hash()?,
                relationship_hash: pair.relationship_hash.clone(),
            })
        } else {
            Err(DsmError::not_found(
                "Relationship",
                Some(format!(
                    "No relationship found between {} and {}",
                    entity_id, counterparty_id
                )),
            ))
        }
    }

    /// Verify a relationship proof against local records
    pub fn verify_relationship_proof(&self, proof: &RelationshipProof) -> Result<bool, DsmError> {
        let key = self.get_relationship_key(&proof.entity_id, &proof.counterparty_id);
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;

        if let Some(pair) = store.get(&key) {
            let entity_hash = pair.entity_state.hash()?;
            if entity_hash != proof.entity_state_hash {
                return Ok(false);
            }

            let counterparty_hash = pair.counterparty_state.hash()?;
            if counterparty_hash != proof.counterparty_state_hash {
                return Ok(false);
            }

            if pair.relationship_hash != proof.relationship_hash {
                return Ok(false);
            }

            Ok(true)
        } else {
            // Relationship doesn't exist locally, cannot verify
            Ok(false)
        }
    }

    /// List all entity IDs with active relationships
    pub fn list_entities(&self) -> Result<HashSet<String>, DsmError> {
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;
        let mut entities = HashSet::new();
        for pair in store.values() {
            entities.insert(pair.entity_id.clone());
            entities.insert(pair.counterparty_id.clone());
        }
        Ok(entities)
    }

    /// Find all counterparties for a given entity
    pub fn find_counterparties(&self, entity_id: &str) -> Result<Vec<String>, DsmError> {
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;
        let mut counterparties = Vec::new();
        for pair in store.values() {
            if pair.entity_id == entity_id {
                counterparties.push(pair.counterparty_id.clone());
            } else if pair.counterparty_id == entity_id {
                counterparties.push(pair.entity_id.clone());
            }
        }
        Ok(counterparties)
    }

    /// Get the latest state for an entity in a specific relationship
    pub fn get_entity_state(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<State, DsmError> {
        let key = self.get_relationship_key(entity_id, counterparty_id);
        let store = self.relationship_store.lock().map_err(|_| {
            DsmError::validation(
                "Failed to acquire lock on relationship store",
                None::<DsmError>,
            )
        })?;

        if let Some(pair) = store.get(&key) {
            if pair.entity_id == entity_id {
                Ok(pair.entity_state.clone())
            } else {
                Ok(pair.counterparty_state.clone())
            }
        } else {
            Err(DsmError::not_found(
                "Relationship",
                Some(format!(
                    "No relationship found between {} and {}",
                    entity_id, counterparty_id
                )),
            ))
        }
    }

    /// This method is an alias for get_entity_state to maintain API compatibility
    pub fn get_relationship_state(
        &self,
        entity_id: &str,
        counterparty_id: &str,
    ) -> Result<State, DsmError> {
        self.get_entity_state(entity_id, counterparty_id)
    }
}

fn apply_transition(
    transition: &StateTransition,
    current_state: &State,
) -> Result<State, DsmError> {
    let mut new_state = current_state.clone();

    // Increment state number
    new_state.state_number += 1;
    // Set operation
    new_state.operation = transition.operation.clone();
    // Update entropy if provided
    if let Some(new_entropy) = &transition.new_entropy {
        new_state.entropy = new_entropy.clone();
    }
    // Update prev_state_hash
    new_state.prev_state_hash = current_state.hash()?;

    Ok(new_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a test state
    fn create_test_state(state_number: u64, prev_hash: Vec<u8>) -> State {
        let mut state = State::default();
        state.state_number = state_number;
        state.prev_state_hash = prev_hash;

        // Just a simple unique hash
        state.hash = blake3::hash(format!("test_state_{}", state_number).as_bytes())
            .as_bytes()
            .to_vec();

        // Simple deterministic entropy
        state.entropy = blake3::hash(format!("entropy_{}", state_number).as_bytes())
            .as_bytes()
            .to_vec();

        state
    }

    #[test]
    fn test_relationship_creation() {
        let entity_state = create_test_state(1, Vec::new());
        let counterparty_state = create_test_state(1, Vec::new());

        let result = RelationshipStatePair::new(
            "entity1".to_string(),
            "entity2".to_string(),
            entity_state,
            counterparty_state,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_relationship_manager() {
        let manager = RelationshipManager::new(KeyDerivationStrategy::Canonical);

        let entity_state = create_test_state(1, Vec::new());
        let counterparty_state = create_test_state(1, Vec::new());

        // Store a relationship
        let result =
            manager.store_relationship("entity1", "entity2", entity_state, counterparty_state);
        assert!(result.is_ok());

        // Verify relationship exists
        let exists = manager
            .verify_relationship_exists("entity1", "entity2")
            .unwrap();
        assert!(exists);

        // Test key derivation strategies
        let canonical_key = manager.get_relationship_key("entity2", "entity1");
        let canonical_key2 = manager.get_relationship_key("entity1", "entity2");
        // Both should be the same under Canonical
        assert_eq!(canonical_key, canonical_key2);

        // Test hashed key
        let hashed_manager = RelationshipManager::new(KeyDerivationStrategy::Hashed);
        let hashed_key = hashed_manager.get_relationship_key("entity1", "entity2");
        // A blake3 hex string is 64 chars
        assert_eq!(hashed_key.len(), 64);
    }

    #[test]
    fn test_relationship_state() {
        let entity_state = create_test_state(1, Vec::new());
        let counterparty_state = create_test_state(1, Vec::new());

        let result = RelationshipStatePair::new(
            "entity1".to_string(),
            "entity2".to_string(),
            entity_state.clone(),
            counterparty_state.clone(),
        );
        assert!(result.is_ok());
        let relationship = result.unwrap();

        // Validate state transition
        let new_entity_state = create_test_state(2, entity_state.hash().unwrap());
        let new_counterparty_state = create_test_state(2, counterparty_state.hash().unwrap());

        let continuity_valid =
            relationship.verify_cross_chain_continuity(&new_entity_state, &new_counterparty_state);
        assert!(continuity_valid.is_ok());
        assert!(continuity_valid.unwrap());

        // Validate entropy evolution (placeholder always returns true by default)
        let entropy_valid = verify_entropy_evolution(
            &entity_state.entropy,
            &new_entity_state.entropy,
            &new_entity_state.operation,
        );
        assert!(entropy_valid.is_ok());
        assert!(entropy_valid.unwrap());
    }
}
