//! Batched Transaction Processing API
//!
//! This module provides a high-level API for working with batched transactions in DSM.
//! Batching transactions offers several benefits:
//!
//! 1. Improved efficiency by processing multiple state transitions at once
//! 2. Atomic commitment of related state changes
//! 3. Reduced overhead for verification via Merkle proofs
//! 4. Simplified client-side transaction management
//!
//! # Example Usage
//! ```rust,no_run
//! use dsm::api::batch_api::{BatchBuilder, TransactionBatch};
//! use dsm::types::state_types::{State, DeviceInfo};
//! use dsm::types::operations::Operation;
//!
//! # fn main() -> Result<(), dsm::types::error::DsmError> {
//! let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
//! let genesis_state = State::new_genesis(vec![0, 1, 2, 3], device_info);
//!
//! // Create a batch builder
//! let mut batch_builder = BatchBuilder::new("my_device");
//!
//! // Add transactions to the batch
//! batch_builder.add_transaction(
//!     "Operation 1",
//!     vec![1, 2, 3],
//!     &genesis_state
//! )?;
//!
//! batch_builder.add_transaction(
//!     "Operation 2",
//!     vec![4, 5, 6],
//!     &genesis_state
//! )?;
//!
//! // Build the batch
//! let batch = batch_builder.build()?;
//!
//! // Process the batch
//! let chain = batch.process()?;
//! # Ok(())
//! # }
//! ```

use std::time::SystemTime;

use crate::{
    core::state_machine::{hashchain::HashChain, transition::StateTransition},
    merkle::tree::MerkleTree,
    types::{error::DsmError, operations::Operation, state_types::State},
};

/// Initialize the batch processing module
pub fn init() {
    // Initialization logic if needed
}

/// Represents a batch of transactions to be processed together
#[derive(Debug)]
pub struct TransactionBatch {
    /// Unique identifier for this batch
    pub id: String,

    /// List of transitions in the batch
    pub transitions: Vec<StateTransition>,

    /// Timestamp when the batch was created
    pub created_at: u64,

    /// Status of the batch
    pub status: BatchStatus,
}

/// Status of a transaction batch
#[derive(Debug, Clone, PartialEq, Default)]
pub enum BatchStatus {
    /// Batch is being constructed
    #[default]
    Building,

    /// Batch is ready for processing
    Ready,

    /// Batch has been finalized with Merkle root
    Finalized,

    /// Batch has been committed to the chain
    Committed,

    /// Batch processing failed
    Failed(String),
}

impl TransactionBatch {
    /// Create a new transaction batch
    pub fn new(id: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: id.to_string(),
            transitions: Vec::new(),
            created_at: now,
            status: BatchStatus::Building,
        }
    }

    /// Add a transition to this batch
    pub fn add_transition(&mut self, transition: StateTransition) -> Result<(), DsmError> {
        if self.status != BatchStatus::Building {
            return Err(DsmError::validation(
                "Cannot add transitions to a batch that is not in building state",
                None::<std::convert::Infallible>,
            ));
        }

        self.transitions.push(transition);
        Ok(())
    }

    /// Mark this batch as ready for processing
    pub fn ready(mut self) -> Self {
        self.status = BatchStatus::Ready;
        self
    }

    /// Process this batch using a HashChain
    pub fn process(self) -> Result<HashChain, DsmError> {
        let mut chain = HashChain::new();

        // Create a batch in the chain
        let batch_id = chain.create_batch()?;

        // Add all transitions to the batch
        for transition in &self.transitions {
            chain.add_transition_to_batch(batch_id, transition.clone())?;
        }

        // Finalize the batch
        chain.finalize_batch(batch_id)?;

        // Commit the batch
        chain.commit_batch(batch_id)?;

        Ok(chain)
    }

    /// Process this batch against an existing HashChain
    pub fn process_with_chain(self, chain: &mut HashChain) -> Result<u64, DsmError> {
        // Create a batch in the chain
        let batch_id = chain.create_batch()?;

        // Add all transitions to the batch
        for transition in &self.transitions {
            chain.add_transition_to_batch(batch_id, transition.clone())?;
        }

        // Finalize the batch
        chain.finalize_batch(batch_id)?;

        // Commit the batch
        chain.commit_batch(batch_id)?;

        Ok(batch_id)
    }

    /// Verify a specific transition in this batch
    pub fn verify_transition(
        &self,
        chain: &HashChain,
        batch_id: u64,
        transition_index: usize,
    ) -> Result<bool, DsmError> {
        if transition_index >= self.transitions.len() {
            return Err(DsmError::invalid_parameter(format!(
                "Transition index {} is out of range",
                transition_index
            )));
        }

        // Get the transition to verify
        let transition = &self.transitions[transition_index];

        // Serialize transition to bytes for hashing
        let serialized_transition = bincode::serialize(transition)?;
        let transition_bytes = serialized_transition.as_slice();

        // Check token balances if present - prevent insufficient balance
        if let Some(balances) = &transition.token_balances {
            // Get the current state for this device from the chain
            let device_id = &transition.device_id;
            let current_state = chain.get_state(device_id).ok_or(DsmError::not_found(
                "State",
                Some(format!("No state found for device {}", device_id)),
            ))?;

            // Check each token balance for sufficient funds
            for (token_id, new_balance) in balances {
                if let Some(current_balance) = current_state.token_balances.get(token_id) {
                    if new_balance.value() < current_balance.value()
                        && transition.operation.affects_balance(token_id)
                    {
                        return Err(DsmError::insufficient_balance(
                            token_id.clone(),
                            current_balance.value(),
                            new_balance.value(),
                        ));
                    }
                }
            }
        }

        // Create a Merkle proof for the transition
        let transition_hash = blake3::hash(transition_bytes).as_bytes().to_vec();

        // Get all transactions in the batch from the chain
        let batch_info = match chain.get_batch(batch_id) {
            Ok(info) => info,
            Err(_) => {
                return Err(DsmError::not_found(
                    "Batch",
                    Some(format!("Batch {} not found", batch_id)),
                ))
            }
        };

        // Build a Merkle tree from all transitions in the batch
        let mut tree_leaves = Vec::with_capacity(self.transitions.len());
        for transition in &self.transitions {
            let serialized_t = bincode::serialize(transition)?;
            let t_bytes = serialized_t.as_slice();
            let hash = blake3::hash(t_bytes).as_bytes().to_vec();
            tree_leaves.push(hash);
        }

        // Create the Merkle tree
        let tree = MerkleTree::new(tree_leaves);

        // Get the Merkle proof for the target transition
        let proof = tree.generate_proof(transition_index);

        // Verify the proof
        let mut root_hash_array = [0u8; 32];
        let mut transition_hash_array = [0u8; 32];

        if let Some(root) = tree.root_hash() {
            root_hash_array.copy_from_slice(&root);
        } else {
            return Ok(false);
        }

        if transition_hash.len() >= 32 {
            transition_hash_array.copy_from_slice(&transition_hash[0..32]);
        } else {
            return Ok(false);
        }

        let result = MerkleTree::verify_proof(
            &root_hash_array,
            &transition_hash_array,
            &proof.path,
            proof.leaf_index,
        );

        // If the batch has a transitions root, compare it
        if !batch_info.transitions_root.is_empty() {
            let root_opt = tree.root_hash();
            if let Some(root) = root_opt {
                if root.to_vec() != batch_info.transitions_root {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        Ok(result)
    }
}

/// Builder for constructing transaction batches
#[derive(Debug)]
pub struct BatchBuilder {
    /// Device ID to use for transitions
    device_id: String,

    /// Batch being constructed
    batch: TransactionBatch,
}

impl Default for TransactionBatch {
    fn default() -> Self {
        TransactionBatch::new("default_batch")
    }
}

impl BatchBuilder {
    /// Create a new batch builder
    pub fn new(device_id: &str) -> Self {
        Self {
            device_id: device_id.to_string(),
            batch: TransactionBatch::new(&format!("batch_{}", generate_unique_id())),
        }
    }

    /// Add a transaction to the batch
    pub fn add_transaction(
        &mut self,
        operation_type: &str,
        data: Vec<u8>,
        _from_state: &State,
    ) -> Result<&mut Self, DsmError> {
        // Create the operation
        let operation = Operation::Generic {
            operation_type: operation_type.to_string(),
            data,
            message: "".to_string(), // Empty message as default
        };

        // Create a state transition
        let transition = StateTransition::new(
            operation,
            Some(self.device_id.clone().into_bytes()),
            Some(generate_entropy()),
            &self.batch.created_at.to_string(),
        );

        // Add to batch
        self.batch.add_transition(transition)?;

        Ok(self)
    }

    /// Build the batch
    pub fn build(self) -> Result<TransactionBatch, DsmError> {
        if self.batch.transitions.is_empty() {
            return Err(DsmError::validation(
                "Cannot build an empty batch",
                None::<std::convert::Infallible>,
            ));
        }

        Ok(self.batch.ready())
    }
}

// Helper function to generate a unique ID
fn generate_unique_id() -> String {
    use std::time::SystemTime;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    format!("{:x}", now)
}

// Helper function to generate entropy
fn generate_entropy() -> Vec<u8> {
    use rand::{thread_rng, RngCore};

    let mut entropy = vec![0u8; 32];
    thread_rng().fill_bytes(&mut entropy);
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::state_types::DeviceInfo;

    #[test]
    fn test_batch_builder() -> Result<(), DsmError> {
        // Create a device and genesis state
        let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
        let mut genesis_state = State::new_genesis(vec![0, 1, 2, 3], device_info);

        // Compute and set hash
        let hash = genesis_state.compute_hash()?;
        genesis_state.hash = hash;

        // Create a batch builder
        let mut builder = BatchBuilder::new("test_device");

        // Add transactions
        builder.add_transaction("op_1", vec![1, 2, 3], &genesis_state)?;
        builder.add_transaction("op_2", vec![4, 5, 6], &genesis_state)?;

        // Build the batch
        let batch = builder.build()?;

        // Check batch properties
        assert_eq!(batch.transitions.len(), 2);
        assert_eq!(batch.status, BatchStatus::Ready);

        Ok(())
    }
}
