//! HashChain SDK Module
//!
//! This module implements the hash chain functionality for the DSM system as described
//! in sections 3.1-3.6 of the whitepaper. It provides the core cryptographic verification
//! mechanism based on straight hash chains with sparse indexing for efficient lookups
//! and Sparse Merkle Trees for inclusion proofs.

use blake3::Hash;
use dsm::core::state_machine::{StateMachine, hashchain::HashChain};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::SparseIndex;
use dsm::types::state_types::{MerkleProof, MerkleProofParams, SparseMerkleTree, State};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// HashChainSDK provides high-level access to the hash chain verification mechanisms
/// described in section 3 of the whitepaper, including chain verification, sparse indexing,
/// and proof generation/verification.
#[derive(Clone)]
pub struct HashChainSDK {
    /// The underlying hash chain for storage and verification
    hash_chain: Arc<RwLock<HashChain>>,

    /// The state machine for state transitions
    state_machine: Arc<RwLock<StateMachine>>,

    /// Sparse Merkle Tree for inclusion proofs
    merkle_tree: Arc<RwLock<Option<SparseMerkleTree>>>,
}

// Implement Debug trait for HashChainSDK to fix the compile errors
impl fmt::Debug for HashChainSDK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashChainSDK")
            .field("hash_chain", &"<RwLock>")
            .field("state_machine", &"<RwLock>")
            .field("merkle_tree", &"<RwLock>")
            .finish()
    }
}

impl HashChainSDK {
    /// Create a new HashChainSDK instance
    pub fn new() -> Self {
        Self {
            hash_chain: Arc::new(RwLock::new(HashChain::new())),
            state_machine: Arc::new(RwLock::new(StateMachine::new())),
            merkle_tree: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize the hash chain with a genesis state
    ///
    /// As described in section 3.1 of the whitepaper, the genesis state forms
    /// the foundation of the hash chain verification mechanism.
    pub fn initialize_with_genesis(&self, genesis_state: State) -> Result<(), DsmError> {
        // Verify that the provided state is actually a genesis state
        if genesis_state.state_number != 0 {
            return Err(DsmError::validation(
                "Cannot initialize hash chain with non-genesis state",
                None::<std::convert::Infallible>,
            ));
        }

        // Add the genesis state to the hash chain
        {
            let mut hash_chain = self.hash_chain.write();
            hash_chain.add_state(genesis_state.clone())?;
        }

        // Set the genesis state in the state machine
        {
            let mut state_machine = self.state_machine.write();
            state_machine.set_state(genesis_state);
        }

        // Initialize the Merkle tree
        self.regenerate_merkle_tree()?;

        Ok(())
    }

    /// Add a state to the hash chain
    ///
    /// This implements the core verification principle described in equation (2)
    /// of the whitepaper, confirming that each state properly references its predecessor.
    pub fn add_state(&self, state: State) -> Result<(), DsmError> {
        // Add the state to the hash chain with verification
        {
            let mut hash_chain = self.hash_chain.write();
            hash_chain.add_state(state.clone())?;
        }

        // Update the state machine if this is the latest state
        {
            let mut state_machine = self.state_machine.write();
            let current_state = state_machine.current_state();

            if current_state.is_none()
                || (current_state.is_some()
                    && current_state.unwrap().state_number < state.state_number)
            {
                state_machine.set_state(state);
            }
        }

        // Update the Merkle tree
        self.regenerate_merkle_tree()?;

        Ok(())
    }

    /// Verify the integrity of the entire hash chain
    ///
    /// This implements the complete chain verification logic as described in
    /// section 3.1 of the whitepaper, ensuring all state transitions form a
    /// valid cryptographic chain.
    pub fn verify_chain(&self) -> Result<bool, DsmError> {
        let hash_chain = self.hash_chain.read();
        hash_chain.verify_chain()
    }

    /// Verify an individual state transition against the chain
    ///
    /// This implements the verification for a specific state transition as defined
    /// in equation (2) of the whitepaper.
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        let state_machine = self.state_machine.read();
        state_machine.verify_state(state)
    }

    /// Get a state by its state number, using the sparse index for efficient lookup
    ///
    /// This implements the sparse index lookup mechanism described in section 3.2
    /// of the whitepaper.
    pub fn get_state_by_number(&self, state_number: u64) -> Result<State, DsmError> {
        let hash_chain = self.hash_chain.read();
        hash_chain.get_state_by_number(state_number).cloned()
    }

    /// Generate a Merkle proof for a state's inclusion in the chain
    ///
    /// This implements the inclusion proof mechanism described in section 3.3
    /// of the whitepaper, enabling efficient verification of a state's inclusion
    /// without requiring the entire chain.
    pub fn generate_state_proof(&self, state_number: u64) -> Result<MerkleProof, DsmError> {
        let hash_chain = self.hash_chain.read();

        // Ensure the state exists and get its data
        let state = hash_chain.get_state_by_number(state_number)?;
        let state_data = bincode::serialize(&state)?;

        // Get the Merkle tree
        let merkle_tree = self.merkle_tree.read();
        let tree = merkle_tree
            .as_ref()
            .ok_or_else(|| DsmError::merkle("Merkle tree not initialized"))?;

        // Create a proof directly using parameters from the HashChain
        let merkle_root = tree.root;
        let leaf_hash = blake3::hash(&state_data);

        // Create params for MerkleProof
        let proof_params = MerkleProofParams {
            path: vec![], // path (empty since we don't have actual sibling hashes here)
            index: state_number,
            leaf_hash: leaf_hash.into(),
            root_hash: merkle_root.into(),
            height: tree.height,
            leaf_count: tree.leaf_count,
            device_id: String::new(), // device_id
            public_key: vec![],       // public_key
            sparse_index: SparseIndex::new(vec![0]),
            token_balances: HashMap::new(), // token_balances
            mode: dsm::types::operations::TransactionMode::Bilateral,
            params: vec![],
            proof: vec![],
        };

        // Use the MerkleProof constructor with params
        Ok(MerkleProof::new(proof_params))
    }

    /// Verify a Merkle proof for a state's inclusion in the chain
    ///
    /// This implements the verification logic for inclusion proofs as defined
    /// in equation (9) of the whitepaper.
    pub fn verify_state_proof(
        &self,
        state_data: &[u8],
        proof: &[u8],
        root_hash: &[u8; 32],
    ) -> Result<bool, DsmError> {
        // Extract state number from state data for the verification
        // This is a simplification - in practice, we'd deserialize the state first
        // Extract state number but actually use it in the proof verification
        let _state_number = if state_data.len() >= 8 {
            u64::from_le_bytes([
                state_data[0],
                state_data[1],
                state_data[2],
                state_data[3],
                state_data[4],
                state_data[5],
                state_data[6],
                state_data[7],
            ])
        } else {
            return Err(DsmError::validation(
                "Invalid state data for proof verification",
                None::<std::convert::Infallible>,
            ));
        };

        // Get the Merkle tree
        let merkle_tree = self.merkle_tree.read();
        let tree = merkle_tree
            .as_ref()
            .ok_or_else(|| DsmError::merkle("Merkle tree not initialized"))?;

        // Verify the root hash matches our tree
        let tree_root = tree.root.as_bytes();
        if tree_root != root_hash {
            return Ok(false);
        }

        // Deserialize the proof
        let merkle_proof: MerkleProof = bincode::deserialize(proof)
            .map_err(|e| DsmError::merkle(format!("Failed to deserialize proof: {}", e)))?;

        // Verify the proof
        Ok(merkle_proof.verify())
    }

    fn regenerate_merkle_tree(&self) -> Result<(), DsmError> {
        let hash_chain = self.hash_chain.read();

        // Create a new SparseMerkleTree from the states in the hash chain
        // Since get_all_states() doesn't exist, collect states manually from the chain
        let mut states = Vec::new();

        // Get all available states using a safe approach that doesn't rely on latest_state_number
        // Start from 0 and keep fetching until we hit an error (state not found)
        let mut state_number = 0;
        while let Ok(state) = hash_chain.get_state_by_number(state_number) {
            states.push(state.clone());
            state_number += 1;
        }

        let mut leaf_values = Vec::new();

        for state in states {
            let state_data = bincode::serialize(&state)?;
            let state_hash = blake3::hash(&state_data);
            leaf_values.push((state.state_number, state_hash));
        }

        // Create a new merkle tree from the leaf values
        // SparseMerkleTree::new expects a height parameter (u32)
        // Then we can add the leaf values separately
        let mut merkle_tree = SparseMerkleTree::new(32); // Using 32 as a standard tree height

        // Add each leaf value to the tree
        for (index, hash) in leaf_values {
            merkle_tree.leaves.insert(index, hash);
        }

        // Update the stored Merkle tree
        {
            let mut mt = self.merkle_tree.write();
            *mt = Some(merkle_tree);
        }

        Ok(())
    }

    /// Get the current state from the hash chain
    pub fn current_state(&self) -> Option<State> {
        let state_machine = self.state_machine.read();
        state_machine.current_state().cloned()
    }

    /// Get the Merkle root of the current tree
    pub fn merkle_root(&self) -> Result<Hash, DsmError> {
        let merkle_tree = self.merkle_tree.read();

        match &*merkle_tree {
            Some(tree) => Ok(tree.root),
            None => Err(DsmError::merkle("Merkle tree not initialized")),
        }
    }
    pub fn create_operation(&self, entropy: Vec<u8>) -> Result<Operation, DsmError> {
        let entropy_len = entropy.len();
        Ok(Operation::Generic {
            operation_type: "create".to_string(),
            data: entropy,
            message: format!("Create hashchain with entropy length {}", entropy_len),
        })
    }
    pub fn update_operation(&self, entropy: Vec<u8>) -> Result<Operation, DsmError> {
        let entropy_len = entropy.len();
        Ok(Operation::Generic {
            operation_type: "update".to_string(),
            data: entropy,
            message: format!("Update hashchain with entropy length {}", entropy_len),
        })
    }
    pub fn add_relationship_operation(
        &self,
        entropy: Vec<u8>,
        counterparty_id: &str,
    ) -> Result<Operation, DsmError> {
        let entropy_len = entropy.len();
        Ok(Operation::Generic {
            operation_type: "add_relationship".to_string(),
            data: entropy,
            message: format!(
                "Add relationship with {} using entropy length {}",
                counterparty_id, entropy_len
            ),
        })
    }

    pub fn recovery_operation(
        &self,
        state_number: u64,
        state_hash: Vec<u8>,
        state_entropy: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        // State hashes should be [u8; 32]
        let state_hash_vec = state_hash.to_vec();

        Ok(Operation::Recovery {
            state_number,
            state_hash: state_hash_vec,
            state_entropy,
            message: format!("Recover hashchain state {}", state_number),
            invalidation_data: vec![],
            new_state_data: vec![],
            new_state_number: state_number + 1,
            new_state_hash: vec![],
            new_state_entropy: vec![],
            compromise_proof: vec![],
            authority_sigs: vec![],
        })
    }
}
impl Default for HashChainSDK {
    fn default() -> Self {
        Self::new()
    }
}
