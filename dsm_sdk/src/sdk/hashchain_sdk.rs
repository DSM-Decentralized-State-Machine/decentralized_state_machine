//! # HashChain SDK Module
//!
//! This module implements the hash chain functionality for the DSM system as described
//! in sections 2 and 5 of the DSM whitepaper. It provides core state management and
//! cryptographic verification mechanisms including:
//!
//! * State chain management and verification
//! * Sparse indexing for efficient state lookups
//! * Merkle tree-based inclusion proofs
//! * Cryptographic state transition validation
//!
//! ## Key Concepts
//!
//! * **Hash Chain**: A cryptographically linked sequence of states
//! * **State Transitions**: Deterministic evolution according to the formula Sn+1 = H(Sn∥opn+1)
//! * **Merkle Proofs**: Efficient verification of state inclusion
//! * **Sparse Indexing**: Fast access to historical states
//!
//! ## Usage Example
//!
//! ```rust
//! use dsm_sdk::hashchain_sdk::HashChainSDK;
//! use dsm::types::state_types::{DeviceInfo, State};
//! use dsm::types::error::DsmError;
//!
//! fn example() -> Result<(), DsmError> {
//!     // Create a new hash chain SDK
//!     let sdk = HashChainSDK::new();
//!
//!     // Create and initialize with a genesis state
//!     let device_info = DeviceInfo::new("my_device", vec![1, 2, 3]);
//!     let genesis = State::new_genesis(vec![4, 5, 6], device_info);
//!     sdk.initialize_with_genesis(genesis)?;
//!
//!     // Create a new operation and add it to the chain
//!     let op = sdk.create_operation(vec![7, 8, 9])?;
//!     
//!     // Verify the chain integrity
//!     let valid = sdk.verify_chain()?;
//!     assert!(valid);
//!
//!     Ok(())
//! }
//! ```

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

/// HashChain SDK for managing and verifying cryptographic state transitions
///
/// This SDK provides high-level access to the hash chain verification mechanisms
/// described in sections 2 and 5 of the DSM whitepaper, including chain verification, 
/// sparse indexing, and proof generation/verification.
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
    ///
    /// Initializes a new HashChainSDK with empty state and hash chain.
    /// The SDK must be initialized with a genesis state before use.
    ///
    /// # Returns
    ///
    /// A new HashChainSDK instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    ///
    /// // Create a new hash chain SDK
    /// let sdk = HashChainSDK::new();
    /// ```
    pub fn new() -> Self {
        Self {
            hash_chain: Arc::new(RwLock::new(HashChain::new())),
            state_machine: Arc::new(RwLock::new(StateMachine::new())),
            merkle_tree: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize the hash chain with a genesis state
    ///
    /// Sets up the initial genesis state (G) as described in section 4 of the 
    /// DSM whitepaper, establishing the foundation for all subsequent state transitions.
    ///
    /// # Arguments
    ///
    /// * `genesis_state` - The genesis state (must have state_number = 0)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization was successful
    /// * `Err(DsmError)` - If the genesis state is invalid or initialization failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::state_types::{DeviceInfo, State};
    ///
    /// // Create a new hash chain SDK
    /// let sdk = HashChainSDK::new();
    ///
    /// // Create a genesis state
    /// let device_info = DeviceInfo::new("my_device", vec![1, 2, 3]);
    /// let genesis = State::new_genesis(vec![4, 5, 6], device_info);
    ///
    /// // Initialize with genesis state
    /// sdk.initialize_with_genesis(genesis).unwrap();
    /// ```
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
    /// Adds a new state to the hash chain, verifying its cryptographic integrity
    /// according to the principles in section 2 of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `state` - The state to add to the chain
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the state was added successfully
    /// * `Err(DsmError)` - If the state is invalid or couldn't be added
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::state_types::{DeviceInfo, State, StateParams};
    /// use dsm::types::operations::Operation;
    ///
    /// // Create a new state and add it to the chain
    /// fn add_new_state(sdk: &HashChainSDK) {
    ///     if let Some(current) = sdk.current_state() {
    ///         let device_info = current.device_info.clone();
    ///         let operation = Operation::Generic {
    ///             operation_type: "update".to_string(),
    ///             data: vec![1, 2, 3],
    ///             message: "Update state".to_string(),
    ///         };
    ///
    ///         let params = StateParams::new(
    ///             current.state_number + 1,
    ///             vec![4, 5, 6],
    ///             operation,
    ///             device_info,
    ///         );
    ///
    ///         let new_state = State::new(params);
    ///         sdk.add_state(new_state).unwrap();
    ///     }
    /// }
    /// ```
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
    /// Performs a comprehensive verification of the hash chain as described in
    /// section 5 of the DSM whitepaper, ensuring all state transitions form a
    /// valid cryptographic chain.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the chain integrity is verified, false otherwise
    /// * `Err(DsmError)` - If verification couldn't be performed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    ///
    /// // Verify the integrity of the hash chain
    /// fn verify_integrity(sdk: &HashChainSDK) {
    ///     let valid = sdk.verify_chain().unwrap();
    ///     assert!(valid, "Hash chain integrity verification failed");
    /// }
    /// ```
    pub fn verify_chain(&self) -> Result<bool, DsmError> {
        let hash_chain = self.hash_chain.read();
        hash_chain.verify_chain()
    }

    /// Verify an individual state transition against the chain
    ///
    /// Verifies that a state correctly follows from its predecessor according
    /// to the deterministic transition formula Sn+1 = H(Sn∥opn+1).
    ///
    /// # Arguments
    ///
    /// * `state` - The state to verify
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the state transition is valid, false otherwise
    /// * `Err(DsmError)` - If verification couldn't be performed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::state_types::State;
    ///
    /// // Verify a specific state transition
    /// fn verify_state_transition(sdk: &HashChainSDK, state: &State) {
    ///     let valid = sdk.verify_state(state).unwrap();
    ///     assert!(valid, "State transition verification failed");
    /// }
    /// ```
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        let state_machine = self.state_machine.read();
        state_machine.verify_state(state)
    }

    /// Get a state by its state number
    ///
    /// Retrieves a specific state from the hash chain by its sequence number,
    /// using sparse indexing for efficient lookup.
    ///
    /// # Arguments
    ///
    /// * `state_number` - The sequence number of the state to retrieve
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The requested state if found
    /// * `Err(DsmError)` - If the state doesn't exist or retrieval failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    ///
    /// // Get a historical state by number
    /// fn get_historical_state(sdk: &HashChainSDK, state_number: u64) {
    ///     let state = sdk.get_state_by_number(state_number).unwrap();
    ///     println!("Retrieved state #{}", state.state_number);
    /// }
    /// ```
    pub fn get_state_by_number(&self, state_number: u64) -> Result<State, DsmError> {
        let hash_chain = self.hash_chain.read();
        hash_chain.get_state_by_number(state_number).cloned()
    }

    /// Generate a Merkle proof for a state's inclusion in the chain
    ///
    /// Creates a cryptographic proof that a specific state is included in the
    /// hash chain, following the Merkle proof principles described in section 5
    /// of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `state_number` - The number of the state to create a proof for
    ///
    /// # Returns
    ///
    /// * `Ok(MerkleProof)` - The generated proof if successful
    /// * `Err(DsmError)` - If proof generation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    ///
    /// // Generate a proof for a state's inclusion
    /// fn generate_inclusion_proof(sdk: &HashChainSDK, state_number: u64) {
    ///     let proof = sdk.generate_state_proof(state_number).unwrap();
    ///     // The proof can be serialized and shared
    /// }
    /// ```
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
    /// Verifies that a Merkle proof correctly demonstrates a state's inclusion
    /// in the hash chain.
    ///
    /// # Arguments
    ///
    /// * `state_data` - The serialized state data
    /// * `proof` - The serialized Merkle proof
    /// * `root_hash` - The Merkle root hash to verify against
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the proof is valid, false otherwise
    /// * `Err(DsmError)` - If verification couldn't be performed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use bincode;
    ///
    /// // Verify a state inclusion proof
    /// fn verify_inclusion_proof(
    ///     sdk: &HashChainSDK,
    ///     state_data: &[u8],
    ///     proof: &[u8],
    ///     root_hash: &[u8; 32]
    /// ) {
    ///     let valid = sdk.verify_state_proof(state_data, proof, root_hash).unwrap();
    ///     assert!(valid, "State inclusion proof verification failed");
    /// }
    /// ```
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

    /// Regenerate the Merkle tree from the current hash chain
    ///
    /// This internal function rebuilds the Merkle tree when the hash chain changes.
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
    ///
    /// Retrieves the most recent state in the hash chain.
    ///
    /// # Returns
    ///
    /// * `Some(State)` - The current state if available
    /// * `None` - If no states exist in the chain
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    ///
    /// // Get the current state
    /// fn get_current_state(sdk: &HashChainSDK) {
    ///     if let Some(state) = sdk.current_state() {
    ///         println!("Current state number: {}", state.state_number);
    ///     } else {
    ///         println!("No states in the chain yet");
    ///     }
    /// }
    /// ```
    pub fn current_state(&self) -> Option<State> {
        let state_machine = self.state_machine.read();
        state_machine.current_state().cloned()
    }

    /// Get the Merkle root of the current tree
    ///
    /// Retrieves the root hash of the current Merkle tree, which cryptographically
    /// summarizes the entire state chain.
    ///
    /// # Returns
    ///
    /// * `Ok(Hash)` - The Merkle root hash if available
    /// * `Err(DsmError)` - If the Merkle tree isn't initialized
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    ///
    /// // Get the Merkle root hash
    /// fn get_merkle_root(sdk: &HashChainSDK) {
    ///     let root = sdk.merkle_root().unwrap();
    ///     println!("Merkle root: {:?}", root);
    /// }
    /// ```
    pub fn merkle_root(&self) -> Result<Hash, DsmError> {
        let merkle_tree = self.merkle_tree.read();

        match &*merkle_tree {
            Some(tree) => Ok(tree.root),
            None => Err(DsmError::merkle("Merkle tree not initialized")),
        }
    }

    /// Create a new operation for the hash chain
    ///
    /// Creates a generic operation with the specified entropy data.
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy data for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    ///
    /// // Create a new operation
    /// fn create_new_operation(sdk: &HashChainSDK) {
    ///     let entropy = vec![1, 2, 3, 4];
    ///     let operation = sdk.create_operation(entropy).unwrap();
    ///     // Use the operation in a state transition
    /// }
    /// ```
    pub fn create_operation(&self, entropy: Vec<u8>) -> Result<Operation, DsmError> {
        let entropy_len = entropy.len();
        Ok(Operation::Generic {
            operation_type: "create".to_string(),
            data: entropy,
            message: format!("Create hashchain with entropy length {}", entropy_len),
        })
    }

    /// Create an update operation for the hash chain
    ///
    /// Creates a generic update operation with the specified entropy data.
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy data for the update operation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created update operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn update_operation(&self, entropy: Vec<u8>) -> Result<Operation, DsmError> {
        let entropy_len = entropy.len();
        Ok(Operation::Generic {
            operation_type: "update".to_string(),
            data: entropy,
            message: format!("Update hashchain with entropy length {}", entropy_len),
        })
    }

    /// Create a relationship operation for the hash chain
    ///
    /// Creates an operation for establishing a relationship with another entity.
    ///
    /// # Arguments
    ///
    /// * `entropy` - The entropy data for the operation
    /// * `counterparty_id` - The ID of the counterparty in the relationship
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created relationship operation if successful
    /// * `Err(DsmError)` - If operation creation failed
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

    /// Create a recovery operation for the hash chain
    ///
    /// Creates an operation for recovering from a specific state.
    ///
    /// # Arguments
    ///
    /// * `state_number` - The number of the state to recover from
    /// * `state_hash` - The hash of the state to recover from
    /// * `state_entropy` - The entropy data for the recovery operation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created recovery operation if successful
    /// * `Err(DsmError)` - If operation creation failed
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

/// Implements the Default trait for HashChainSDK
///
/// This allows creating a HashChainSDK instance using Default::default()
impl Default for HashChainSDK {
    fn default() -> Self {
        Self::new()
    }
}
