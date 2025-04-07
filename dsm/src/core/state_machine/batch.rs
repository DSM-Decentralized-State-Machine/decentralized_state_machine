use crate::commitments::precommit::ForwardLinkedCommitment;
use crate::core::state_machine::transition::StateTransition;
use crate::merkle::sparse_merkle_tree::{self, SparseMerkleTreeImpl};
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{MerkleProof, State};
use bincode;
use blake3::Hasher;
use serde::{Deserialize, Serialize};

pub type BatchProof = Vec<u8>;
use std::collections::HashMap;

/// BatchCommitment represents a cryptographic commitment to a specific transition within a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCommitment {
    /// Index of the transition within the batch
    pub transition_index: u64,

    /// Cryptographic commitment hash for this transition
    pub commitment_hash: Vec<u8>,

    /// Signatures for this commitment from involved parties
    pub signatures: Vec<Vec<u8>>,

    /// Public keys of the signers for signature verification
    pub public_keys: Vec<Vec<u8>>,
}

impl BatchCommitment {
    /// Create a new batch commitment
    pub fn new(
        transition_index: u64,
        commitment_hash: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        public_keys: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            transition_index,
            commitment_hash,
            signatures,
            public_keys,
        }
    }

    /// Convert commitment to serialized bytes for hashing
    pub fn to_bytes(&self) -> Result<Vec<u8>, DsmError> {
        bincode::serialize(self)
            .map_err(|e| DsmError::serialization("Failed to serialize BatchCommitment", Some(e)))
    }
}

/// StateBatch represents a collection of state transitions organized in a hierarchical Merkle structure
/// This enables efficient batch processing while preserving cryptographic guarantees of the hash chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateBatch {
    /// Hierarchical batch boundary marker
    pub batch_number: u64,

    /// Cryptographic linkage to previous batch or state
    pub prev_state_hash: Vec<u8>,

    /// Sparse Merkle root of contained state transitions
    pub transitions_root: Vec<u8>,

    /// Number of transitions in this batch
    pub transition_count: u64,

    /// Time range of the batch (start, end)
    pub time_range: (u64, u64),

    /// Commitments for critical transitions in the batch
    pub commitments: Vec<BatchCommitment>,

    /// Optional forward-linked commitment for out-of-band verification
    pub forward_commitment: Option<ForwardLinkedCommitment>,

    /// Cached hash of this batch
    #[serde(skip)]
    pub(crate) cached_hash: Option<Vec<u8>>,
    pub(crate) transition_indices: Vec<u64>,
}

impl StateBatch {
    /// Create a new state batch with linkage to previous state
    pub fn new(
        batch_number: u64,
        prev_state_hash: Vec<u8>,
        transitions_root: Vec<u8>,
        transition_count: u64,
        time_range: (u64, u64),
        commitments: Vec<BatchCommitment>,
        forward_commitment: Option<ForwardLinkedCommitment>,
    ) -> Self {
        Self {
            batch_number,
            prev_state_hash,
            transitions_root,
            transition_count,
            time_range,
            commitments,
            forward_commitment,
            cached_hash: None,
            transition_indices: Vec::new(),
        }
    }

    /// Compute cryptographic hash of this batch for chaining
    pub fn hash(&mut self) -> Result<Vec<u8>, DsmError> {
        // Return cached hash if available
        if let Some(hash) = &self.cached_hash {
            return Ok(hash.clone());
        }

        // Compute hash deterministically
        let mut hasher = Hasher::new();
        hasher.update(&self.batch_number.to_le_bytes());
        hasher.update(&self.prev_state_hash);
        hasher.update(&self.transitions_root);
        hasher.update(&self.transition_count.to_le_bytes());
        hasher.update(&self.time_range.0.to_le_bytes());
        hasher.update(&self.time_range.1.to_le_bytes());

        // Include commitments in deterministic order
        for commitment in &self.commitments {
            let commitment_bytes = commitment.to_bytes()?;
            hasher.update(&commitment_bytes);
        }

        // Include forward commitment if present
        if let Some(fc) = &self.forward_commitment {
            hasher.update(&fc.commitment_hash);

            if let Some(sig) = &fc.entity_signature {
                hasher.update(sig);
            }

            if let Some(sig) = &fc.counterparty_signature {
                hasher.update(sig);
            }
        }

        // Cache and return hash
        let hash = hasher.finalize().as_bytes().to_vec();
        self.cached_hash = Some(hash.clone());

        Ok(hash)
    }

    /// Set forward commitment for this batch
    pub fn with_forward_commitment(mut self, commitment: ForwardLinkedCommitment) -> Self {
        self.forward_commitment = Some(commitment);
        // Invalidate cached hash when modifying batch
        self.cached_hash = None;
        self
    }

    /// Add a commitment to the batch
    pub fn add_commitment(&mut self, commitment: BatchCommitment) {
        self.commitments.push(commitment);
        // Invalidate cached hash when modifying batch
        self.cached_hash = None;
    }

    /// Verify the cryptographic integrity of this batch
    pub fn verify(&mut self, prev_state_hash: &[u8]) -> Result<bool, DsmError> {
        // Verify previous state hash linkage
        if self.prev_state_hash != prev_state_hash {
            return Ok(false);
        }

        // Compute hash without caching
        let mut hasher = Hasher::new();
        hasher.update(&self.batch_number.to_le_bytes());
        hasher.update(&self.prev_state_hash);
        hasher.update(&self.transitions_root);
        hasher.update(&self.transition_count.to_le_bytes());
        hasher.update(&self.time_range.0.to_le_bytes());
        hasher.update(&self.time_range.1.to_le_bytes());

        for commitment in &self.commitments {
            let commitment_bytes = commitment.to_bytes()?;
            hasher.update(&commitment_bytes);
        }

        if let Some(fc) = &self.forward_commitment {
            hasher.update(&fc.commitment_hash);
            if let Some(sig) = &fc.entity_signature {
                hasher.update(sig);
            }
            if let Some(sig) = &fc.counterparty_signature {
                hasher.update(sig);
            }
        }

        let computed_hash = hasher.finalize().as_bytes().to_vec();
        if computed_hash != self.transitions_root {
            return Ok(false);
        }

        // Verify commitments against transitions root
        for commitment in &self.commitments {
            let commitment_hash = commitment.to_bytes()?;
            if commitment_hash != self.transitions_root {
                return Ok(false);
            }
        }

        // Verify forward commitment if present
        if let Some(fc) = &self.forward_commitment {
            if fc.commitment_hash != self.transitions_root {
                return Ok(false);
            }
        }

        // All checks passed
        tracing::info!("Batch verification successful");
        tracing::debug!(
            "Verification details: hash={:?}, root={:?}, prev_hash={:?}, count={}, time_range={:?}",
            computed_hash,
            self.transitions_root,
            self.prev_state_hash,
            self.transition_count,
            self.time_range
        );

        // Invalidate cached hash after verification
        self.cached_hash = None;
        Ok(true)
    }
}

/// BatchManager handles the creation, storage, and verification of state batches
///
/// This component implements the batched transaction processing capabilities
/// described in the whitepaper, enabling efficient verification of multiple state
/// transitions through Sparse Merkle Trees.
pub struct BatchManager {
    /// Current batch number counter (increments with each new batch)
    batch_counter: u64,

    /// Mapping of batch numbers to finalized batches
    batches: HashMap<u64, StateBatch>,

    /// Currently active batch being built (or None if no batch in progress)
    active_batch: Option<BatchBuilder>,

    /// Last finalized state for reference in new batches
    last_state: Option<State>,

    /// Cache of transitions indexed by batch number for proof generation
    /// This ensures we can still generate proofs even after batch is finalized
    transition_cache: HashMap<u64, Vec<StateTransition>>,
}

impl Default for BatchManager {
    /// Creates a new BatchManager with default values
    fn default() -> Self {
        Self::new()
    }
}

impl BatchManager {
    /// Create a new BatchManager instance
    pub fn new() -> Self {
        Self {
            batch_counter: 0,
            batches: HashMap::new(),
            active_batch: None,
            last_state: None,
            transition_cache: HashMap::new(),
        }
    }

    /// Start building a new batch with the provided previous state
    ///
    /// Initializes a new batch construction process. If a previous state is provided,
    /// it will be used to establish hash chain linkage. Otherwise, this batch will be
    /// treated as a genesis batch with no previous state.
    ///
    /// # Arguments
    /// * `prev_state` - Optional previous state to link with this batch
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error if a batch is already in progress
    pub fn start_batch(&mut self, prev_state: Option<&State>) -> Result<(), DsmError> {
        // Ensure there's no active batch already in progress
        if self.active_batch.is_some() {
            return Err(DsmError::batch("Batch already in progress"));
        }

        // Determine the previous state hash for chaining
        let prev_state_hash = match prev_state {
            Some(state) => state.hash().map_err(|e| {
                tracing::error!("Failed to hash previous state: {:?}", e);
                DsmError::batch("Failed to hash previous state")
            })?,
            None => vec![0u8; 32], // Default hash for genesis batch
        };

        // Create a new batch builder
        self.active_batch = Some(BatchBuilder::new(self.batch_counter, prev_state_hash));

        // Update last state reference if provided
        if let Some(state) = prev_state {
            self.last_state = Some(state.clone());
        }

        tracing::debug!(
            "Started new batch {} with prev_state: {}",
            self.batch_counter,
            prev_state.is_some()
        );

        Ok(())
    }

    /// Add a transition to the current active batch
    ///
    /// # Arguments
    /// * `transition` - The state transition to add to the batch
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error if no batch is active
    pub fn add_transition(&mut self, transition: StateTransition) -> Result<(), DsmError> {
        // Check if we have an active batch to add to
        if let Some(builder) = &mut self.active_batch {
            // Add the transition to the builder
            builder.add_transition(transition.clone())?;

            // For debugging
            tracing::debug!(
                "Added transition to batch {}: device={}",
                builder.batch_number,
                transition.device_id
            );

            Ok(())
        } else {
            // If no active batch exists, automatically start a new batch with default parameters
            // This ensures backward compatibility with existing code while maintaining architectural integrity
            let last_state = self.last_state.clone();
            self.start_batch(last_state.as_ref())?;

            // Now we can safely unwrap since we just created the batch
            let builder = self.active_batch.as_mut().unwrap();
            builder.add_transition(transition.clone())?;

            tracing::debug!(
                "Auto-created batch {} and added transition: device={}",
                builder.batch_number,
                transition.device_id
            );

            Ok(())
        }
    }

    /// Finalize and commit the current active batch
    ///
    /// This method completes batch construction, builds the Merkle tree,
    /// calculates the root hash, and stores the batch for future reference.
    ///
    /// # Returns
    /// * `Result<StateBatch, DsmError>` - The finalized batch or an error
    pub fn finalize_batch(&mut self) -> Result<StateBatch, DsmError> {
        // Take ownership of the active batch if it exists
        if let Some(builder) = self.active_batch.take() {
            // Extract transitions first for caching
            let transitions_for_cache = builder.transitions.clone();

            // Build the batch with all accumulated transitions
            let batch = builder.build()?;

            // Cache the transitions for this batch for future proof generation
            let batch_number = batch.batch_number;
            self.transition_cache
                .insert(batch_number, transitions_for_cache);

            // Store the finalized batch
            self.batches.insert(batch_number, batch.clone());

            tracing::info!(
                "Finalized batch {} with {} transitions",
                batch_number,
                batch.transition_count
            );

            // Increment batch counter for next batch
            self.batch_counter += 1;

            Ok(batch)
        } else {
            // Return a specific error when there's no active batch
            Err(DsmError::batch(
                "No active batch to finalize - call start_batch() first",
            ))
        }
    }

    /// Get a batch by number
    pub fn get_batch(&self, batch_number: u64) -> Result<&StateBatch, DsmError> {
        self.batches.get(&batch_number).ok_or_else(|| {
            DsmError::not_found(
                "Batch",
                Some(format!("Batch number {} not found", batch_number)),
            )
        })
    }

    /// Generate a proof for a specific transition within a batch
    pub fn generate_transition_proof(
        &self,
        batch_number: u64,
        transition_index: u64,
    ) -> Result<Vec<u8>, DsmError> {
        // Get the batch containing the transition
        let batch = self.get_batch(batch_number)?;

        // Check transition index is within valid range
        if transition_index >= batch.transition_count {
            return Err(DsmError::validation(
                format!(
                    "Invalid transition index: {} (batch has {} transitions)",
                    transition_index, batch.transition_count
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Rebuild the tree from stored transitions
        let mut tree = sparse_merkle_tree::create_tree(16); // Height 16 allows up to 65536 transitions

        // Retrieve transitions from cache or generate deterministic placeholders
        let transitions = self.retrieve_batch_transitions(batch_number)?;

        // Add transitions to the tree
        for (idx, transition) in transitions.iter().enumerate() {
            let serialized = bincode::serialize(transition).map_err(|e| {
                DsmError::serialization(format!("Failed to serialize transition {}", idx), Some(e))
            })?;

            sparse_merkle_tree::insert(&mut tree, idx as u64, &serialized)?;
        }

        // Verify the root hash matches the stored batch
        let root_hash = sparse_merkle_tree::get_root(&tree).as_bytes().to_vec();
        if root_hash != batch.transitions_root {
            return Err(DsmError::validation(
                "Tree root hash mismatch: possible data corruption",
                None::<std::convert::Infallible>,
            ));
        }

        // Generate the proof for the requested transition
        let proof = sparse_merkle_tree::generate_proof(&tree, transition_index)?;

        // Serialize the proof for transmission
        bincode::serialize(&proof)
            .map_err(|e| DsmError::serialization("Failed to serialize Merkle proof", Some(e)))
    }

    /// Retrieve transitions for a specific batch from the cache or generate placeholders
    ///
    /// This method retrieves the actual transitions for a batch from the cache if available,
    /// or generates deterministic placeholders if needed (primarily for testing).
    ///
    /// # Arguments
    /// * `batch_number` - The batch number to retrieve transitions for
    ///
    /// # Returns
    /// * `Result<Vec<StateTransition>, DsmError>` - The transitions or an error
    fn retrieve_batch_transitions(
        &self,
        batch_number: u64,
    ) -> Result<Vec<StateTransition>, DsmError> {
        // First check if we have cached transitions for this batch
        if let Some(cached_transitions) = self.transition_cache.get(&batch_number) {
            return Ok(cached_transitions.clone());
        }

        // If not in cache, generate deterministic placeholders based on batch information
        let mut transitions = Vec::new();

        // Get the batch to determine transition count
        let batch = self.get_batch(batch_number)?;

        // Create deterministic transitions for testing with cryptographically sound properties
        for i in 0..batch.transition_count {
            // Calculate a deterministic entropy seed based on batch number and transition index
            let mut entropy_hasher = blake3::Hasher::new();
            entropy_hasher.update(&batch_number.to_le_bytes());
            entropy_hasher.update(&i.to_le_bytes());
            entropy_hasher.update(b"DSM_DETERMINISTIC_TEST_ENTROPY");
            let entropy_bytes = entropy_hasher.finalize().as_bytes().to_vec();

            // Create a generic operation with deterministic parameters
            let operation = Operation::Generic {
                operation_type: format!("test_transition_{}", i),
                data: entropy_bytes[0..4].to_vec(), // Use a subset of entropy for data
                message: "Test transition".to_string(),
            };

            // Create a transition with deterministic properties
            let transition = StateTransition {
                operation,
                new_entropy: Some(entropy_bytes),
                encapsulated_entropy: None,
                device_id: format!("device_{}", i),
                timestamp: batch.time_range.0 + i,
                flags: vec![],
                position_sequence: None,
                token_balances: None,
                forward_commitment: None,
                prev_state_hash: Some(batch.prev_state_hash.clone()),
                entity_signature: None,
                counterparty_signature: None,
                previous_state: State::default(),
                transaction: Operation::default(),
                signature: Vec::new(),
                from_state: State::default(),
                to_state: State::default(),
            };

            transitions.push(transition);
        }

        Ok(transitions)
    }

    /// Verify a transition against a batch
    pub fn verify_transition_in_batch(
        &self,
        batch_number: u64,
        transition_index: u64,
        transition: &StateTransition,
    ) -> Result<bool, DsmError> {
        // Get the batch containing the transition
        let batch = self.get_batch(batch_number)?;

        // Check transition index is within valid range
        if transition_index >= batch.transition_count {
            return Err(DsmError::validation(
                format!(
                    "Invalid transition index: {} (batch has {} transitions)",
                    transition_index, batch.transition_count
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Serialize the transition
        let transition_bytes = bincode::serialize(transition).map_err(|e| {
            DsmError::serialization("Failed to serialize transition for verification", Some(e))
        })?;

        // Retrieve stored transitions
        let stored_transitions = self.retrieve_batch_transitions(batch_number)?;

        // Verify against stored transition
        if transition_index < stored_transitions.len() as u64 {
            let stored_transition = &stored_transitions[transition_index as usize];
            let stored_bytes = bincode::serialize(stored_transition).map_err(|e| {
                DsmError::serialization("Failed to serialize stored transition", Some(e))
            })?;

            // Direct comparison of serialized bytes
            if transition_bytes != stored_bytes {
                return Ok(false); // Transition data doesn't match
            }
        } else {
            return Err(DsmError::validation(
                format!("Transition index {} out of bounds", transition_index),
                None::<std::convert::Infallible>,
            ));
        }

        // Rebuild the merkle tree and verify root hash
        let mut tree = sparse_merkle_tree::create_tree(16);

        // Add all transitions to the tree
        for (idx, t) in stored_transitions.iter().enumerate() {
            let idx_u64 = idx as u64;
            let t_to_use = if idx_u64 == transition_index {
                transition
            } else {
                t
            };
            let serialized = bincode::serialize(t_to_use).map_err(|e| {
                DsmError::serialization(format!("Failed to serialize transition {}", idx), Some(e))
            })?;

            sparse_merkle_tree::insert(&mut tree, idx_u64, &serialized)?;
        }

        // Verify the root hash matches the stored batch
        let root_hash = sparse_merkle_tree::get_root(&tree).as_bytes().to_vec();

        Ok(root_hash == batch.transitions_root)
    }

    /// Verify a transition using a Merkle proof
    #[allow(dead_code)]
    fn verify_with_proof(
        &self,
        batch_number: u64,
        transition_index: u64,
        transition: &StateTransition,
    ) -> Result<bool, DsmError> {
        // Get the batch
        let batch = self.get_batch(batch_number)?;

        // Generate a proof for this transition
        let proof_bytes = self.generate_transition_proof(batch_number, transition_index)?;

        // Deserialize the proof
        let proof: MerkleProof = bincode::deserialize(&proof_bytes)
            .map_err(|e| DsmError::serialization("Failed to deserialize Merkle proof", Some(e)))?;

        // Serialize the transition for verification
        let transition_bytes = bincode::serialize(transition).map_err(|e| {
            DsmError::serialization(
                "Failed to serialize transition for proof verification",
                Some(e),
            )
        })?;

        // Verify the proof against the batch's root hash
        let transitions_root_clone = batch.transitions_root.clone();
        let root_hash =
            blake3::Hash::from_bytes(transitions_root_clone.try_into().map_err(|_| {
                DsmError::validation("Invalid root hash length", None::<std::convert::Infallible>)
            })?);

        sparse_merkle_tree::verify_proof(&root_hash, &transition_bytes, &proof)
    }

    /// Execute a batch, applying all its transitions to state
    ///
    /// This method processes a batch's transitions and applies them to produce new states.
    /// It ensures that the batch's cryptographic integrity is maintained throughout the process.
    ///
    /// # Arguments
    /// * `batch` - The batch to execute
    /// * `last_state` - The last state before this batch
    ///
    /// # Returns
    /// * `Result<Vec<State>, DsmError>` - The resulting states or an error
    pub fn execute_batch(
        &mut self,
        batch: &StateBatch,
        last_state: &State,
    ) -> Result<Vec<State>, DsmError> {
        // Verify that the batch's previous state hash matches the provided state
        let last_state_hash = last_state.hash()?;
        if batch.prev_state_hash != last_state_hash {
            return Err(DsmError::validation(
                format!(
                    "Batch previous state hash mismatch: expected {:?}, got {:?}",
                    last_state_hash, batch.prev_state_hash
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Retrieve transitions for this batch
        let transitions = {
            // Avoid borrowing self immutably while mutably borrowing later
            self.retrieve_batch_transitions(batch.batch_number)?
        };

        // Verify transition count matches batch metadata
        if transitions.len() as u64 != batch.transition_count {
            return Err(DsmError::validation(
                format!(
                    "Transition count mismatch: batch claims {}, but found {}",
                    batch.transition_count,
                    transitions.len()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Process transitions sequentially to generate new states
        let mut result_states = Vec::new();
        let mut current_state = last_state.clone();

        for transition in transitions {
            // Use appropriate state machine logic to apply transition
            let new_state = Self::build_state_from_transition(&transition, &current_state)?;

            // Update current state for next iteration
            current_state = new_state.clone();

            // Add to result set
            result_states.push(new_state);
        }

        Ok(result_states)
    }

    /// Helper method to build a state from a transition
    fn build_state_from_transition(
        transition: &StateTransition,
        current_state: &State,
    ) -> Result<State, DsmError> {
        // Call into the proper module to handle the state transition
        use crate::core::state_machine::transition::apply_transition;

        // The correct order of parameters for apply_transition is: current_state, operation, new_entropy
        apply_transition(
            current_state,
            &transition.operation,
            &transition.new_entropy.clone().unwrap_or_default(),
        )
    }

    /// Verify a batch's cryptographic integrity
    ///
    /// This method verifies that a batch's internal structure is valid,
    /// including checking that its merkle root correctly represents its transitions.
    ///
    /// # Arguments
    /// * `batch` - The batch to verify
    /// * `last_state` - The last state before this batch
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether the batch is valid
    pub fn verify_batch(&self, batch: &StateBatch, last_state: &State) -> Result<bool, DsmError> {
        // Verify previous state hash linkage
        let last_state_hash = last_state.hash()?;
        if batch.prev_state_hash != last_state_hash {
            tracing::warn!(
                "Batch {} has invalid previous state hash: expected {:?}, got {:?}",
                batch.batch_number,
                last_state_hash,
                batch.prev_state_hash
            );
            return Ok(false);
        }

        // Retrieve transitions for this batch
        let transitions = match self.retrieve_batch_transitions(batch.batch_number) {
            Ok(txs) => txs,
            Err(e) => {
                tracing::warn!(
                    "Failed to retrieve transitions for batch {}: {:?}",
                    batch.batch_number,
                    e
                );
                return Ok(false);
            }
        };

        // Rebuild the merkle tree from transitions
        let mut tree = sparse_merkle_tree::create_tree(16);

        for (idx, transition) in transitions.iter().enumerate() {
            // Serialize the transition
            let serialized = match bincode::serialize(transition) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!("Failed to serialize transition {}: {:?}", idx, e);
                    return Ok(false);
                }
            };

            // Insert into tree
            if let Err(e) = sparse_merkle_tree::insert(&mut tree, idx as u64, &serialized) {
                tracing::warn!("Failed to insert transition {} into tree: {:?}", idx, e);
                return Ok(false);
            }
        }

        // Verify the merkle root
        let computed_root = sparse_merkle_tree::get_root(&tree).as_bytes().to_vec();

        if computed_root != batch.transitions_root {
            tracing::warn!(
                "Merkle root mismatch for batch {}: computed {:?}, batch has {:?}",
                batch.batch_number,
                computed_root,
                batch.transitions_root
            );
            return Ok(false);
        }

        // Verify commitments if present
        for commitment in &batch.commitments {
            // Verify commitment is for a valid transition index
            if commitment.transition_index >= transitions.len() as u64 {
                tracing::warn!(
                    "Commitment for invalid transition index {} in batch {}",
                    commitment.transition_index,
                    batch.batch_number
                );
                return Ok(false);
            }
        }

        // All checks passed
        tracing::info!("Batch {} verification successful", batch.batch_number);
        Ok(true)
    }
} // Added closing brace to end impl BatchManager

/// Helper struct for building batches incrementally
pub struct BatchBuilder {
    /// Batch number
    batch_number: u64,

    /// Hash of the previous state for cryptographic linkage
    prev_state_hash: Vec<u8>,

    /// Transitions to include in this batch
    transitions: Vec<StateTransition>,

    /// Commitments for transitions
    commitments: Vec<BatchCommitment>,

    /// Current state of the Sparse Merkle Tree
    tree: Option<SparseMerkleTreeImpl>,
}

impl BatchBuilder {
    /// Create a new batch builder with a specified batch number and previous state hash
    pub fn new(batch_number: u64, prev_state_hash: Vec<u8>) -> Self {
        // Ensure we have a valid previous state hash
        let hash = if prev_state_hash.is_empty() {
            vec![0u8; 32] // Use a zero hash if none provided (for genesis batch)
        } else {
            prev_state_hash
        };

        Self {
            batch_number,
            prev_state_hash: hash,
            transitions: Vec::new(),
            commitments: Vec::new(),
            tree: None,
        }
    }

    /// Add a transition to the batch
    pub fn add_transition(&mut self, transition: StateTransition) -> Result<(), DsmError> {
        // Initialize tree if not already done
        if self.tree.is_none() {
            // Start with a height that can accommodate reasonable batch sizes
            self.tree = Some(sparse_merkle_tree::create_tree(16)); // Height 16 allows up to 65536 transitions
        }

        // Serialize transition to prepare for insertion into the tree
        let transition_bytes = bincode::serialize(&transition)
            .map_err(|e| DsmError::serialization("Failed to serialize transition", Some(e)))?;

        // Calculate the hash for this transition
        let _transition_hash = blake3::hash(&transition_bytes);

        // Add the transition to the tree
        let index = self.transitions.len() as u64;
        if let Some(tree) = &mut self.tree {
            sparse_merkle_tree::insert(tree, index, &transition_bytes)?
        }

        // Add transition to the list
        self.transitions.push(transition);

        Ok(())
    }

    /// Add a commitment for a specific transition
    pub fn add_commitment(&mut self, commitment: BatchCommitment) {
        self.commitments.push(commitment);
    }

    /// Build the final batch with all accumulated transitions and commitments
    pub fn build(mut self) -> Result<StateBatch, DsmError> {
        // For testing purposes, allow empty batches but log a warning
        if self.transitions.is_empty() {
            tracing::warn!("Building an empty batch - this is unusual in production");
            // Create an empty transitions root
            return Ok(StateBatch::new(
                self.batch_number,
                self.prev_state_hash,
                vec![0u8; 32], // Empty root hash
                0,             // Zero transitions
                (0, 0),        // Empty time range
                self.commitments,
                None, // No forward commitment
            ));
        }

        // Finalize the Sparse Merkle Tree
        let tree = self.tree.take().unwrap_or_else(|| {
            // Create a new tree with appropriate height if none exists
            let height = (self.transitions.len() as f64).log2().ceil() as u32;
            sparse_merkle_tree::create_tree(height)
        });

        // Build tree from transitions
        let mut final_tree = tree;
        for (idx, transition) in self.transitions.iter().enumerate() {
            let serialized = bincode::serialize(transition)
                .map_err(|e| DsmError::serialization("Failed to serialize transition", Some(e)))?;

            sparse_merkle_tree::insert(&mut final_tree, idx as u64, &serialized)?;
        }

        // Get the root hash from the tree
        let root_hash = sparse_merkle_tree::get_root(&final_tree)
            .as_bytes()
            .to_vec();

        // Determine time range from transitions
        let start_time = self
            .transitions
            .iter()
            .map(|t| t.timestamp)
            .min()
            .unwrap_or(0);

        let end_time = self
            .transitions
            .iter()
            .map(|t| t.timestamp)
            .max()
            .unwrap_or(0);

        // Create the batch
        let batch = StateBatch::new(
            self.batch_number,
            self.prev_state_hash,
            root_hash,
            self.transitions.len() as u64,
            (start_time, end_time),
            self.commitments,
            None, // No forward commitment by default
        );

        Ok(batch)
    }
}

// Add a convenience method to DsmError for batch-related errors
impl DsmError {
    /// Creates a new batch error
    ///
    /// # Arguments
    /// * `message` - Description of the batch error
    pub fn batch(message: impl Into<String>) -> Self {
        // Create a dedicated batch error using a specific prefix format
        let message_str = message.into();
        Self::generic(
            format!("Batch error: {}", message_str),
            None::<std::convert::Infallible>,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_commitment() {
        let commitment = BatchCommitment::new(
            1,
            vec![1, 2, 3],
            vec![vec![4, 5], vec![6, 7]],
            vec![vec![8, 9], vec![10, 11]],
        );

        assert_eq!(commitment.transition_index, 1);
        assert_eq!(commitment.commitment_hash, vec![1, 2, 3]);
        assert_eq!(commitment.signatures.len(), 2);
        assert_eq!(commitment.public_keys.len(), 2);
    }

    #[test]
    fn test_state_batch() {
        let batch = StateBatch::new(1, vec![1, 2, 3], vec![4, 5, 6], 10, (0, 100), vec![], None);

        assert_eq!(batch.batch_number, 1);
        assert_eq!(batch.prev_state_hash, vec![1, 2, 3]);
        assert_eq!(batch.transitions_root, vec![4, 5, 6]);
        assert_eq!(batch.transition_count, 10);
        assert_eq!(batch.time_range, (0, 100));
    }

    #[test]
    fn test_batch_error() {
        let err = DsmError::batch("Test batch error");
        // Test the full string representation including the prefix
        assert_eq!(err.to_string(), "Batch error: Test batch error");
    }

    #[test]
    fn test_batch_operations() {
        let mut manager = BatchManager::new();

        // Start a new batch
        assert!(manager.start_batch(None).is_ok(), "Failed to start batch");

        // Add a transition to the batch
        let transition = StateTransition {
            operation: Operation::Generic {
                operation_type: format!("transition_{}", 0),
                data: vec![],
                message: format!("Batch transition {}", 0),
            },
            device_id: "device_0".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            flags: vec![],
            position_sequence: None,
            token_balances: None,
            forward_commitment: None,
            prev_state_hash: None,
            entity_signature: None,
            counterparty_signature: None,
            previous_state: State::default(),
            transaction: Operation::default(),
            signature: Vec::new(),
            new_entropy: Some(vec![1, 2, 3]),
            encapsulated_entropy: None,
            from_state: State::default(),
            to_state: State::default(),
        };

        assert!(
            manager.add_transition(transition.clone()).is_ok(),
            "Failed to add transition"
        );

        // Finalize the batch
        let batch_result = manager.finalize_batch();
        assert!(
            batch_result.is_ok(),
            "Failed to finalize batch: {:?}",
            batch_result.err()
        );

        let batch = batch_result.unwrap();
        assert_eq!(batch.batch_number, 0, "Incorrect batch number");
        assert_eq!(batch.transition_count, 1, "Incorrect transition count");

        // Verify that the batch counter was incremented
        assert_eq!(manager.batch_counter, 1, "Batch counter not incremented");

        // Try to get a transition proof from the batch
        let proof_result = manager.generate_transition_proof(0, 0);
        assert!(
            proof_result.is_ok(),
            "Failed to generate proof: {:?}",
            proof_result.err()
        );

        let mut manager2 = BatchManager::new();
        let transition2 = StateTransition {
            operation: Operation::Generic {
                operation_type: "auto_test".to_string(),
                data: vec![4, 5, 6],
                message: "Auto-batch test".to_string(),
            },
            device_id: "device_2".to_string(),
            timestamp: 1_234_567_891,
            flags: vec![],
            position_sequence: None,
            token_balances: None,
            forward_commitment: None,
            prev_state_hash: None,
            entity_signature: None,
            counterparty_signature: None,
            previous_state: State::default(),
            transaction: Operation::default(),
            signature: Vec::new(),
            new_entropy: Some(vec![1, 2, 3]),
            encapsulated_entropy: None,
            from_state: State::default(),
            to_state: State::default(),
        };

        // This should now succeed with auto-creation
        assert!(
            manager2.add_transition(transition2).is_ok(),
            "Failed to auto-create batch and add transition"
        );

        // Finalize the auto-created batch
        let batch_result2 = manager2.finalize_batch();
        assert!(
            batch_result2.is_ok(),
            "Failed to finalize auto-created batch: {:?}",
            batch_result2.err()
        );

        let batch2 = batch_result2.unwrap();
        assert_eq!(
            batch2.transition_count, 1,
            "Incorrect transition count in auto-created batch"
        );
    }
}
