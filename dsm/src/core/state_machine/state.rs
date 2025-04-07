// State implementation based on DSM whitepaper Section 3.1 and 6
// Implements forward-only state evolution with cryptographic binding

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{DeviceInfo, SparseIndex, StateParams};
use sha3::digest::XofReader;
use sha3::{Digest, Sha3_512, Shake256};

/// Represents a cryptographic state in the DSM system
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct State {
    /// State identifier
    pub id: String,

    /// State number in sequence
    pub state_number: u64,

    /// State hash
    pub hash: Vec<u8>,

    /// Previous state hash
    pub prev_state_hash: Vec<u8>,

    /// State entropy
    pub entropy: Vec<u8>,

    /// Encapsulated entropy from quantum-resistant KEM
    pub encapsulated_entropy: Option<Vec<u8>>,

    /// Operation that produced this state
    pub operation: Operation,

    /// Device info
    pub device_info: DeviceInfo,

    /// Forward commitment for future states
    pub forward_commitment: Option<Vec<u8>>,

    /// Whether state matches forward commitment parameters
    pub matches_parameters: bool,

    /// Type of state
    pub state_type: String,

    /// State value
    pub value: Vec<u8>,

    /// Commitment value
    pub commitment: Vec<u8>,

    /// Sparse indexing for efficient traversal
    pub sparse_index: SparseIndex,
}

impl State {
    /// Create a new state
    pub fn new(params: StateParams) -> Self {
        Self {
            id: String::new(),
            state_number: params.state_number,
            hash: Vec::new(),
            prev_state_hash: params.prev_state_hash,
            entropy: params.entropy,
            encapsulated_entropy: params.encapsulated_entropy,
            operation: params.operation,
            device_info: params.device_info,
            // Convert the PreCommitment to Vec<u8> if present
            forward_commitment: params.forward_commitment.map(|_pc| {
                // Serialize the PreCommitment to Vec<u8> - dummy implementation
                let pc_bytes = vec![0u8; 32]; // Placeholder
                pc_bytes
            }),
            matches_parameters: params.matches_parameters,
            state_type: params.state_type,
            value: params.value.into_iter().map(|i| i as u8).collect(),
            commitment: params.commitment.into_iter().map(|i| i as u8).collect(),
            sparse_index: params.sparse_index,
        }
    }

    /// Create a new genesis state
    pub fn new_genesis(entropy: Vec<u8>, device_info: DeviceInfo) -> Self {
        Self {
            id: String::new(),
            state_number: 0,
            hash: Vec::new(),
            prev_state_hash: Vec::new(),
            entropy,
            encapsulated_entropy: None,
            operation: Operation::Genesis,
            device_info,
            forward_commitment: None,
            matches_parameters: false,
            state_type: "genesis".to_string(),
            value: Vec::new(),
            commitment: Vec::new(),
            sparse_index: SparseIndex::new(vec![]),
        }
    }

    /// Compute quantum-resistant hash of the state
    pub fn compute_hash(&self) -> Result<Vec<u8>, DsmError> {
        // First layer: SHA3-512 (quantum resistant)
        let mut sha3_hasher = Sha3_512::new();
        sha3::digest::Update::update(&mut sha3_hasher, &self.state_number.to_le_bytes());
        sha3::digest::Update::update(&mut sha3_hasher, &self.prev_state_hash);
        sha3::digest::Update::update(&mut sha3_hasher, &self.entropy);

        // Add operation bytes
        let operation_bytes = bincode::serialize(&self.operation)
            .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;
        sha3::digest::Update::update(&mut sha3_hasher, &operation_bytes);

        // Add device info
        let device_bytes = bincode::serialize(&self.device_info)
            .map_err(|e| DsmError::serialization("Failed to serialize device info", Some(e)))?;
        sha3::digest::Update::update(&mut sha3_hasher, &device_bytes);

        let sha3_result = sha3_hasher.finalize();

        // Second layer: BLAKE3 for performance
        let mut blake3_hasher = blake3::Hasher::new();
        blake3_hasher.update(&sha3_result);

        // Final layer: SHAKE256 XOF for extra security
        let mut shake = Shake256::default();
        sha3::digest::Update::update(&mut shake, blake3_hasher.finalize().as_bytes());
        let mut final_output = vec![0u8; 32];
        sha3::digest::ExtendableOutput::finalize_xof(shake).read(&mut final_output);

        Ok(final_output)
    }

    /// Hash function for the state
    pub fn hash(&self) -> Result<Vec<u8>, DsmError> {
        self.compute_hash()
    }

    /// Calculate sparse indices for a state
    pub fn calculate_sparse_indices(state_number: u64) -> Result<Vec<u64>, DsmError> {
        if state_number == 0 {
            return Ok(vec![]);
        }

        let mut indices = Vec::new();

        // Always include previous state
        indices.push(state_number - 1);

        // Add exponentially spaced checkpoints
        let mut checkpoint = state_number;
        while checkpoint > 0 {
            checkpoint = checkpoint.saturating_sub(checkpoint.next_power_of_two() / 2);
            if checkpoint > 0 && checkpoint < state_number {
                indices.push(checkpoint);
            }
        }

        // Add genesis state if not already included
        if !indices.contains(&0) {
            indices.push(0);
        }

        Ok(indices)
    }

    /// Validate state integrity using quantum-resistant verification
    ///
    /// Verifies the cryptographic integrity of a state according to whitepaper Section 14
    pub fn validate_state_integrity(state: &State) -> Result<bool, DsmError> {
        // For genesis states, validation is different
        if state.state_number == 0 {
            // Genesis states should have empty prev_state_hash
            if !state.prev_state_hash.is_empty() {
                return Ok(false);
            }

            // Verify hash integrity with quantum-resistant sandwich
            let computed_hash = state.compute_hash()?;
            return Ok(constant_time_eq::constant_time_eq(
                &computed_hash,
                &state.hash,
            ));
        }

        // Non-genesis states must have a non-empty prev_state_hash
        if state.prev_state_hash.is_empty() {
            return Ok(false);
        }

        // Verify hash integrity with quantum-resistant sandwich
        let computed_hash = state.compute_hash()?;
        if !constant_time_eq::constant_time_eq(&computed_hash, &state.hash) {
            return Ok(false);
        }

        // For states with encapsulated entropy, verify it derives correctly
        if let Some(encapsulated) = &state.encapsulated_entropy {
            // Hash encapsulated entropy with SHA3
            let mut sha3 = Sha3_512::new();
            sha3::digest::Update::update(&mut sha3, encapsulated);
            let sha3_result = sha3.finalize();

            // Apply BLAKE3
            let mut blake3_hasher = blake3::Hasher::new();
            blake3_hasher.update(&sha3_result);
            let derived = blake3_hasher.finalize();

            // Compare with state entropy
            if !constant_time_eq::constant_time_eq(derived.as_bytes(), &state.entropy) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify hash chain integrity between two consecutive states
    pub fn verify_hash_chain(prev_state: &State, next_state: &State) -> Result<bool, DsmError> {
        // Verify state numbers are sequential
        if next_state.state_number != prev_state.state_number + 1 {
            return Ok(false);
        }

        // Verify both states individually
        if !Self::validate_state_integrity(prev_state)?
            || !Self::validate_state_integrity(next_state)?
        {
            return Ok(false);
        }

        // Verify hash chain linkage with quantum-resistant comparison
        let prev_hash = prev_state.compute_hash()?;
        Ok(constant_time_eq::constant_time_eq(
            &prev_hash,
            &next_state.prev_state_hash,
        ))
    }
}
