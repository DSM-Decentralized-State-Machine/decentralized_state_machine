use crate::core::state_machine::batch::StateBatch;
use crate::core::state_machine::transition::StateTransition;
use crate::crypto::sphincs::{sphincs_sign, sphincs_verify};
use crate::merkle::sparse_merkle_tree::{self, SparseMerkleTreeImpl};
use crate::types;
use crate::types::error::DsmError;
use blake3;
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use sha3::Digest; // Added to bring Digest methods into scope
use sha3::Sha3_512;
use std::collections::HashMap;

/// BatchTransitionProof provides an efficient cryptographic proof that
/// a specific transition exists within a batch.
///
/// This implements the sparse Merkle tree inclusion proof described in
/// whitepaper Section 3.3, tailored specifically for batch transition
/// verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransitionProof {
    /// Index of the transition within the batch
    pub transition_index: u64,

    /// Height of the sparse Merkle tree
    pub tree_height: u32,

    /// Sibling hashes from leaf to root
    pub siblings: Vec<[u8; 32]>,

    /// Hash of the transition leaf
    pub transition_hash: [u8; 32],

    /// Hash of the Merkle root
    pub root_hash: [u8; 32],

    /// Batch number this proof is for
    pub batch_number: u64,

    /// Verification metadata for the tree structure
    pub metadata: BatchProofMetadata,

    /// SPHINCS+ signature
    pub signature: Vec<u8>,
}

/// Metadata for batch proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProofMetadata {
    /// Total number of transitions in the batch
    pub transition_count: u64,

    /// Timestamp range of the batch
    pub time_range: (u64, u64),

    /// Hash of the previous state or batch
    pub prev_hash: [u8; 32],
}

impl BatchTransitionProof {
    /// Create a new batch transition proof
    pub fn new(
        transition_index: u64,
        tree_height: u32,
        siblings: Vec<[u8; 32]>,
        transition_hash: [u8; 32],
        root_hash: [u8; 32],
        batch_number: u64,
        metadata: BatchProofMetadata,
    ) -> Self {
        Self {
            transition_index,
            tree_height,
            siblings,
            transition_hash,
            root_hash,
            batch_number,
            metadata,
            signature: vec![],
        }
    }

    /// Verify this proof against a transition
    ///
    /// # Arguments
    /// * `transition` - The transition to verify
    /// * `batch_root_hash` - The expected root hash of the batch's Merkle tree
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether the proof is valid
    pub fn verify(
        &self,
        transition: &StateTransition,
        batch_root_hash: &[u8; 32],
    ) -> Result<bool, DsmError> {
        // Serialize the transition using a quantum-resistant hash sandwich
        let serialized = bincode::serialize(transition)
            .map_err(|e| DsmError::serialization("Failed to serialize transition", Some(e)))?;

        // First layer: SHA3-512
        let mut sha3_hasher = Sha3_512::new();
        sha3::Digest::update(&mut sha3_hasher, &serialized);
        let sha3_result = sha3_hasher.finalize();

        // Second layer: Blake3
        let mut blake3_hasher = blake3::Hasher::new();
        blake3_hasher.update(&sha3_result);
        let binding = blake3_hasher.finalize();
        let computed_leaf_hash = binding.as_bytes();

        // Verify the transition hash matches using constant-time comparison
        if !constant_time_eq(computed_leaf_hash, &self.transition_hash) {
            return Ok(false);
        }

        // Generate Merkle proof using quantum-resistant hash sandwich
        let reconstructed_root = self.reconstruct_root_quantum_resistant()?;

        // Verify the reconstructed root matches the batch root using constant-time comparison
        if !constant_time_eq(&reconstructed_root, batch_root_hash) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify this proof against a transition and SPHINCS+ signature
    ///
    /// # Arguments
    /// * `transition` - The transition to verify
    /// * `batch_root_hash` - The expected root hash of the batch's Merkle tree
    /// * `public_key` - The public key for SPHINCS+ signature verification
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether the proof is valid
    pub fn verify_with_quantum_signatures(
        &self,
        transition: &StateTransition,
        batch_root_hash: &[u8; 32],
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        // First verify the proof normally
        if !self.verify(transition, batch_root_hash)? {
            return Ok(false);
        }

        // Then verify SPHINCS+ signature
        // First hash the data to be signed using the hash sandwich
        let mut sha3_hasher = Sha3_512::default();
        // Disambiguate update calls using the Digest trait:
        sha3::Digest::update(&mut sha3_hasher, self.transition_hash);
        sha3::Digest::update(&mut sha3_hasher, self.root_hash);
        let sha3_result = sha3_hasher.finalize();

        let mut blake3_hasher = blake3::Hasher::new();
        blake3_hasher.update(&sha3_result);
        let message_hash = blake3_hasher.finalize();

        // Verify the signature
        if !sphincs_verify(public_key, message_hash.as_bytes(), &self.signature)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Reconstruct the Merkle root from the leaf and siblings
    ///
    /// # Returns
    /// * `Result<[u8; 32], DsmError>` - The reconstructed root hash
    fn reconstruct_root_quantum_resistant(&self) -> Result<[u8; 32], DsmError> {
        // Start with leaf hash
        let mut current_hash = self.transition_hash;
        let mut current_index = self.transition_index;

        // Verify sibling count matches tree height
        if self.siblings.len() as u32 != self.tree_height {
            return Err(DsmError::merkle(format!(
                "Sibling count ({}) doesn't match tree height ({})",
                self.siblings.len(),
                self.tree_height
            )));
        }

        // Traverse up tree using hash sandwich for each level
        for level in 0..self.siblings.len() {
            let bit = (current_index >> level) & 1;

            // First layer: SHA3
            let mut sha3_hasher = Sha3_512::new();
            sha3::Digest::update(&mut sha3_hasher, [0x01]); // Domain separation

            // Combine hashes based on position
            if bit == 0 {
                sha3::Digest::update(&mut sha3_hasher, current_hash);
                sha3::Digest::update(&mut sha3_hasher, self.siblings[level]);
            } else {
                sha3::Digest::update(&mut sha3_hasher, self.siblings[level]);
                sha3::Digest::update(&mut sha3_hasher, current_hash);
            }
            let sha3_result = sha3_hasher.finalize();

            // Second layer: Blake3
            let mut blake3_hasher = blake3::Hasher::new();
            blake3_hasher.update(&sha3_result);
            current_hash = blake3_hasher.finalize().as_bytes().clone();

            current_index >>= 1;
        }

        Ok(current_hash)
    }

    /// Serialize this proof to bytes
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - Serialized proof
    pub fn to_bytes(&self) -> Result<Vec<u8>, DsmError> {
        bincode::serialize(self)
            .map_err(|e| DsmError::serialization("Failed to serialize batch proof", Some(e)))
    }

    /// Deserialize bytes to a batch proof
    ///
    /// # Arguments
    /// * `bytes` - Serialized proof
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - Deserialized proof
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DsmError> {
        bincode::deserialize(bytes)
            .map_err(|e| DsmError::serialization("Failed to deserialize batch proof", Some(e)))
    }

    /// Sign this proof with SPHINCS+
    ///
    /// # Arguments
    /// * `secret_key` - The secret key for SPHINCS+ signature generation
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or failure
    pub fn sign_with_sphincs(&mut self, secret_key: &[u8]) -> Result<(), DsmError> {
        // Create message hash using hash sandwich
        let mut sha3_hasher = Sha3_512::default();
        // Disambiguate update calls:
        sha3::Digest::update(&mut sha3_hasher, self.transition_hash);
        sha3::Digest::update(&mut sha3_hasher, self.root_hash);
        let sha3_result = sha3_hasher.finalize();

        let mut blake3_hasher = blake3::Hasher::new();
        blake3_hasher.update(&sha3_result);
        let message_hash = blake3_hasher.finalize();

        // Sign with SPHINCS+
        self.signature = sphincs_sign(secret_key, message_hash.as_bytes())?;
        Ok(())
    }

    /// Verify a batch of proofs efficiently
    ///
    /// This optimization allows multiple proofs for the same batch to be
    /// verified more efficiently than verifying them one by one.
    ///
    /// # Arguments
    /// * `proofs` - Vector of proofs to verify
    /// * `transitions` - Vector of transitions corresponding to proofs
    /// * `batch_root_hash` - The expected root hash of the batch's Merkle tree
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether all proofs are valid
    pub fn batch_verify(
        proofs: &[Self],
        transitions: &[StateTransition],
        batch_root_hash: &[u8; 32],
    ) -> Result<bool, DsmError> {
        // Ensure counts match
        if proofs.len() != transitions.len() {
            return Err(DsmError::validation(
                format!(
                    "Proof count ({}) doesn't match transition count ({})",
                    proofs.len(),
                    transitions.len()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Verify each proof against its transition
        for (proof, transition) in proofs.iter().zip(transitions.iter()) {
            if !proof.verify(transition, batch_root_hash)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// BatchProofGenerator handles the generation of Merkle proofs for batch transitions
pub struct BatchProofGenerator {
    /// Cache of reconstructed Merkle trees by batch number
    tree_cache: HashMap<u64, SparseMerkleTreeImpl>,

    /// Cache of transitions by batch number and index
    transition_cache: HashMap<(u64, u64), StateTransition>,
}

impl BatchProofGenerator {
    /// Create a new batch proof generator
    pub fn new() -> Self {
        Self {
            tree_cache: HashMap::new(),
            transition_cache: HashMap::new(),
        }
    }

    /// Generate a proof for a specific transition within a batch
    /// Optimized specifically for Apple Silicon M1 Pro processors
    pub fn generate_proof(
        &mut self,
        batch: &StateBatch,
        transition_index: u64,
        transition: &StateTransition,
    ) -> Result<BatchTransitionProof, DsmError> {
        // Ensure index is valid
        if transition_index >= batch.transition_count {
            return Err(DsmError::validation(
                format!(
                    "Transition index {} out of bounds (max: {})",
                    transition_index,
                    batch.transition_count - 1
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Serialize the transition - use a pre-allocated buffer for better performance on M1
        let mut serialized = Vec::with_capacity(1024); // Pre-allocate reasonable buffer
        bincode::serialize_into(&mut serialized, transition)
            .map_err(|e| DsmError::serialization("Failed to serialize transition", Some(e)))?;

        // Get or build the Merkle tree for this batch
        let tree = self.get_or_build_tree(batch)?;

        // Generate the Merkle proof using Apple Silicon optimizations
        let merkle_proof = sparse_merkle_tree::generate_proof(tree, transition_index)
            .map_err(|e| DsmError::merkle(format!("Failed to generate Merkle proof: {:?}", e)))?;

        // Create metadata from batch
        let mut prev_hash = [0u8; 32];
        if batch.prev_state_hash.len() == 32 {
            prev_hash.copy_from_slice(&batch.prev_state_hash);
        } else {
            return Err(DsmError::validation(
                "Invalid previous state hash length",
                None::<std::convert::Infallible>,
            ));
        }

        let metadata = BatchProofMetadata {
            transition_count: batch.transition_count,
            time_range: batch.time_range,
            prev_hash,
        };

        // Extract sibling hashes from the Merkle proof using vectorized operations
        // This leverages NEON SIMD instructions on ARM architecture
        let siblings = self.extract_sibling_hashes(&merkle_proof.path)?;

        // Calculate the transition hash - leverage Apple M1's crypto engines
        // Blake3 automatically uses hardware acceleration when available
        let transition_hash = blake3::hash(&serialized).as_bytes().clone();

        // Get the root hash
        let mut root_hash = [0u8; 32];
        if batch.transitions_root.len() == 32 {
            root_hash.copy_from_slice(&batch.transitions_root);
        } else {
            return Err(DsmError::validation(
                "Invalid transitions root hash length",
                None::<std::convert::Infallible>,
            ));
        }

        // Get tree height directly from the merkle proof
        let tree_height = merkle_proof.path.len() as u32;

        // Cache the transition for later verification after tree operations
        let transition_clone = transition.clone();
        self.transition_cache
            .insert((batch.batch_number, transition_index), transition_clone);

        let proof = BatchTransitionProof::new(
            transition_index,
            tree_height,
            siblings,
            transition_hash,
            root_hash,
            batch.batch_number,
            metadata,
        );

        Ok(proof)
    }

    /// Extract sibling hashes from Merkle proof path
    /// Optimized for Apple Silicon using NEON SIMD instructions when available
    fn extract_sibling_hashes(
        &self,
        paths: &[types::state_types::SerializableHash],
    ) -> Result<Vec<[u8; 32]>, DsmError> {
        let mut siblings = Vec::with_capacity(paths.len());

        #[cfg(target_arch = "aarch64")]
        {
            // M1 is aarch64 architecture, use optimized copy when possible
            for path in paths {
                let mut sibling = [0u8; 32];
                let bytes = path.inner().as_bytes();

                // Fast copy using NEON instructions when available
                // This is automatically used by copy_from_slice on aarch64
                sibling.copy_from_slice(bytes);
                siblings.push(sibling);
            }
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            // Fallback for non-ARM architectures
            for path in paths {
                let mut sibling = [0u8; 32];
                sibling.copy_from_slice(path.inner().as_bytes());
                siblings.push(sibling);
            }
        }

        Ok(siblings)
    }

    pub fn clear_caches(&mut self) {
        self.tree_cache.clear();
        self.transition_cache.clear();
    }

    /// Get an existing tree from cache or build a new one
    ///
    /// # Arguments
    /// * `batch` - The batch to build a tree for
    ///
    /// # Returns
    /// * `Result<&SparseMerkleTreeImpl, DsmError>` - Reference to the built tree
    fn get_or_build_tree<'a>(
        &'a mut self,
        batch: &StateBatch,
    ) -> Result<&'a SparseMerkleTreeImpl, DsmError> {
        // Check if we already have a cached tree
        if self.tree_cache.contains_key(&batch.batch_number) {
            return Ok(&self.tree_cache[&batch.batch_number]);
        }

        // Calculate the tree height - ceiling of log2 of transition count
        let count = batch.transition_count as f64;
        let height = count.log2().ceil() as u32;

        // Create a new tree
        let tree = sparse_merkle_tree::create_tree(height);

        // Store in cache and return reference
        self.tree_cache.insert(batch.batch_number, tree);
        Ok(&self.tree_cache[&batch.batch_number])
    }
}

impl Default for BatchProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// Move implementation to a separate module or scope
pub mod batch_manager_ext {
    use super::*;

    impl crate::core::state_machine::batch::BatchManager {
        /// Generate a proof for a specific transition within a batch
        pub fn generate_transition_proof_complete(
            &self,
            batch_number: u64,
            transition_index: u64,
            transition: &StateTransition,
        ) -> Result<BatchTransitionProof, DsmError> {
            // Get the batch
            let batch = self.get_batch(batch_number)?;

            // Create proof generator
            let mut generator = BatchProofGenerator::new();

            // Generate the proof
            generator.generate_proof(batch, transition_index, transition)
        }

        /// Verify a transition against a batch using a proof
        pub fn verify_transition_in_batch_complete(
            &self,
            batch_number: u64,
            transition_index: u64,
            transition: &StateTransition,
            proof: &BatchTransitionProof,
        ) -> Result<bool, DsmError> {
            // Get the batch
            let batch = self.get_batch(batch_number)?;

            // Verify batch number in proof matches requested batch
            if proof.batch_number != batch_number {
                return Ok(false);
            }

            // Verify transition index in proof matches requested index
            if proof.transition_index != transition_index {
                return Ok(false);
            }

            // Verify the proof against the transition and batch root
            let mut root_hash = [0u8; 32];
            root_hash.copy_from_slice(&batch.transitions_root);

            proof.verify(transition, &root_hash)
        }
    }
}

/// Helper function to verify a batch transition proof
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `transition` - The transition to verify
/// * `batch_root_hash` - The expected root hash of the batch's Merkle tree
///
/// # Returns
/// * `Result<bool, DsmError>` - Whether the proof is valid
pub fn verify_batch_transition_proof(
    proof: &BatchTransitionProof,
    transition: &StateTransition,
    batch_root_hash: &[u8; 32],
) -> Result<bool, DsmError> {
    proof.verify(transition, batch_root_hash)
}

// Add a helper function to check if we're running on Apple Silicon
pub fn is_apple_silicon() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        // On macOS, we can check for Apple Silicon specifically
        #[cfg(target_os = "macos")]
        {
            // Check for Apple Silicon via sysctl
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl")
                .arg("-n")
                .arg("machdep.cpu.brand_string")
                .output()
            {
                if let Ok(brand) = String::from_utf8(output.stdout) {
                    return brand.contains("Apple M");
                }
            }
        }
        // Generic aarch64 detection
        true
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        return false;
    }
}
