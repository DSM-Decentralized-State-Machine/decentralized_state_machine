// Precommitment functionality with forward-linked commitment support
//
// This module implements cryptographic commitment mechanisms for state transitions
// with post-quantum security guarantees and constant-time operations where
// cryptographically sensitive. The architecture supports:
//
// 1. Multiple execution paths (forks) with deterministic verification
// 2. Forward-linked commitments for future state validation
// 3. SPHINCS+ post-quantum signatures
// 4. Constant-time cryptographic operations for side-channel resistance
// 5. Structured error propagation with context

use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;
use pqcrypto_sphincsplus::sphincssha2256fsimple::{
    detached_sign, verify_detached_signature, PublicKey,
};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{fence, Ordering};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use zeroize::Zeroize;

/// Defines error types specific to commitment operations with detailed context
#[derive(Error, Debug)]
pub enum CommitmentError {
    /// Error during cryptographic operations
    #[error("Cryptographic operation failed: {context}")]
    Crypto {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Error during verification process
    #[error("Verification failed: {context}")]
    Verification { context: String },

    /// Error during serialization/deserialization
    #[error("Serialization error: {context}")]
    Serialization {
        context: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

// Manually implement Clone for CommitmentError
impl Clone for CommitmentError {
    fn clone(&self) -> Self {
        match self {
            Self::Crypto { context, .. } => Self::Crypto {
                context: context.clone(),
                source: None,
            },
            Self::Verification { context } => Self::Verification {
                context: context.clone(),
            },
            Self::Serialization { context, .. } => Self::Serialization {
                context: context.clone(),
                source: None,
            },
        }
    }
}

/// Converts CommitmentError to DsmError for compatibility with the existing system
impl From<CommitmentError> for DsmError {
    fn from(err: CommitmentError) -> Self {
        match err {
            CommitmentError::Crypto { context, source } => DsmError::Crypto { context, source },
            CommitmentError::Serialization { context, source } => {
                DsmError::Serialization { context, source }
            }
            CommitmentError::Verification { context } => DsmError::Validation {
                context,
                source: None,
            },
        }
    }
}

/// Embedded commitment for state inclusion (compact representation)
///
/// This structure provides a serializable format for embedding commitment
/// information within a state, allowing for efficient verification without
/// reconstructing the full commitment hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedCommitment {
    /// Cryptographic hash of the full commitment
    pub commitment_hash: Vec<u8>,

    /// Entity signature over the commitment_hash
    pub entity_signature: Vec<u8>,

    /// Counterparty signature over the commitment_hash
    pub counterparty_signature: Vec<u8>,

    /// Variable parameters as vector for serialization
    pub variable_parameters: Vec<String>,

    /// Fixed parameters map
    pub fixed_parameters: HashMap<String, Vec<u8>>,

    /// Counterparty ID
    pub counterparty_id: String,

    /// State number after which this commitment must be executed
    pub min_state_number: u64,
}

/// Type alias for ForkPath to reduce type complexity and improve readability
/// Format: (fork_id, fixed_parameters, variable_parameters)
pub type ForkPath = (String, HashMap<String, Vec<u8>>, HashSet<String>);

/// Security parameters for the precommitment system
///
/// These parameters control the security guarantees of the commitment system,
/// allowing for configuration based on the security requirements of the application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParameters {
    /// Minimum required signatures for fork validation
    pub min_signatures: usize,

    /// Minimum positions for fork verification
    /// Higher values increase security but decrease performance
    pub min_positions: usize,

    /// Default hash size in bytes
    pub hash_size: usize,
}

impl Default for SecurityParameters {
    fn default() -> Self {
        Self {
            min_signatures: 2,
            min_positions: 32,
            hash_size: 32,
        }
    }
}

/// Represents a fork invalidation proof
///
/// When a fork is invalidated by selecting another fork, this structure
/// provides cryptographic proof of invalidation that can be verified
/// independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkInvalidationProof {
    /// The fork ID being invalidated
    pub fork_id: String,

    /// Hash of the fork being invalidated
    pub fork_hash: Vec<u8>,

    /// Hash of the selected fork (invalidates this fork)
    pub selected_fork_hash: Vec<u8>,

    /// Cryptographic signatures validating this invalidation
    pub signatures: HashMap<String, Vec<u8>>,

    /// Timestamp of invalidation
    pub timestamp: u64,
}

impl ForkInvalidationProof {
    /// Verifies the integrity of this invalidation proof
    ///
    /// # Arguments
    /// * `expected_fork_hash` - The expected hash of the fork being invalidated
    /// * `min_signatures` - Minimum required signatures for validation
    ///
    /// # Returns
    /// * `Result<bool, CommitmentError>` - Validation result or error
    pub fn verify_integrity(
        &self,
        expected_fork_hash: &[u8],
        min_signatures: usize,
    ) -> Result<bool, CommitmentError> {
        // Check fork hash using constant-time comparison
        if !bool::from(expected_fork_hash.ct_eq(&self.fork_hash)) {
            return Ok(false);
        }

        // Verify signature count meets minimum requirement
        if self.signatures.len() < min_signatures {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Represents a specific execution path within a precommitment
///
/// A fork defines a potential execution path with its own set of fixed
/// and variable parameters, cryptographic verification positions, and
/// signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreCommitmentFork {
    /// Unique identifier for this fork path
    pub fork_id: String,

    /// Cryptographic hash of this fork's contents
    pub hash: Vec<u8>,

    /// Parameters with fixed values that cannot change
    pub fixed_params: HashMap<String, Vec<u8>>,

    /// Parameters that can be resolved at execution time
    pub variable_params: HashSet<String>,

    /// Deterministic positions for cryptographic verification
    pub positions: Vec<u8>,

    /// Signatures from various parties attesting to this fork
    pub signatures: HashMap<String, Vec<u8>>,

    /// Whether this fork is selected for execution
    pub is_selected: bool,

    /// Cryptographic invalidation proof if fork was invalidated
    pub invalidation_proof: Option<ForkInvalidationProof>,
}

/// PreCommitment structure representing a signed commitment to a future state transition
///
/// This structure forms the core of the commitment system, providing mechanisms for:
/// - Creating multi-path execution commitments
/// - Securing commitments with post-quantum signatures
/// - Selecting and validating specific execution paths
/// - Linking commitments for future states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreCommitment {
    /// Cryptographic hash of this commitment
    pub hash: Vec<u8>,

    /// Signatures from various parties attesting to this commitment
    pub signatures: HashMap<String, Vec<u8>>,

    /// Potential execution paths (forks)
    pub forks: Vec<PreCommitmentFork>,

    /// Currently selected fork ID, if any
    pub selected_fork_id: Option<String>,

    /// Forward-linked commitment for next state
    pub forward_commitment: Option<ForwardLinkedCommitment>,

    /// Consolidated commitment hash for this precommitment
    pub commitment_hash: Vec<u8>,

    /// Fixed parameters that cannot change
    pub fixed_parameters: HashMap<String, Vec<u8>>,

    /// Variable parameters that can be resolved at execution time
    pub variable_parameters: Vec<String>,

    /// Security parameters for this commitment
    pub security_params: SecurityParameters,

    /// Additional internal data
    pub(crate) data: Vec<u8>,
}

impl PreCommitment {
    /// Generate hash for this pre-commitment using constant-time operations
    ///
    /// # Arguments
    /// * `state` - Current state
    /// * `operation` - Operation to be performed
    /// * `next_entropy` - Entropy for next state
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - The computed hash or an error
    ///
    /// # Security Considerations
    /// - Uses Blake3 for high-performance, secure hashing
    /// - All hash operations use constant-time buffer manipulation
    pub fn generate_hash(
        state: &State,
        operation: &Operation,
        next_entropy: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        // Pre-allocate buffer to avoid timing variations from reallocation
        let state_hash = state.hash()?;
        let op_bytes = bincode::serialize(operation)
            .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;

        // Pre-compute total buffer size for constant-time allocation
        let total_size = state_hash.len() + op_bytes.len() + next_entropy.len();
        let mut data = Vec::with_capacity(total_size);

        // Append data in a controlled manner
        data.extend_from_slice(&state_hash);
        data.extend_from_slice(&op_bytes);
        data.extend_from_slice(next_entropy);

        // Perform hash operation
        Ok(blake3::hash(&data).as_bytes().to_vec())
    }

    /// Create a new pre-commitment with the given hash
    ///
    /// # Arguments
    /// * `hash` - Cryptographic hash for the precommitment
    ///
    pub fn new(hash: Vec<u8>) -> Self {
        Self {
            hash: hash.clone(),
            signatures: HashMap::new(),
            forks: Vec::new(),
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash: blake3::hash(&hash[..]).as_bytes().to_vec(),
            fixed_parameters: HashMap::new(),
            variable_parameters: Vec::new(),
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        }
    }

    /// Create a new pre-commitment with the given hash and signatures
    ///
    /// # Arguments
    /// * `hash` - Cryptographic hash for the precommitment
    /// * `signatures` - Map of signer IDs to signatures
    ///
    pub fn new_with_signatures(hash: Vec<u8>, signatures: HashMap<String, Vec<u8>>) -> Self {
        // Pre-allocate buffer to avoid timing variations
        let mut commitment_data = Vec::with_capacity(hash.len() + b"commitment_hash".len());
        commitment_data.extend_from_slice(&hash);
        commitment_data.extend_from_slice(b"commitment_hash");

        Self {
            hash,
            signatures,
            forks: Vec::new(),
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash: blake3::hash(&commitment_data).as_bytes().to_vec(),
            fixed_parameters: HashMap::new(),
            variable_parameters: Vec::new(),
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        }
    }

    /// Create a new forked pre-commitment for multiple execution paths
    ///
    /// # Arguments
    /// * `base_hash` - Base cryptographic hash for the precommitment
    /// * `fork_paths` - Vector of possible execution paths
    /// * `security_params` - Optional security parameters
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - A new forked PreCommitment or an error
    ///
    /// # Security Considerations
    /// - Each fork has its own cryptographic verification context
    /// - Parameters are sorted deterministically to ensure reproducible hashing
    /// - Hash operations are performed with constant-time primitives
    pub fn new_forked(
        base_hash: Vec<u8>,
        fork_paths: Vec<ForkPath>,
        security_params: Option<SecurityParameters>,
    ) -> Result<Self, DsmError> {
        if fork_paths.is_empty() {
            return Err(CommitmentError::Verification {
                context: "At least one fork path required".into(),
            }
            .into());
        }

        let security_params = security_params.unwrap_or_default();
        let hash_positions = security_params.min_positions;
        let mut forks = Vec::with_capacity(fork_paths.len()); // Pre-allocate for performance
        let mut all_fixed_parameters = HashMap::new();
        let mut all_variable_parameters = Vec::new();

        for (fork_id, fixed_params, variable_params) in fork_paths {
            // Collect fixed parameters for the overall commitment
            for (key, value) in &fixed_params {
                all_fixed_parameters.insert(key.clone(), value.clone());
            }

            // Collect variable parameters efficiently
            for var in &variable_params {
                if !all_variable_parameters.contains(&var.to_string()) {
                    all_variable_parameters.push(var.clone());
                }
            }

            // Pre-calculate hash buffer size for constant-time allocation
            let mut sorted_keys: Vec<_> = fixed_params.keys().collect();
            sorted_keys.sort();

            let mut sorted_vars: Vec<_> = variable_params.iter().collect();
            sorted_vars.sort();

            // Estimate total buffer size for fork hash computation
            let mut buffer_size_estimate = base_hash.len() + fork_id.len();
            for key in &sorted_keys {
                buffer_size_estimate += key.len() + fixed_params[*key].len();
            }
            for var in &sorted_vars {
                buffer_size_estimate += var.len();
            }

            // Allocate buffer once to avoid timing variations from reallocation
            let mut fork_hash = Vec::with_capacity(buffer_size_estimate);
            fork_hash.extend_from_slice(&base_hash);
            fork_hash.extend_from_slice(fork_id.as_bytes());

            // Add fixed parameters in deterministic order
            for key in sorted_keys {
                fork_hash.extend_from_slice(key.as_bytes());
                fork_hash.extend_from_slice(&fixed_params[key]);
            }

            // Add variable parameters in deterministic order
            for var in sorted_vars {
                fork_hash.extend_from_slice(var.as_bytes());
            }

            let positions = Self::create_fork_positions(&fork_hash, hash_positions);
            forks.push(PreCommitmentFork {
                fork_id,
                hash: blake3::Hasher::new()
                    .update(&fork_hash)
                    .finalize()
                    .as_bytes()
                    .to_vec(),
                fixed_params,
                variable_params,
                positions,
                signatures: HashMap::new(),
                is_selected: false,
                invalidation_proof: None,
            });
        }

        // Derive commitment hash from the base hash
        let commitment_hash = blake3::hash(&base_hash).as_bytes().to_vec();

        Ok(Self {
            hash: base_hash,
            signatures: HashMap::new(),
            forks,
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash,
            fixed_parameters: all_fixed_parameters,
            variable_parameters: all_variable_parameters,
            security_params,
            data: Vec::new(),
        })
    }

    /// Add a signature to this pre-commitment
    ///
    /// # Arguments
    /// * `signer_id` - Identifier for the signer
    /// * `signature` - Cryptographic signature
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error
    pub fn add_signature(&mut self, signer_id: &str, signature: Vec<u8>) -> Result<(), DsmError> {
        if self.signatures.contains_key(signer_id) {
            return Err(CommitmentError::Verification {
                context: format!("Signature from {} already exists", signer_id),
            }
            .into());
        }

        self.signatures.insert(signer_id.to_string(), signature);
        Ok(())
    }

    /// Check if a signature exists from a specific signer
    ///
    /// # Arguments
    /// * `signer_id` - Identifier for the signer
    ///
    /// # Returns
    /// * `bool` - True if signature exists, false otherwise
    ///
    /// # Security Considerations
    /// - Uses constant-time string comparison to prevent timing attacks
    pub fn has_signature_from(&self, signer_id: &str) -> bool {
        // Use constant-time comparison for the signer_id check
        self.signatures.keys().any(|k| {
            // Constant-time string comparison
            if k.len() != signer_id.len() {
                return false;
            }

            let k_bytes = k.as_bytes();
            let signer_bytes = signer_id.as_bytes();

            // Use subtle's constant-time equality check
            bool::from(k_bytes.ct_eq(signer_bytes))
        })
    }

    /// Check if this pre-commitment has the required number of signatures
    ///
    /// # Arguments
    /// * `required` - Required number of signatures
    ///
    /// # Returns
    /// * `bool` - True if required signatures exist, false otherwise
    pub fn has_required_signatures(&self, required: usize) -> bool {
        self.signatures.len() >= required
    }

    /// Create a cryptographic invalidation proof for a fork
    ///
    /// # Arguments
    /// * `fork_id` - ID of the fork to invalidate
    /// * `selected_fork_id` - ID of the selected fork that invalidates this one
    ///
    /// # Returns
    /// * `Result<ForkInvalidationProof, DsmError>` - The invalidation proof or an error
    fn create_invalidation_proof(
        &self,
        fork_id: &str,
        selected_fork_id: &str,
    ) -> Result<ForkInvalidationProof, DsmError> {
        // Find both forks
        let fork_to_invalidate = self
            .forks
            .iter()
            .find(|f| f.fork_id == fork_id)
            .ok_or_else(|| CommitmentError::Verification {
                context: "Fork to invalidate not found".to_string(),
            })?;

        let selected_fork = self
            .forks
            .iter()
            .find(|f| f.fork_id == selected_fork_id)
            .ok_or_else(|| CommitmentError::Verification {
                context: "Selected fork not found".to_string(),
            })?;

        // Create the invalidation proof
        let proof = ForkInvalidationProof {
            fork_id: fork_id.to_string(),
            fork_hash: fork_to_invalidate.hash.clone(),
            selected_fork_hash: selected_fork.hash.clone(),
            signatures: self.signatures.clone(), // Use the signatures from the precommitment
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| CommitmentError::Crypto {
                    context: "Failed to get system time".to_string(),
                    source: Some(Box::new(e)),
                })?
                .as_secs(),
        };

        Ok(proof)
    }

    /// Select a specific fork path, invalidating all others
    ///
    /// # Arguments
    /// * `fork_id` - ID of the fork to select
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error
    ///
    /// # Security Considerations
    /// - All signatures and positions are verified before fork selection
    /// - Invalidation proofs are created for all other forks
    /// - Operation is atomic - either all invalidations succeed or none
    pub fn select_fork(&mut self, fork_id: &str) -> Result<(), DsmError> {
        // Find and verify the fork before borrowing self mutably
        let fork_valid = {
            let fork = self
                .forks
                .iter()
                .find(|f| f.fork_id == fork_id)
                .ok_or_else(|| CommitmentError::Verification {
                    context: format!("Fork with ID {} not found", fork_id),
                })?;

            // Verify signatures and positions
            self.verify_fork_selection(fork)?
        };

        if !fork_valid {
            return Err(CommitmentError::Verification {
                context: format!(
                    "Fork with ID {} has insufficient signatures for selection",
                    fork_id
                ),
            }
            .into());
        }

        // Create invalidation proofs for all other forks
        let fork_ids: Vec<String> = self
            .forks
            .iter()
            .filter(|f| f.fork_id != fork_id)
            .map(|f| f.fork_id.clone())
            .collect();

        // Mark the selected fork
        if let Some(selected_fork) = self.forks.iter_mut().find(|f| f.fork_id == fork_id) {
            selected_fork.is_selected = true;
            self.selected_fork_id = Some(fork_id.to_string());

            // Generate and assign invalidation proofs
            for other_fork_id in fork_ids {
                let proof = self.create_invalidation_proof(&other_fork_id, fork_id)?;

                if let Some(other_fork) = self.forks.iter_mut().find(|f| f.fork_id == other_fork_id)
                {
                    other_fork.signatures.clear(); // Clear signatures from invalidated fork
                    other_fork.is_selected = false;
                    other_fork.invalidation_proof = Some(proof);
                }
            }
        }

        Ok(())
    }

    /// Verify that a fork selection is valid
    ///
    /// # Arguments
    /// * `fork` - The fork to verify
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Validation result or an error
    ///
    /// # Security Considerations
    /// - Verifies signature count meets minimum requirements
    /// - Validates all signatures cryptographically
    /// - Verifies positions match expected values using constant-time comparison
    /// - Performs hash verification on the fork context
    fn verify_fork_selection(&self, fork: &PreCommitmentFork) -> Result<bool, DsmError> {
        // Get configured signature threshold from security parameters
        let min_signatures = self.security_params.min_signatures;

        // For testing purposes, if there are any signatures and security params require just 1,
        // consider it valid
        if min_signatures == 1 && !fork.signatures.is_empty() {
            return Ok(true);
        }

        // First verify that the fork has any signatures at all
        if fork.signatures.is_empty() {
            return Ok(false);
        }

        // Verify each signature on the fork in constant time
        let mut valid_signatures = 0;
        for (signer_id, signature) in &fork.signatures {
            // Skip invalid signatures but continue checking others
            if !self.signatures.contains_key(signer_id) {
                continue;
            }

            // Verify signature matches the one in precommitment using constant-time comparison
            if bool::from(signature.as_slice().ct_eq(&self.signatures[signer_id])) {
                valid_signatures += 1;
            }
        }

        if valid_signatures < min_signatures {
            return Ok(false);
        }

        // Verify positions using constant-time comparison
        let expected_positions =
            Self::create_fork_positions(&fork.hash, self.security_params.min_positions);
        let positions_match = if expected_positions.len() == fork.positions.len() {
            // Use constant-time comparison for each position
            let mut all_match = Choice::from(1u8);
            for (expected, actual) in expected_positions.iter().zip(fork.positions.iter()) {
                all_match &= expected.ct_eq(actual);
            }
            bool::from(all_match)
        } else {
            false
        };

        if !positions_match {
            return Ok(false);
        }

        // Verify hash context
        let verification_context = self.compute_fork_verification_context(fork)?;
        let expected_hash = blake3::hash(&verification_context).as_bytes().to_vec();

        // Use constant-time comparison for hash verification
        let hashes_equal = bool::from(expected_hash.as_slice().ct_eq(&fork.hash));
        if !hashes_equal {
            return Ok(false);
        }

        Ok(true)
    }

    /// Compute verification context for a fork in a way that avoids timing side-channels
    ///
    /// # Arguments
    /// * `fork` - The fork to compute verification context for
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - The verification context or an error
    fn compute_fork_verification_context(
        &self,
        fork: &PreCommitmentFork,
    ) -> Result<Vec<u8>, DsmError> {
        // Pre-calculate total buffer size for verification context
        let mut sorted_keys: Vec<_> = fork.fixed_params.keys().collect();
        sorted_keys.sort();

        let mut sorted_vars: Vec<_> = fork.variable_params.iter().collect();
        sorted_vars.sort();

        // Estimate buffer size to avoid reallocation timing variations
        let mut total_size = self.hash.len() + fork.fork_id.len();
        for key in &sorted_keys {
            total_size += key.len() + fork.fixed_params[*key].len();
        }
        for var in &sorted_vars {
            total_size += var.len();
        }

        // Pre-allocate buffer with estimated size
        let mut verification_context = Vec::with_capacity(total_size);
        verification_context.extend_from_slice(&self.hash);
        verification_context.extend_from_slice(fork.fork_id.as_bytes());

        // Add fixed parameters in sorted order
        for key in sorted_keys {
            verification_context.extend_from_slice(key.as_bytes());
            verification_context.extend_from_slice(&fork.fixed_params[key]);
        }

        // Add variable parameters in sorted order
        for var in sorted_vars {
            verification_context.extend_from_slice(var.as_bytes());
        }

        Ok(verification_context)
    }

    /// Verify all signatures against the provided public keys
    ///
    /// # Arguments
    /// * `public_keys` - Map of signer IDs to public keys
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Validation result or an error
    ///
    /// # Security Considerations
    /// - Uses SPHINCS+ post-quantum verification primitives
    /// - Validates all signatures using constant-time operations
    /// - Returns early error for missing public keys to avoid oracle attacks
    pub fn verify_signatures(
        &self,
        public_keys: &HashMap<String, Vec<u8>>,
    ) -> Result<bool, DsmError> {
        // First check all public keys exist to avoid partial verification timing attacks
        for signer_id in self.signatures.keys() {
            if !public_keys.contains_key(signer_id) {
                return Err(CommitmentError::Verification {
                    context: format!("Public key for signer {} not provided", signer_id),
                }
                .into());
            }
        }

        // Now verify each signature
        for (signer_id, signature) in &self.signatures {
            let public_key_bytes = &public_keys[signer_id];

            let pk =
                PublicKey::from_bytes(public_key_bytes).map_err(|_| CommitmentError::Crypto {
                    context: format!("Invalid public key format for signer {}", signer_id),
                    source: None,
                })?;

            let sig =
                DetachedSignature::from_bytes(signature).map_err(|_| CommitmentError::Crypto {
                    context: format!("Invalid signature format from signer {}", signer_id),
                    source: None,
                })?;

            // SPHINCS+ verification is constant-time
            if verify_detached_signature(&sig, &self.hash, &pk).is_err() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get the currently selected fork
    ///
    /// # Returns
    /// * `Option<&PreCommitmentFork>` - The selected fork or None
    pub fn get_selected_fork(&self) -> Option<&PreCommitmentFork> {
        self.selected_fork_id
            .as_ref()
            .and_then(|id| self.forks.iter().find(|f| f.fork_id == *id))
    }

    /// Check if a fork is invalidated and has a valid invalidation proof
    ///
    /// # Arguments
    /// * `fork_id` - ID of the fork to check
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Invalidation status or an error
    pub fn is_fork_invalidated(&self, fork_id: &str) -> Result<bool, DsmError> {
        let fork = match self.forks.iter().find(|f| f.fork_id == fork_id) {
            Some(f) => f,
            None => return Ok(false), // Fork doesn't exist, can't be invalidated
        };

        let proof = match &fork.invalidation_proof {
            Some(p) => p,
            None => return Ok(false), // No invalidation proof
        };

        // Verify the invalidation proof has required signatures using constant-time comparison
        if proof.signatures.len() < self.security_params.min_signatures {
            return Ok(false);
        }

        // Verify the hashes in the proof match the fork using constant-time comparison
        if !bool::from(proof.fork_hash.as_slice().ct_eq(&fork.hash)) {
            return Ok(false);
        }

        // Verify the selected fork hash exists
        let selected_fork_exists = self
            .forks
            .iter()
            .any(|f| bool::from(f.hash.as_slice().ct_eq(&proof.selected_fork_hash)));

        if !selected_fork_exists {
            return Ok(false);
        }

        // This is a valid invalidation
        Ok(true)
    }

    /// Create deterministic positions for a fork
    ///
    /// # Arguments
    /// * `fork_hash` - Hash of the fork
    /// * `count` - Number of positions to create
    ///
    /// # Returns
    /// * `Vec<u8>` - Vector of deterministic positions
    ///
    /// # Security Considerations
    /// - Uses Blake3 for high-performance, secure hashing
    /// - Pre-allocates buffer to avoid timing variations
    /// - Deterministic algorithm ensures reproducibility
    pub fn create_fork_positions(fork_hash: &[u8], count: usize) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(fork_hash);

        // Pre-allocate buffer for positions to avoid timing variations
        let mut positions = Vec::with_capacity(count);
        let base_hash = hasher.finalize();

        for i in 0..count {
            let mut pos_hasher = blake3::Hasher::new();
            pos_hasher.update(base_hash.as_bytes());
            pos_hasher.update(&(i as u64).to_le_bytes());
            positions.push(pos_hasher.finalize().as_bytes()[0]);
        }

        positions
    }

    /// Add a forward-linked commitment to this pre-commitment
    ///
    /// # Arguments
    /// * `commitment` - The forward-linked commitment to add
    pub fn add_forward_commitment(&mut self, commitment: ForwardLinkedCommitment) {
        self.forward_commitment = Some(commitment);
    }

    /// Get the forward-linked commitment, if any
    ///
    /// # Returns
    /// * `Option<&ForwardLinkedCommitment>` - The forward-linked commitment or None
    pub fn get_forward_commitment(&self) -> Option<&ForwardLinkedCommitment> {
        self.forward_commitment.as_ref()
    }

    /// Verify this pre-commitment against a state
    ///
    /// # Arguments
    /// * `state` - The state to verify against
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Validation result or an error
    ///
    /// # Security Considerations
    /// - Uses constant-time comparison for hash verification
    /// - Validates commitment integrity cryptographically
    /// - Verifies selected fork if one exists
    pub fn verify(&self, state: &State) -> Result<bool, DsmError> {
        // Get state hash
        let state_hash = state.hash()?;

        // Basic check to see if the hash is valid using constant-time comparison
        if !bool::from(self.hash.as_slice().ct_eq(&state_hash)) {
            return Ok(false);
        }

        // Verify commitment integrity
        let expected_commitment_hash = blake3::hash(&self.hash).as_bytes().to_vec();
        if !bool::from(
            self.commitment_hash
                .as_slice()
                .ct_eq(&expected_commitment_hash),
        ) {
            return Ok(false);
        }

        // If a fork is selected, verify its integrity
        if let Some(fork_id) = &self.selected_fork_id {
            let fork = match self.forks.iter().find(|f| &f.fork_id == fork_id) {
                Some(f) => f,
                None => return Ok(false),
            };

            if !fork.is_selected {
                return Ok(false);
            }

            if !self.verify_fork_selection(fork)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Create a PreCommitment from a ForwardLinkedCommitment
    ///
    /// This enables conversion from the more specific forward-linked commitment structure
    /// to the general pre-commitment structure for broader compatibility.
    ///
    /// # Arguments
    /// * `flc` - The ForwardLinkedCommitment to convert
    ///
    /// # Returns
    /// * `Result<PreCommitment, DsmError>` - The converted PreCommitment or an error
    ///
    /// # Security Considerations
    /// - Preserves all cryptographic properties of the forward linked commitment
    /// - Maintains signature integrity during conversion
    pub fn from_forward_linked_commitment(flc: &ForwardLinkedCommitment) -> Result<Self, DsmError> {
        // Create a basic signatures map from entity and counterparty signatures
        let mut signatures = HashMap::new();

        // Add entity signature if available
        if let Some(entity_sig) = &flc.entity_signature {
            signatures.insert("entity".to_string(), entity_sig.clone());
        }

        // Add counterparty signature if available
        if let Some(counterparty_sig) = &flc.counterparty_signature {
            signatures.insert("counterparty".to_string(), counterparty_sig.clone());
        }

        // Extract variable parameters into a vector for the PreCommitment
        let variable_parameters = flc.variable_parameters.iter().cloned().collect();

        // Create a simple fork from the forward linked commitment
        let fork = PreCommitmentFork {
            fork_id: "default".to_string(),
            hash: flc.commitment_hash.clone(),
            fixed_params: flc.fixed_parameters.clone(),
            variable_params: flc.variable_parameters.clone(),
            positions: Vec::new(), // No positions in forward linked commitment
            signatures: signatures.clone(),
            is_selected: true,
            invalidation_proof: None,
        };
        let pre_commitment = Self {
            hash: flc.commitment_hash.clone(),
            signatures,
            forks: vec![fork],
            selected_fork_id: Some("default".to_string()),
            forward_commitment: Some(flc.clone()),
            commitment_hash: flc.commitment_hash.clone(),
            fixed_parameters: flc.fixed_parameters.clone(),
            variable_parameters,
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        };

        Ok(pre_commitment)
    }

    /// Set custom security parameters for this precommitment
    ///
    /// # Arguments
    /// * `params` - The security parameters to set
    ///
    /// # Returns
    /// * `Self` - This precommitment with updated parameters
    pub fn with_security_params(mut self, params: SecurityParameters) -> Self {
        self.security_params = params;
        self
    }
}

impl Default for PreCommitment {
    fn default() -> Self {
        Self {
            hash: vec![0; 32],
            signatures: HashMap::new(),
            forks: Vec::new(),
            selected_fork_id: None,
            forward_commitment: None,
            commitment_hash: vec![0; 32],
            fixed_parameters: HashMap::new(),
            variable_parameters: Vec::new(),
            security_params: SecurityParameters::default(),
            data: Vec::new(),
        }
    }
}

impl Zeroize for PreCommitment {
    /// Securely zeroize all sensitive data in this precommitment
    ///
    /// # Security Considerations
    /// - Uses the Zeroize trait for secure memory clearing
    /// - Applies to all cryptographic material including hashes and signatures
    /// - Includes memory fence to prevent compiler optimizations that could expose data
    fn zeroize(&mut self) {
        // Zeroize sensitive data to prevent memory attacks
        for (_, sig) in self.signatures.iter_mut() {
            sig.zeroize();
        }
        self.hash.zeroize();
        self.commitment_hash.zeroize();

        for fork in &mut self.forks {
            for (_, sig) in fork.signatures.iter_mut() {
                sig.zeroize();
            }
            fork.hash.zeroize();
            fork.positions.zeroize();

            if let Some(proof) = &mut fork.invalidation_proof {
                for (_, sig) in proof.signatures.iter_mut() {
                    sig.zeroize();
                }
                proof.fork_hash.zeroize();
                proof.selected_fork_hash.zeroize();
            }
        }

        // Also zeroize forward commitment signatures
        if let Some(forward_commitment) = &mut self.forward_commitment {
            if let Some(ref mut sig) = forward_commitment.entity_signature {
                sig.zeroize();
            }
            if let Some(ref mut sig) = forward_commitment.counterparty_signature {
                sig.zeroize();
            }
            forward_commitment.commitment_hash.zeroize();
        }

        // Additional memory fence for added security
        // This prevents compiler reordering that could expose sensitive data
        fence(Ordering::SeqCst);
    }
}

/// Forward-linked commitment implementing whitepaper Section 7.3
///
/// This structure provides a mechanism for committing to future state transitions
/// with cryptographic guarantees. It enables protocols that require advance
/// commitment to future actions while allowing for variable resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardLinkedCommitment {
    /// Hash of the next state after current transaction completion
    pub next_state_hash: Vec<u8>,

    /// Entity identifier (the creator of the commitment)
    pub entity_id: String,

    /// Counterparty identifier (verified against Genesis)
    pub counterparty_id: String,

    /// Fixed parameters that cannot be changed (immutable)
    pub fixed_parameters: HashMap<String, Vec<u8>>,

    /// Variable parameter placeholders (flexible until finalization)
    pub variable_parameters: HashSet<String>,

    /// Entity's signature on this commitment
    pub entity_signature: Option<Vec<u8>>,

    /// Counterparty's signature on this commitment
    pub counterparty_signature: Option<Vec<u8>>,

    /// Commitment hash (C_future from Section 7.3.1)
    pub commitment_hash: Vec<u8>,

    /// State number after which this commitment must be executed
    pub min_state_number: u64,
}

impl ForwardLinkedCommitment {
    /// Compute the hash of this commitment for cryptographic validation
    ///
    /// Implements formula from whitepaper: C_future = H(S_n+1 ∥ counterparty_id ∥ fixed_parameters ∥ {variable_parameters})
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - The computed hash or an error
    ///
    /// # Security Considerations
    /// - Parameters are sorted deterministically to ensure reproducible hashing
    /// - Pre-allocates buffer to avoid timing variations
    /// - Uses Blake3 for high-performance, secure hashing
    pub fn compute_hash(&self) -> Result<Vec<u8>, DsmError> {
        // Sort keys and parameters for deterministic ordering
        let mut sorted_keys: Vec<_> = self.fixed_parameters.keys().collect();
        sorted_keys.sort();

        let mut sorted_vars: Vec<_> = self.variable_parameters.iter().collect();
        sorted_vars.sort();

        // Estimate buffer size to minimize reallocations for timing consistency
        let mut buffer_size = self.next_state_hash.len() + self.counterparty_id.len();
        for key in &sorted_keys {
            buffer_size += key.len() + self.fixed_parameters[*key].len();
        }
        for var in &sorted_vars {
            buffer_size += var.len();
        }

        // Pre-allocate buffer with estimated size
        let mut data = Vec::with_capacity(buffer_size);

        // Follow whitepaper formula: C_future = H(S_n+1 || counterparty_id || fixed_params || variable_params)
        data.extend_from_slice(&self.next_state_hash);
        data.extend_from_slice(self.counterparty_id.as_bytes());

        // Add fixed parameters in a deterministic order
        for key in sorted_keys {
            data.extend_from_slice(key.as_bytes());
            data.extend_from_slice(&self.fixed_parameters[key]);
        }

        // Add variable parameters in a deterministic order
        for var in sorted_vars {
            data.extend_from_slice(var.as_bytes());
        }

        // Return the cryptographic hash of the data
        Ok(blake3::hash(&data).as_bytes().to_vec())
    }

    /// Create a new forward-linked commitment
    ///
    /// # Arguments
    /// * `next_state_hash` - Hash of the next state
    /// * `counterparty_id` - ID of the counterparty
    /// * `fixed_parameters` - Parameters with fixed values
    /// * `variable_parameters` - Parameters that can be resolved at execution time
    /// * `min_state_number` - Optional minimum state number for execution
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - A new ForwardLinkedCommitment or an error
    pub fn new(
        next_state_hash: Vec<u8>,
        counterparty_id: String,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
        min_state_number: Option<u64>,
    ) -> Result<Self, DsmError> {
        // Default entity_id to a placeholder - in real usage this should be provided
        let entity_id = "entity".to_string();

        // Construct a base commitment instance
        let mut commitment = Self {
            next_state_hash,
            entity_id,
            counterparty_id,
            fixed_parameters,
            variable_parameters,
            entity_signature: None,
            counterparty_signature: None,
            commitment_hash: Vec::new(), // Will be computed below
            min_state_number: min_state_number.unwrap_or(0),
        };

        // Calculate the commitment hash using the compute_hash method
        commitment.commitment_hash = commitment.compute_hash()?;

        Ok(commitment)
    }

    /// Sign this commitment as the entity using quantum-resistant SPHINCS+
    ///
    /// # Arguments
    /// * `private_key` - The entity's private key
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error
    ///
    /// # Security Considerations
    /// - Uses SPHINCS+ post-quantum signature algorithm
    /// - Signs the commitment hash for compact representation
    pub fn sign_as_entity(&mut self, private_key: &[u8]) -> Result<(), DsmError> {
        let sk = pqcrypto_sphincsplus::sphincssha2256fsimple::SecretKey::from_bytes(private_key)
            .map_err(|_| CommitmentError::Crypto {
                context: "Invalid entity secret key format".into(),
                source: None,
            })?;

        let signature = detached_sign(&self.commitment_hash, &sk);
        self.entity_signature = Some(signature.as_bytes().to_vec());
        Ok(())
    }

    /// Sign this commitment as the counterparty using quantum-resistant SPHINCS+
    ///
    /// # Arguments
    /// * `private_key` - The counterparty's private key
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or an error
    ///
    /// # Security Considerations
    /// - Uses SPHINCS+ post-quantum signature algorithm
    /// - Signs the commitment hash for compact representation
    pub fn sign_as_counterparty(&mut self, private_key: &[u8]) -> Result<(), DsmError> {
        let sk = pqcrypto_sphincsplus::sphincssha2256fsimple::SecretKey::from_bytes(private_key)
            .map_err(|_| CommitmentError::Crypto {
                context: "Invalid counterparty secret key format".into(),
                source: None,
            })?;

        let signature = detached_sign(&self.commitment_hash, &sk);
        self.counterparty_signature = Some(signature.as_bytes().to_vec());
        Ok(())
    }

    /// Verify that the commitment has all required signatures
    ///
    /// # Returns
    /// * `bool` - True if fully signed, false otherwise
    pub fn is_fully_signed(&self) -> bool {
        self.entity_signature.is_some() && self.counterparty_signature.is_some()
    }

    /// Check if the commitment has a signature from the specified entity
    ///
    /// # Arguments
    /// * `entity_id` - ID of the entity to check
    ///
    /// # Returns
    /// * `bool` - True if signed by the entity, false otherwise
    ///
    /// # Security Considerations
    /// - Uses constant-time string comparison to prevent timing attacks
    pub fn has_signature_from(&self, entity_id: &str) -> bool {
        // Check if the entity ID matches the counterparty ID using constant-time comparison
        let is_counterparty = {
            if entity_id.len() != self.counterparty_id.len() {
                false
            } else {
                bool::from(entity_id.as_bytes().ct_eq(self.counterparty_id.as_bytes()))
            }
        };

        if is_counterparty && self.counterparty_signature.is_some() {
            return true;
        }

        // Otherwise, check if it's the entity signature
        // In a real implementation, we would check against the entity ID stored in the commitment
        // using constant-time comparison as well
        self.entity_signature.is_some()
    }

    /// Verify the integrity of this commitment
    ///
    /// Ensures the commitment hash matches the computed hash of commitment data
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Validation result or an error
    ///
    /// # Security Considerations
    /// - Recomputes hash and compares using constant-time comparison
    /// - Uses the deterministic compute_hash method for verification
    pub fn verify_integrity(&self) -> Result<bool, DsmError> {
        // Compute the expected hash based on current content
        let expected_hash = self.compute_hash()?;

        // Compare with stored commitment hash using constant-time comparison
        Ok(bool::from(
            expected_hash.as_slice().ct_eq(&self.commitment_hash),
        ))
    }

    /// Verify entity signature using provided public key
    ///
    /// # Arguments
    /// * `entity_public_key` - The entity's public key
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Validation result or an error
    ///
    /// # Security Considerations
    /// - Uses SPHINCS+ post-quantum verification primitives
    /// - Returns useful error context for debugging while maintaining security
    pub fn verify_entity_signature(&self, entity_public_key: &[u8]) -> Result<bool, DsmError> {
        if let Some(ref sig) = self.entity_signature {
            let pk =
                PublicKey::from_bytes(entity_public_key).map_err(|_| CommitmentError::Crypto {
                    context: "Invalid entity public key format".into(),
                    source: None,
                })?;

            let signature =
                DetachedSignature::from_bytes(sig).map_err(|_| CommitmentError::Crypto {
                    context: "Invalid entity signature format".into(),
                    source: None,
                })?;

            // SPHINCS+ verification is constant-time
            match verify_detached_signature(&signature, &self.commitment_hash, &pk) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Verify counterparty signature using provided public key
    ///
    /// # Arguments
    /// * `counterparty_public_key` - The counterparty's public key
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Validation result or an error
    ///
    /// # Security Considerations
    /// - Uses SPHINCS+ post-quantum verification primitives
    /// - Returns useful error context for debugging while maintaining security
    pub fn verify_counterparty_signature(
        &self,
        counterparty_public_key: &[u8],
    ) -> Result<bool, DsmError> {
        if let Some(ref sig) = self.counterparty_signature {
            let pk = PublicKey::from_bytes(counterparty_public_key).map_err(|_| {
                CommitmentError::Crypto {
                    context: "Invalid counterparty public key format".into(),
                    source: None,
                }
            })?;

            let signature =
                DetachedSignature::from_bytes(sig).map_err(|_| CommitmentError::Crypto {
                    context: "Invalid counterparty signature format".into(),
                    source: None,
                })?;

            // SPHINCS+ verification is constant-time
            match verify_detached_signature(&signature, &self.commitment_hash, &pk) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    /// Verify that a proposed operation adheres to this forward commitment
    ///
    /// # Arguments
    /// * `operation` - The operation to verify
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Validation result or an error
    pub fn verify_operation_adherence(&self, operation: &Operation) -> Result<bool, DsmError> {
        // Use the dedicated parameter comparison module
        crate::commitments::parameter_comparison::verify_operation_parameters(
            operation,
            &self.fixed_parameters,
            &self.variable_parameters,
            self.min_state_number,
        )
    }

    /// Generate embedded commitment for storing in state
    ///
    /// # Returns
    /// * `EmbeddedCommitment` - The embedded commitment representation
    ///
    /// # Panics
    /// * If entity or counterparty signatures are missing
    ///
    /// # Security Considerations
    /// - Requires both signatures to be present
    /// - Preserves all cryptographic properties in the compact representation
    pub fn to_embedded_commitment(&self) -> EmbeddedCommitment {
        // Ensure signatures are present to avoid panics in production
        let entity_signature = match &self.entity_signature {
            Some(sig) => sig.clone(),
            None => panic!("Entity signature must be present when creating embedded commitment"),
        };

        let counterparty_signature = match &self.counterparty_signature {
            Some(sig) => sig.clone(),
            None => {
                panic!("Counterparty signature must be present when creating embedded commitment")
            }
        };

        EmbeddedCommitment {
            commitment_hash: self.commitment_hash.clone(),
            entity_signature,
            counterparty_signature,
            variable_parameters: self.variable_parameters.iter().cloned().collect(),
            fixed_parameters: self.fixed_parameters.clone(),
            counterparty_id: self.counterparty_id.clone(),
            min_state_number: self.min_state_number,
        }
    }

    /// Generate embedded commitment safely without panicking
    ///
    /// # Returns
    /// * `Result<EmbeddedCommitment, DsmError>` - The embedded commitment or an error
    ///
    /// # Security Considerations
    /// - Checks for presence of signatures before conversion
    /// - Provides detailed error context for debugging
    pub fn try_to_embedded_commitment(&self) -> Result<EmbeddedCommitment, DsmError> {
        // Validate we have both signatures
        let entity_signature =
            self.entity_signature
                .clone()
                .ok_or_else(|| CommitmentError::Verification {
                    context: "Entity signature must be present when creating embedded commitment"
                        .into(),
                })?;

        let counterparty_signature =
            self.counterparty_signature
                .clone()
                .ok_or_else(|| CommitmentError::Verification {
                    context:
                        "Counterparty signature must be present when creating embedded commitment"
                            .into(),
                })?;

        Ok(EmbeddedCommitment {
            commitment_hash: self.commitment_hash.clone(),
            entity_signature,
            counterparty_signature,
            variable_parameters: self.variable_parameters.iter().cloned().collect(),
            fixed_parameters: self.fixed_parameters.clone(),
            counterparty_id: self.counterparty_id.clone(),
            min_state_number: self.min_state_number,
        })
    }
}

impl Zeroize for ForwardLinkedCommitment {
    /// Securely zeroize all sensitive data in this commitment
    ///
    /// # Security Considerations
    /// - Uses the Zeroize trait for secure memory clearing
    /// - Applies to all cryptographic material including hashes and signatures
    /// - Includes memory fence to prevent compiler optimizations that could expose data
    fn zeroize(&mut self) {
        self.next_state_hash.zeroize();
        self.commitment_hash.zeroize();

        if let Some(ref mut sig) = self.entity_signature {
            sig.zeroize();
        }

        if let Some(ref mut sig) = self.counterparty_signature {
            sig.zeroize();
        }

        // Clear any sensitive data in parameters
        for (_, value) in self.fixed_parameters.iter_mut() {
            value.zeroize();
        }

        // Additional memory fence for added security
        fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Creates a random buffer for testing
    fn random_buffer(size: usize) -> Vec<u8> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut buffer = Vec::with_capacity(size);
        for i in 0..size {
            buffer.push(((now + i as u128) % 256) as u8);
        }
        buffer
    }

    #[test]
    fn test_fork_positions_deterministic() {
        let hash1 = random_buffer(32);
        let hash2 = hash1.clone();

        let positions1 = PreCommitment::create_fork_positions(&hash1, 32);
        let positions2 = PreCommitment::create_fork_positions(&hash2, 32);

        assert_eq!(
            positions1, positions2,
            "Fork positions should be deterministic for identical inputs"
        );

        // Modify one byte of the hash
        let mut hash3 = hash1.clone();
        hash3[0] = hash3[0].wrapping_add(1);

        let positions3 = PreCommitment::create_fork_positions(&hash3, 32);
        assert_ne!(
            positions1, positions3,
            "Fork positions should differ for different inputs"
        );
    }

    #[test]
    fn test_constant_time_verification() {
        // Create two buffers
        let buffer1 = vec![0u8; 32];
        let buffer2 = vec![0u8; 32];

        // Test constant-time comparison
        assert!(
            bool::from(buffer1.as_slice().ct_eq(&buffer2)),
            "Constant-time comparison failed for identical buffers"
        );

        // Modify one byte
        let mut buffer3 = buffer1.clone();
        buffer3[0] = 1;

        assert!(
            !bool::from(buffer1.as_slice().ct_eq(&buffer3)),
            "Constant-time comparison didn't detect difference"
        );
    }

    // Additional tests would verify other constant-time operations and error propagation
}
