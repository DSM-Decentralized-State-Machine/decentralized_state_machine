//! # Identity SDK Module
//!
//! This module implements the identity management functionality as described
//! in sections 4 and 7 of the DSM whitepaper, providing secure identity
//! operations including device management, relationship tracking, and recovery.
//!
//! ## Key Concepts
//!
//! * **Hierarchical Identity**: Master and device-specific sub-genesis states
//! * **Cryptographic State Isolation**: Separate state chains for different contexts
//! * **Bilateral Relationships**: Managed contexts for secure peer interactions
//! * **Pre-commitments**: Cryptographic commitments to future operations
//! * **Identity Recovery**: Mechanisms for recovering from key compromise
//!
//! ## Architecture
//!
//! The identity module implements a hierarchical device-specific sub-genesis architecture
//! with cryptographic state isolation and bilateral relationship context management.
//! It follows the mathematical blueprint laid out in sections 4 and 7 of the DSM whitepaper.
//!
//! ## Usage Example
//!
//! ```rust
//! use dsm_sdk::identity_sdk::IdentitySDK;
//! use dsm_sdk::hashchain_sdk::HashChainSDK;
//! use dsm::types::state_types::DeviceInfo;
//! use std::sync::Arc;
//!
//! // Create identity SDK with hash chain
//! let hash_chain_sdk = Arc::new(HashChainSDK::new());
//! let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
//!
//! // Create a device and genesis state
//! let device_info = DeviceInfo::new("device1", vec![1, 2, 3, 4]);
//! let participant_inputs = vec![vec![5, 6, 7, 8]];
//! let genesis = identity_sdk.create_genesis(device_info, participant_inputs, None).unwrap();
//!
//! // Create relationship with another identity
//! identity_sdk.create_relationship_context("user456", vec![9, 10, 11, 12]).unwrap();
//! ```

use super::hashchain_sdk::HashChainSDK;
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::state_types::{DeviceInfo, State};
use dsm::crypto::signatures::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Type alias for state hash values used throughout the identity system
///
/// State hashes are used to reference specific states in the DSM system
/// and verify state transitions.
pub type StateHash = Vec<u8>;

/// Types of tombstone markers for invalidation
///
/// These markers are used in the identity invalidation process as defined
/// in section 9 of the DSM whitepaper, enabling specific types of invalidation.
#[derive(Debug, Clone, PartialEq)]
pub enum TombstoneType {
    /// State invalidation - marks a specific state as invalid
    ///
    /// This type of tombstone invalidates a single state in the chain,
    /// typically used for correcting errors or marking compromised states.
    StateInvalidation,
    
    /// Identity revocation - marks an entire identity as invalid
    ///
    /// This type of tombstone invalidates an entire identity, used in
    /// cases of severe compromise or when an identity is no longer needed.
    IdentityRevocation,
    
    /// Device revocation - marks a specific device as invalid
    ///
    /// This type of tombstone invalidates a specific device under an identity,
    /// used when a device is lost, stolen, or compromised.
    DeviceRevocation,
}

/// Bilateral relationship context for secure peer interactions
///
/// This structure manages the cryptographic context between two entities
/// as defined in section 7 of the DSM whitepaper, enabling secure bilateral
/// communication with state isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRelationshipContext {
    /// Current state number of the entity in this relationship
    pub entity_state_number: u64,

    /// Identifier of the counterparty in this relationship
    pub counterparty_id: String,

    /// Current state number of the counterparty in this relationship
    pub counterparty_state_number: u64,

    /// Public key of the counterparty for verification
    pub counterparty_public_key: Vec<u8>,

    /// Hash of the current relationship state
    pub current_state_hash: StateHash,

    /// Sequence of state hashes in this relationship
    pub state_sequence: Vec<StateHash>,

    /// Additional metadata for the relationship
    pub metadata: HashMap<String, Vec<u8>>,

    /// Timestamp of the last interaction in this relationship
    pub last_interaction: u64,
}

/// Identity management SDK for the DSM system
///
/// This SDK provides a comprehensive interface for managing cryptographic
/// identities in the DSM system, including device management, relationship
/// tracking, state transitions, and recovery mechanisms as defined in 
/// sections 4 and 7 of the DSM whitepaper.
#[derive(Debug, Clone)]
pub struct IdentitySDK {
    /// Identifier for this identity
    pub identity_id: String,

    /// Registry of device-specific genesis states
    pub device_genesis_states: Arc<RwLock<HashMap<String, State>>>,

    /// Reference to the hash chain tracking states
    pub hash_chain_sdk: Arc<HashChainSDK>,

    /// Registry of bilateral relationship contexts
    relationship_contexts: Arc<RwLock<HashMap<String, ExtendedRelationshipContext>>>,

    /// Cryptographic key pair for this identity
    signing_keypair: Arc<RwLock<Option<SignatureKeyPair>>>,
}

impl IdentitySDK {
    /// Create a new IdentitySDK instance
    ///
    /// Initializes a new identity with the specified ID and hash chain,
    /// and generates cryptographic keys for this identity.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The unique identifier for this identity
    /// * `hash_chain_sdk` - An Arc-wrapped HashChainSDK for state tracking
    ///
    /// # Returns
    ///
    /// A new IdentitySDK instance
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    /// ```
    pub fn new(identity_id: String, hash_chain_sdk: Arc<HashChainSDK>) -> Self {
        let sdk = Self {
            identity_id,
            device_genesis_states: Arc::new(RwLock::new(HashMap::new())),
            hash_chain_sdk,
            relationship_contexts: Arc::new(RwLock::new(HashMap::new())),
            signing_keypair: Arc::new(RwLock::new(None)),
        };

        // Initialize cryptographic keys
        let _ = sdk.initialize_keys();

        sdk
    }

    /// Initialize cryptographic keys for this identity
    ///
    /// Generates a new SPHINCS+ key pair for this identity and stores it
    /// for later use in signatures and verification.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If key initialization was successful
    /// * `Err(DsmError)` - If key generation failed
    pub fn initialize_keys(&self) -> Result<(), DsmError> {
        // Generate a new SPHINCS+ key pair for signatures
        let keypair = SignatureKeyPair::generate()?;

        // Store the key pair
        let mut key_guard = self.signing_keypair.write().unwrap();
        *key_guard = Some(keypair);

        Ok(())
    }

    /// Get the current identity's public key
    ///
    /// Retrieves the public key component of this identity's signing key pair.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The public key if available
    /// * `Err(DsmError)` - If no keys are available
    pub fn get_public_key(&self) -> Result<Vec<u8>, DsmError> {
        let key_guard = self.signing_keypair.read().unwrap();

        match &*key_guard {
            Some(keypair) => Ok(keypair.public_key.clone()),
            None => Err(DsmError::crypto(
                "No signing keys available".to_string(),
                None::<std::io::Error>,
            )),
        }
    }

    /// Sign data using the identity's private key
    ///
    /// Creates a cryptographic signature for the provided data using
    /// the identity's SPHINCS+ private key.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The signature if signing was successful
    /// * `Err(DsmError)` - If signing failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// let data = b"Data to sign";
    /// let signature = identity_sdk.sign_data(data).unwrap();
    /// ```
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        let key_guard = self.signing_keypair.read().unwrap();

        match &*key_guard {
            Some(keypair) => {
                // Use the SignatureKeyPair to sign the data
                keypair.sign(data)
            }
            None => Err(DsmError::crypto(
                "No signing keys available".to_string(),
                None::<std::io::Error>,
            )),
        }
    }

    /// Verify a signature against data
    ///
    /// Verifies that a signature is valid for the provided data using
    /// the identity's public key.
    ///
    /// # Arguments
    ///
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the signature is valid, false otherwise
    /// * `Err(DsmError)` - If verification failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// let data = b"Data to sign";
    /// let signature = identity_sdk.sign_data(data).unwrap();
    /// let is_valid = identity_sdk.verify_signature(data, &signature).unwrap();
    /// assert!(is_valid);
    /// ```
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, DsmError> {
        let key_guard = self.signing_keypair.read().unwrap();

        match &*key_guard {
            Some(keypair) => {
                // Use the SignatureKeyPair to verify the signature
                // Convert the byte slice to a Vec<u8> since that's what the method expects
                let signature_vec = signature.to_vec();
                keypair.verify(data, &signature_vec)
            }
            None => Err(DsmError::crypto(
                "No signing keys available".to_string(),
                None::<std::io::Error>,
            )),
        }
    }

    /// Get the current identity ID
    ///
    /// # Returns
    ///
    /// The identity ID as a String
    pub fn get_identity(&self) -> String {
        self.identity_id.clone()
    }

    /// Create a genesis state for this identity
    ///
    /// Creates the initial genesis state for this identity as described in
    /// section 4 of the DSM whitepaper, establishing the foundation for
    /// all subsequent state transitions.
    ///
    /// # Arguments
    ///
    /// * `device_info` - Information about the device creating the genesis
    /// * `participant_inputs` - Entropy contributions from participants
    /// * `metadata` - Optional metadata to include in the genesis state
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The created genesis state if successful
    /// * `Err(DsmError)` - If genesis creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::state_types::DeviceInfo;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// let device_info = DeviceInfo::new("device1", vec![1, 2, 3, 4]);
    /// let participant_inputs = vec![vec![5, 6, 7, 8]];
    /// let genesis = identity_sdk.create_genesis(
    ///     device_info,
    ///     participant_inputs,
    ///     Some(vec![9, 10, 11, 12])
    /// ).unwrap();
    /// ```
    pub fn create_genesis(
        &self,
        device_info: DeviceInfo,
        participant_inputs: Vec<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    ) -> Result<State, DsmError> {
        // Clone device_id early since we need it twice
        let device_id = device_info.device_id.clone();

        // Generate entropy from participant inputs
        let mut combined_entropy = Vec::new();
        for input in participant_inputs {
            combined_entropy.extend_from_slice(&input);
        }

        // Hash the combined inputs to create the genesis entropy
        let entropy = blake3::hash(&combined_entropy).as_bytes().to_vec();

        // Create a basic genesis state
        let mut state = State::new_genesis(entropy, device_info);

        // Add metadata if provided
        if let Some(meta) = metadata {
            state.add_metadata("metadata", meta)?;
        }

        // Calculate the hash
        let hash = state.compute_hash()?;
        state.hash = hash;

        // Store in the device genesis states
        {
            let mut device_states = self.device_genesis_states.write().unwrap();
            device_states.insert(device_id, state.clone());
        }

        Ok(state)
    }

    /// Create a device-specific sub-genesis state
    ///
    /// Creates a genesis state for a specific device under this identity,
    /// derived from the master genesis state. This implements the hierarchical
    /// device management approach described in section 4 of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `master_genesis` - The master genesis state
    /// * `device_info` - Information about the device
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The created device genesis state if successful
    /// * `Err(DsmError)` - If device genesis creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::state_types::DeviceInfo;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// // First create master genesis
    /// let master_device = DeviceInfo::new("master", vec![1, 2, 3, 4]);
    /// let master_genesis = identity_sdk.create_genesis(
    ///     master_device,
    ///     vec![vec![5, 6, 7, 8]],
    ///     None
    /// ).unwrap();
    ///
    /// // Then create device-specific sub-genesis
    /// let device_info = DeviceInfo::new("phone", vec![9, 10, 11, 12]);
    /// let device_genesis = identity_sdk.create_device_genesis(
    ///     &master_genesis,
    ///     device_info
    /// ).unwrap();
    /// ```
    pub fn create_device_genesis(
        &self,
        master_genesis: &State,
        device_info: DeviceInfo,
    ) -> Result<State, DsmError> {
        // Clone device_info early since we need it twice
        let device_id = device_info.device_id.clone();

        // Derive entropy from master genesis
        let mut hasher = blake3::Hasher::new();
        hasher.update(&master_genesis.entropy);
        hasher.update(device_id.as_bytes());
        let device_entropy = hasher.finalize().as_bytes().to_vec();

        // Create a new sub-genesis state
        let mut state = State::new_genesis(device_entropy, device_info);

        // Link to master genesis through metadata
        let master_link_key = "master_genesis_hash";

        // Store master genesis hash in metadata
        let metadata = master_genesis.hash.clone();
        state.add_metadata(master_link_key, metadata)?;

        // Calculate hash
        let hash = state.compute_hash()?;
        state.hash = hash;

        // Store in device genesis states
        {
            let mut device_states = self.device_genesis_states.write().unwrap();
            device_states.insert(device_id, state.clone());
        }

        Ok(state)
    }

    /// Create a pre-commitment for a future operation
    ///
    /// Creates a cryptographic commitment to a future operation without
    /// revealing the operation details, as described in section 8 of the
    /// DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `operation` - The operation to create a pre-commitment for
    /// * `counterparty_id` - Optional ID of the counterparty in a bilateral operation
    /// * `fixed_params` - Optional fixed parameters for the commitment
    /// * `variable_params` - Optional variable parameters for the commitment
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The pre-commitment if successful
    /// * `Err(DsmError)` - If pre-commitment creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::operations::Operation;
    /// use std::sync::Arc;
    ///
    /// // Create a pre-commitment for a future operation
    /// fn create_commitment(sdk: &IdentitySDK, operation: &Operation) {
    ///     let pre_commitment = sdk.create_pre_commitment(
    ///         operation,
    ///         Some("counterparty123".into()),
    ///         Some(vec![1, 2, 3]),
    ///         Some(vec![4, 5, 6])
    ///     ).unwrap();
    ///     
    ///     // The pre-commitment can be shared and later verified
    ///     // when the operation is executed
    /// }
    /// ```
    pub fn create_pre_commitment(
        &self,
        operation: &Operation,
        counterparty_id: Option<String>,
        fixed_params: Option<Vec<u8>>,
        variable_params: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, DsmError> {
        // Get current state
        let current_state = self
            .hash_chain_sdk
            .current_state()
            .ok_or_else(|| DsmError::state("No current state available for pre-commitment"))?;

        // Serialize the operation
        let operation_bytes = bincode::serialize(operation).map_err(|e| {
            DsmError::serialization("Failed to serialize operation for pre-commitment", Some(e))
        })?;

        // Calculate next entropy based on the deterministic formula en+1 = H(en || opn+1 || n+1)
        let mut entropy_hasher = blake3::Hasher::new();
        entropy_hasher.update(&current_state.entropy);
        entropy_hasher.update(&operation_bytes);
        entropy_hasher.update(&(current_state.state_number + 1).to_le_bytes());
        let next_entropy = entropy_hasher.finalize();

        // Create parameters for pre-commitment
        let mut params = Vec::new();
        if let Some(counter_id) = counterparty_id {
            params.extend_from_slice(counter_id.as_bytes());
        }
        if let Some(fixed) = fixed_params {
            params.extend_from_slice(&fixed);
        }
        if let Some(variable) = variable_params {
            params.extend_from_slice(&variable);
        }

        // Create the pre-commitment as Cpre = H(H(Sn) || opn+1 || en+1 || params)
        let mut pre_commitment_hasher = blake3::Hasher::new();
        pre_commitment_hasher.update(&current_state.hash);
        pre_commitment_hasher.update(&operation_bytes);
        pre_commitment_hasher.update(next_entropy.as_bytes());
        pre_commitment_hasher.update(&params);

        let pre_commitment = pre_commitment_hasher.finalize().as_bytes().to_vec();

        Ok(pre_commitment)
    }

    /// Verify a pre-commitment against an operation
    ///
    /// Verifies that a pre-commitment matches the provided operation,
    /// confirming that the operation matches what was previously committed to.
    ///
    /// # Arguments
    ///
    /// * `pre_commitment` - The pre-commitment to verify
    /// * `operation` - The operation to verify against the pre-commitment
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the pre-commitment is valid, false otherwise
    /// * `Err(DsmError)` - If verification failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use dsm::types::operations::Operation;
    /// use std::sync::Arc;
    ///
    /// // Verify a pre-commitment against an operation
    /// fn verify_commitment(sdk: &IdentitySDK, pre_commitment: &[u8], operation: &Operation) {
    ///     let is_valid = sdk.verify_pre_commitment(pre_commitment, operation).unwrap();
    ///     assert!(is_valid, "Pre-commitment verification failed");
    /// }
    /// ```
    pub fn verify_pre_commitment(
        &self,
        pre_commitment: &[u8],
        operation: &Operation,
    ) -> Result<bool, DsmError> {
        // Regenerate the pre-commitment using the same logic
        let regenerated = self.create_pre_commitment(
            operation,
            None, // Simplified for verification - in real implementation, these would be retrieved from context
            None, None,
        )?;

        // Compare using constant-time equality to prevent timing attacks
        Ok(constant_time_eq::constant_time_eq(
            pre_commitment,
            &regenerated,
        ))
    }

    /// Create a relationship context with another identity
    ///
    /// Establishes a bilateral relationship context with another identity,
    /// enabling secure state transitions in the context of that relationship
    /// as described in section 7 of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `counterparty_id` - The ID of the counterparty identity
    /// * `counterparty_public_key` - The public key of the counterparty
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If relationship creation was successful
    /// * `Err(DsmError)` - If relationship creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::identity_sdk::IdentitySDK;
    /// use dsm_sdk::hashchain_sdk::HashChainSDK;
    /// use std::sync::Arc;
    ///
    /// let hash_chain_sdk = Arc::new(HashChainSDK::new());
    /// let identity_sdk = IdentitySDK::new("user123".into(), hash_chain_sdk);
    ///
    /// // Create relationship with another identity
    /// identity_sdk.create_relationship_context(
    ///     "user456",
    ///     vec![1, 2, 3, 4]  // Public key
    /// ).unwrap();
    /// ```
    pub fn create_relationship_context(
        &self,
        counterparty_id: &str,
        counterparty_public_key: Vec<u8>,
    ) -> Result<(), DsmError> {
        let current_state = self.hash_chain_sdk.current_state().ok_or_else(|| {
            DsmError::state("No current state available for relationship creation")
        })?;

        let context = ExtendedRelationshipContext {
            entity_state_number: current_state.state_number,
            counterparty_id: counterparty_id.to_string(),
            counterparty_state_number: 0, // Initial state
            counterparty_public_key,
            current_state_hash: current_state.hash.clone(),
            state_sequence: vec![current_state.hash.clone()],
            metadata: HashMap::new(),
            last_interaction: chrono::Utc::now().timestamp() as u64,
        };

        // Store the relationship context
        {
            let mut contexts = self.relationship_contexts.write().unwrap();
            contexts.insert(counterparty_id.to_string(), context);
        }

        Ok(())
    }

    /// Get a relationship context by counterparty ID
    ///
    /// Retrieves the bilateral relationship context for a specific counterparty.
    ///
    /// # Arguments
    ///
    /// * `counterparty_id` - The ID of the counterparty
    ///
    /// # Returns
    ///
    /// * `Some(ExtendedRelationshipContext)` - The relationship context if found
    /// * `None` - If no relationship exists with the counterparty
    pub fn get_relationship_context(
        &self,
        counterparty_id: &str,
    ) -> Option<ExtendedRelationshipContext> {
        let contexts = self.relationship_contexts.read().unwrap();
        contexts.get(counterparty_id).cloned()
    }

    /// Invalidate a state in the chain
    ///
    /// Creates an invalidation operation for a specific state,
    /// implementing the tombstone mechanism described in section 9
    /// of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `_state_number` - The number of the state to invalidate
    /// * `reason` - The reason for invalidation
    /// * `proof` - Proof data justifying the invalidation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The invalidation operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn invalidate_state(
        &self,
        _state_number: u64,
        reason: &str,
        proof: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Invalidate {
            reason: reason.to_string(),
            proof,
            mode: TransactionMode::Bilateral, // Use Bilateral mode for invalidation
        })
    }

    /// Create a generic identity operation
    ///
    /// Creates a generic operation for this identity with the specified
    /// data and message.
    ///
    /// # Arguments
    ///
    /// * `_operation_type` - The type of operation
    /// * `data` - The operation data
    /// * `message` - A descriptive message for the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn create_generic_operation(
        &self,
        _operation_type: &str,
        data: Vec<u8>,
        message: String,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message,
            identity_data: data,
            public_key: vec![],
            metadata: vec![],
            commitment: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral, // Use Bilateral mode
        })
    }

    /// Create an operation to add a relationship
    ///
    /// Creates an operation that establishes a relationship between identities,
    /// as described in section 7 of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `from_id` - The source identity ID
    /// * `to_id` - The target identity ID
    /// * `relationship_type` - The type of relationship
    /// * `metadata` - Additional metadata for the relationship
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The relationship operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn relationship_operation(
        &self,
        from_id: String,
        to_id: String,
        relationship_type: String,
        metadata: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::AddRelationship {
            message: format!("Add relationship from {} to {}", from_id, to_id),
            from_id,
            to_id,
            relationship_type,
            metadata,
            proof: vec![],
            mode: TransactionMode::Bilateral, // Use Bilateral mode
        })
    }

    /// Create an operation to remove a relationship
    ///
    /// Creates an operation that removes an established relationship between identities.
    ///
    /// # Arguments
    ///
    /// * `from` - The source identity ID
    /// * `to` - The target identity ID
    /// * `rel_type` - The type of relationship
    /// * `proof_data` - Proof data justifying the removal
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The relationship removal operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn remove_relationship_operation(
        &self,
        from: &str,
        to: &str,
        rel_type: String,
        proof_data: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::RemoveRelationship {
            from_id: from.to_string(),
            to_id: to.to_string(),
            relationship_type: rel_type,
            proof: proof_data,
            mode: TransactionMode::Bilateral,
            message: format!("Remove relationship from {} to {}", from, to),
        })
    }

    /// Create an identity recovery operation
    ///
    /// Creates an operation for recovering from identity compromise,
    /// implementing the recovery mechanism described in section 9
    /// of the DSM whitepaper.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the identity to recover
    /// * `auth_sigs` - Authority signatures authorizing the recovery
    /// * `comp_proof` - Proof of compromise
    /// * `invalid_data` - Data about the invalidation
    /// * `_sig_data` - Signature data (unused parameter)
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The recovery operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn recovery_operation(
        &self,
        id: &str,
        auth_sigs: Vec<Vec<u8>>,
        comp_proof: Vec<u8>,
        invalid_data: Vec<u8>,
        _sig_data: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        // Create a Recovery operation with the necessary parameters
        Ok(Operation::Recovery {
            message: format!("Identity recovery for {}", id),
            invalidation_data: invalid_data,
            new_state_data: vec![], // Would be populated in a real implementation
            new_state_number: 0,    // Would be derived from current state
            new_state_hash: vec![], // Would be computed in a real implementation
            new_state_entropy: vec![], // Would be derived from secure sources
            compromise_proof: comp_proof,
            authority_sigs: auth_sigs,
            state_entropy: vec![],     // Would be derived from current state
            state_number: 0,           // Would be derived from current state
            state_hash: vec![0u8; 32], // Would be derived from current state
        })
    }
}
