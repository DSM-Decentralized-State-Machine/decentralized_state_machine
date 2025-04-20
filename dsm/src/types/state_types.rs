use crate::crypto::blake3::hash_blake3;
use crate::merkle::sparse_merkle_tree::SparseMerkleTreeImpl;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::operations::TransactionMode;
use crate::types::token_types::Balance;
use blake3::{self, Hash};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;

/// Parameters for creating a MerkleProof
#[derive(Clone, Debug)]
pub struct MerkleProofParams {
    pub path: Vec<SerializableHash>,
    pub index: u64,
    pub leaf_hash: SerializableHash,
    pub root_hash: SerializableHash,
    pub height: u32,
    pub leaf_count: u64,
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub sparse_index: SparseIndex,
    pub token_balances: HashMap<String, Balance>,
    pub proof: Vec<u8>,
    pub mode: TransactionMode,
    pub params: Vec<u8>,
}

/// Parameters for initializing a State
#[derive(Clone, Debug)]
pub struct StateParams {
    pub state_number: u64,
    pub entropy: Vec<u8>,
    pub encapsulated_entropy: Option<Vec<u8>>,
    pub prev_state_hash: Vec<u8>,
    pub sparse_index: SparseIndex,
    pub operation: Operation,
    pub device_info: DeviceInfo,
    pub forward_commitment: Option<PreCommitment>,
    pub matches_parameters: bool,
    pub state_type: String,
    pub value: Vec<i32>,
    pub commitment: Vec<i32>,
    pub previous_hash: Vec<u8>,
    #[allow(dead_code)]
    pub(crate) none_field: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub(crate) metadata: Vec<u8>,
    #[allow(dead_code)]
    pub(crate) token_balance: Option<Balance>,
    #[allow(dead_code)]
    pub(crate) signature: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub(crate) version: i32,
    #[allow(dead_code)]
    pub(crate) forward_link: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub(crate) large_state: Box<State>,
    #[allow(dead_code)]
    pub entity_sig: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub counterparty_sig: Option<Vec<u8>>,
}

impl StateParams {
    /// Create a new state parameters object
    pub fn new(
        state_number: u64,
        entropy: Vec<u8>,
        operation: Operation,
        device_info: DeviceInfo,
    ) -> Self {
        Self {
            state_number,
            entropy,
            encapsulated_entropy: None,
            prev_state_hash: vec![0u8; 32],
            sparse_index: SparseIndex::default(),
            operation,
            device_info,
            forward_commitment: None,
            matches_parameters: false,
            state_type: "standard".to_string(),
            value: Vec::new(),
            commitment: Vec::new(),
            previous_hash: vec![0u8; 32],
            none_field: None,
            metadata: Vec::new(),
            token_balance: None,
            signature: None,
            version: 0,
            forward_link: None,
            large_state: Box::new(State::default()),
            entity_sig: None,
            counterparty_sig: None,
        }
    }

    /// Set encapsulated entropy
    pub fn with_encapsulated_entropy(mut self, encapsulated_entropy: Vec<u8>) -> Self {
        self.encapsulated_entropy = Some(encapsulated_entropy);
        self
    }

    /// Set previous state hash
    pub fn with_prev_state_hash(mut self, prev_state_hash: Vec<u8>) -> Self {
        self.prev_state_hash = prev_state_hash;
        self
    }

    /// Set sparse index
    pub fn with_sparse_index(mut self, sparse_index: SparseIndex) -> Self {
        self.sparse_index = sparse_index;
        self
    }

    /// Set forward commitment
    pub fn with_forward_commitment(mut self, forward_commitment: PreCommitment) -> Self {
        self.forward_commitment = Some(forward_commitment);
        self
    }
}

/// A serializable wrapper around blake3::Hash
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializableHash(Hash);

impl SerializableHash {
    /// Create a new SerializableHash from a Hash
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Get the inner Hash
    pub fn inner(&self) -> &Hash {
        &self.0
    }

    /// Unwrap the SerializableHash into the inner Hash
    pub fn into_inner(self) -> Hash {
        self.0
    }
}

impl From<Hash> for SerializableHash {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<SerializableHash> for Hash {
    fn from(hash: SerializableHash) -> Self {
        hash.0
    }
}

impl AsRef<Hash> for SerializableHash {
    fn as_ref(&self) -> &Hash {
        &self.0
    }
}

impl Serialize for SerializableHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the Hash as a byte array
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for SerializableHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashVisitor;

        impl<'de> Visitor<'de> for HashVisitor {
            type Value = SerializableHash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array representing a blake3 hash")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != 32 {
                    return Err(E::custom(format!(
                        "Expected 32 bytes for blake3 hash, got {}",
                        v.len()
                    )));
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(v);
                Ok(SerializableHash(Hash::from_bytes(bytes)))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    match seq.next_element()? {
                        Some(b) => *byte = b,
                        None => return Err(de::Error::invalid_length(i, &self)),
                    }
                }
                Ok(SerializableHash(Hash::from_bytes(bytes)))
            }
        }

        deserializer.deserialize_bytes(HashVisitor)
    }
}

/// Device identification and cryptographic information
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DeviceInfo {
    /// Unique identifier for the device
    pub device_id: String,
    /// Public key associated with the device
    pub public_key: Vec<u8>,
}

// Default implementation is now derived through #[derive(Default)]

impl DeviceInfo {
    /// Create a new DeviceInfo instance
    ///
    /// # Arguments
    /// * `device_id` - Unique identifier for the device
    /// * `public_key` - Public key associated with the device
    pub fn new(device_id: &str, public_key: Vec<u8>) -> Self {
        Self {
            device_id: device_id.to_string(),
            public_key,
        }
    }
}

/// Represents the core state structure as defined in the whitepaper.
/// Each state forms a node in the straight hash chain, containing all
/// necessary data to cryptographically bind it to its predecessor.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct State {
    /// Unique identifier for this state, typically using the format "state_{state_number}"
    pub id: String,

    /// State sequence number, monotonically increasing as per whitepaper Section 6.1
    pub state_number: u64,

    /// Current entropy value, evolved deterministically as per whitepaper Section 6
    pub entropy: Vec<u8>,

    /// Cryptographic hash of this state
    pub hash: Vec<u8>,

    /// Hash of the previous state, creating the cryptographic chain as per Section 3.1
    pub prev_state_hash: Vec<u8>,

    /// Sparse index for efficient lookups as per whitepaper Section 3.2
    pub sparse_index: SparseIndex,

    /// Operation performed in this state transition
    pub operation: Operation,

    /// Kyber-encapsulated entropy for quantum resistance as per whitepaper Section 6
    pub encapsulated_entropy: Option<Vec<u8>>,

    /// Device information
    pub device_info: DeviceInfo,

    /// State flags for additional metadata
    pub flags: HashSet<StateFlag>,

    /// Token balances integrated directly in state transition as per whitepaper Section 9
    /// Maps token identifiers to balances, format: "owner_id:token_id" -> Balance
    pub token_balances: HashMap<String, Balance>,

    /// Matches parameters in the state transition
    pub matches_parameters: bool,

    /// Relationship context for tracking state relationships
    pub relationship_context: Option<RelationshipContext>,
    pub(crate) forward_commitment: Option<PreCommitment>,
    pub(crate) position_sequence: Option<PositionSequence>,
    pub(crate) positions: Vec<Vec<i32>>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) device_id: String,
    hashchain_head: Option<Vec<u8>>,
    external_data: HashMap<String, Vec<u8>>,
    pub(crate) entity_sig: Option<Vec<u8>>,
    pub(crate) counterparty_sig: Option<Vec<u8>>,
    pub(crate) value: Vec<i32>,
    pub(crate) commitment: Vec<i32>,
    pub(crate) state_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub enum StateFlag {
    Recovered,
    Compromised,
    Invalidated,
    Synced,
    Custom(String),
}

impl State {
    /// Create a new state using the parameter object pattern
    ///
    /// # Arguments
    /// * `params` - StateParams containing all necessary components for state initialization
    ///
    /// # Returns
    /// A new State initialized with the provided parameters
    pub fn new(params: StateParams) -> Self {
        let public_key = params.device_info.public_key.clone();
        Self {
            id: format!("state_{}", params.state_number),
            state_number: params.state_number,
            entropy: params.entropy,
            hash: Vec::new(), // Will be computed after construction
            prev_state_hash: params.prev_state_hash,
            sparse_index: params.sparse_index,
            operation: params.operation,
            encapsulated_entropy: params.encapsulated_entropy,
            device_id: params.device_info.device_id.clone(),
            device_info: params.device_info,
            flags: HashSet::new(),
            token_balances: HashMap::new(),
            relationship_context: None,
            forward_commitment: params.forward_commitment,
            positions: Vec::new(),
            position_sequence: None,
            public_key,
            matches_parameters: params.matches_parameters,
            hashchain_head: None,
            external_data: HashMap::new(),
            value: params.value,
            commitment: params.commitment,
            entity_sig: None,
            counterparty_sig: None,
            state_type: params.state_type,
        }
    }

    /// Create a new genesis state (state_number = 0)
    ///
    /// # Arguments
    /// * `initial_entropy` - Initial entropy for the genesis state
    /// * `device_info` - Device information
    pub fn new_genesis(initial_entropy: Vec<u8>, device_info: DeviceInfo) -> Self {
        let mut flags = HashSet::new();
        flags.insert(StateFlag::Recovered);
        let public_key = device_info.public_key.clone();

        let operation = Operation::Create {
            message: "Genesis state creation".to_string(),
            identity_data: Vec::new(),
            public_key: public_key.clone(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: TransactionMode::Bilateral,
        };

        Self {
            id: "genesis".to_string(),
            state_number: 0,
            entropy: initial_entropy,
            hash: Vec::new(),
            prev_state_hash: Vec::new(),
            sparse_index: SparseIndex::new(Vec::new()),
            operation,
            encapsulated_entropy: None,
            device_info: device_info.clone(),
            flags,
            token_balances: HashMap::new(), // Initialize empty token balances
            relationship_context: None,
            forward_commitment: None,
            positions: Vec::new(),
            position_sequence: None,
            public_key,
            matches_parameters: false,
            device_id: device_info.device_id.clone(),
            hashchain_head: None,
            external_data: HashMap::new(),
            value: Vec::new(),
            commitment: Vec::new(),
            entity_sig: None,
            counterparty_sig: None,
            state_type: String::from("standard"),
        }
    }

    pub fn with_relationship_context(
        mut self,
        counterparty_id: String,
        counterparty_state_number: u64,
        counterparty_public_key: Vec<u8>,
    ) -> Self {
        self.relationship_context = Some(RelationshipContext {
            entity_id: self.device_id.clone(),
            entity_state_number: self.state_number,
            counterparty_id,
            counterparty_state_number,
            counterparty_public_key,
            relationship_hash: Vec::new(),
            active: true,
        });
        self
    }

    pub fn in_relationship_with(&self, counterparty_id: &str) -> bool {
        self.relationship_context
            .as_ref()
            .map(|ctx| ctx.counterparty_id == counterparty_id)
            .unwrap_or(false)
    }

    pub fn get_counterparty_state(&self) -> Option<u64> {
        self.relationship_context
            .as_ref()
            .map(|ctx| ctx.counterparty_state_number)
    }

    pub fn is_genesis(&self) -> bool {
        self.flags.contains(&StateFlag::Recovered)
    }

    pub fn is_invalidated(&self) -> bool {
        self.flags.contains(&StateFlag::Invalidated)
    }

    pub fn has_pending_commitment(&self) -> bool {
        self.flags.contains(&StateFlag::Compromised)
    }

    pub fn add_flag(&mut self, flag: StateFlag) {
        self.flags.insert(flag);
    }

    /// Add metadata to the state's external data
    pub fn add_metadata(&mut self, key: &str, value: Vec<u8>) -> Result<(), DsmError> {
        self.external_data.insert(key.to_string(), value);
        Ok(())
    }

    /// Calculate the hash of this state, as specified in whitepaper Section 3.1
    ///
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - The calculated hash or an error
    pub fn hash(&self) -> Result<Vec<u8>, DsmError> {
        // If hash is already calculated, return it
        if self.hash.is_empty() {
            return self.compute_hash();
        }
        Ok(self.hash.clone())
    }

    /// Compute the hash of this state
    pub fn compute_hash(&self) -> Result<Vec<u8>, DsmError> {
        let mut hasher = blake3::Hasher::new();

        // Core state properties in deterministic order
        hasher.update(&self.state_number.to_le_bytes());
        hasher.update(&self.prev_state_hash);
        hasher.update(&self.entropy);

        // Optional fields
        if let Some(enc) = &self.encapsulated_entropy {
            hasher.update(enc);
        }

        // Deterministic serialization of operation
        let op_bytes = bincode::serialize(&self.operation)
            .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;
        hasher.update(&op_bytes);

        // Include device info
        hasher.update(self.device_info.device_id.as_bytes());
        hasher.update(&self.device_info.public_key);

        // Forward commitment if present
        if let Some(fc) = &self.forward_commitment {
            let fc_bytes = bincode::serialize(fc).map_err(|e| {
                DsmError::serialization("Failed to serialize forward commitment", Some(e))
            })?;
            hasher.update(&fc_bytes);
        }

        // Token balances must be sorted for deterministic ordering
        let mut sorted_balances: Vec<(&String, &Balance)> = self.token_balances.iter().collect();
        sorted_balances.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));
        for (token_id, balance) in sorted_balances {
            hasher.update(token_id.as_bytes());
            let balance_bytes = bincode::serialize(balance)
                .map_err(|e| DsmError::serialization("Failed to serialize balance", Some(e)))?;
            hasher.update(&balance_bytes);
        }

        Ok(hasher.finalize().as_bytes().to_vec())
    }
    
    /// Set the entity signature
    pub fn set_entity_signature(&mut self, signature: Option<Vec<u8>>) {
        self.entity_sig = signature;
    }
    
    /// Set the counterparty signature
    pub fn set_counterparty_signature(&mut self, signature: Option<Vec<u8>>) {
        self.counterparty_sig = signature;
    }
    
    /// Get the entity signature
    pub fn entity_signature(&self) -> Option<&Vec<u8>> {
        self.entity_sig.as_ref()
    }
    
    /// Get the counterparty signature
    pub fn counterparty_signature(&self) -> Option<&Vec<u8>> {
        self.counterparty_sig.as_ref()
    }

    /// Compute the pre-finalization hash that excludes token balances
    pub fn pre_finalization_hash(&self) -> Result<Vec<u8>, DsmError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.state_number.to_le_bytes());
        hasher.update(&self.entropy);
        hasher.update(&self.prev_state_hash);
        hasher.update(
            &bincode::serialize(&self.operation)
                .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?,
        );

        Ok(hasher.finalize().as_bytes().to_vec())
    }
    /// Compute the verification hash that includes token balances for finalized verification
    /// This implements the atomic state update with token integration as per whitepaper Section 9
    pub fn finalized_verification_hash(&self) -> Result<Vec<u8>, DsmError> {
        // Get the pre-finalization hash first
        let pre_hash = self.pre_finalization_hash()?;

        // Now construct the balance verification layer
        let mut balance_data = Vec::new();

        // Add the pre-finalization hash as base layer
        balance_data.extend_from_slice(&pre_hash);

        // Add a domain separator for token balance layer
        balance_data.extend_from_slice(b"TOKEN_BALANCES");

        // Add token balances in a deterministic, canonicalized order (sorted by key)
        // This ensures balance verification while allowing pre-commitment flexibility
        let mut sorted_balances: Vec<(&String, &Balance)> = self.token_balances.iter().collect();
        sorted_balances.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

        for (token_id, balance) in sorted_balances {
            balance_data.extend_from_slice(token_id.as_bytes());
            balance_data.extend_from_slice(&bincode::serialize(balance).unwrap());
        }

        // Calculate final hash including balance data
        Ok(hash_blake3(&balance_data).as_bytes().to_vec())
    }

    /// Get the value of this sparse index
    ///
    /// # Returns
    /// * `u64` - Deterministic value derived from the indices
    pub fn value(&self) -> u64 {
        // Hash all indices together to get a deterministic value
        let mut hasher = blake3::Hasher::new();
        let mut sorted_indices: Vec<usize> = self
            .sparse_index
            .indices
            .iter()
            .map(|&x| x as usize)
            .collect();
        sorted_indices.sort(); // Sort indices for deterministic ordering
        hasher.update(&self.state_number.to_le_bytes());

        // Sort for deterministic ordering

        for idx in sorted_indices {
            hasher.update(&idx.to_le_bytes());
        }

        u64::from_le_bytes(hasher.finalize().as_bytes()[0..8].try_into().unwrap())
    }

    /// Calculate sparse indices for a given state number as described in whitepaper Section 3.2
    ///
    /// This implementation follows the mathematical model from whitepaper Section 3.2,
    /// creating a logarithmic set of reference points for efficient state traversal.
    /// Critical references (genesis and direct predecessor) are guaranteed to be included
    /// for consistent hash chain verification.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, DsmError>` - Calculated indices
    pub fn calculate_sparse_indices(state_number: u64) -> Result<Vec<u64>, DsmError> {
        // First, calculate basic sparse indices using powers of 2 algorithm
        let mut indices = Self::calculate_basic_sparse_indices(state_number)?;

        // Critical reference guarantee: Always include genesis state (0)
        if state_number > 0 && !indices.contains(&0) {
            indices.push(0);
        }

        // Critical reference guarantee: Always include direct predecessor
        if state_number > 0 && !indices.contains(&(state_number - 1)) {
            indices.push(state_number - 1);
        }

        // Ensure deterministic ordering for verification consistency
        indices.sort_unstable();
        indices.dedup();

        Ok(indices)
    }

    /// Calculate basic sparse indices using powers of 2 distance algorithm
    ///
    /// This implements the power-of-2 checkpoint mechanism described in whitepaper Section 3.2,
    /// providing logarithmic-complexity state traversal.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, DsmError>` - Calculated basic indices
    fn calculate_basic_sparse_indices(state_number: u64) -> Result<Vec<u64>, DsmError> {
        if state_number == 0 {
            return Ok(Vec::new());
        }

        let mut indices = Vec::new();
        let mut power = 0;

        // Generate power-of-2 distance references
        while (1 << power) <= state_number {
            let idx = state_number - (1 << power);
            indices.push(idx);
            power += 1;
        }

        Ok(indices)
    }

    pub fn new_with_operation(prev_state: &Self, operation: Operation) -> Result<Self, DsmError> {
        // Serialize the operation for deterministic entropy evolution
        let op_bytes = bincode::serialize(&operation)
            .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;

        // Combine previous entropy and the serialized operation to derive new entropy
        let mut combined = prev_state.entropy.clone();
        combined.extend_from_slice(&op_bytes);
        let new_entropy = hash_blake3(&combined).as_bytes().to_vec();

        // Derive the new hash by combining the new entropy with the previous state hash
        let mut hash_input = new_entropy.clone();
        hash_input.extend_from_slice(&prev_state.hash);
        let new_hash = hash_blake3(&hash_input).as_bytes().to_vec();

        // Calculate the sparse index for the new state
        let sparse_index_vec = SparseIndex::calculate_sparse_indices(prev_state.state_number + 1)?;
        let sparse_index = SparseIndex::new(sparse_index_vec);

        let new_hash_cloned = new_hash.clone();
        Ok(State {
            id: format!("state_{}", prev_state.state_number + 1),
            state_number: prev_state.state_number + 1,
            entropy: new_entropy,
            hash: new_hash,
            prev_state_hash: prev_state.hash.clone(),
            sparse_index,
            operation,
            encapsulated_entropy: None,
            device_info: prev_state.device_info.clone(),
            flags: HashSet::new(),
            token_balances: prev_state.token_balances.clone(),
            matches_parameters: false,
            relationship_context: None,
            forward_commitment: None,
            position_sequence: None,
            positions: Vec::new(),
            public_key: prev_state.device_info.public_key.clone(),
            device_id: prev_state.device_info.device_id.clone(),
            hashchain_head: Some(new_hash_cloned),
            external_data: HashMap::new(),
            entity_sig: None,
            counterparty_sig: None,
            value: Vec::new(),
            commitment: Vec::new(),
            state_type: String::from("benchmark"),
        })
    }

    /// Set the forward commitment for this state
    pub fn set_forward_commitment(&mut self, commitment: Option<PreCommitment>) {
        self.forward_commitment = commitment;
    }

    /// Get the forward commitment from this state
    pub fn get_forward_commitment(&self) -> Option<&PreCommitment> {
        self.forward_commitment.as_ref()
    }

    /// Get a parameter value from the state
    pub fn get_parameter(&self, key: &str) -> Option<&Vec<u8>> {
        // Extract parameter from external data
        if let Some(value) = self.external_data.get(key) {
            return Some(value);
        }

        // If parameter is not found in external data, check operation-specific fields
        match &self.operation {
            Operation::Transfer { .. } if key == "token_id" => {
                // If token_id is already in external_data, return it
                if let Some(value) = self.external_data.get("token_id") {
                    return Some(value);
                }

                // For immutable access, we can't store the token_bytes in external_data
                // A mutable method would be needed for that functionality
                // Just return None since we can't store the computed value
                None
            }
            Operation::AddRelationship { .. } if key == "relationship_type" => {
                if let Some(value) = self.external_data.get("relationship_type") {
                    Some(value)
                } else {
                    // Return None since we can't create a reference to a temporary value
                    // The caller would need to use a mutable method to store this value
                    None
                }
            }
            _ => None,
        }
    }
}

/// SparseIndex represents a sparse index for efficient lookups
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseIndex {
    /// Indices for efficient lookups
    pub indices: Vec<u64>,
}

impl SparseIndex {
    /// Create a new sparse index with the given indices
    pub fn new(indices: Vec<u64>) -> Self {
        Self { indices }
    }

    /// Calculate a deterministic value from the indices
    pub fn value(&self) -> u64 {
        // Hash all indices together to get a deterministic value
        let mut hasher = blake3::Hasher::new();
        let mut sorted_indices = self.indices.clone();
        sorted_indices.sort(); // Sort for deterministic ordering

        for idx in sorted_indices {
            hasher.update(&idx.to_le_bytes());
        }

        u64::from_le_bytes(hasher.finalize().as_bytes()[0..8].try_into().unwrap())
    }

    /// Create a new SparseIndex with the given indices
    pub fn with_indices(mut self, indices: Vec<u64>) -> Self {
        self.indices = indices;
        self
    }

    /// Calculate sparse indices for a given state number as described in whitepaper Section 3.2
    ///
    /// This implementation follows the mathematical model from whitepaper Section 3.2,
    /// creating a logarithmic set of reference points for efficient state traversal.
    /// Critical references (genesis and direct predecessor) are guaranteed to be included
    /// for consistent hash chain verification.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, crate::types::error::DsmError>` - Calculated indices
    pub fn calculate_sparse_indices(
        state_number: u64,
    ) -> Result<Vec<u64>, crate::types::error::DsmError> {
        // First, calculate basic sparse indices using powers of 2 algorithm
        let mut indices = Self::calculate_basic_sparse_indices(state_number)?;

        // Critical reference guarantee: Always include genesis state (0)
        if state_number > 0 && !indices.contains(&0) {
            indices.push(0);
        }

        // Critical reference guarantee: Always include direct predecessor
        if state_number > 0 && !indices.contains(&(state_number - 1)) {
            indices.push(state_number - 1);
        }

        // Ensure deterministic ordering for verification consistency
        indices.sort_unstable();
        indices.dedup();

        Ok(indices)
    }

    /// Calculate basic sparse indices using powers of 2 distance algorithm
    ///
    /// This implements the power-of-2 checkpoint mechanism described in whitepaper Section 3.2,
    /// providing logarithmic-complexity state traversal.
    ///
    /// # Arguments
    /// * `state_number` - State number to calculate indices for
    ///
    /// # Returns
    /// * `Result<Vec<u64>, crate::types::error::DsmError>` - Calculated basic indices
    fn calculate_basic_sparse_indices(
        state_number: u64,
    ) -> Result<Vec<u64>, crate::types::error::DsmError> {
        if state_number == 0 {
            return Ok(Vec::new());
        }

        let mut indices = Vec::new();
        let mut power = 0;

        // Generate power-of-2 distance references
        while (1 << power) <= state_number {
            let idx = state_number - (1 << power);
            indices.push(idx);
            power += 1;
        }

        Ok(indices)
    }
}

impl Default for SparseIndex {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Serializable Merkle proof for efficient inclusion verification
pub struct SerializableMerkleProof {
    /// Root of the Merkle tree
    pub root: Vec<u8>,

    /// Proof elements
    pub proof: Vec<Vec<u8>>,

    /// Root hash for backward compatibility
    pub root_hash: SerializableHash,
}

impl SerializableMerkleProof {
    /// Create a new serializable Merkle proof
    ///
    /// # Arguments
    /// * `root` - Root of the Merkle tree
    /// * `proof` - Proof elements
    pub fn new(root: Vec<u8>, proof: Vec<Vec<u8>>) -> Self {
        // Create a SerializableHash from the root
        let root_hash = SerializableHash::new(blake3::hash(&root));

        Self {
            root,
            proof,
            root_hash,
        }
    }

    /// Get proof bytes for verification
    pub fn proof_bytes(&self) -> Vec<u8> {
        self.root_hash.inner().as_bytes().to_vec()
    }

    /// Serialize this proof
    ///
    /// # Returns
    /// * `Vec<u8>` - Serialized proof
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Add the root hash
        result.extend_from_slice(&self.root);

        // Add all proofs
        for hash in &self.proof {
            result.extend_from_slice(hash);
        }

        result
    }

    /// Verify this proof against a leaf hash
    ///
    /// # Arguments
    /// * `leaf_hash` - Leaf hash to verify
    ///
    /// # Returns
    /// * `bool` - True if the proof is valid, false otherwise
    pub fn verify(&self, leaf_hash: &[u8]) -> bool {
        // Start with the leaf hash
        let mut current_hash = leaf_hash.to_vec();

        // Apply each proof element to verify path to root
        for proof_element in &self.proof {
            // Hash the current hash with the proof element
            let mut hasher = blake3::Hasher::new();
            hasher.update(&current_hash);
            hasher.update(proof_element);
            current_hash = hasher.finalize().as_bytes().to_vec();
        }

        // Verify that we arrived at the expected root
        current_hash == self.root
    }
}

/// Represents a proof of inclusion in a Sparse Merkle Tree
/// This structure contains the minimal set of hashes needed to
/// reconstruct the path from a leaf to the root, as described in whitepaper Section 3.3
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Path from leaf to root, containing sibling hashes
    pub path: Vec<SerializableHash>,

    /// Leaf position in the tree
    pub index: u64,

    /// Hash of the leaf node
    pub leaf_hash: SerializableHash,

    /// Hash of the root node
    pub root_hash: SerializableHash,

    /// Height of the tree
    pub height: u32,

    /// Total number of leaves in the tree
    pub leaf_count: u64,

    /// Device ID associated with this proof
    pub device_id: String,

    /// Public key associated with this proof
    pub public_key: Vec<u8>,

    /// Sparse index for efficient lookups
    pub sparse_index: SparseIndex,

    /// Token balances associated with this proof
    pub token_balances: HashMap<String, Balance>,

    /// Transaction mode for this proof
    pub mode: TransactionMode,

    pub(crate) root: SerializableHash,
    pub(crate) siblings: Vec<SerializableHash>,
    pub(crate) data: Vec<u8>,
    pub(crate) proof: Vec<SerializableHash>,
    pub(crate) proof_leaf_count: i32,
    pub(crate) proof_index: i32,
    pub(crate) proof_height: i32,
    pub(crate) proof_token_balances: HashMap<String, Balance>,
    pub(crate) proof_device_id: String,
}

impl MerkleProof {
    /// Generate a Merkle proof for the specified leaf index in the tree
    ///
    /// # Arguments
    /// * `tree` - The Sparse Merkle Tree containing the data
    /// * `index` - The index of the leaf to generate a proof for
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - The generated proof or an error
    pub fn generate(tree: &SparseMerkleTree, index: u64) -> Result<Self, DsmError> {
        let height = tree.height;
        let mut siblings = Vec::with_capacity(height as usize);

        // Traverse the tree from leaf to root, collecting sibling hashes
        let mut current_index = index;

        for level in (0..height).rev() {
            // Calculate sibling index (flip the bit at current level)
            let sibling_index = current_index ^ (1 << level);

            // Get hash from tree's nodes HashMap if available
            let sibling_hash = tree
                .nodes
                .get(&crate::types::state_types::NodeId {
                    level,
                    index: sibling_index,
                })
                .map(|h| *h.as_bytes())
                .unwrap_or([0u8; 32]);

            siblings.push(SerializableHash::new(blake3::Hash::from_bytes(
                sibling_hash,
            )));

            // Update current_index for next level (clear the bit we just processed)
            current_index &= !(1 << level);
        }

        // Get leaf data from leaves HashMap
        let leaf_hash = match tree.leaves.get(&index) {
            Some(hash) => SerializableHash::new(*hash),
            None => return Err(DsmError::merkle("Leaf data not found")),
        };

        // Create the proof parameters
        let params = MerkleProofParams {
            path: siblings,
            index,
            leaf_hash,
            root_hash: SerializableHash::new(tree.root),
            height,
            leaf_count: tree.leaf_count,
            device_id: String::new(),
            public_key: Vec::new(),
            sparse_index: SparseIndex::new(vec![]),
            token_balances: HashMap::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Bilateral,
            params: Vec::new(),
        };

        Ok(Self::new(params))
    }
    /// Add proof_bytes method for MerkleProof
    ///
    /// Generates the serialized bytes for the proof
    pub fn proof_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Add serialized path elements
        for hash in &self.path {
            bytes.extend_from_slice(hash.inner().as_bytes());
        }

        // Add leaf hash
        bytes.extend_from_slice(self.leaf_hash.inner().as_bytes());

        // Finalize with root hash
        bytes.extend_from_slice(self.root_hash.inner().as_bytes());

        bytes
    }

    /// Verify if the proof is valid by reconstructing the path up to the root
    pub fn verify(&self) -> bool {
        let proof_bytes = self.proof_bytes();
        // Use the constant_time_eq module from crate imports
        crate::core::state_machine::utils::constant_time_eq(
            self.root_hash.inner().as_bytes(),
            &proof_bytes,
        )
    }

    /// Serialize the proof to a byte vector
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        result.extend_from_slice(&self.index.to_le_bytes());
        result.extend_from_slice(self.leaf_hash.inner().as_bytes());
        result.extend_from_slice(self.root_hash.inner().as_bytes());
        result.extend_from_slice(&self.height.to_le_bytes());
        result.extend_from_slice(&self.leaf_count.to_le_bytes());
        result.extend_from_slice(self.device_id.as_bytes());
        result.extend_from_slice(&self.public_key);

        for (token, balance) in &self.token_balances {
            result.extend_from_slice(token.as_bytes());
            result.extend_from_slice(&balance.to_le_bytes());
        }

        result
    }

    /// Create a new MerkleProof with parameters
    pub fn new(params: MerkleProofParams) -> Self {
        // Convert public fields to crate-internal fields
        let root = SerializableHash::new(*params.root_hash.inner());
        let siblings = params.path.clone();
        let data = Vec::new();
        let proof = Vec::new();
        let proof_leaf_count = params.leaf_count as i32;
        let proof_index = params.index as i32;
        let proof_height = params.height as i32;
        let proof_token_balances = HashMap::new();
        let proof_device_id = params.device_id.clone();

        Self {
            path: params.path,
            index: params.index,
            leaf_hash: params.leaf_hash,
            root_hash: params.root_hash,
            height: params.height,
            leaf_count: params.leaf_count,
            device_id: params.device_id,
            public_key: params.public_key,
            sparse_index: params.sparse_index,
            token_balances: params.token_balances,
            root,
            siblings,
            data,
            proof,
            proof_leaf_count,
            proof_index,
            proof_height,
            proof_token_balances,
            proof_device_id,
            mode: TransactionMode::Bilateral, // Use Bilateral mode by default
        }
    }
}

/// Sparse Merkle Tree implementation for efficient inclusion proofs
/// as described in whitepaper Section 3.3
pub struct SparseMerkleTree {
    /// Root hash of the tree
    pub root: Hash,

    /// Map of indexes to leaf hashes
    pub leaves: HashMap<u64, Hash>,

    /// Map of node identifiers to their hash values
    pub nodes: HashMap<NodeId, Hash>,

    /// Height of the tree
    pub height: u32,

    /// Total number of leaves in the tree
    pub leaf_count: u64,
}

impl SparseMerkleTree {
    /// Compute Merkle root hash
    pub fn compute_root(&self) -> Result<Hash, DsmError> {
        let tree_impl = SparseMerkleTreeImpl::from_sparse_merkle_tree(self);
        let root_hash = tree_impl.compute_root()?;
        Ok(root_hash)
    }

    /// Insert a state into the Merkle tree
    pub fn insert(&mut self, key: Vec<u8>, value: State) -> Result<(), DsmError> {
        // Hash the key to get a deterministic index
        let mut hasher = blake3::Hasher::new();
        hasher.update(&key);
        let hash = hasher.finalize();

        // Use the first 8 bytes as a u64 index
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        let index = u64::from_le_bytes(index_bytes);

        // Hash the state to get a leaf hash
        let state_hash = if key.is_empty() {
            // Convert the vector to a Hash object
            let hash_bytes = value.hash()?;
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash_bytes);
            blake3::Hash::from_bytes(bytes)
        } else {
            // Already returns a Hash
            blake3::hash(&key)
        };

        // Store in the tree
        self.leaves.insert(index, state_hash);

        Ok(())
    }

    /// Generate proof for a specific key
    pub fn generate_proof(&self, key: &[u8]) -> Result<Vec<u8>, DsmError> {
        // Hash the key to get a deterministic index
        let mut hasher = blake3::Hasher::new();
        hasher.update(key);
        let hash = hasher.finalize();

        // Use the first 8 bytes as a u64 index
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        let index = u64::from_le_bytes(index_bytes);

        // Create MerkleProof
        let proof = MerkleProof::generate(self, index)?;

        // Serialize the proof to bytes
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|e| DsmError::serialization("Failed to serialize Merkle proof", Some(e)))?;

        Ok(proof_bytes)
    }

    /// Verify a Merkle proof
    pub fn verify_proof(&self, key: &[u8], proof_bytes: &[u8]) -> Result<bool, DsmError> {
        // Deserialize the proof
        let proof: MerkleProof = bincode::deserialize(proof_bytes)
            .map_err(|e| DsmError::serialization("Failed to deserialize Merkle proof", Some(e)))?;

        // Hash the key to get its leaf hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(key);
        let hash = hasher.finalize().as_bytes().to_vec();

        // Verify the proof
        // The verify method doesn't take arguments but works with the internal state
        let verified = proof.verify();

        // Additionally check if leaf hash matches our expected hash
        let leaf_hash_matches = proof.leaf_hash.inner().as_bytes() == hash.as_slice();

        Ok(verified && leaf_hash_matches)
    }

    /// Get the root hash
    pub fn root_hash(&self) -> Vec<u8> {
        self.root.as_bytes().to_vec()
    }
}

/// Internal node identifier for efficient tree operations
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    /// Level in the tree (0 = leaves)
    pub level: u32,

    /// Index within the level
    pub index: u64,
}

impl SparseMerkleTree {
    /// Create a new Sparse Merkle Tree with a given height
    pub fn new(height: u32) -> Self {
        Self {
            root: Hash::from([0u8; 32]), // Initialize root with empty hash
            leaves: HashMap::new(),      // Start with empty leaves
            nodes: HashMap::new(),       // Start with empty nodes
            height,                      // Store the specified height
            leaf_count: 0,               // Start with no leaves
        }
    }

    /// Verify a Merkle proof against a root and leaf hash
    ///
    /// This implementation is called as a standalone function
    pub fn verify_proof_static(
        root: &Hash,
        leaf_hash: &[u8],
        proof: &MerkleProof,
    ) -> Result<bool, DsmError> {
        if !proof.verify() {
            return Ok(false);
        }

        // Verify leaf hash matches
        if proof.leaf_hash.inner().as_bytes() != leaf_hash {
            return Ok(false);
        }

        // Verify root hash matches
        if proof.root_hash.inner() != root {
            return Ok(false);
        }

        Ok(true)
    }
}

/// PreCommitment represents a commitment to a future state transition
/// Represents a forward commitment for future state transitions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreCommitment {
    /// Type of operation being committed to
    pub operation_type: String,
    /// Fixed parameters that cannot be changed during execution
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    /// Variable parameters that can be set during execution
    pub variable_parameters: HashSet<String>,
    /// Minimum state number this commitment applies to
    pub min_state_number: u64,
    /// Hash of the commitment
    pub hash: Vec<u8>,
    /// List of signatures
    pub signatures: Vec<Vec<u8>>,
    /// Signature from the entity creating the commitment
    pub entity_signature: Option<Vec<u8>>,
    /// Signature from the counterparty accepting the commitment
    pub counterparty_signature: Option<Vec<u8>>,
    /// Timestamp of creation
    pub timestamp: u64,
    /// Optional expiration timestamp
    pub expires_at: Option<u64>,
    /// Value used in calculations (previously private)
    pub value: Vec<i32>,
    /// Commitment data (previously private)
    pub commitment: Vec<i32>,
    /// Counterparty identifier (previously private)
    pub counterparty_id: String,
}

impl PreCommitment {
    /// Generate hash for this pre-commitment
    ///
    /// # Arguments
    /// * `state` - Current state
    /// * `operation` - Operation to be performed
    /// * `next_entropy` - Entropy for next state
    pub fn generate_hash(
        state: &State,
        operation: &Operation,
        next_entropy: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        let mut data = Vec::new();
        data.extend_from_slice(&state.hash()?);
        let op_bytes = bincode::serialize(operation)
            .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;
        data.extend_from_slice(&op_bytes);
        data.extend_from_slice(next_entropy);
        Ok(hash_blake3(&data).as_bytes().to_vec())
    }

    /// Add a signature to this pre-commitment
    ///
    /// # Arguments
    /// * `signature` - Signature to add
    pub fn add_signature(&mut self, signature: Vec<u8>) {
        self.signatures.push(signature);
    }

    /// Set an expiration timestamp for this pre-commitment
    ///
    /// # Arguments
    /// * `expires_at` - Expiration timestamp
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Create a new PreCommitment with constructor parameters
    pub fn new(
        operation_type: String,
        fixed_parameters: HashMap<String, Vec<u8>>,
        variable_parameters: HashSet<String>,
        min_state_number: u64,
        counterparty_id: String,
    ) -> Self {
        Self {
            operation_type,
            fixed_parameters,
            variable_parameters,
            min_state_number,
            hash: Vec::new(),
            signatures: Vec::new(),
            entity_signature: None,
            counterparty_signature: None,
            timestamp: 0,
            expires_at: None,
            value: Vec::new(),
            commitment: Vec::new(),
            counterparty_id,
        }
    }

    /// Convert a ForwardLinkedCommitment to a PreCommitment
    pub fn from_forward_linked_commitment(
        flc: crate::commitments::precommit::ForwardLinkedCommitment,
        commitment_bytes: Vec<u8>,
    ) -> Result<Self, DsmError> {
        // Create a PreCommitment from a ForwardLinkedCommitment
        let fixed_parameters = flc.fixed_parameters.clone();
        let mut variable_parameters = HashSet::new();
        for param in flc.variable_parameters {
            variable_parameters.insert(param);
        }

        // Derive operation type from fixed parameters if available
        let operation_type = if let Some(op_type) = fixed_parameters.get("operation_type") {
            String::from_utf8_lossy(op_type).to_string()
        } else {
            "transfer".to_string() // Default to transfer if not specified
        };

        // Create with constructor
        let mut pre_commitment = Self::new(
            operation_type,
            fixed_parameters,
            variable_parameters,
            flc.min_state_number,
            flc.counterparty_id.clone(),
        );

        // Set additional fields
        pre_commitment.hash = commitment_bytes;
        pre_commitment.entity_signature = flc.entity_signature;
        pre_commitment.counterparty_signature = flc.counterparty_signature;

        Ok(pre_commitment)
    }
}

/// Represents a sequence of random walk positions used for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PositionSequence {
    /// Sequence of positions
    pub positions: Vec<Vec<i32>>,

    /// Seed used to generate the positions
    pub seed: Vec<u8>,
}

impl PositionSequence {
    /// Create a new position sequence
    ///
    /// # Arguments
    /// * `positions` - Sequence of positions
    /// * `seed` - Seed used to generate the positions
    pub fn new(positions: Vec<Vec<i32>>, seed: Vec<u8>) -> Self {
        Self { positions, seed }
    }

    /// Verify this position sequence against a given seed
    ///
    /// # Arguments
    /// * `expected_seed` - Expected seed
    ///
    /// # Returns
    /// * `bool` - True if the verification succeeds, false otherwise
    pub fn verify(&self, expected_seed: &[u8]) -> bool {
        self.seed == expected_seed
    }
}

/// Cryptographic identity anchor described in whitepaper Section 5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAnchor {
    /// Unique identifier for this identity
    pub id: String,

    /// Genesis state hash
    pub genesis_hash: Vec<u8>,

    /// Public key for identity verification
    pub public_key: Vec<u8>,

    /// Commitment proof from MPC threshold ceremony
    pub commitment_proof: Vec<u8>,
}

impl IdentityAnchor {
    pub fn new(
        id: String,
        genesis_hash: Vec<u8>,
        public_key: Vec<u8>,
        commitment_proof: Vec<u8>,
    ) -> Self {
        Self {
            id,
            genesis_hash,
            public_key,
            commitment_proof,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.id.as_bytes());
        bytes.extend(&self.genesis_hash);
        bytes.extend(&self.public_key);
        bytes.extend(&self.commitment_proof);
        bytes
    }
}

/// Context for relationship state tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelationshipContext {
    pub entity_id: String,
    pub entity_state_number: u64,
    pub counterparty_id: String,
    pub counterparty_state_number: u64,
    pub counterparty_public_key: Vec<u8>,
    pub relationship_hash: Vec<u8>,
    pub active: bool,
}

impl RelationshipContext {
    /// Create a new relationship context
    pub fn new(
        entity_id: String,
        counterparty_id: String,
        counterparty_public_key: Vec<u8>,
    ) -> Self {
        Self {
            entity_id,
            entity_state_number: 0,
            counterparty_id,
            counterparty_state_number: 0,
            counterparty_public_key,
            relationship_hash: Vec::new(),
            active: true,
        }
    }
}
