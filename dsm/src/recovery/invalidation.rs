use std::sync::atomic::{AtomicBool, Ordering};

static INVALIDATION_SYSTEM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the invalidation recovery subsystem
pub fn init_invalidation_subsystem() {
    if !INVALIDATION_SYSTEM_INITIALIZED.load(Ordering::SeqCst) {
        // Perform any necessary initialization
        tracing::info!("Invalidation recovery subsystem initialized");
        INVALIDATION_SYSTEM_INITIALIZED.store(true, Ordering::SeqCst);
    }
}

use crate::crypto::sphincs::sphincs_sign;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{State, StateFlag};
use blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

/// Signature for cryptographic validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Identifier of the signer
    pub signer_id: String,

    /// Actual signature data
    pub signature_data: Vec<u8>,

    /// Optional signer metadata
    pub metadata: HashMap<String, String>,
}

impl Signature {
    /// Create a new signature
    pub fn new(signer_id: String, signature_data: Vec<u8>) -> Self {
        Self {
            signer_id,
            signature_data,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the signature
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Structure for marking states as invalidated
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvalidationMarker {
    /// Device ID this marker applies to
    pub device_id: String,
    /// State number being invalidated
    pub state_number: u64,
    /// Hash of the state being invalidated
    pub state_hash: Vec<u8>,
    /// Entropy of the state being invalidated
    pub state_entropy: Vec<u8>,
    /// Signatures from authorized participants
    pub signatures: HashMap<String, Vec<u8>>,
    /// Reason for invalidation
    pub reason: String,
    /// Timestamp when invalidation occurred
    pub timestamp: u64,
    /// Hash of all invalidation data
    pub marker_hash: Vec<u8>,
}

impl InvalidationMarker {
    /// Create a new invalidation marker
    pub fn create(state: &State, reason: &str, timestamp: u64) -> Result<Self, DsmError> {
        // Create base invalidation marker
        let mut marker = InvalidationMarker {
            device_id: state.device_info.device_id.clone(),
            state_number: state.state_number,
            state_hash: state.hash.clone(),
            state_entropy: state.entropy.clone(),
            reason: reason.to_string(),
            timestamp,
            signatures: HashMap::new(),
            marker_hash: Vec::new(),
        };

        // Generate marker hash according to whitepaper formula:
        // I(Sk) = (k, H(Sk), ek, σI, m)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&marker.state_number.to_le_bytes());
        hasher.update(&marker.state_hash);
        hasher.update(&marker.state_entropy);
        hasher.update(reason.as_bytes());
        marker.marker_hash = hasher.finalize().as_bytes().to_vec();

        Ok(marker)
    }

    /// Verify the integrity of this invalidation marker
    pub fn verify_integrity(&self) -> Result<bool, DsmError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.state_number.to_le_bytes());
        hasher.update(&self.state_hash);
        hasher.update(&self.state_entropy);
        hasher.update(self.reason.as_bytes());
        let computed_hash = hasher.finalize().as_bytes().to_vec();
        Ok(constant_time_eq::constant_time_eq(
            &computed_hash,
            &self.marker_hash,
        ))
    }

    /// Verify signatures against provided public keys
    pub fn verify_signatures(
        &self,
        public_keys: &[Vec<u8>],
        threshold: usize,
    ) -> Result<bool, DsmError> {
        if self.signatures.len() < threshold {
            return Ok(false);
        }

        let mut valid_signatures = 0;
        for signature in self.signatures.values() {
            for pubkey in public_keys {
                if crate::crypto::sphincs::sphincs_verify(pubkey, &self.marker_hash, signature)? {
                    valid_signatures += 1;
                    break;
                }
            }
        }

        Ok(valid_signatures >= threshold)
    }
}

/// Wrapper for safely handling private keys in memory.
pub struct RecoveryKey {
    /// Private key for recovery operations.
    private_key: Vec<u8>,
}

impl RecoveryKey {
    pub fn new(private_key: Vec<u8>) -> Self {
        Self { private_key }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DsmError> {
        sphincs_sign(&self.private_key, data)
    }
}

impl Drop for RecoveryKey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Manager for recovery-related operations
#[derive(Default)]
pub struct RecoveryManager {
    /// Map of signer IDs to recovery public keys
    pub public_keys: HashMap<String, Vec<u8>>,
    /// Recovery keys for signing invalidation markers
    pub recovery_keys: HashMap<String, RecoveryKey>,
    /// Required signature threshold
    pub threshold: usize,
}

impl RecoveryManager {
    pub fn new(threshold: usize) -> Self {
        Self {
            public_keys: HashMap::new(),
            recovery_keys: HashMap::new(),
            threshold,
        }
    }

    pub fn add_public_key(&mut self, signer_id: &str, public_key: Vec<u8>) {
        self.public_keys.insert(signer_id.to_string(), public_key);
    }

    pub fn add_recovery_key(&mut self, signer_id: &str, private_key: Vec<u8>) {
        let key = RecoveryKey::new(private_key);
        self.recovery_keys.insert(signer_id.to_string(), key);
    }

    /// Create an invalidation marker
    pub fn create_invalidation_marker(
        &self,
        state: &State,
        reason: &str,
        primary_signer_id: &str,
    ) -> Result<InvalidationMarker, DsmError> {
        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create the marker
        let mut marker = InvalidationMarker::create(state, reason, timestamp)?;

        // Get the primary signer's key
        let primary_key = self.recovery_keys.get(primary_signer_id).ok_or_else(|| {
            DsmError::validation(
                format!("No recovery key found for signer {}", primary_signer_id),
                None::<std::convert::Infallible>,
            )
        })?;

        // Sign with primary key
        let signature = primary_key.sign(&marker.marker_hash)?;
        marker
            .signatures
            .insert(primary_signer_id.to_string(), signature);

        Ok(marker)
    }

    /// Verify an invalidation marker against stored public keys
    pub fn verify_invalidation_marker(
        &self,
        marker: &InvalidationMarker,
    ) -> Result<bool, DsmError> {
        // First verify marker integrity
        if !marker.verify_integrity()? {
            return Ok(false);
        }

        // Get public keys for verification
        let pubkeys: Vec<Vec<u8>> = self.public_keys.values().cloned().collect();

        // Verify signatures meet threshold
        marker.verify_signatures(&pubkeys, self.threshold)
    }

    /// Create a recovery state from an invalidation marker
    pub fn create_recovery_state(
        &self,
        marker: &InvalidationMarker,
        invalidated_state: &State,
    ) -> Result<State, DsmError> {
        // Verify marker first
        if !self.verify_invalidation_marker(marker)? {
            return Err(DsmError::validation(
                "Invalid invalidation marker",
                None::<std::convert::Infallible>,
            ));
        }

        // Generate new recovery entropy as per whitepaper:
        // enew = H(ek || "RECOVERY" || timestamp)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&marker.state_entropy);
        hasher.update(b"RECOVERY");
        hasher.update(&marker.timestamp.to_le_bytes());
        let recovery_entropy = hasher.finalize().as_bytes().to_vec();

        // Create recovery operation with correct hash typing
        let recovery_op = Operation::Recovery {
            message: marker.reason.clone(),
            state_number: marker.state_number,
            state_hash: marker.state_hash.clone(),
            state_entropy: marker.state_entropy.clone(),
            invalidation_data: marker.marker_hash.clone(),
            new_state_data: Vec::new(),
            new_state_number: marker.state_number + 1,
            new_state_hash: Vec::new(),
            new_state_entropy: recovery_entropy.clone(),
            compromise_proof: Vec::new(),
            authority_sigs: marker.signatures.values().cloned().collect(),
        };

        // Create state parameters
        let state_params = crate::types::state_types::StateParams::new(
            marker.state_number + 1,
            recovery_entropy,
            recovery_op,
            invalidated_state.device_info.clone(),
        );

        // Create recovery state
        let mut recovery_state = State::new(state_params);

        // Set recovery flags
        let mut flags = std::collections::HashSet::new();
        flags.insert(StateFlag::Recovered);
        recovery_state.flags = flags;

        // Set previous state hash - ensure it's a Vec<u8>
        recovery_state.prev_state_hash = marker.state_hash.clone();

        // Copy over relationship context if any
        recovery_state.relationship_context = invalidated_state.relationship_context.clone();

        // Compute and set state hash
        recovery_state.hash = recovery_state.compute_hash()?;

        Ok(recovery_state)
    }
}

/// Parse an invalidation marker from raw bytes.
pub fn parse_invalidation_marker(data: &[u8]) -> Result<Option<InvalidationMarker>, DsmError> {
    if data.is_empty() {
        return Ok(None);
    }
    match bincode::deserialize::<InvalidationMarker>(data) {
        Ok(marker) => Ok(Some(marker)),
        Err(e) => {
            tracing::debug!("Failed to parse invalidation marker: {}", e);
            Err(DsmError::serialization(
                "Invalid invalidation marker format",
                Some(e),
            ))
        }
    }
}

/// Verify an invalidation marker’s signatures and integrity.
pub fn verify_invalidation_marker(marker: &InvalidationMarker) -> Result<bool, DsmError> {
    if !marker.verify_integrity()? {
        tracing::warn!("Invalidation marker failed integrity check");
        return Ok(false);
    }
    if marker.signatures.is_empty() {
        tracing::warn!("Invalidation marker contains no signatures");
        return Ok(false);
    }
    // In a full implementation, one would verify against a set of authorized public keys.
    Ok(true)
}
