use crate::types::error::DsmError;
use serde::{Deserialize, Serialize};

/// Represents a cryptographic identity anchor as defined in whitepaper Section 5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAnchor {
    /// Unique identifier for this identity
    pub id: String,

    /// Genesis state hash
    pub genesis_hash: Vec<u8>,

    /// Public key for identity verification
    pub public_key: Vec<u8>,

    /// Threshold commitment proof from MPC ceremony
    pub commitment_proof: Vec<u8>,
}

impl IdentityAnchor {
    /// Create a new identity anchor
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

    /// Get the canonical bytes representation
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.id.as_bytes());
        bytes.extend(&self.genesis_hash);
        bytes.extend(&self.public_key);
        bytes.extend(&self.commitment_proof);
        bytes
    }

    /// Verify this identity anchor's commitment proof
    pub fn verify_commitment(&self) -> Result<bool, DsmError> {
        // Implementation of threshold verification according to whitepaper Section 5.2
        // For single-party verification, we simply verify the hash matches
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.id.as_bytes());
        hasher.update(&self.genesis_hash);
        hasher.update(&self.public_key);

        // Calculate the expected commitment hash
        let commitment_hash = hasher.finalize().as_bytes().to_vec();

        // Compare with the stored commitment
        // Use constant-time comparison to avoid timing attacks
        Ok(crate::core::state_machine::utils::constant_time_eq(
            &self.commitment_proof,
            &commitment_hash,
        ))
    }

    /// Derive a child identity anchor for a specific device
    pub fn derive_device_anchor(
        &self,
        device_id: &str,
        device_key: &[u8],
    ) -> Result<Self, DsmError> {
        // Create combined entropy source
        let mut entropy = Vec::new();
        entropy.extend(self.as_bytes());
        entropy.extend(device_id.as_bytes());
        entropy.extend(device_key);

        // Generate new commitment proof using entropy
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entropy);
        let commitment = hasher.finalize();

        Ok(Self {
            id: format!("{}:{}", self.id, device_id),
            genesis_hash: self.genesis_hash.clone(),
            public_key: device_key.to_vec(),
            commitment_proof: commitment.as_bytes().to_vec(),
        })
    }
}
