use crate::types::error::DsmError;
use serde::{Deserialize, Serialize};

/// Device-specific cryptographic identity information as specified in whitepaper Section 6.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Unique device identifier
    pub device_id: String,

    /// Device public key for signatures
    pub public_key: Vec<u8>,

    /// Device entropy for state derivation
    pub device_entropy: Vec<u8>,

    /// Parent identity ID
    pub parent_id: String,
}

impl DeviceIdentity {
    /// Create a new device identity
    pub fn new(
        device_id: String,
        public_key: Vec<u8>,
        device_entropy: Vec<u8>,
        parent_id: String,
    ) -> Self {
        Self {
            device_id,
            public_key,
            device_entropy,
            parent_id,
        }
    }

    /// Generate device-specific entropy for state transitions
    pub fn generate_state_entropy(&self, state_number: u64) -> Result<Vec<u8>, DsmError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.device_entropy);
        hasher.update(&state_number.to_le_bytes());
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Derive a new device entropy from parent and device data
    pub fn derive_device_entropy(
        parent_entropy: &[u8],
        device_id: &str,
        public_key: &[u8],
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(parent_entropy);
        hasher.update(device_id.as_bytes());
        hasher.update(public_key);
        hasher.finalize().as_bytes().to_vec()
    }
}
