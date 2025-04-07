//! Identity Module
//!
//! This module handles all aspects of identity management in DSM, including:
//! - Secure genesis state creation
//! - Hierarchical device-specific sub-identities
//! - Device management and invalidation
//! - Cross-device identity verification

pub mod genesis;
pub mod hierarchical_device_management;

use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use crate::types::error::DsmError;
use crate::types::state_types::{DeviceInfo, State};

// Re-export key components for easier access
pub use genesis::{
    create_composite_genesis, create_genesis_state, derive_device_genesis, verify_genesis_state,
    GenesisState, KyberKey, SigningKey,
};

pub use hierarchical_device_management::{
    DeviceInvalidationMarker, DeviceSubIdentity, HierarchicalDeviceManager,
};

/// Error types specific to identity operations
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Genesis error: {0}")]
    GenesisError(String),

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("Duplicate device: {0}")]
    DuplicateDevice(String),

    #[error("Identity invalidated: {0}")]
    IdentityInvalidated(String),
}

/// Identity provider interface
pub trait IdentityProvider {
    /// Create a new identity
    fn create_identity(&self, device_id: &str, entropy: &[u8]) -> Result<Identity, DsmError>;

    /// Validate an identity
    fn validate_identity(&self, state: &State) -> Result<bool, DsmError>;

    /// Generate an invalidation marker
    fn generate_invalidation(&self, state: &State, reason: &str) -> Result<Vec<u8>, DsmError>;

    /// Verify an invalidation marker
    fn verify_invalidation(&self, state: &State, invalidation: &[u8]) -> Result<bool, DsmError>;
}

/// Define DeviceIdentity struct
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub sub_genesis: GenesisState,
    pub current_state: Option<State>,
    pub sparse_indices: HashMap<u64, Vec<u8>>,
}

/// Define Identity struct
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Identity {
    pub name: String,
    pub master_genesis: GenesisState,
    pub devices: Vec<DeviceIdentity>,
    pub invalidated: bool,
}

impl Identity {
    pub fn id(&self) -> String {
        let genesis_hash = &self.master_genesis.hash;
        // Create a digest of the hash to use as ID
        let hash = blake3::hash(genesis_hash);
        hex::encode(&hash.as_bytes()[0..16]) // Use first 16 bytes as hex ID
    }
}

// Global identity store
lazy_static::lazy_static! {
    static ref IDENTITY_STORE: Arc<RwLock<HashMap<String, Identity>>> = Arc::new(RwLock::new(HashMap::new()));
}

/// Get identity by genesis ID
pub async fn get_identity(genesis_id: &str) -> Option<Identity> {
    if let Ok(store) = IDENTITY_STORE.read() {
        store.get(genesis_id).cloned()
    } else {
        None
    }
}

/// Create a new identity
pub async fn create_identity(
    name: &str,
    threshold: usize,
    participants: Vec<String>,
) -> Result<Identity, IdentityError> {
    if threshold > participants.len() {
        return Err(IdentityError::InvalidParameter(
            "Threshold cannot be greater than number of participants".into(),
        ));
    }

    let device_id = Uuid::new_v4().to_string(); // Generate unique device ID

    // Create genesis state
    let genesis = match genesis::create_genesis_state(threshold, participants.clone()) {
        Ok(g) => g,
        Err(e) => {
            return Err(IdentityError::GenesisError(format!(
                "Genesis creation failed: {:?}",
                e
            )))
        }
    };

    // Get device-specific entropy
    let device_entropy = vec![0u8; 32]; // Mock device entropy

    let device_identity =
        match genesis::derive_device_genesis(&genesis, &device_id, &device_entropy) {
            Ok(g) => DeviceIdentity {
                device_id: device_id.clone(),
                sub_genesis: g,
                current_state: None,
                sparse_indices: HashMap::new(),
            },
            Err(e) => {
                return Err(IdentityError::DeviceError(format!(
                    "Device genesis derivation failed: {:?}",
                    e
                )))
            }
        };

    let identity = Identity {
        name: name.to_string(),
        master_genesis: genesis,
        devices: vec![device_identity],
        invalidated: false,
    };

    if let Ok(mut store) = IDENTITY_STORE.write() {
        store.insert(identity.id(), identity.clone());
    }

    Ok(identity)
}

/// Verify if an identity has been invalidated
pub async fn is_invalidated(genesis_id: &str) -> Result<bool, IdentityError> {
    if let Ok(store) = IDENTITY_STORE.read() {
        let identity = store
            .get(genesis_id)
            .ok_or_else(|| IdentityError::IdentityNotFound("Identity not found".into()))?;

        Ok(identity.invalidated)
    } else {
        Err(IdentityError::IdentityNotFound(
            "Failed to access identity store".into(),
        ))
    }
}

/// Add a new device to an existing identity
pub async fn add_device(genesis_id: &str) -> Result<DeviceIdentity, IdentityError> {
    if let Ok(mut store) = IDENTITY_STORE.write() {
        let identity = store
            .get_mut(genesis_id)
            .ok_or_else(|| IdentityError::IdentityNotFound("Identity not found".into()))?;

        let device_id = Uuid::new_v4().to_string(); // Generate unique device ID

        // Check if device already exists (shouldn't happen with UUID but keep as safeguard)
        if identity.devices.iter().any(|d| d.device_id == device_id) {
            return Err(IdentityError::DuplicateDevice(
                "Device already registered for this identity".into(),
            ));
        }

        // Get device-specific entropy
        let device_entropy = vec![0u8; 32]; // Mock device entropy

        // Create device sub-genesis
        let device_identity = match genesis::derive_device_genesis(
            &identity.master_genesis,
            &device_id,
            &device_entropy,
        ) {
            Ok(g) => DeviceIdentity {
                device_id: device_id.clone(),
                sub_genesis: g,
                current_state: None,
                sparse_indices: HashMap::new(),
            },
            Err(e) => {
                return Err(IdentityError::DeviceError(format!(
                    "Device genesis derivation failed: {:?}",
                    e
                )))
            }
        };

        identity.devices.push(device_identity.clone());

        Ok(device_identity)
    } else {
        Err(IdentityError::IdentityNotFound(
            "Failed to access identity store".into(),
        ))
    }
}

/// Create a master identity with hierarchical device support
pub fn create_master_identity(
    master_id: &str,
    master_entropy: &[u8],
    device_ids: &[&str],
    device_entropies: &[&[u8]],
) -> Result<(State, Vec<DeviceSubIdentity>), DsmError> {
    // Create master Genesis state
    let device_info = DeviceInfo::new(
        master_id,
        vec![1, 2, 3, 4], // Placeholder public key, in real implementation this would be a real key
    );

    let master_genesis = State::new_genesis(
        master_entropy.to_vec(), // Add initial entropy
        device_info,
    );

    // Create hierarchical device manager
    let mut device_manager = HierarchicalDeviceManager::new(master_genesis.clone());

    // Add each device
    let mut device_identities = Vec::new();
    for (i, device_id) in device_ids.iter().enumerate() {
        if i < device_entropies.len() {
            let device_identity = device_manager.add_device(device_id, device_entropies[i])?;
            device_identities.push(device_identity);
        } else {
            return Err(DsmError::validation(
                "Device entropy not provided for all device IDs",
                None::<std::convert::Infallible>,
            ));
        }
    }

    Ok((master_genesis, device_identities))
}

#[allow(dead_code)]
fn generate_entropy() -> Result<Vec<u8>, DsmError> {
    // Create random entropy using rand
    let mut entropy = vec![0u8; 32];
    rand::thread_rng().fill(&mut entropy[..]);
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_master_identity() -> Result<(), DsmError> {
        let master_id = "master_device";
        let master_entropy = b"master_entropy";
        let device_ids = vec!["device1", "device2"];
        let device_entropies = vec![b"entropy1" as &[u8], b"entropy2" as &[u8]];

        let result =
            create_master_identity(master_id, master_entropy, &device_ids, &device_entropies)?;

        assert_eq!(result.1.len(), 2);
        assert_eq!(result.1[0].device_id, "device1");
        assert_eq!(result.1[1].device_id, "device2");

        Ok(())
    }

    #[test]
    fn test_generate_entropy() -> Result<(), DsmError> {
        let entropy1 = generate_entropy()?;
        let entropy2 = generate_entropy()?;

        // Entropy should be 32 bytes
        assert_eq!(entropy1.len(), 32);

        // Two consecutive calls should produce different entropy
        assert_ne!(entropy1, entropy2);

        Ok(())
    }
}
