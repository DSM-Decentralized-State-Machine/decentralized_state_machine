// This module handles identity management, including creation, verification, and credential rotation.
use crate::types::error::DsmError;
use blake3;
use lazy_static::lazy_static;
use ring::rand;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::sync::Mutex;
use uuid::Uuid;

// Core identity structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    id: String,
    genesis_hash: Vec<u8>,
    current_state_hash: Vec<u8>,
    state_number: u64,
    device_id: String,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Identity(id: {}, state: {}, device: {})",
            self.id, self.state_number, self.device_id
        )
    }
}

impl Identity {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn verify_device_binding(&self, device_id: &str) -> bool {
        self.device_id == device_id
    }
}

// Add this near the top of the file with other uses
lazy_static! {
    static ref IDENTITY_STORE: Mutex<HashMap<String, Identity>> = Mutex::new(HashMap::new());
}

// Add this function to store identities when created
fn store_identity(identity: &Identity) -> Result<(), DsmError> {
    // Store in memory
    let mut store = IDENTITY_STORE.lock().map_err(|_| {
        DsmError::internal(
            "Failed to acquire identity store lock",
            None::<std::convert::Infallible>,
        )
    })?;
    store.insert(identity.id().to_string(), identity.clone());

    // Store on disk
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|e| DsmError::internal("Failed to get home directory", Some(e)))?;
    let identity_dir = std::path::Path::new(&home_dir)
        .join(".dsm_config")
        .join("identities");
    std::fs::create_dir_all(&identity_dir)
        .map_err(|e| DsmError::internal("Failed to create identity directory", Some(e)))?;

    let identity_path = identity_dir.join(format!("{}.json", identity.id()));
    let identity_json = serde_json::to_string_pretty(identity)
        .map_err(|e| DsmError::serialization("Failed to serialize identity", Some(e)))?;

    std::fs::write(&identity_path, identity_json)
        .map_err(|e| DsmError::internal("Failed to write identity file", Some(e)))?;

    Ok(())
}

pub fn init_identity() {
    println!("Identity module initialized with secure RNG");
    // Load existing identities when initializing
    if let Err(e) = load_identities() {
        eprintln!("Warning: Failed to load existing identities: {}", e);
    }
}

fn load_identities() -> Result<(), DsmError> {
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|e| DsmError::internal("Failed to get home directory", Some(e)))?;
    let identity_dir = std::path::Path::new(&home_dir)
        .join(".dsm_config")
        .join("identities");

    // If directory doesn't exist yet, that's fine - no identities to load
    if !identity_dir.exists() {
        return Ok(());
    }

    let mut store = IDENTITY_STORE.lock().map_err(|_| {
        DsmError::internal(
            "Failed to acquire identity store lock",
            None::<std::convert::Infallible>,
        )
    })?;

    for entry in fs::read_dir(&identity_dir)
        .map_err(|e| DsmError::internal("Failed to read identity directory", Some(e)))?
    {
        let entry =
            entry.map_err(|e| DsmError::internal("Failed to read directory entry", Some(e)))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let contents = fs::read_to_string(&path)
                .map_err(|e| DsmError::internal("Failed to read identity file", Some(e)))?;
            let identity: Identity = serde_json::from_str(&contents)
                .map_err(|e| DsmError::serialization("Failed to deserialize identity", Some(e)))?;
            store.insert(identity.id().to_string(), identity);
        }
    }

    Ok(())
}

// Add the get_identities function
pub fn get_identities() -> Result<Vec<Identity>, DsmError> {
    let store = IDENTITY_STORE.lock().map_err(|_| {
        DsmError::internal(
            "Failed to acquire identity store lock",
            None::<std::convert::Infallible>,
        )
    })?;

    Ok(store.values().cloned().collect())
}

pub fn create_identity(device_id: String) -> Result<Identity, DsmError> {
    let rng = rand::SystemRandom::new();
    let mut genesis_bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut genesis_bytes)
        .map_err(|e| DsmError::validation("Failed to generate random bytes", Some(e)))?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(&genesis_bytes);
    let genesis_hash = hasher.finalize().as_bytes().to_vec();

    let identity = Identity {
        id: Uuid::new_v4().to_string(),
        genesis_hash: genesis_hash.clone(),
        current_state_hash: genesis_hash,
        state_number: 0,
        device_id,
    };

    store_identity(&identity)?;
    Ok(identity)
}

pub fn verify_identity(identity: &Identity) -> Result<bool, DsmError> {
    // Verify state number validity
    if identity.state_number == 0 && identity.genesis_hash != identity.current_state_hash {
        return Ok(false);
    }

    // Verify genesis hash is valid length
    if identity.genesis_hash.len() != 32 {
        return Ok(false);
    }

    Ok(true)
}

pub fn rebind_device(identity: &mut Identity, new_device_id: String) -> Result<(), DsmError> {
    // Update device binding
    identity.device_id = new_device_id;
    Ok(())
}

pub fn rotate_credentials(identity: &mut Identity) -> Result<(), DsmError> {
    // Generate new state hash
    let rng = rand::SystemRandom::new();
    let mut new_state_bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut new_state_bytes)
        .map_err(|e| DsmError::validation("Failed to generate random bytes", Some(e)))?;

    // Update identity state
    let mut hasher = blake3::Hasher::new();
    hasher.update(&new_state_bytes);
    identity.current_state_hash = hasher.finalize().as_bytes().to_vec();
    identity.state_number += 1;
    Ok(())
}

pub fn add_device(genesis_id: &str, device_id: String) -> Result<Identity, DsmError> {
    let store = IDENTITY_STORE.lock().map_err(|_| {
        DsmError::internal(
            "Failed to acquire identity store lock",
            None::<std::convert::Infallible>,
        )
    })?;

    // Get the genesis identity
    let genesis_identity = store.get(genesis_id).ok_or_else(|| {
        DsmError::validation(
            format!("Genesis identity {} not found", genesis_id),
            None::<std::convert::Infallible>,
        )
    })?;

    // Generate device-specific entropy
    let rng = rand::SystemRandom::new();
    let mut device_entropy = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut device_entropy)
        .map_err(|e| DsmError::validation("Failed to generate random bytes", Some(e)))?;

    // Create sub-identity with device-specific genesis state derived from master genesis
    let mut hasher = blake3::Hasher::new();
    hasher.update(&genesis_identity.genesis_hash);
    hasher.update(device_id.as_bytes());
    hasher.update(&device_entropy);
    let sub_genesis_hash = hasher.finalize().as_bytes().to_vec();

    let sub_identity = Identity {
        id: Uuid::new_v4().to_string(),
        genesis_hash: sub_genesis_hash.clone(),
        current_state_hash: sub_genesis_hash,
        state_number: 0,
        device_id,
    };

    store_identity(&sub_identity)?;
    Ok(sub_identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let device_id = "test_device_1".to_string();
        let identity = create_identity(device_id.clone()).unwrap();
        assert_eq!(identity.state_number, 0);
        assert_eq!(identity.genesis_hash.len(), 32);
        assert!(verify_identity(&identity).unwrap());
    }

    #[test]
    fn test_credential_rotation() {
        let device_id = "test_device_1".to_string();
        let mut identity = create_identity(device_id.clone()).unwrap();
        let original_hash = identity.current_state_hash.clone();
        rotate_credentials(&mut identity).unwrap();
        assert_eq!(identity.state_number, 1);
        assert_ne!(identity.current_state_hash, original_hash);
        assert!(verify_identity(&identity).unwrap());
    }

    #[test]
    fn test_device_binding() {
        let device_id = "test_device_1".to_string();
        let identity = create_identity(device_id.clone()).unwrap();
        assert!(identity.verify_device_binding(&device_id));
        assert!(!identity.verify_device_binding("wrong_device_id"));
    }

    #[test]
    fn test_device_rebinding() {
        let device_id = "test_device_1".to_string();
        let mut identity = create_identity(device_id.clone()).unwrap();

        // Create a new device ID and test rebinding
        let new_device_id = "new_test_device_id".to_string();
        rebind_device(&mut identity, new_device_id.clone()).unwrap();
        assert_eq!(&identity.device_id, &new_device_id);
    }
}
