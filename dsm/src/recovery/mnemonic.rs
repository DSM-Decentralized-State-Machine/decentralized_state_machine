//! Mnemonic-based recovery implementation
//!
//! This module implements secure recovery mechanisms using BIP39 mnemonic phrases
//! as described in the whitepaper section 12.

use std::sync::atomic::{AtomicBool, Ordering};

static MNEMONIC_SYSTEM_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the mnemonic recovery subsystem
pub fn init_mnemonic_subsystem() {
    if !MNEMONIC_SYSTEM_INITIALIZED.load(Ordering::SeqCst) {
        // Verify the system can generate random entropy
        let _test = MnemonicPhrase::new_random(MnemonicStrength::Words12)
            .expect("Failed to initialize mnemonic subsystem");
            
        // Mark as initialized
        tracing::info!("Mnemonic recovery subsystem initialized");
        MNEMONIC_SYSTEM_INITIALIZED.store(true, Ordering::SeqCst);
    }
}
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::{DeviceInfo, State, StateFlag, StateParams};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bip39::Mnemonic;
use blake3::Hasher;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use zeroize::Zeroize;

/// Enum defining mnemonic strength
#[derive(Debug, Clone, Copy, Default)]
pub enum MnemonicStrength {
    Words12,
    Words15,
    Words18,
    Words21,
    #[default]
    Words24,
}

impl MnemonicStrength {
    fn entropy_size(self) -> usize {
        match self {
            MnemonicStrength::Words12 => 16, // 128 bits
            MnemonicStrength::Words15 => 20, // 160 bits
            MnemonicStrength::Words18 => 24, // 192 bits
            MnemonicStrength::Words21 => 28, // 224 bits
            MnemonicStrength::Words24 => 32, // 256 bits
        }
    }
}

/// Represents a recoverable mnemonic phrase
#[derive(Debug, Clone)]
pub struct MnemonicPhrase {
    /// The mnemonic phrase as a string
    phrase: String,
    /// Recovery entropy derived from the mnemonic
    entropy: Vec<u8>,
    #[allow(dead_code)]
    inner: Mnemonic,
}

impl Drop for MnemonicPhrase {
    fn drop(&mut self) {
        self.phrase.zeroize();
        self.entropy.zeroize();
    }
}

impl MnemonicPhrase {
    /// Generate a new random mnemonic phrase with specified strength
    pub fn new_random(strength: MnemonicStrength) -> Result<Self, DsmError> {
        // Generate random entropy of appropriate size
        let mut entropy_bytes = vec![0u8; strength.entropy_size()];
        OsRng.fill_bytes(&mut entropy_bytes);

        // Create mnemonic from entropy
        let mnemonic = Mnemonic::from_entropy(&entropy_bytes)
            .map_err(|e| DsmError::crypto("Failed to create mnemonic", Some(Box::new(e))))?;

        // Derive entropy from the mnemonic
        let derived_entropy = Self::derive_entropy_from_mnemonic(&mnemonic)?;

        Ok(Self {
            inner: mnemonic.clone(),
            entropy: derived_entropy,
            phrase: mnemonic.to_string(),
        })
    }

    /// Create a mnemonic from an existing phrase
    pub fn from_phrase(phrase: &str) -> Result<Self, DsmError> {
        let mnemonic = Mnemonic::from_str(phrase)
            .map_err(|e| DsmError::validation("Invalid mnemonic phrase", Some(Box::new(e))))?;

        let entropy = Self::derive_entropy_from_mnemonic(&mnemonic)?;

        Ok(Self {
            inner: mnemonic,
            entropy,
            phrase: phrase.to_string(),
        })
    }

    /// Get the mnemonic phrase as a string
    pub fn as_string(&self) -> String {
        self.phrase.clone()
    }

    /// Derive the entropy from a mnemonic
    fn derive_entropy_from_mnemonic(mnemonic: &Mnemonic) -> Result<Vec<u8>, DsmError> {
        // Get the entropy bytes from the mnemonic
        let entropy_bytes = mnemonic.to_entropy();

        // Create a Blake3 hash of the entropy for stronger security
        let mut hasher = Hasher::new();
        hasher.update(&entropy_bytes);

        // Finalize and return the hash as bytes
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Get the entropy derived from this mnemonic
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }
}

impl Zeroize for MnemonicPhrase {
    fn zeroize(&mut self) {
        self.entropy.zeroize();
        // Note: We cannot zeroize the inner Mnemonic as it doesn't implement Zeroize
        // but we'll handle that at drop time via ZeroizeOnDrop
    }
}

/// Recovery phrase with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPhrase {
    /// The mnemonic phrase as a string (should be encrypted in storage)
    phrase: String,
    /// Identifier for this recovery phrase
    id: String,
    /// State number this phrase can recover
    recoverable_state: u64,
    /// Hash of the state this can recover
    state_hash: Vec<u8>,
    /// Timestamp when this recovery phrase was created
    created_at: u64,
    /// Optional expiration timestamp
    expires_at: Option<u64>,
    /// Additional metadata
    metadata: HashMap<String, Vec<u8>>,
}

impl RecoveryPhrase {
    /// Create a new recovery phrase for the given state
    pub fn new(state: &State, phrase: &MnemonicPhrase) -> Result<Self, DsmError> {
        let state_hash = state.hash.clone();

        // Create deterministic ID for this recovery phrase by hashing
        let mut hasher = Hasher::new();
        hasher.update(&state_hash);
        hasher.update(phrase.entropy());
        let id_hash = hasher.finalize();

        // Use the first 16 bytes of the hash to create a hex ID
        let id = hex::encode(&id_hash.as_bytes()[0..16]);

        // Get current timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DsmError::crypto("Failed to get system time", Some(e)))?
            .as_secs();

        Ok(Self {
            phrase: phrase.as_string(),
            id,
            recoverable_state: state.state_number,
            state_hash,
            created_at: now,
            expires_at: None,
            metadata: HashMap::new(),
        })
    }

    /// Set an expiration date for this recovery phrase
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add metadata to this recovery phrase
    pub fn with_metadata(mut self, key: &str, value: Vec<u8>) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    /// Get the recovery phrase as a mnemonic
    pub fn to_mnemonic(&self) -> Result<MnemonicPhrase, DsmError> {
        MnemonicPhrase::from_phrase(&self.phrase)
    }

    /// Check if this recovery phrase is expired
    pub fn is_expired(&self) -> Result<bool, DsmError> {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| DsmError::crypto("Failed to get system time", Some(e)))?
                .as_secs();

            return Ok(now >= expires_at);
        }

        Ok(false)
    }

    /// Verify that this recovery phrase matches the given state
    pub fn verify_for_state(&self, state: &State) -> Result<bool, DsmError> {
        if state.state_number != self.recoverable_state {
            return Ok(false);
        }

        let state_hash = &state.hash;

        Ok(self.state_hash == *state_hash)
    }
}

/// Sharable recovery seed for secure transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareableSeed {
    /// Encrypted recovery data
    encrypted_data: Vec<u8>,
    /// Nonce used for encryption
    nonce: Vec<u8>,
    /// Salt used for key derivation
    salt: Vec<u8>,
    /// Recovery hints
    hints: HashMap<String, String>,
}

impl ShareableSeed {
    /// Create a new sharable seed from a recovery phrase
    pub fn new(recovery_phrase: &RecoveryPhrase, password: &str) -> Result<Self, DsmError> {
        // Convert recovery phrase to bytes
        let data = bincode::serialize(recovery_phrase)
            .map_err(|e| DsmError::serialization("Failed to serialize recovery phrase", Some(e)))?;

        // Generate salt and nonce
        let salt = generate_random_bytes(16)?;
        let nonce = generate_random_bytes(24)?; // Changed from 12 to 24 bytes for XChaCha20-Poly1305

        // Derive key from password and salt
        let key = derive_key_from_password(password, &salt)?;

        // Encrypt the data
        let encrypted_data = encrypt_data(&data, &key, &nonce)?;

        Ok(Self {
            encrypted_data,
            nonce,
            salt,
            hints: HashMap::new(),
        })
    }

    /// Add a hint to this sharable seed
    pub fn with_hint(mut self, key: &str, hint: &str) -> Self {
        self.hints.insert(key.to_string(), hint.to_string());
        self
    }

    /// Recover the original recovery phrase using a password
    pub fn recover(&self, password: &str) -> Result<RecoveryPhrase, DsmError> {
        // Derive key from password and salt
        let key = derive_key_from_password(password, &self.salt)?;

        // Decrypt the data
        let data = decrypt_data(&self.encrypted_data, &key, &self.nonce)?;

        // Deserialize into recovery phrase
        let recovery_phrase: RecoveryPhrase = bincode::deserialize(&data).map_err(|e| {
            DsmError::serialization("Failed to deserialize recovery phrase", Some(e))
        })?;

        Ok(recovery_phrase)
    }

    /// Get a hint value by key
    pub fn get_hint(&self, key: &str) -> Option<&str> {
        self.hints.get(key).map(|s| s.as_str())
    }
}

/// Data structure for device recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecoveryData {
    /// Device information
    pub device_info: DeviceInfo,
    /// Recovery entropy
    pub recovery_entropy: Vec<u8>,
    /// Last known state hash
    pub last_state_hash: Vec<u8>,
    /// Last known state number
    pub last_state_number: u64,
    /// Additional recovery metadata
    pub metadata: HashMap<String, Vec<u8>>,
}

impl DeviceRecoveryData {
    /// Create new device recovery data
    pub fn new(
        device_info: DeviceInfo,
        recovery_entropy: Vec<u8>,
        last_state_hash: Vec<u8>,
        last_state_number: u64,
    ) -> Self {
        Self {
            device_info,
            recovery_entropy,
            last_state_hash,
            last_state_number,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to this recovery data
    pub fn with_metadata(mut self, key: &str, value: Vec<u8>) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    /// Generate seed for device recovery
    pub fn generate_recovery_seed(&self, state_entropy: &[u8]) -> Result<Vec<u8>, DsmError> {
        // Create a Blake3 hash combining recovery entropy and state entropy
        let mut hasher = Hasher::new();
        hasher.update(&self.recovery_entropy);
        hasher.update(state_entropy);
        hasher.update(b"DEVICE_RECOVERY");

        // Create deterministic seed
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    /// Verify this recovery data matches the given state
    pub fn verify_for_state(&self, state: &State) -> bool {
        state.hash == self.last_state_hash && state.state_number == self.last_state_number
    }

    /// Create an invalidation marker for this device
    pub fn create_invalidation_marker(&self) -> Vec<u8> {
        // Create invalidation marker as described in whitepaper
        let mut hasher = Hasher::new();
        hasher.update(self.device_info.device_id.as_bytes());
        hasher.update(&self.last_state_hash);
        hasher.update(&self.last_state_number.to_le_bytes());
        hasher.update(b"INVALIDATE");

        hasher.finalize().as_bytes().to_vec()
    }
}

/// Generate random bytes of the specified length
fn generate_random_bytes(len: usize) -> Result<Vec<u8>, DsmError> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Derive a key from a password and salt using Argon2id
fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<Vec<u8>, DsmError> {
    use argon2::{
        password_hash::{PasswordHasher, SaltString},
        Argon2,
    };

    // Convert salt to a valid salt string format, removing any Base64 padding characters
    // because SaltString doesn't accept standard Base64 with padding
    let encoded_salt = BASE64_STANDARD.encode(salt);
    let salt_str = encoded_salt.trim_end_matches('=');

    // Create a valid salt string
    let salt_string = SaltString::from_b64(salt_str).map_err(|e| {
        DsmError::crypto(
            "Invalid salt",
            Some(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        )
    })?;

    // Configure Argon2id for key derivation
    let argon2 = Argon2::default();

    // Hash password to derive key
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| {
            DsmError::crypto(
                "Key derivation failed",
                Some(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))),
            )
        })?;

    // Use the hash as the key
    Ok(password_hash.hash.unwrap().as_bytes().to_vec())
}

/// Encrypt data using XChaCha20-Poly1305
fn encrypt_data(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, DsmError> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};

    // Create cipher instance
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| DsmError::crypto("Invalid key length", Some(Box::new(e))))?;

    // Encrypt data
    cipher
        .encrypt(nonce.into(), data)
        .map_err(|e| DsmError::crypto("Encryption failed", Some(Box::new(e))))
}

/// Decrypt data using XChaCha20-Poly1305
fn decrypt_data(encrypted_data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, DsmError> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};

    // Create cipher instance
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| DsmError::crypto("Invalid key length", Some(Box::new(e))))?;

    // Decrypt data
    cipher
        .decrypt(nonce.into(), encrypted_data)
        .map_err(|e| DsmError::crypto("Decryption failed", Some(Box::new(e))))
}

/// Create a recovery seed from a mnemonic phrase and additional context
pub fn create_recovery_seed(phrase: &MnemonicPhrase, context: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(phrase.entropy());
    hasher.update(context);

    hasher.finalize().as_bytes().to_vec()
}

/// Generate a mnemonic phrase from state for backup/recovery
pub fn generate_mnemonic_from_state(state: &State) -> Result<MnemonicPhrase, DsmError> {
    // Derive entropy from state
    let mut hasher = Hasher::new();
    hasher.update(&state.hash);
    hasher.update(&state.state_number.to_le_bytes());
    hasher.update(&state.entropy);

    // Generate entropy for mnemonic
    let entropy = hasher.finalize().as_bytes()[0..16].to_vec();

    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|e| {
        DsmError::crypto("Failed to create mnemonic from entropy", Some(Box::new(e)))
    })?;

    let derived_entropy = MnemonicPhrase::derive_entropy_from_mnemonic(&mnemonic)?;

    Ok(MnemonicPhrase {
        inner: mnemonic.clone(),
        entropy: derived_entropy,
        phrase: mnemonic.to_string(),
    })
}

/// Recover entropy from a mnemonic phrase
pub fn recover_entropy_from_mnemonic(
    mnemonic_phrase: &str,
    passphrase: &str,
    state_hash: &[u8],
) -> Result<Vec<u8>, DsmError> {
    // Parse mnemonic
    let mnemonic = MnemonicPhrase::from_phrase(mnemonic_phrase)?;

    // Derive entropy with passphrase and state hash
    let mut hasher = Hasher::new();
    hasher.update(mnemonic.entropy());
    hasher.update(passphrase.as_bytes());
    hasher.update(state_hash);

    Ok(hasher.finalize().as_bytes().to_vec())
}

/// Split entropy into recovery shares for social recovery using Shamir's Secret Sharing
pub fn split_entropy_into_shares(
    entropy: &[u8],
    threshold: u8,
    shares_count: u8,
) -> Result<Vec<Vec<u8>>, DsmError> {
    if threshold > shares_count {
        return Err(DsmError::validation(
            "Threshold must be less than or equal to shares count",
            None::<std::convert::Infallible>,
        ));
    }

    // Simple implementation - in a real system, use a proper SSS library
    // This is just a placeholder implementation
    let mut shares = Vec::new();

    // Generate random shares
    for i in 0..shares_count {
        let mut share = entropy.to_vec();
        // XOR with a unique value for each share
        for byte in share.iter_mut() {
            *byte ^= i + 1;
        }
        shares.push(share);
    }

    Ok(shares)
}

/// Combine recovery shares to recover original entropy
pub fn combine_entropy_shares(shares: &[Vec<u8>]) -> Result<Vec<u8>, DsmError> {
    if shares.is_empty() {
        return Err(DsmError::validation(
            "At least one share is required",
            None::<std::convert::Infallible>,
        ));
    }

    // Simple implementation - in a real system, use a proper SSS library
    // This is just a placeholder implementation
    let mut result = shares[0].clone();

    // XOR with the first share's index to recover the original value
    for byte in result.iter_mut() {
        *byte ^= 1;
    }

    Ok(result)
}

/// Recover a state using recovery data and a mnemonic phrase
pub fn recover_state(
    recovery_data: &DeviceRecoveryData,
    _phrase: &MnemonicPhrase,
) -> Result<State, DsmError> {
    // Generate recovery entropy using the formula from whitepaper
    let mut hasher = Hasher::new();
    hasher.update(&recovery_data.recovery_entropy);
    hasher.update(b"RECOVERY");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    hasher.update(&timestamp.to_le_bytes());
    let recovery_entropy = hasher.finalize().as_bytes().to_vec();

    // Verify state hash length
    if recovery_data.last_state_hash.len() != 32 {
        return Err(DsmError::validation(
            "State hash has invalid length",
            None::<std::convert::Infallible>,
        ));
    }

    // Generate recovery seed
    let recovery_seed = recovery_data.generate_recovery_seed(&recovery_entropy)?;

    // Create recovery operation
    let recovery_operation = Operation::Recovery {
        message: "Device recovery using mnemonic".to_string(),
        state_number: recovery_data.last_state_number,
        state_hash: recovery_data.last_state_hash.clone(),
        state_entropy: recovery_entropy.clone(),
        invalidation_data: Vec::new(),
        new_state_data: recovery_seed.clone(),
        new_state_number: recovery_data.last_state_number + 1,
        new_state_hash: Vec::new(),
        new_state_entropy: recovery_entropy.clone(),
        compromise_proof: Vec::new(),
        authority_sigs: Vec::new(),
    };

    // Create state parameters
    let state_params = StateParams::new(
        recovery_data.last_state_number + 1,
        recovery_entropy,
        recovery_operation,
        recovery_data.device_info.clone(),
    );

    // Create recovery state
    let mut state = State::new(state_params);

    // Set recovery flags
    let mut flags = HashSet::new();
    flags.insert(StateFlag::Recovered);
    state.flags = flags;

    // Set previous state hash
    state.prev_state_hash = recovery_data.last_state_hash.clone();

    // Set device relationship info if present
    if let Some(relationship_data) = recovery_data.metadata.get("relationship_context") {
        // Use the module-scope RelationshipContext instead of a direct import
        if let Ok(context) = bincode::deserialize::<crate::types::state_types::RelationshipContext>(
            relationship_data,
        ) {
            state.relationship_context = Some(context);
        }
    }

    // Compute and set state hash
    state.hash = state.compute_hash()?;

    Ok(state)
}

/// Verify a mnemonic phrase against recovery data
pub fn verify_recovery_phrase(
    phrase: &MnemonicPhrase,
    recovery_data: &DeviceRecoveryData,
) -> Result<bool, DsmError> {
    let recovery_seed = create_recovery_seed(phrase, b"VERIFICATION");

    let mut hasher = Hasher::new();
    hasher.update(&recovery_seed);
    hasher.update(&recovery_data.last_state_hash);
    let verification_hash = hasher.finalize().as_bytes().to_vec();

    // Get expected verification hash from metadata
    if let Some(expected) = recovery_data.metadata.get("verification_hash") {
        Ok(&verification_hash == expected)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation() -> Result<(), DsmError> {
        let phrase = MnemonicPhrase::new_random(MnemonicStrength::Words12)?;

        // Ensure we got a valid phrase
        assert!(!phrase.as_string().is_empty());
        assert!(!phrase.entropy().is_empty());

        // Try recreating from the phrase
        let recreated = MnemonicPhrase::from_phrase(&phrase.as_string())?;

        // Entropy should match
        assert_eq!(phrase.entropy(), recreated.entropy());

        Ok(())
    }

    #[test]
    fn test_recovery_phrase() -> Result<(), DsmError> {
        // Create a test state
        let device_info = DeviceInfo::new("test_device", vec![0u8; 32]);
        let state = State::new_genesis(vec![0u8; 32], device_info.clone());

        // Create a mnemonic
        let mnemonic = MnemonicPhrase::new_random(MnemonicStrength::Words12)?;

        // Create a recovery phrase
        let recovery_phrase = RecoveryPhrase::new(&state, &mnemonic)?;

        // Verify it works for the state
        assert!(recovery_phrase.verify_for_state(&state)?);

        // Verify we can recreate the mnemonic
        let recreated = recovery_phrase.to_mnemonic()?;
        assert_eq!(mnemonic.as_string(), recreated.as_string());

        Ok(())
    }

    #[test]
    fn test_sharable_seed() -> Result<(), DsmError> {
        // Create a test state
        let device_info = DeviceInfo::new("test_device", vec![0u8; 32]);
        let state = State::new_genesis(vec![0u8; 32], device_info.clone());

        // Create a mnemonic
        let mnemonic = MnemonicPhrase::new_random(MnemonicStrength::Words12)?;

        // Create a recovery phrase
        let recovery_phrase = RecoveryPhrase::new(&state, &mnemonic)?;

        // Create a sharable seed with a password
        let password = "test_password";
        let sharable_seed = ShareableSeed::new(&recovery_phrase, password)?;

        // Add a hint
        let sharable_seed = sharable_seed.with_hint("test_hint", "This is a test hint");

        // Recover the original recovery phrase
        let recovered_phrase = sharable_seed.recover(password)?;

        // Verify the recovery phrase matches
        assert_eq!(recovery_phrase.id, recovered_phrase.id);
        assert_eq!(recovery_phrase.phrase, recovered_phrase.phrase);
        assert_eq!(
            recovery_phrase.recoverable_state,
            recovered_phrase.recoverable_state
        );

        // Verify hint works
        assert_eq!(
            sharable_seed.get_hint("test_hint"),
            Some("This is a test hint")
        );

        Ok(())
    }

    #[test]
    fn test_device_recovery() -> Result<(), DsmError> {
        // Create initial device state
        let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
        let mut state = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
        let computed_hash = state.compute_hash()?;
        state.hash = computed_hash;

        // Create recovery data
        let recovery_data = DeviceRecoveryData::new(
            device_info.clone(),
            vec![9, 10, 11, 12], // Recovery entropy
            state.hash.clone(),
            state.state_number,
        );

        // Create mnemonic for recovery
        let mnemonic = MnemonicPhrase::new_random(MnemonicStrength::Words12)?;

        // Perform recovery
        let recovered_state = recover_state(&recovery_data, &mnemonic)?;

        // Verify recovered state properties per whitepaper section 12
        assert_eq!(recovered_state.state_number, state.state_number + 1);
        assert_eq!(recovered_state.device_info.device_id, device_info.device_id);
        assert!(recovered_state
            .flags
            .contains(&crate::types::state_types::StateFlag::Recovered));
        assert_eq!(recovered_state.prev_state_hash, state.hash);

        // Verify entropy evolution
        let mut hasher = blake3::Hasher::new();
        hasher.update(&recovery_data.recovery_entropy);
        hasher.update(b"RECOVERY");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        hasher.update(&timestamp.to_le_bytes());
        let expected_entropy = hasher.finalize().as_bytes().to_vec();
        assert_eq!(recovered_state.entropy, expected_entropy);

        // Verify operation type and data
        match recovered_state.operation {
            Operation::Recovery {
                state_number,
                state_hash,
                state_entropy: _,
                ..
            } => {
                assert_eq!(state_number, state.state_number);
                assert_eq!(state_hash, state.hash);
                // The recovery entropy in the state is generated from the recovery data entropy
                // but they are not expected to be equal - so we don't assert equality here
            }
            _ => panic!("Expected Recovery operation"),
        }

        Ok(())
    }

    #[test]
    fn test_device_recovery_with_relationship() -> Result<(), DsmError> {
        // Create initial device states for relationship
        let device_info_a = DeviceInfo::new("device_a", vec![1, 2, 3, 4]);
        let device_info_b = DeviceInfo::new("device_b", vec![5, 6, 7, 8]);

        // Create initial state for device A
        let mut state_a = State::new_genesis(vec![9, 10, 11, 12], device_info_a.clone());

        // Create relationship context
        // Create a simplified RelationshipContext for testing
        let relationship = crate::types::state_types::RelationshipContext {
            entity_id: "device_a".to_string(),
            entity_state_number: 0,
            counterparty_id: "device_b".to_string(),
            counterparty_state_number: 0,
            counterparty_public_key: device_info_b.public_key.clone(),
            relationship_hash: vec![],
            active: true,
        };

        // Add relationship to state
        state_a.relationship_context = Some(relationship.clone());

        // Compute hash
        let computed_hash = state_a.compute_hash()?;
        state_a.hash = computed_hash;

        // Create recovery data with relationship context
        let mut recovery_data = DeviceRecoveryData::new(
            device_info_a.clone(),
            vec![17, 18, 19, 20],
            state_a.hash.clone(),
            state_a.state_number,
        );

        // Add relationship context to recovery metadata
        // Serialize the relationship context directly
        let relationship_bytes = bincode::serialize(&relationship.clone())
            .map_err(|e| DsmError::serialization("Failed to serialize relationship", Some(e)))?;
        recovery_data = recovery_data.with_metadata("relationship_context", relationship_bytes);

        // Create mnemonic and perform recovery
        let mnemonic = MnemonicPhrase::new_random(MnemonicStrength::Words12)?;
        let recovered_state = recover_state(&recovery_data, &mnemonic)?;

        // Verify relationship context was restored
        assert!(recovered_state.relationship_context.is_some());
        let recovered_relationship = recovered_state.relationship_context.unwrap();
        assert_eq!(recovered_relationship.entity_id, relationship.entity_id);
        assert_eq!(
            recovered_relationship.counterparty_id,
            relationship.counterparty_id
        );
        assert_eq!(recovered_relationship.active, relationship.active);

        Ok(())
    }
}
