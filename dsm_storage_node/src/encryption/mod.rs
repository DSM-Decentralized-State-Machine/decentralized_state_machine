// Encryption module for DSM Storage Node
//
// This module implements quantum-resistant cryptographic functions
// based on Section 16.3 of the whitepaper "Quantum-Resistant Encryption and Blind Storage"

use crate::error::{Result, StorageNodeError};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::{rngs::OsRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::collections::HashMap;
use zeroize::Zeroize;

pub mod blind_encryption;
pub mod quantum_resistant;

/// Blinded ID derivation from original ID
///
/// This function creates privacy-preserving blinded identifiers from original IDs
/// using quantum-resistant hash functions
pub fn derive_blinded_id(original_id: &[u8], blinding_factor: &[u8]) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(original_id);
    hasher.update(blinding_factor);
    let hash = hasher.finalize();

    Ok(STANDARD.encode(hash.as_bytes()))
}

/// Generate a cryptographically secure blinding factor
pub fn generate_blinding_factor() -> [u8; 32] {
    let mut blinding_factor = [0u8; 32];
    OsRng.fill_bytes(&mut blinding_factor);
    blinding_factor
}

/// Quantum-resistant encryption of data
pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Use SHAKE-256 for key derivation (quantum-resistant)
    let mut shake = Shake256::default();
    shake.update(key);

    // Generate 32-byte encryption key and 12-byte nonce
    let mut xof = shake.finalize_xof();
    let mut encryption_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    xof.read(&mut encryption_key);
    xof.read(&mut nonce);

    // Use ChaCha20Poly1305 for authenticated encryption
    let cipher = ChaCha20Poly1305::new(&encryption_key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|e| StorageNodeError::Encryption(format!("Encryption failed: {}", e)))?;

    // Zeroize sensitive data
    encryption_key.zeroize();

    Ok(ciphertext)
}

/// Quantum-resistant decryption of data
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Use SHAKE-256 for key derivation (quantum-resistant)
    let mut shake = Shake256::default();
    shake.update(key);

    // Generate 32-byte encryption key and 12-byte nonce (same as encryption)
    let mut xof = shake.finalize_xof();
    let mut encryption_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    xof.read(&mut encryption_key);
    xof.read(&mut nonce);

    // Use ChaCha20Poly1305 for authenticated decryption
    let cipher = ChaCha20Poly1305::new(&encryption_key.into());
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), encrypted_data)
        .map_err(|e| StorageNodeError::Encryption(format!("Decryption failed: {}", e)))?;

    // Zeroize sensitive data
    encryption_key.zeroize();

    Ok(plaintext)
}

/// Hash data using Blake3 (quantum-resistant)
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(hash.as_bytes());
    hash_bytes
}

/// Generate metadata encryption key
pub fn generate_metadata_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt metadata
pub fn encrypt_metadata(metadata: &HashMap<String, String>, key: &[u8]) -> Result<Vec<u8>> {
    // Serialize metadata to JSON
    let json = serde_json::to_vec(metadata).map_err(|e| {
        StorageNodeError::Encryption(format!("Failed to serialize metadata: {}", e))
    })?;

    // Encrypt serialized metadata
    encrypt_data(&json, key)
}

/// Decrypt metadata
pub fn decrypt_metadata(encrypted_metadata: &[u8], key: &[u8]) -> Result<HashMap<String, String>> {
    // Decrypt metadata
    let json = decrypt_data(encrypted_metadata, key)?;

    // Deserialize JSON to metadata
    let metadata = serde_json::from_slice(&json).map_err(|e| {
        StorageNodeError::Encryption(format!("Failed to deserialize metadata: {}", e))
    })?;

    Ok(metadata)
}
