// Blind encryption module for DSM Storage Node
//
// This module implements blinded encryption operations for privacy-preserving storage

use crate::encryption::quantum_resistant::{
    bytes_to_public_key, bytes_to_secret_key, generate_random_bytes,
};
use crate::error::{Result, StorageNodeError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use blake3;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use rand::{rngs::OsRng, RngCore};

// Define the constant that was missing
// This is the correct size for ML-KEM-1024 ciphertext
#[allow(dead_code)]
const MLKEM1024_CIPHERTEXT_BYTES: usize = 1568;

/// Generate a blinded ID from an original ID using one-way hashing
pub fn generate_blinded_id(original_id: &str, blinding_factor: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(original_id.as_bytes());
    hasher.update(blinding_factor);
    let hash = hasher.finalize();

    // Return base64-encoded hash as the blinded ID using the new API
    BASE64_STANDARD.encode(hash.as_bytes())
}

/// Encrypt payload using quantum-resistant encryption with blinding
pub fn blind_encrypt(
    data: &[u8],
    public_key_bytes: &[u8],
    blinding_factor: &[u8],
) -> Result<Vec<u8>> {
    // Convert bytes to public key
    let public_key = bytes_to_public_key(public_key_bytes)?;

    // Encapsulate to get shared secret and ciphertext
    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&public_key);

    // Derive encryption key from shared secret and blinding factor
    let encryption_key = derive_encryption_key(shared_secret.as_bytes(), blinding_factor);

    // Encrypt the data with AES-GCM
    let encrypted_data = aes_gcm_encrypt(data, &encryption_key)?;

    // Combine ciphertext and encrypted data
    let mut result = Vec::new();
    result.extend_from_slice(ciphertext.as_bytes());
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

/// Decrypt blinded encrypted payload using quantum-resistant decryption
pub fn blind_decrypt(
    encrypted_data: &[u8],
    secret_key_bytes: &[u8],
    blinding_factor: &[u8],
) -> Result<Vec<u8>> {
    // Check minimum length requirements
    let ct_len = mlkem1024::ciphertext_bytes();
    if encrypted_data.len() <= ct_len {
        return Err(StorageNodeError::Encryption(
            "Invalid encrypted data length".into(),
        ));
    }

    // Split the input into ciphertext and encrypted payload
    let (ciphertext_bytes, aes_encrypted) = encrypted_data.split_at(ct_len);

    // Convert bytes to secret key and ciphertext
    let secret_key = bytes_to_secret_key(secret_key_bytes)?;

    let ciphertext = match pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(ciphertext_bytes) {
        Ok(ct) => ct,
        Err(_) => {
            return Err(StorageNodeError::Encryption(
                "Invalid ciphertext format".into(),
            ))
        }
    };

    // Decapsulate to get shared secret
    let shared_secret = mlkem1024::decapsulate(&ciphertext, &secret_key);

    // Derive encryption key from shared secret and blinding factor
    let encryption_key = derive_encryption_key(shared_secret.as_bytes(), blinding_factor);

    // Decrypt the data with AES-GCM
    aes_gcm_decrypt(aes_encrypted, &encryption_key)
}

/// Derive an encryption key from a shared secret and blinding factor
fn derive_encryption_key(shared_secret: &[u8], blinding_factor: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(shared_secret);
    hasher.update(blinding_factor);
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Encrypt data with AES-GCM
fn aes_gcm_encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher instance
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    // Encrypt the data
    let encrypted = cipher
        .encrypt(nonce, data)
        .map_err(|e| StorageNodeError::Encryption(format!("AES encryption failed: {}", e)))?;

    // Combine nonce and encrypted data
    let mut result = Vec::new();
    result.extend_from_slice(nonce);
    result.extend_from_slice(&encrypted);

    Ok(result)
}

/// Decrypt data with AES-GCM
fn aes_gcm_decrypt(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    // Check minimum length requirements
    if encrypted_data.len() <= 12 {
        return Err(StorageNodeError::Encryption(
            "Invalid encrypted data length".into(),
        ));
    }

    // Split the input into nonce and encrypted payload
    let (nonce_bytes, encrypted) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Create cipher instance
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    // Decrypt the data
    let decrypted = cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| StorageNodeError::Encryption(format!("AES decryption failed: {}", e)))?;

    Ok(decrypted)
}

/// Generate a proof hash for the encrypted payload
pub fn generate_proof_hash(blinded_id: &str, encrypted_payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(blinded_id.as_bytes());
    hasher.update(encrypted_payload);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Verify a proof hash for the encrypted payload
pub fn verify_proof_hash(
    blinded_id: &str,
    encrypted_payload: &[u8],
    proof_hash: &[u8; 32],
) -> bool {
    let computed_hash = generate_proof_hash(blinded_id, encrypted_payload);
    computed_hash == *proof_hash
}

/// Generate random blinding factor
pub fn generate_blinding_factor() -> Vec<u8> {
    generate_random_bytes(32)
}
