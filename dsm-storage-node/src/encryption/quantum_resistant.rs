// Quantum-resistant cryptography module for DSM Storage Node
//
// This module implements quantum-resistant cryptographic operations
// using post-quantum algorithms like SPHINCS+, ML-KEM, etc.

use crate::error::{Result, StorageNodeError};
use pqcrypto_mlkem::mlkem1024::{self, Ciphertext, PublicKey, SecretKey};
use pqcrypto_traits::kem::{
    Ciphertext as CipherText, PublicKey as PubKey, SecretKey as SecKey, SharedSecret,
};
use rand::{rngs::OsRng, RngCore};
use std::fmt;

/// Generate a new quantum-resistant key pair for key encapsulation
pub fn generate_kyber_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mlkem1024::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Convert bytes to Kyber public key
pub fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_bytes(bytes)
        .map_err(|_| StorageNodeError::Encryption("Invalid public key format".into()))
}

/// Convert bytes to Kyber secret key
pub fn bytes_to_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    SecretKey::from_bytes(bytes)
        .map_err(|_| StorageNodeError::Encryption("Invalid secret key format".into()))
}

/// Encapsulate a shared secret using a public key
pub fn kyber_encapsulate(public_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Convert bytes to public key
    let public_key = bytes_to_public_key(public_key_bytes)?;

    // Encapsulate to get shared secret and ciphertext
    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&public_key);

    // Convert to bytes
    Ok((
        shared_secret.as_bytes().to_vec(),
        ciphertext.as_bytes().to_vec(),
    ))
}

/// Decapsulate a shared secret using a secret key and ciphertext
pub fn kyber_decapsulate(secret_key_bytes: &[u8], ciphertext_bytes: &[u8]) -> Result<Vec<u8>> {
    // Convert bytes to secret key
    let secret_key = bytes_to_secret_key(secret_key_bytes)?;

    // Convert bytes to ciphertext
    let ciphertext = match Ciphertext::from_bytes(ciphertext_bytes) {
        Ok(ct) => ct,
        Err(_) => {
            return Err(StorageNodeError::Encryption(
                "Invalid ciphertext format".into(),
            ))
        }
    };

    // Decapsulate to get shared secret
    let shared_secret = mlkem1024::decapsulate(&ciphertext, &secret_key);

    // Convert to bytes
    Ok(shared_secret.as_bytes().to_vec())
}

/// Generate a quantum-resistant signature for data
pub fn sphincs_sign(data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    // This is a placeholder for SPHINCS+ signing
    // In a real implementation, this would use the SPHINCS+ algorithm
    // For now, we'll use a simple wrapper around Blake3 with the secret key

    let mut hasher = blake3::Hasher::new();
    hasher.update(secret_key);
    hasher.update(data);
    let hash = hasher.finalize();

    Ok(hash.as_bytes().to_vec())
}

/// Verify a quantum-resistant signature
pub fn sphincs_verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // This is a placeholder for SPHINCS+ verification
    // In a real implementation, this would use the SPHINCS+ algorithm
    // For now, we'll use a simple wrapper around Blake3 with the public key

    let mut hasher = blake3::Hasher::new();
    hasher.update(public_key);
    hasher.update(data);
    let hash = hasher.finalize();

    let signature_hash = if signature.len() >= 32 {
        &signature[0..32]
    } else {
        return Err(StorageNodeError::Encryption(
            "Invalid signature length".into(),
        ));
    };

    Ok(hash.as_bytes() == signature_hash)
}

/// Generate random bytes using a quantum-resistant PRNG
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A wrapper for quantum-resistant key pair
#[derive(Clone)]
pub struct QuantumKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Default for QuantumKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl QuantumKeyPair {
    /// Create a new quantum-resistant key pair
    pub fn new() -> Self {
        let (public_key, secret_key) = generate_kyber_keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Create from existing keys
    pub fn from_keys(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }
}

impl fmt::Debug for QuantumKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuantumKeyPair")
            .field("public_key", &format!("[{} bytes]", self.public_key.len()))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}
