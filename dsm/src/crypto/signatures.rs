// signatures.rs
//
// Enhanced signature implementation using pure cryptographic guarantees
// as described in the DSM whitepaper to replace TEE/enclave approach

use crate::crypto::sphincs;
use crate::types::error::DsmError;

/// Signature type for DSM
pub type Signature = Vec<u8>;

/// SignatureKeyPair is a quantum-resistant key pair for creating and verifying signatures
#[derive(Debug, Clone)]
pub struct SignatureKeyPair {
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// Secret key for signature creation
    pub secret_key: Vec<u8>,
}

impl SignatureKeyPair {
    /// Generate a new SPHINCS+ key pair
    pub fn generate() -> Result<Self, DsmError> {
        let (public_key, secret_key) = sphincs::generate_sphincs_keypair();

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Generate a key pair from existing entropy
    pub fn generate_from_entropy(entropy: &[u8]) -> Result<Self, DsmError> {
        // Hash the entropy to get a fixed-size seed
        let seed = crate::crypto::blake3::hash_blake3_as_bytes(entropy);
        let seed_array: [u8; 32] = seed;

        // Generate deterministic SPHINCS+ keypair using the seed
        let (public_key, secret_key) = sphincs::generate_sphincs_keypair_from_seed(&seed_array)
            .map_err(|e| DsmError::Crypto {
                context: format!("Failed to generate keypair from seed: {}", e),
                source: None,
            })?;

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Sign data using SPHINCS+
    pub fn sign(&self, data: &[u8]) -> Result<Signature, DsmError> {
        sphincs::sphincs_sign(&self.secret_key, data)
    }

    /// Verify a signature using SPHINCS+
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<bool, DsmError> {
        sphincs::sphincs_verify(&self.public_key, data, signature)
    }

    /// Verify a signature with a raw public key
    pub fn verify_raw(
        data: &[u8],
        signature: &Signature,
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        sphincs::sphincs_verify(public_key, data, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = SignatureKeyPair::generate().unwrap();

        // Ensure keys are not empty
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.secret_key.is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let data = b"test data";

        // Sign the data
        let signature = keypair.sign(data).unwrap();

        // Verify the signature
        let result = keypair.verify(data, &signature).unwrap();
        assert!(result);

        // Verify with wrong data
        let wrong_data = b"wrong data";
        let result = keypair.verify(wrong_data, &signature).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_raw() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let data = b"test data";

        // Sign the data
        let signature = keypair.sign(data).unwrap();

        // Verify using raw public key
        let result = SignatureKeyPair::verify_raw(data, &signature, &keypair.public_key).unwrap();
        assert!(result);
    }
}
