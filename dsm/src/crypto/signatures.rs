// signatures.rs
//
// Enhanced signature implementation using pure cryptographic guarantees
// as described in the DSM whitepaper to replace TEE/enclave approach

use crate::crypto::sphincs;
use crate::types::error::DsmError;
use crate::crypto::blake3;

/// Signature type for DSM
pub type Signature = Vec<u8>;

/// Quantum-resistant SPHINCS+ key pair for DSM signatures
#[derive(Debug, Clone)]
pub struct SignatureKeyPair {
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// Secret key for signature creation
    pub secret_key: Vec<u8>,
}

impl SignatureKeyPair {
    /// Generate a new random SPHINCS+ key pair
    pub fn generate() -> Result<Self, DsmError> {
        let (public_key, secret_key) = sphincs::generate_sphincs_keypair()?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Deterministically generate a SPHINCS+ key pair from user-provided entropy
    pub fn generate_from_entropy(entropy: &[u8]) -> Result<Self, DsmError> {
        if entropy.is_empty() {
            return Err(DsmError::Crypto {
                context: "Entropy must not be empty.".to_string(),
                source: None,
            });
        }

        // Hash the entropy to derive a fixed-size seed for deterministic keypair generation
        let seed_hash = blake3::hash_blake3_as_bytes(entropy);
        let seed_array: [u8; 32] = seed_hash;

        let (public_key, secret_key) = sphincs::generate_sphincs_keypair_from_seed(&seed_array)
            .map_err(|e| DsmError::Crypto {
                context: format!("Failed to generate deterministic keypair: {}", e),
                source: None,
            })?;

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Sign arbitrary data using SPHINCS+ and the secret key
    pub fn sign(&self, data: &[u8]) -> Result<Signature, DsmError> {
        if data.is_empty() {
            return Err(DsmError::Crypto {
                context: "Data to sign cannot be empty.".to_string(),
                source: None,
            });
        }

        sphincs::sphincs_sign(&self.secret_key, data)
    }

    /// Verify a signature against the provided data using the stored public key
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<bool, DsmError> {
        if data.is_empty() || signature.is_empty() {
            return Err(DsmError::Crypto {
                context: "Data and signature cannot be empty.".to_string(),
                source: None,
            });
        }

        sphincs::sphincs_verify(&self.public_key, data, signature)
    }

    /// Verify a signature using an externally provided raw public key
    pub fn verify_raw(
        data: &[u8],
        signature: &Signature,
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        if data.is_empty() || signature.is_empty() || public_key.is_empty() {
            return Err(DsmError::Crypto {
                context: "Data, signature, and public key must not be empty.".to_string(),
                source: None,
            });
        }

        sphincs::sphincs_verify(public_key, data, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = SignatureKeyPair::generate().unwrap();

        assert_eq!(keypair.public_key.len(), sphincs::public_key_bytes());
        assert_eq!(keypair.secret_key.len(), sphincs::secret_key_bytes());
    }

    #[test]
    fn test_deterministic_keypair_generation() {
        let entropy = b"strong entropy source";
        let keypair1 = SignatureKeyPair::generate_from_entropy(entropy).unwrap();
        let keypair2 = SignatureKeyPair::generate_from_entropy(entropy).unwrap();

        assert_eq!(keypair1.public_key, keypair2.public_key);
        assert_eq!(keypair1.secret_key, keypair2.secret_key);

        let different_entropy = b"different entropy";
        let keypair3 = SignatureKeyPair::generate_from_entropy(different_entropy).unwrap();

        assert_ne!(keypair1.public_key, keypair3.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let data = b"test data for signing";

        let signature = keypair.sign(data).unwrap();
        assert_eq!(signature.len(), sphincs::signature_bytes());

        let verification_result = keypair.verify(data, &signature).unwrap();
        assert!(verification_result);

        let invalid_verification_result = keypair.verify(b"modified data", &signature).unwrap();
        assert!(!invalid_verification_result);
    }

    #[test]
    fn test_verify_raw() {
        let keypair = SignatureKeyPair::generate().unwrap();
        let data = b"data verification with raw key";

        let signature = keypair.sign(data).unwrap();
        let verification_result =
            SignatureKeyPair::verify_raw(data, &signature, &keypair.public_key).unwrap();

        assert!(verification_result);
    }

    #[test]
    fn test_invalid_inputs() {
        let keypair = SignatureKeyPair::generate().unwrap();

        // Test empty data signing
        assert!(keypair.sign(b"").is_err());

        // Test verification with empty data or signature
        assert!(keypair.verify(b"", &vec![]).is_err());
        assert!(SignatureKeyPair::verify_raw(b"", &vec![], &[]).is_err());
    }
}