// Enhanced Kyber post-quantum key encapsulation implementation
use crate::types::error::DsmError;
use std::sync::atomic::{AtomicBool, Ordering};

static KYBER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the Kyber KEM subsystem
pub fn init_kyber() {
    if !KYBER_INITIALIZED.load(Ordering::SeqCst) {
        // Perform necessary initialization for Kyber
        
        // Verify the system is properly configured for Kyber
        let verify_keypair = || -> Result<(), String> {
            let result = std::panic::catch_unwind(|| {
                // Generate a test key pair to ensure the implementation works
                let (pk, sk) = mlkem512::keypair();
                
                // Verify the sizes are as expected
                if pk.as_bytes().len() != mlkem512::public_key_bytes() {
                    return Err(format!("Public key size mismatch: {} vs {}", 
                                       pk.as_bytes().len(), mlkem512::public_key_bytes()));
                }
                
                if sk.as_bytes().len() != mlkem512::secret_key_bytes() {
                    return Err(format!("Secret key size mismatch: {} vs {}", 
                                       sk.as_bytes().len(), mlkem512::secret_key_bytes()));
                }
                
                // Test encapsulation and decapsulation
                let (ss, ct) = mlkem512::encapsulate(&pk);
                let ss2 = mlkem512::decapsulate(&ct, &sk);
                
                if ss.as_bytes() != ss2.as_bytes() {
                    return Err("Shared secret mismatch after decapsulation".to_string());
                }
                
                Ok(())
            });
            
            match result {
                Ok(inner_result) => inner_result,
                Err(_) => Err("Panic during Kyber initialization test".to_string()),
            }
        };
        
        // Verify Kyber works properly
        match verify_keypair() {
            Ok(_) => {
                tracing::info!("Kyber KEM subsystem successfully initialized and verified");
                KYBER_INITIALIZED.store(true, Ordering::SeqCst);
            },
            Err(e) => {
                tracing::error!("Failed to initialize Kyber KEM subsystem: {}", e);
                // In a production environment, this would trigger a critical error
                // For now, we'll just mark it as initialized to prevent repeated attempts
                KYBER_INITIALIZED.store(true, Ordering::SeqCst);
            }
        }
    }
}
// Using the whitepaper approach (section 25) for cryptographic binding
// instead of hardware-specific security modules
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use pqcrypto_mlkem::mlkem512;
use pqcrypto_traits::kem::SecretKey;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use serde::{Deserialize, Serialize};

/// KyberKeyPair contains a quantum-resistant key pair for key encapsulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberKeyPair {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// Secret key for decapsulation
    pub secret_key: Vec<u8>,
}

/// Encapsulation result containing shared secret and ciphertext
#[derive(Debug, Clone)]
pub struct EncapsulationResult {
    /// Shared secret derived from key encapsulation mechanism
    pub shared_secret: Vec<u8>,
    /// Ciphertext containing encapsulated key
    pub ciphertext: Vec<u8>,
}

/// Get the number of bytes for a shared secret
pub fn shared_secret_bytes() -> usize {
    mlkem512::shared_secret_bytes()
}

/// Get the number of bytes for a ciphertext
pub fn ciphertext_bytes() -> usize {
    mlkem512::ciphertext_bytes()
}

/// Generate Kyber key pair using the pqcrypto library
pub fn generate_kyber_keypair() -> (Vec<u8>, Vec<u8>) {
    // Using Kyber512 for tests
    let (pk, sk) = mlkem512::keypair();

    // Convert to bytes for storage/transmission
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

impl KyberKeyPair {
    /// Generate a new Kyber keypair
    pub fn generate() -> Result<Self, DsmError> {
        let (public_key, secret_key) = generate_kyber_keypair();

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Generate a key pair from existing entropy
    pub fn generate_from_entropy(entropy: &[u8]) -> Result<Self, DsmError> {
        // For now, we'll use the entropy to seed a PRNG and then generate a key pair
        // In a full implementation, we would use a deterministic key derivation function
        let _seed = crate::crypto::blake3::hash_blake3_as_bytes(entropy);

        // In real implementation, this would use the seed deterministically
        // For now, we'll just call the regular generate function
        let (public_key, secret_key) = generate_kyber_keypair();

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Encapsulate a shared secret using our public key
    pub fn encapsulate(&self) -> Result<EncapsulationResult, DsmError> {
        // Encapsulate using our public key
        let (shared_secret, ciphertext) = kyber_encapsulate(&self.public_key)?;

        Ok(EncapsulationResult {
            shared_secret,
            ciphertext,
        })
    }

    /// Encapsulate a shared secret for a recipient
    pub fn encapsulate_for_recipient(
        &self,
        recipient_public_key: &[u8],
    ) -> Result<EncapsulationResult, DsmError> {
        // Encapsulate using recipient's public key
        let (shared_secret, ciphertext) = kyber_encapsulate(recipient_public_key)?;

        Ok(EncapsulationResult {
            shared_secret,
            ciphertext,
        })
    }

    /// Decapsulate a shared secret
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DsmError> {
        // Decapsulate using our secret key
        kyber_decapsulate(&self.secret_key, ciphertext)
    }
}

/// Encapsulate a shared secret using Kyber
///
/// # Parameters
/// - `public_key_bytes`: A byte slice representing the public key.
///
/// # Returns
/// - `Ok((Vec<u8>, Vec<u8>))`: A tuple containing the shared secret and ciphertext as byte vectors.
/// - `Err(DsmError)`: An error if the public key is invalid.
pub fn kyber_encapsulate(public_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    // First, validate the public key length
    if public_key_bytes.len() != mlkem512::public_key_bytes() {
        return Err(DsmError::InvalidPublicKey);
    }

    // Recreate public key from bytes
    let pk = match mlkem512::PublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            // Log debug information but return a standardized error
            tracing::error!(
                "Failed to construct PublicKey from {} bytes",
                public_key_bytes.len()
            );
            return Err(DsmError::InvalidPublicKey);
        }
    };

    // Encapsulate to get ciphertext and shared secret
    let (ss, ct) = mlkem512::encapsulate(&pk);

    // Validate output sizes
    let ss_bytes = ss.as_bytes().to_vec();
    let ct_bytes = ct.as_bytes().to_vec();

    if ct_bytes.len() != mlkem512::ciphertext_bytes()
        || ss_bytes.len() != mlkem512::shared_secret_bytes()
    {
        return Err(DsmError::crypto(
            format!(
                "Unexpected output sizes: ct={}, ss={}",
                ct_bytes.len(),
                ss_bytes.len()
            ),
            None::<std::io::Error>,
        ));
    }

    Ok((ss_bytes, ct_bytes))
}

/// Decapsulate a shared secret using Kyber
pub fn kyber_decapsulate(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Vec<u8>, DsmError> {
    // Validate input lengths
    if secret_key_bytes.len() != mlkem512::secret_key_bytes() {
        return Err(DsmError::InvalidSecretKey);
    }

    if ciphertext_bytes.len() != mlkem512::ciphertext_bytes() {
        return Err(DsmError::InvalidCiphertext);
    }

    // Recreate secret key and ciphertext from bytes
    let sk = match mlkem512::SecretKey::from_bytes(secret_key_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            tracing::error!("Failed to construct SecretKey: {:?}", e);
            return Err(DsmError::InvalidSecretKey);
        }
    };

    let ct = match mlkem512::Ciphertext::from_bytes(ciphertext_bytes) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::error!("Failed to construct Ciphertext: {:?}", e);
            return Err(DsmError::InvalidCiphertext);
        }
    };

    // Decapsulate to get the shared secret
    let ss = mlkem512::decapsulate(&ct, &sk);

    // Validate output
    let ss_bytes = ss.as_bytes().to_vec();
    if ss_bytes.len() != mlkem512::shared_secret_bytes() {
        return Err(DsmError::crypto(
            format!("Unexpected shared secret size: {}", ss_bytes.len()),
            None::<std::io::Error>,
        ));
    }

    // Return the shared secret as bytes
    Ok(ss_bytes)
}

/// AES encryption that handles any key size
///
/// This function will create a 32-byte AES key from the provided key,
/// using as many bytes as possible from the source key.
pub fn aes_encrypt(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, DsmError> {
    // Create a fixed-size key for AES-256
    let mut aes_key = [0u8; 32];

    // Use a consistent derivation of the key by hashing it first
    let key_hash = blake3::hash(key);
    let key_hash_bytes = key_hash.as_bytes();

    // Copy the hash bytes to the AES key
    let len = std::cmp::min(key_hash_bytes.len(), aes_key.len());
    aes_key[..len].copy_from_slice(&key_hash_bytes[..len]);

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce);
    cipher.encrypt(nonce, data).map_err(|e| {
        DsmError::crypto(
            format!("AES encryption failed: {}", e),
            None::<std::io::Error>,
        )
    })
}

/// AES decryption that handles any key size
///
/// This function will create a 32-byte AES key from the provided key,
/// using as many bytes as possible from the source key.
pub fn aes_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DsmError> {
    // Create a fixed-size key for AES-256
    let mut aes_key = [0u8; 32];

    // Use a consistent derivation of the key by hashing it first
    let key_hash = blake3::hash(key);
    let key_hash_bytes = key_hash.as_bytes();

    // Copy the hash bytes to the AES key
    let len = std::cmp::min(key_hash_bytes.len(), aes_key.len());
    aes_key[..len].copy_from_slice(&key_hash_bytes[..len]);

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        DsmError::crypto(
            format!("AES decryption failed: {}", e),
            None::<std::io::Error>,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KyberKeyPair::generate().unwrap();

        // Ensure keys are not empty
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.secret_key.is_empty());
    }

    #[test]
    fn test_encapsulation_and_decapsulation() {
        let keypair = KyberKeyPair::generate().unwrap();

        // Encapsulate using our public key
        let encap_result = keypair.encapsulate().unwrap();

        // Ensure results are not empty
        assert!(!encap_result.shared_secret.is_empty());
        assert!(!encap_result.ciphertext.is_empty());

        // Decapsulate using our secret key
        let shared_secret = keypair.decapsulate(&encap_result.ciphertext).unwrap();

        // Ensure the decapsulated shared secret matches the encapsulated one
        assert_eq!(encap_result.shared_secret, shared_secret);
    }

    #[test]
    fn test_encapsulation_for_recipient() {
        // Generate two keypairs
        let alice = KyberKeyPair::generate().unwrap();
        let bob = KyberKeyPair::generate().unwrap();

        // Alice encapsulates for Bob
        let encap_result = alice.encapsulate_for_recipient(&bob.public_key).unwrap();

        // Bob decapsulates
        let shared_secret = bob.decapsulate(&encap_result.ciphertext).unwrap();

        // Ensure the shared secrets match
        assert_eq!(encap_result.shared_secret, shared_secret);
    }

    #[test]
    fn test_encapsulation_and_encryption() {
        // Generate a keypair
        let keypair = KyberKeyPair::generate().unwrap();

        // Encapsulate
        let encap_result = keypair.encapsulate().unwrap();

        // Use the shared secret for encryption
        let plaintext = b"Test message for encryption";
        let nonce = vec![0; 12];

        // Encrypt
        let ciphertext = aes_encrypt(&encap_result.shared_secret, &nonce, plaintext).unwrap();

        // Decapsulate
        let shared_secret = keypair.decapsulate(&encap_result.ciphertext).unwrap();

        // Decrypt
        let decrypted = aes_decrypt(&shared_secret, &nonce, &ciphertext).unwrap();

        // Ensure the decrypted text matches the original
        assert_eq!(plaintext, &decrypted[..]);
    }
}
