    // Crypto module for DSM Storage Node
    //
    // This module integrates with the DSM cryptography system and provides
    // cryptographic operations for the storage node.

    use crate::error::{Result, StorageNodeError};
    use dsm::crypto::{
        decrypt_from_sender, encrypt_for_recipient, sphincs::generate_sphincs_keypair,
        sphincs::sphincs_sign, sphincs::sphincs_verify
    };

    use base64::engine::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rand::{rngs::OsRng, Rng};
    use std::sync::Once;
    use std::path::Path;
    use std::fs;
    use tracing::{debug, info};

    // Ensure crypto initialization happens only once
    static INIT: Once = Once::new();

    /// Initialize cryptography system
    pub fn init_crypto() {
        INIT.call_once(|| {
            // Initialize DSM crypto module
            dsm::crypto::init_crypto();
            info!("Cryptography system initialized");
        });
    }

    /// Generate node keypair
    pub fn generate_node_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        debug!("Generating node keypair");
        
        // Use SPHINCS+ for node identity
        let (public_key, private_key) = generate_sphincs_keypair();
        
        Ok((public_key.to_vec(), private_key.to_vec()))
    }

    /// Load or generate node keypair
    pub fn load_or_generate_keypair(
        private_key_path: &Path,
        public_key_path: &Path,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Check if keys exist
        if private_key_path.exists() && public_key_path.exists() {
            debug!("Loading existing node keypair");
            
            // Load keys from files
            let private_key = fs::read(private_key_path)
                .map_err(|e| StorageNodeError::Encryption(format!("Failed to read private key: {}", e)))?;
                
            let public_key = fs::read(public_key_path)
                .map_err(|e| StorageNodeError::Encryption(format!("Failed to read public key: {}", e)))?;
                
            Ok((public_key, private_key))
        } else {
            debug!("Generating new node keypair");
            
            // Generate new keypair
            let (public_key, private_key) = generate_node_keypair()?;
            
            // Create parent directories if they don't exist
            if let Some(parent) = private_key_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)
                        .map_err(|e| StorageNodeError::Encryption(format!("Failed to create key directory: {}", e)))?;
                }
            }
            
            if let Some(parent) = public_key_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)
                        .map_err(|e| StorageNodeError::Encryption(format!("Failed to create key directory: {}", e)))?;
                }
            }
            
            // Save keys to files
            fs::write(private_key_path, &private_key)
                .map_err(|e| StorageNodeError::Encryption(format!("Failed to write private key: {}", e)))?;
                
            fs::write(public_key_path, &public_key)
                .map_err(|e| StorageNodeError::Encryption(format!("Failed to write public key: {}", e)))?;
                
            debug!("Generated and saved new node keypair");
            
            Ok((public_key, private_key))
        }
    }

    /// Sign data with node private key
    pub fn sign_with_node_key(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        debug!("Signing data with node key");
        
        // Use SPHINCS+ for signing
        let signature = sphincs_sign(data, private_key)
            .map_err(|e| StorageNodeError::Encryption(format!("Failed to sign data: {}", e)))?;
        
        Ok(signature)
    }

    /// Verify signature with node public key
    pub fn verify_with_node_key(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        debug!("Verifying signature with node key");
        
        // Use SPHINCS+ for verification
        let result = sphincs_verify(data, signature, public_key)
            .map_err(|e| StorageNodeError::Encryption(format!("Failed to verify signature: {}", e)))?;
        
        Ok(result)
    }

    /// Encrypt data for a recipient
    pub fn encrypt_data(recipient_public_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        debug!("Encrypting data for recipient");
        
        // Use DSM encrypt_for_recipient
        let encrypted = encrypt_for_recipient(recipient_public_key, data)
            .ok_or_else(|| StorageNodeError::Encryption(format!("Failed to encrypt data")))?;
            
        Ok(encrypted)
    }

    /// Decrypt data from a sender
    pub fn decrypt_data(sender_public_key: &[u8], private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        debug!("Decrypting data from sender");
        
        // Use DSM decrypt_from_sender
        let decrypted = decrypt_from_sender(sender_public_key, data)
            .ok_or_else(|| StorageNodeError::Encryption(format!("Failed to decrypt data")))?;
            
        Ok(decrypted)
    // / Generate a blinded state ID from data
    pub fn generate_blinded_id(data: &[u8], salt: &[u8]) -> String {
        debug!("Generating blinded state ID");
        
        // Use Blake3 for blinded ID generation
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        hasher.update(salt);
        let hash = hasher.finalize();
        // Convert to base64 for easier handling
        STANDARD.encode(hash.as_bytes())
    }

    /// Generate a random salt
    pub fn generate_random_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        OsRng.fill(&mut salt);
        salt
    }

    /// Generate a deterministic id for a storage node based on public key
    pub fn generate_node_id(public_key: &[u8]) -> String {
        debug!("Generating node ID from public key");
        
        // Hash the public key
        let mut hasher = blake3::Hasher::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        
        // Take first 16 bytes and convert to hex for a readable node ID
        let id_bytes = &hash.as_bytes()[0..16];
        hex::encode(id_bytes)
    }
    }
