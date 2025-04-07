// cryptographic_identity.rs
//
// Implementation of cryptographic identity mechanisms that replace hardware-specific
// TEE/enclave approaches with pure mathematical guarantees as described in the whitepaper.

use std::collections::HashMap;

use crate::crypto::hash::{blake3, HashOutput};
use crate::crypto::kyber::KyberKeyPair;
use crate::crypto::signatures::Signature;
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::error::DsmError;

/// CryptoIdentity replaces hardware-bound identity with cryptographic guarantees
///
/// This implements the cryptographic approach described in whitepaper section 5 and 25,
/// providing quantum-resistant device binding without relying on hardware-specific features.
#[derive(Debug, Clone)]
pub struct CryptoIdentity {
    /// Genesis hash for this identity
    pub genesis_hash: HashOutput,

    /// Device identifier hash
    pub device_hash: HashOutput,

    /// SPHINCS+ public key
    pub sphincs_public_key: Vec<u8>,

    /// Kyber public key
    pub kyber_public_key: Vec<u8>,

    /// Application identifier
    pub app_id: String,

    /// Device-specific salt value (for fingerprinting resistance)
    pub device_salt: Vec<u8>,

    /// MPC seed share (contribution to genesis creation)
    pub mpc_seed_share: Vec<u8>,

    /// Current identity state number
    pub state_number: u64,

    /// History of previous identity states (for verification)
    pub state_history: HashMap<u64, HashOutput>,
}

impl CryptoIdentity {
    /// Create a new cryptographic identity with post-quantum security
    ///
    /// This implements the cryptographic identity creation described in whitepaper section 5.1,
    /// using a threshold-based approach for identity origination without TEE dependencies.
    ///
    /// # Arguments
    /// * `app_id` - Application identifier
    /// * `mpc_seed_share` - Seed share from multiparty computation
    /// * `sphincs_keypair` - SPHINCS+ keypair for signatures
    /// * `kyber_keypair` - Kyber keypair for key encapsulation
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - New identity or error
    pub fn new(
        app_id: &str,
        mpc_seed_share: &[u8],
        sphincs_keypair: &SignatureKeyPair,
        kyber_keypair: &KyberKeyPair,
    ) -> Result<Self, DsmError> {
        // Generate device-specific entropy for device hash
        let device_salt = Self::generate_device_salt();

        // Combine all inputs for device hash calculation
        let mut device_data = Vec::new();
        device_data.extend_from_slice(mpc_seed_share);
        device_data.extend_from_slice(app_id.as_bytes());
        device_data.extend_from_slice(&device_salt);

        // Generate device hash
        let device_hash = blake3(&device_data);

        // Generate genesis hash from public keys
        let mut genesis_data = Vec::new();
        genesis_data.extend_from_slice(&kyber_keypair.public_key);
        genesis_data.extend_from_slice(&sphincs_keypair.public_key);
        let genesis_hash = blake3(&genesis_data);

        // Initialize state history with genesis hash
        let mut state_history = HashMap::new();
        state_history.insert(0, genesis_hash.clone());

        Ok(Self {
            genesis_hash,
            device_hash,
            sphincs_public_key: sphincs_keypair.public_key.clone(),
            kyber_public_key: kyber_keypair.public_key.clone(),
            app_id: app_id.to_string(),
            device_salt,
            mpc_seed_share: mpc_seed_share.to_vec(),
            state_number: 0,
            state_history,
        })
    }

    /// Generate a unique device salt using runtime characteristics
    ///
    /// # Returns
    /// * `Vec<u8>` - Device salt
    fn generate_device_salt() -> Vec<u8> {
        // Use runtime characteristics that are unique to the device
        let mut salt_data = Vec::new();

        // Add timestamp for entropy
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        salt_data.extend_from_slice(&timestamp.as_secs().to_be_bytes());
        salt_data.extend_from_slice(&timestamp.subsec_nanos().to_be_bytes());

        // Add process and thread IDs
        let pid = std::process::id();
        salt_data.extend_from_slice(&pid.to_be_bytes());

        // Add random entropy
        let mut random_bytes = [0u8; 32];
        getrandom::getrandom(&mut random_bytes).unwrap_or_default();
        salt_data.extend_from_slice(&random_bytes);

        // Hash everything together for the final salt
        blake3(&salt_data).as_bytes().to_vec()
    }

    /// Verify this identity matches expected parameters
    ///
    /// # Arguments
    /// * `app_id` - Expected application ID
    /// * `mpc_seed_share` - Expected MPC seed share
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether verification passed
    pub fn verify(&self, app_id: &str, mpc_seed_share: &[u8]) -> Result<bool, DsmError> {
        // Reconstruct the expected device hash
        let mut device_data = Vec::new();
        device_data.extend_from_slice(mpc_seed_share);
        device_data.extend_from_slice(app_id.as_bytes());
        device_data.extend_from_slice(&self.device_salt);

        let expected_device_hash = blake3(&device_data);

        // Check device hash matches
        if self.device_hash != expected_device_hash {
            return Ok(false);
        }

        // Check app ID matches
        if self.app_id != app_id {
            return Ok(false);
        }

        // Verify genesis hash from public keys
        let mut genesis_data = Vec::new();
        genesis_data.extend_from_slice(&self.kyber_public_key);
        genesis_data.extend_from_slice(&self.sphincs_public_key);
        let expected_genesis_hash = blake3(&genesis_data);

        if self.genesis_hash != expected_genesis_hash {
            return Ok(false);
        }

        Ok(true)
    }

    /// Sign data using this identity's SPHINCS+ keypair
    ///
    /// # Arguments
    /// * `data` - Data to sign
    /// * `sphincs_keypair` - SPHINCS+ keypair for signing
    ///
    /// # Returns
    /// * `Result<Signature, DsmError>` - Signature or error
    pub fn sign_data(
        &self,
        data: &[u8],
        sphincs_keypair: &SignatureKeyPair,
    ) -> Result<Signature, DsmError> {
        // Verify the keypair matches this identity
        if sphincs_keypair.public_key != self.sphincs_public_key {
            return Err(DsmError::verification(
                "SPHINCS+ keypair doesn't match identity",
            ));
        }

        sphincs_keypair.sign(data)
    }

    /// Verify a signature using this identity's public key
    ///
    /// # Arguments
    /// * `data` - Signed data
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether signature is valid
    pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> Result<bool, DsmError> {
        SignatureKeyPair::verify_raw(data, signature, &self.sphincs_public_key)
    }

    /// Evolve this identity to a new state
    ///
    /// # Arguments
    /// * `operation` - Operation data for this state transition
    /// * `entropy` - New entropy for this state
    ///
    /// # Returns
    /// * `Result<HashOutput, DsmError>` - Hash of the new state
    pub fn evolve_state(
        &mut self,
        operation: &[u8],
        entropy: &[u8],
    ) -> Result<HashOutput, DsmError> {
        // Calculate new state number
        let new_state_number = self.state_number + 1;

        // Get the previous state hash
        let prev_hash = self
            .state_history
            .get(&self.state_number)
            .ok_or_else(|| DsmError::state("Previous state not found in history"))?
            .clone();

        // Create state transition data
        let mut state_data = Vec::new();
        state_data.extend_from_slice(&new_state_number.to_be_bytes());
        state_data.extend_from_slice(prev_hash.as_bytes());
        state_data.extend_from_slice(operation);
        state_data.extend_from_slice(entropy);

        // Hash the new state
        let new_state_hash = blake3(&state_data);

        // Update state
        self.state_number = new_state_number;
        self.state_history
            .insert(new_state_number, new_state_hash.clone());

        Ok(new_state_hash)
    }

    /// Calculate next deterministic entropy
    ///
    /// # Arguments
    /// * `current_entropy` - Current entropy value
    /// * `operation` - Operation for state transition
    /// * `state_number` - State number for transition
    ///
    /// # Returns
    /// * `HashOutput` - Deterministic next entropy
    pub fn calculate_next_entropy(
        current_entropy: &[u8],
        operation: &[u8],
        state_number: u64,
    ) -> HashOutput {
        let mut data = Vec::new();
        data.extend_from_slice(current_entropy);
        data.extend_from_slice(operation);
        data.extend_from_slice(&state_number.to_be_bytes());

        blake3(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation_and_verification() {
        // Create test app ID and MPC seed share
        let app_id = "com.dsm.testapp";
        let mpc_seed_share = b"test_mpc_seed_share_12345";

        // Generate keypairs
        let sphincs_keypair = SignatureKeyPair::generate().unwrap();
        let kyber_keypair = KyberKeyPair::generate().unwrap();

        // Create identity
        let identity =
            CryptoIdentity::new(app_id, mpc_seed_share, &sphincs_keypair, &kyber_keypair).unwrap();

        // Verify identity
        let verification_result = identity.verify(app_id, mpc_seed_share).unwrap();
        assert!(verification_result);

        // Test with wrong app ID
        let wrong_app_id = "com.dsm.wrongapp";
        let wrong_verification = identity.verify(wrong_app_id, mpc_seed_share).unwrap();
        assert!(!wrong_verification);
    }

    #[test]
    fn test_signing_and_verification() {
        // Create test app ID and MPC seed share
        let app_id = "com.dsm.testapp";
        let mpc_seed_share = b"test_mpc_seed_share_12345";

        // Generate keypairs
        let sphincs_keypair = SignatureKeyPair::generate().unwrap();
        let kyber_keypair = KyberKeyPair::generate().unwrap();

        // Create identity
        let identity =
            CryptoIdentity::new(app_id, mpc_seed_share, &sphincs_keypair, &kyber_keypair).unwrap();

        // Sign data
        let data = b"test data for signing";
        let signature = identity.sign_data(data, &sphincs_keypair).unwrap();

        // Verify signature
        let verification_result = identity.verify_signature(data, &signature).unwrap();
        assert!(verification_result);

        // Test with wrong data
        let wrong_data = b"wrong data";
        let wrong_verification = identity.verify_signature(wrong_data, &signature).unwrap();
        assert!(!wrong_verification);
    }

    #[test]
    fn test_state_evolution() {
        // Create test app ID and MPC seed share
        let app_id = "com.dsm.testapp";
        let mpc_seed_share = b"test_mpc_seed_share_12345";

        // Generate keypairs
        let sphincs_keypair = SignatureKeyPair::generate().unwrap();
        let kyber_keypair = KyberKeyPair::generate().unwrap();

        // Create identity
        let mut identity =
            CryptoIdentity::new(app_id, mpc_seed_share, &sphincs_keypair, &kyber_keypair).unwrap();

        // Initial state
        assert_eq!(identity.state_number, 0);
        assert!(identity.state_history.contains_key(&0));

        // Evolve state
        let operation = b"test_operation";
        let entropy = b"test_entropy";
        let new_state_hash = identity.evolve_state(operation, entropy).unwrap();

        // Verify state evolved
        assert_eq!(identity.state_number, 1);
        assert!(identity.state_history.contains_key(&1));
        assert_eq!(identity.state_history.get(&1).unwrap(), &new_state_hash);
    }

    #[test]
    fn test_deterministic_entropy() {
        let current_entropy = b"current_entropy";
        let operation = b"test_operation";
        let state_number = 42;

        let entropy1 =
            CryptoIdentity::calculate_next_entropy(current_entropy, operation, state_number);
        let entropy2 =
            CryptoIdentity::calculate_next_entropy(current_entropy, operation, state_number);

        // Same inputs should produce same entropy
        assert_eq!(entropy1, entropy2);

        // Different inputs should produce different entropy
        let different_entropy = CryptoIdentity::calculate_next_entropy(
            current_entropy,
            b"different_operation",
            state_number,
        );
        assert_ne!(entropy1, different_entropy);
    }
}
