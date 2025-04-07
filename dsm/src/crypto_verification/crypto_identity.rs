// crypto_identity.rs
//
// Enhanced identity implementation using cryptographic guarantees
// rather than hardware-specific TEE/enclave features

use std::collections::HashMap;

use crate::crypto::{
    cryptographic_verification::{CryptoVerifier, MpcContribution},
    hash::{blake3, HashOutput},
    kyber::KyberKeyPair,
    signatures::SignatureKeyPair,
};
use crate::types::error::DsmError;
use crate::types::state_types::{DeviceInfo, SparseIndex, State};

/// CryptoIdentity represents an identity secured by pure cryptographic guarantees
/// rather than hardware-specific TEE/enclave features.
#[derive(Debug, Clone)]
pub struct CryptoIdentity {
    /// Genesis hash for this identity
    pub genesis_hash: HashOutput,

    /// Device identifier hash
    pub device_hash: HashOutput,

    /// Application identifier
    pub app_id: String,

    /// Device-specific salt value (for fingerprinting resistance)
    pub device_salt: Vec<u8>,

    /// SPHINCS+ public key
    pub sphincs_public_key: Vec<u8>,

    /// Kyber public key
    pub kyber_public_key: Vec<u8>,

    /// MPC seed share
    pub mpc_seed_share: Vec<u8>,

    /// Current state number
    pub state_number: u64,

    /// Mapping of state numbers to state hashes
    pub state_history: HashMap<u64, HashOutput>,
}

impl CryptoIdentity {
    /// Create a new identity using multiparty computation for genesis
    ///
    /// # Arguments
    /// * `app_id` - Application identifier
    /// * `mpc_seed_share` - MPC seed share
    /// * `sphincs_keypair` - SPHINCS+ keypair
    /// * `kyber_keypair` - Kyber keypair
    ///
    /// # Returns
    /// * `Result<Self, DsmError>` - New identity
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
            app_id: app_id.to_string(),
            device_salt,
            sphincs_public_key: sphincs_keypair.public_key.clone(),
            kyber_public_key: kyber_keypair.public_key.clone(),
            mpc_seed_share: mpc_seed_share.to_vec(),
            state_number: 0,
            state_history,
        })
    }

    /// Generate a unique device salt using runtime characteristics
    fn generate_device_salt() -> Vec<u8> {
        // Use runtime characteristics that are unique to the device
        let mut salt_data = Vec::new();

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

    /// Create a state for this identity
    ///
    /// # Arguments
    /// * `previous_state` - Previous state (for transitions)
    /// * `operation` - Operation data
    /// * `timestamp` - Timestamp for the state
    ///
    /// # Returns
    /// * `Result<State, DsmError>` - New state
    pub fn create_state(
        &mut self,
        previous_state: Option<&State>,
        operation: &[u8],
    ) -> Result<State, DsmError> {
        let state_number = match previous_state {
            Some(state) => state.state_number + 1,
            None => 0, // Genesis state
        };

        // Get previous state hash
        let prev_state_hash = match previous_state {
            Some(state) => state.hash()?,
            None => vec![0; 32], // Empty hash for genesis
        };

        // Calculate entropy
        let entropy = match previous_state {
            Some(state) => {
                crate::crypto::hash::calculate_next_entropy(&state.entropy, operation, state_number)
                    .as_bytes()
                    .to_vec()
            }
            None => self.mpc_seed_share.clone(), // Genesis state uses MPC seed share
        };

        // Create sparse index
        let indices = State::calculate_sparse_indices(state_number)?;
        let sparse_index = SparseIndex::new(indices);

        // Create device info
        let device_info = DeviceInfo::new(
            &format!("device_{:?}", self.device_hash.as_bytes()),
            self.sphincs_public_key.clone(),
        );

        // Create state params
        let state_params = crate::types::state_types::StateParams {
            state_number,
            entropy,
            encapsulated_entropy: None,
            prev_state_hash: prev_state_hash.clone(),
            previous_hash: prev_state_hash,
            sparse_index,
            operation: crate::types::operations::Operation::Generic {
                operation_type: "generic".to_string(),
                data: operation.to_vec(),
                message: "Generic operation: test".to_string(),
            },
            device_info,
            forward_commitment: None,
            matches_parameters: false,
            state_type: "test".to_string(),
            value: vec![1, 2, 3],
            commitment: vec![13, 14, 15, 16],
            version: 1,
            forward_link: None,
            none_field: None,
            signature: None,
            metadata: Vec::new(),
            token_balance: None,
            large_state: Box::new(State::default()),
        };

        // Create the new state
        let mut new_state = State::new(state_params);

        // Set ID in a deterministic fashion
        new_state.id = format!("state_{}", state_number);

        // Compute and set the hash
        let hash = new_state.compute_hash()?;
        new_state.hash = hash.clone();

        // Update state number and history
        self.state_number = state_number;
        self.state_history.insert(state_number, blake3(&hash));

        Ok(new_state)
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
        if self.device_hash.as_bytes() != expected_device_hash.as_bytes() {
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

        if self.genesis_hash.as_bytes() != expected_genesis_hash.as_bytes() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the device identifier hash
    pub fn device_hash(&self) -> &HashOutput {
        &self.device_hash
    }

    /// Get the genesis hash
    pub fn genesis_hash(&self) -> &HashOutput {
        &self.genesis_hash
    }
}

/// CryptoIdentityFactory creates identities using threshold MPC
pub struct CryptoIdentityFactory {
    /// Threshold of required contributions (t-of-n security)
    threshold: usize,
    /// Application ID for created identities
    app_id: String,
    /// Collection of received contributions
    contributions: Vec<MpcContribution>,
}

impl CryptoIdentityFactory {
    /// Create a new MPC identity factory
    ///
    /// # Arguments
    /// * `threshold` - Number of required contributions (t-of-n)
    /// * `app_id` - Application identifier
    ///
    /// # Returns
    /// * `Self` - New factory
    pub fn new(threshold: usize, app_id: &str) -> Self {
        Self {
            threshold,
            app_id: app_id.to_string(),
            contributions: Vec::new(),
        }
    }

    /// Add a contribution to the MPC process
    ///
    /// # Arguments
    /// * `contribution` - Party's contribution
    ///
    /// # Returns
    /// * `Result<(), DsmError>` - Success or error
    pub fn add_contribution(&mut self, contribution: MpcContribution) -> Result<(), DsmError> {
        // Check for duplicate party ID
        if self
            .contributions
            .iter()
            .any(|c| c.party_id == contribution.party_id)
        {
            return Err(DsmError::validation(
                "Duplicate party ID in MPC contributions",
                None::<std::convert::Infallible>,
            ));
        }

        self.contributions.push(contribution);
        Ok(())
    }

    /// Create a contribution using secret and blinding factor
    ///
    /// # Arguments
    /// * `secret` - Secret contribution
    /// * `blinding_factor` - Blinding factor for privacy
    /// * `party_id` - Identifier for contributing party
    ///
    /// # Returns
    /// * `MpcContribution` - New contribution
    pub fn create_contribution(
        secret: &[u8],
        blinding_factor: &[u8],
        party_id: &str,
    ) -> MpcContribution {
        CryptoVerifier::create_mpc_contribution(secret, blinding_factor, party_id)
    }

    /// Check if enough contributions have been received
    ///
    /// # Returns
    /// * `bool` - Whether threshold is met
    pub fn threshold_met(&self) -> bool {
        self.contributions.len() >= self.threshold
    }

    /// Create an identity from the collected contributions
    ///
    /// # Returns
    /// * `Result<(CryptoIdentity, SignatureKeyPair, KyberKeyPair), DsmError>` - New identity with keypairs
    pub fn create_identity(
        &self,
    ) -> Result<(CryptoIdentity, SignatureKeyPair, KyberKeyPair), DsmError> {
        if !self.threshold_met() {
            return Err(DsmError::validation(
                format!(
                    "Not enough contributions. Need {} but have {}",
                    self.threshold,
                    self.contributions.len()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Calculate genesis hash
        let genesis_hash = CryptoVerifier::calculate_genesis_hash(
            &self.contributions,
            self.threshold,
            &self.app_id,
        )?;

        // Use the genesis hash to derive entropy for key generation
        let mut key_entropy = genesis_hash.as_bytes().to_vec();
        key_entropy.extend_from_slice(b"key_derivation");

        // Generate SPHINCS+ keypair
        let sphincs_keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)?;

        // Generate Kyber keypair
        let kyber_keypair = KyberKeyPair::generate_from_entropy(&key_entropy)?;

        // Create MPC seed share from contributions
        let mut mpc_data = Vec::new();
        for contribution in self.contributions.iter().take(self.threshold) {
            mpc_data.extend_from_slice(contribution.blinded_hash.as_bytes());
        }
        mpc_data.extend_from_slice(self.app_id.as_bytes());
        let mpc_seed_share = blake3(&mpc_data).as_bytes().to_vec();

        // Create the identity
        let identity = CryptoIdentity::new(
            &self.app_id,
            &mpc_seed_share,
            &sphincs_keypair,
            &kyber_keypair,
        )?;

        Ok((identity, sphincs_keypair, kyber_keypair))
    }

    /// Create a test identity for development/testing purposes
    ///
    /// # Arguments
    /// * `app_id` - Application identifier
    ///
    /// # Returns
    /// * `Result<(CryptoIdentity, SignatureKeyPair, KyberKeyPair), DsmError>` - Test identity
    pub fn create_test_identity(
        app_id: &str,
    ) -> Result<(CryptoIdentity, SignatureKeyPair, KyberKeyPair), DsmError> {
        // Create deterministic test seed
        let test_seed = format!("test_seed_for_{}", app_id);
        let mpc_seed_share = blake3(test_seed.as_bytes()).as_bytes().to_vec();

        // Generate keypairs
        let sphincs_keypair = SignatureKeyPair::generate()?;
        let kyber_keypair = KyberKeyPair::generate()?;

        // Create identity
        let identity =
            CryptoIdentity::new(app_id, &mpc_seed_share, &sphincs_keypair, &kyber_keypair)?;

        Ok((identity, sphincs_keypair, kyber_keypair))
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
    fn test_state_creation() {
        // Create test identity
        let app_id = "com.dsm.testapp";
        let mpc_seed_share = b"test_mpc_seed_share_12345";
        let sphincs_keypair = SignatureKeyPair::generate().unwrap();
        let kyber_keypair = KyberKeyPair::generate().unwrap();

        let mut identity =
            CryptoIdentity::new(app_id, mpc_seed_share, &sphincs_keypair, &kyber_keypair).unwrap();

        // Create genesis state
        let genesis_state = identity.create_state(None, b"genesis_operation").unwrap();
        // Verify genesis state
        assert_eq!(genesis_state.state_number, 0);
        assert_eq!(genesis_state.id, "state_0");

        // Create next state
        let next_state = identity
            .create_state(Some(&genesis_state), b"next_operation")
            .unwrap();

        // Verify next state
        assert_eq!(next_state.state_number, 1);
        assert_eq!(next_state.id, "state_1");
        assert_eq!(next_state.prev_state_hash, genesis_state.hash().unwrap());
    }

    #[test]
    fn test_factory_creation() {
        let app_id = "com.dsm.testapp";
        let threshold = 3;

        let mut factory = CryptoIdentityFactory::new(threshold, app_id);

        // Create and add contributions
        let contribution1 =
            CryptoIdentityFactory::create_contribution(b"secret1", b"blinding1", "party1");

        let contribution2 =
            CryptoIdentityFactory::create_contribution(b"secret2", b"blinding2", "party2");

        let contribution3 =
            CryptoIdentityFactory::create_contribution(b"secret3", b"blinding3", "party3");

        factory.add_contribution(contribution1).unwrap();
        factory.add_contribution(contribution2).unwrap();
        factory.add_contribution(contribution3).unwrap();

        // Check threshold
        assert!(factory.threshold_met());

        // Create identity
        let result = factory.create_identity();
        assert!(result.is_ok());

        let (identity, _sphincs_keypair, _kyber_keypair) = result.unwrap();

        // Check identity properties
        assert_eq!(identity.app_id, app_id);
        assert!(!identity.genesis_hash.as_bytes().is_empty());
        assert!(!identity.device_hash.as_bytes().is_empty());
    }

    #[test]
    fn test_test_identity_creation() {
        let app_id = "com.dsm.testapp";

        // Create test identity
        let result = CryptoIdentityFactory::create_test_identity(app_id);
        assert!(result.is_ok());

        let (identity, _sphincs_keypair, _kyber_keypair) = result.unwrap();

        // Check identity properties
        assert_eq!(identity.app_id, app_id);
        assert!(!identity.genesis_hash.as_bytes().is_empty());
        assert!(!identity.device_hash.as_bytes().is_empty());
    }
}
