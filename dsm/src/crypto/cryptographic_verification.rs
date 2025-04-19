// cryptographic_verification.rs
//
// Implementation of cryptographic verification mechanisms with pure cryptographic guarantees as described in the DSM whitepaper.

use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::crypto::hash::{blake3, HashOutput};
use crate::crypto::kyber::KyberKeyPair;
use crate::crypto::signatures::{Signature, SignatureKeyPair};
use crate::types::error::DsmError;
// use crate::types::state_types::State; // Not currently used

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Represents a cryptographic attestation
#[derive(Debug, Clone)]
pub struct CryptoAttestation {
    /// Attestation timestamp
    pub timestamp: u64,
    /// Device identifier hash
    pub device_hash: HashOutput,
    /// SPHINCS+ signature over attestation data
    pub signature: Signature,
    /// Kyber encapsulated state (for secure communication)
    pub encapsulated_state: Vec<u8>,
    /// Additional entropy for verification
    pub verification_entropy: HashOutput,
}

/// MPC contribution with blinding for privacy-preserving distributed trust
#[derive(Debug, Clone)]
pub struct MpcContribution {
    /// Blinded hash of the contribution
    pub blinded_hash: HashOutput,
    /// Party identifier
    pub party_id: String,
    /// Timestamp
    pub timestamp: u64,
}

/// Implements cryptographic verification without hardware TEE
pub struct CryptoVerifier {
    /// Number of verification steps to perform
    verification_steps: usize,
    /// Seed for deterministic random verification
    verification_seed: Vec<u8>,
    /// Set of already verified state hashes
    verified_states: HashSet<Vec<u8>>,
}

impl CryptoVerifier {
    /// Create a new cryptographic verifier
    ///
    /// # Arguments
    /// * `verification_steps` - Number of steps to verify
    /// * `verification_seed` - Seed for deterministic randomization
    ///
    /// # Returns
    /// * `Self` - New verifier
    pub fn new(verification_steps: usize, verification_seed: Vec<u8>) -> Self {
        Self {
            verification_steps,
            verification_seed,
            verified_states: HashSet::new(),
        }
    }

    /// Verify a state chain through random sampling
    ///
    /// This implements the random walk verification described in whitepaper section 14,
    /// providing efficient verification without hardware TEE dependencies.
    ///
    /// # Arguments
    /// * `states` - States to verify
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether verification passed
    pub fn verify_chain(
        &mut self,
        states: &[crate::types::state_types::State],
    ) -> Result<bool, DsmError> {
        if states.is_empty() {
            return Ok(true); // Empty chain is valid
        }

        // Verify the genesis state
        let genesis_state = &states[0];
        if genesis_state.state_number != 0 {
            return Err(DsmError::validation(
                "First state is not a genesis state",
                None::<std::convert::Infallible>,
            ));
        }

        // Add genesis state to verified states
        self.verified_states.insert(genesis_state.hash()?.to_vec());

        // If only genesis state, we're done
        if states.len() == 1 {
            return Ok(true);
        }

        // Create deterministic RNG from seed
        let seed_hash = blake3(&self.verification_seed);
        let seed_array = *seed_hash.as_bytes();

        let mut rng = ChaCha20Rng::from_seed(seed_array);

        // Determine how many steps to verify (min of steps or states-1)
        let actual_steps = std::cmp::min(self.verification_steps, states.len() - 1);

        // Select random indices to verify, always including the most recent state
        let mut indices = (1..states.len()).collect::<Vec<_>>();
        indices.shuffle(&mut rng);
        let mut selected_indices = indices
            .into_iter()
            .take(actual_steps - 1)
            .collect::<Vec<_>>();
        selected_indices.push(states.len() - 1); // Always verify the last state

        // Verify each selected state
        for &idx in &selected_indices {
            let state = &states[idx];
            let prev_state = &states[idx - 1];

            // Verify state number
            if state.state_number != prev_state.state_number + 1 {
                return Ok(false);
            }

            // Verify hash chain continuity
            if state.prev_state_hash != prev_state.hash()? {
                return Ok(false);
            }

            // Serialize the operation to get operation bytes
            let operation_bytes = bincode::serialize(&state.operation)
                .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;

            // Verify deterministic entropy evolution
            let expected_entropy = crate::crypto::hash::calculate_next_entropy(
                &prev_state.entropy,
                &operation_bytes,
                state.state_number,
            );

            if state.entropy != expected_entropy.as_bytes() {
                return Ok(false);
            }

            // Add to verified states
            self.verified_states.insert(state.hash()?.to_vec());
        }

        Ok(true)
    }

    /// Create a cryptographic attestation to prove device authenticity
    ///
    /// This implements the attestation mechanism described in whitepaper section 25,
    /// providing cryptographic proof of device authenticity without TEE dependencies.
    ///
    /// # Arguments
    /// * `device_hash` - Device identifier hash
    /// * `sphincs_keypair` - SPHINCS+ keypair for signing
    /// * `kyber_keypair` - Kyber keypair for key encapsulation
    /// * `additional_entropy` - Extra entropy for attestation
    ///
    /// # Returns
    /// * `Result<CryptoAttestation, DsmError>` - Attestation or error
    pub fn create_attestation(
        device_hash: &HashOutput,
        sphincs_keypair: &SignatureKeyPair,
        kyber_keypair: &KyberKeyPair,
        additional_entropy: &[u8],
    ) -> Result<CryptoAttestation, DsmError> {
        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                DsmError::internal(
                    "Failed to get system time",
                    None::<std::convert::Infallible>,
                )
            })?
            .as_secs();

        // Create attestation data
        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(&timestamp.to_be_bytes());
        attestation_data.extend_from_slice(device_hash.as_bytes());
        attestation_data.extend_from_slice(additional_entropy);

        // Create verification entropy
        let verification_entropy = blake3(&attestation_data);

        // Sign the attestation data using SPHINCS+
        let signature = sphincs_keypair.sign(&attestation_data)?;

        // Prepare encapsulated state using Kyber
        let self_encapsulation = kyber_keypair.encapsulate()?;
        // Create a clone of the ciphertext rather than moving out of the structure
        let encapsulated_state = self_encapsulation.ciphertext.clone();

        Ok(CryptoAttestation {
            timestamp,
            device_hash: device_hash.clone(),
            signature,
            encapsulated_state,
            verification_entropy,
        })
    }

    /// Verify a cryptographic attestation
    ///
    /// # Arguments
    /// * `attestation` - Attestation to verify
    /// * `device_hash` - Expected device hash
    /// * `public_key` - SPHINCS+ public key
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether attestation is valid
    pub fn verify_attestation(
        attestation: &CryptoAttestation,
        device_hash: &HashOutput,
        public_key: &[u8],
    ) -> Result<bool, DsmError> {
        // Verify device hash
        if attestation.device_hash.as_bytes() != device_hash.as_bytes() {
            return Ok(false);
        }

        // Rebuild attestation data
        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(&attestation.timestamp.to_be_bytes());
        attestation_data.extend_from_slice(device_hash.as_bytes());

        // Derive expected verification entropy
        let expected_verification = blake3(&attestation_data);

        // Verify entropy matches
        if attestation.verification_entropy.as_bytes() != expected_verification.as_bytes() {
            return Ok(false);
        }

        // Verify signature using SPHINCS+
        SignatureKeyPair::verify_raw(&attestation_data, &attestation.signature, public_key)
    }

    /// Create a multiparty computation contribution with blinding for privacy
    ///
    /// This implements the multiparty computation mechanism described in whitepaper section 5,
    /// enabling trustless genesis state creation without hardware dependencies.
    ///
    /// # Arguments
    /// * `secret` - Secret contribution
    /// * `blinding_factor` - Blinding factor for privacy
    /// * `party_id` - Identifier for contributing party
    ///
    /// # Returns
    /// * `MpcContribution` - Blinded contribution
    pub fn create_mpc_contribution(
        secret: &[u8],
        blinding_factor: &[u8],
        party_id: &str,
    ) -> MpcContribution {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create blinded hash
        let mut data = Vec::new();
        data.extend_from_slice(secret);
        data.extend_from_slice(blinding_factor);
        let blinded_hash = blake3(&data);

        MpcContribution {
            blinded_hash,
            party_id: party_id.to_string(),
            timestamp,
        }
    }

    /// Calculate a genesis hash from multiparty contributions
    ///
    /// This implements the genesis hash calculation described in whitepaper section 5.1,
    /// creating a trustless genesis state without hardware dependencies.
    ///
    /// # Arguments
    /// * `contributions` - MPC contributions
    /// * `threshold` - Minimum required contributions
    /// * `app_id` - Application identifier
    ///
    /// # Returns
    /// * `Result<HashOutput, DsmError>` - Genesis hash or error
    pub fn calculate_genesis_hash(
        contributions: &[MpcContribution],
        threshold: usize,
        app_id: &str,
    ) -> Result<HashOutput, DsmError> {
        if contributions.len() < threshold {
            return Err(DsmError::validation(
                format!(
                    "Not enough contributions. Need {} but have {}",
                    threshold,
                    contributions.len()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Sort contributions by party ID for determinism
        let mut sorted_contributions = contributions.to_vec();
        sorted_contributions.sort_by(|a, b| a.party_id.cmp(&b.party_id));

        // Take only the threshold number of contributions
        let threshold_contributions = sorted_contributions
            .iter()
            .take(threshold)
            .map(|c| c.blinded_hash.clone())
            .collect::<Vec<_>>();

        // Combine contributions and app ID
        let mut genesis_data = Vec::new();
        for hash in &threshold_contributions {
            genesis_data.extend_from_slice(hash.as_bytes());
        }
        genesis_data.extend_from_slice(app_id.as_bytes());

        // Calculate genesis hash
        Ok(blake3(&genesis_data))
    }
}
