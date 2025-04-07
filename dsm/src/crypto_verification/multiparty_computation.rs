// multiparty_computation.rs
//
// Implementation of multiparty computation (MPC) for trustless genesis state creation
// as described in the DSM whitepaper, replacing hardware TEE dependency with
// distributed cryptographic security.
use super::cryptographic_identity::CryptoIdentity;
use crate::crypto::hash::{blake3, HashOutput};
use crate::crypto::kyber::KyberKeyPair;
use crate::crypto::signatures::SignatureKeyPair;
use crate::types::error::DsmError;

/// MpcContribution represents a single party's contribution to the MPC process
#[derive(Debug, Clone)]
pub struct MpcContribution {
    /// Blinded contribution hash (privacy-preserving)
    pub blinded_hash: HashOutput,
    /// Party identifier
    pub party_id: String,
    /// Timestamp of contribution
    pub timestamp: u64,
}

impl MpcContribution {
    /// Create a new MPC contribution
    ///
    /// # Arguments
    /// * `secret` - Secret contribution value
    /// * `blinding_factor` - Blinding factor for privacy
    /// * `party_id` - Identifier for the contributing party
    ///
    /// # Returns
    /// * `Self` - New contribution
    pub fn new(secret: &[u8], blinding_factor: &[u8], party_id: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Combine secret and blinding factor to create blinded hash
        let mut data = Vec::new();
        data.extend_from_slice(secret);
        data.extend_from_slice(blinding_factor);
        let blinded_hash = blake3(&data);

        Self {
            blinded_hash,
            party_id: party_id.to_string(),
            timestamp,
        }
    }
}

/// MpcIdentityFactory creates identities using threshold MPC
#[derive(Debug)]
pub struct MpcIdentityFactory {
    /// Threshold of required contributions (t-of-n security)
    threshold: usize,
    /// Application ID for created identities
    app_id: String,
    /// Collection of received contributions
    contributions: Vec<MpcContribution>,
}

impl MpcIdentityFactory {
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

    /// Check if enough contributions have been received
    ///
    /// # Returns
    /// * `bool` - Whether threshold is met
    pub fn threshold_met(&self) -> bool {
        self.contributions.len() >= self.threshold
    }

    /// Create an identity from the collected contributions
    ///
    /// This implements the threshold-based genesis creation described in whitepaper Section 5.1,
    /// ensuring distributed trust during identity origination without TEE dependencies.
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

        // Sort contributions by party ID for determinism
        let mut sorted_contributions = self.contributions.clone();
        sorted_contributions.sort_by(|a, b| a.party_id.cmp(&b.party_id));

        // Take only the threshold number of contributions
        let threshold_contributions = sorted_contributions
            .iter()
            .take(self.threshold)
            .map(|c| c.blinded_hash.clone())
            .collect::<Vec<_>>();

        // Combine all contributions to create the MPC seed share
        let mut combined_data = Vec::new();
        for hash in &threshold_contributions {
            let hash_bytes = hash.as_bytes();
            combined_data.extend_from_slice(hash_bytes);
        }

        // Add application metadata
        combined_data.extend_from_slice(self.app_id.as_bytes());

        // Generate the MPC seed share
        let mpc_seed_share = blake3(&combined_data);

        // Use the seed share to derive entropy for key generation
        let mut key_entropy = Vec::new();
        key_entropy.extend_from_slice(mpc_seed_share.as_bytes());
        key_entropy.extend_from_slice(b"key_derivation");

        // Generate SPHINCS+ and Kyber keypairs
        let sphincs_keypair = SignatureKeyPair::generate_from_entropy(&key_entropy)?;

        // Append a different suffix for Kyber to avoid using the same entropy
        key_entropy.extend_from_slice(b"kyber_specific");
        let kyber_keypair = KyberKeyPair::generate_from_entropy(&key_entropy)?;

        // Create the identity
        let identity = CryptoIdentity::new(
            &self.app_id,
            mpc_seed_share.as_bytes(),
            &sphincs_keypair,
            &kyber_keypair,
        )?;

        Ok((identity, sphincs_keypair, kyber_keypair))
    }

    /// Create a mock identity for testing (non-MPC)
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
        let mpc_seed_share = blake3(test_seed.as_bytes());

        // Generate keypairs
        let sphincs_keypair = SignatureKeyPair::generate()?;
        let kyber_keypair = KyberKeyPair::generate()?;

        // Create identity
        let identity = CryptoIdentity::new(
            app_id,
            mpc_seed_share.as_bytes(),
            &sphincs_keypair,
            &kyber_keypair,
        )?;

        Ok((identity, sphincs_keypair, kyber_keypair))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contribution_creation() {
        let secret = b"test_secret_value";
        let blinding_factor = b"test_blinding_factor";
        let party_id = "party1";

        let contribution = MpcContribution::new(secret, blinding_factor, party_id);

        assert_eq!(contribution.party_id, "party1");

        // Create the same contribution again - should have same hash
        let contribution2 = MpcContribution::new(secret, blinding_factor, party_id);
        assert_eq!(contribution.blinded_hash, contribution2.blinded_hash);

        // Different secret should produce different hash
        let different_contribution =
            MpcContribution::new(b"different_secret", blinding_factor, party_id);
        assert_ne!(
            contribution.blinded_hash,
            different_contribution.blinded_hash
        );
    }

    #[test]
    fn test_identity_creation() {
        let app_id = "com.dsm.testapp";
        let threshold = 3;

        let mut factory = MpcIdentityFactory::new(threshold, app_id);

        // Add 3 contributions
        let contribution1 = MpcContribution::new(b"secret1", b"blinding1", "party1");
        let contribution2 = MpcContribution::new(b"secret2", b"blinding2", "party2");
        let contribution3 = MpcContribution::new(b"secret3", b"blinding3", "party3");

        factory.add_contribution(contribution1).unwrap();
        factory.add_contribution(contribution2).unwrap();
        factory.add_contribution(contribution3).unwrap();

        // Check threshold
        assert!(factory.threshold_met());

        // Create identity
        let result = factory.create_identity();
        assert!(result.is_ok());

        let (identity, _, _) = result.unwrap();
        assert_eq!(identity.app_id, app_id);
    }

    #[test]
    fn test_threshold_enforcement() {
        let app_id = "com.dsm.testapp";
        let threshold = 3;

        let mut factory = MpcIdentityFactory::new(threshold, app_id);

        // Add only 2 contributions
        let contribution1 = MpcContribution::new(b"secret1", b"blinding1", "party1");
        let contribution2 = MpcContribution::new(b"secret2", b"blinding2", "party2");

        factory.add_contribution(contribution1).unwrap();
        factory.add_contribution(contribution2).unwrap();

        // Check threshold
        assert!(!factory.threshold_met());

        // Attempt to create identity - should fail
        let result = factory.create_identity();
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_party_prevention() {
        let app_id = "com.dsm.testapp";
        let threshold = 2;

        let mut factory = MpcIdentityFactory::new(threshold, app_id);

        // Add first contribution
        let contribution1 = MpcContribution::new(b"secret1", b"blinding1", "party1");
        factory.add_contribution(contribution1).unwrap();

        // Try to add another contribution with same party ID
        let contribution2 = MpcContribution::new(b"secret2", b"blinding2", "party1");
        let result = factory.add_contribution(contribution2);

        // Should reject duplicate party
        assert!(result.is_err());
    }

    #[test]
    fn test_test_identity_creation() {
        let app_id = "com.dsm.testapp";

        // Create test identity
        let result = MpcIdentityFactory::create_test_identity(app_id);
        assert!(result.is_ok());

        let (identity, _, _) = result.unwrap();
        assert_eq!(identity.app_id, app_id);
    }
}
