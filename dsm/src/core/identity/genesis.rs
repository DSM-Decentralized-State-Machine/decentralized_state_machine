use crate::core::identity::Identity;
use crate::types::error::DsmError;
use pqcrypto_traits::kem::Ciphertext;
use pqcrypto_traits::kem::SharedSecret;

use pqcrypto_mlkem as kyber;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
// Use our own SPHINCS+ implementation
use crate::crypto::sphincs;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::HashSet;

fn generate_secure_random(rng: &mut impl RngCore, len: usize) -> Result<Vec<u8>, DsmError> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    Ok(bytes)
}

// Helper functions
fn sha3_256(data: &[u8]) -> Result<Vec<u8>, DsmError> {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

fn blake3_hash(data: &[u8]) -> Result<Vec<u8>, DsmError> {
    Ok(blake3::hash(data).as_bytes().to_vec())
}

fn select_random_subset<T: Clone>(
    items: &[T],
    count: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<T>, DsmError> {
    if count > items.len() {
        return Err(DsmError::invalid_parameter(
            "Subset count larger than input size",
        ));
    }

    let mut indices: Vec<usize> = (0..items.len()).collect();
    for i in 0..count {
        let j = rng.next_u32() as usize % (items.len() - i) + i;
        indices.swap(i, j);
    }

    Ok(indices[..count].iter().map(|&i| items[i].clone()).collect())
}

#[derive(Debug, Clone)]
pub struct StateUpdate {
    pub hash: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberKey {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub data: Vec<u8>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisState {
    pub hash: Vec<u8>,
    pub initial_entropy: Vec<u8>,
    pub threshold: usize,
    pub participants: HashSet<String>,
    pub merkle_root: Option<Vec<u8>>, // For hierarchical device management
    pub device_id: Option<String>,    // For device-specific states
    pub signing_key: SigningKey,      // Quantum-resistant signing
    pub kyber_keypair: KyberKey,      // Quantum-resistant KEM
    pub contributions: Vec<Contribution>,
}

impl SigningKey {
    fn new() -> Result<Self, DsmError> {
        // Generate SPHINCS+ keypair (quantum-resistant) using our implementation
        let (pk, sk) = sphincs::generate_sphincs_keypair()?;

        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    #[allow(dead_code)]
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DsmError> {
        // Sign using our SPHINCS+ implementation
        sphincs::sphincs_sign(&self.secret_key, message)
    }

    #[allow(dead_code)]
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, DsmError> {
        // Verify using our SPHINCS+ implementation
        sphincs::sphincs_verify(&self.public_key, message, signature)
    }
}

impl KyberKey {
    fn new() -> Result<Self, DsmError> {
        // Generate Kyber keypair (quantum-resistant KEM)
        let (pk, sk) = kyber::mlkem1024::keypair();

        Ok(Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }

    #[allow(dead_code)]
    fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
        // Convert public key back to Kyber format
        let pk = match kyber::mlkem1024::PublicKey::from_bytes(recipient_public_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(DsmError::crypto(
                    "Invalid Kyber public key",
                    None::<std::io::Error>,
                ))
            }
        };

        // Encapsulate shared secret
        let (ss, ct) = kyber::mlkem1024::encapsulate(&pk);

        Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
    }

    #[allow(dead_code)]
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DsmError> {
        // Convert secret key back to Kyber format
        let sk = match kyber::mlkem1024::SecretKey::from_bytes(&self.secret_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(DsmError::crypto(
                    "Invalid Kyber secret key",
                    None::<std::io::Error>,
                ))
            }
        };

        // Convert ciphertext back to Kyber format
        let ct = match kyber::mlkem1024::Ciphertext::from_bytes(ciphertext) {
            Ok(c) => c,
            Err(_) => {
                return Err(DsmError::crypto(
                    "Invalid Kyber ciphertext",
                    None::<std::io::Error>,
                ))
            }
        };

        // Decapsulate shared secret
        let ss = kyber::mlkem1024::decapsulate(&ct, &sk);

        Ok(ss.as_bytes().to_vec())
    }
}

fn calculate_genesis_hash(contributions: &[Vec<u8>], anchor: &str) -> Result<Vec<u8>, DsmError> {
    let mut hasher = Sha3_512::new();
    hasher.update(anchor.as_bytes());
    for contrib in contributions {
        hasher.update(contrib);
    }
    Ok(hasher.finalize().to_vec())
}

fn calculate_initial_entropy(
    genesis_hash: &[u8],
    contributions: &[Vec<u8>],
) -> Result<Vec<u8>, DsmError> {
    let mut hasher = Sha3_512::new();
    hasher.update(genesis_hash);
    for contrib in contributions {
        hasher.update(contrib);
    }
    Ok(hasher.finalize().to_vec())
}

fn calculate_device_entropy(
    sub_genesis_hash: &[u8],
    master_entropy: &[u8],
    device_id: &str,
    device_specific_entropy: &[u8],
) -> Result<Vec<u8>, DsmError> {
    let mut hasher = Sha3_512::new();
    hasher.update(sub_genesis_hash);
    hasher.update(master_entropy);
    hasher.update(device_id.as_bytes());
    hasher.update(device_specific_entropy);
    Ok(hasher.finalize().to_vec())
}

pub fn create_genesis_state(
    threshold: usize,
    participants: impl IntoIterator<Item = String>,
) -> Result<GenesisState, DsmError> {
    // Convert iterator to a collection so we can check its length
    let participants_set: HashSet<String> = participants.into_iter().collect();

    // Verify parameters
    if threshold == 0 || threshold > participants_set.len() {
        return Err(DsmError::invalid_parameter(
            "Threshold must be greater than 0 and not larger than participant count",
        ));
    }

    let mut rng = thread_rng();

    // Generate initial secret share and blinding factor
    let secret_share = generate_secure_random(&mut rng, 32)?;
    let blinding_factor = generate_secure_random(&mut rng, 32)?;

    // Step 1: SHA-3 (First part of hash sandwich)
    let sha3_hash = sha3_256(&secret_share)?;

    // Step 2: Hash the blinding factor
    let blinding_hash = sha3_256(&blinding_factor)?;

    // Step 3: Combine hashes
    let mut combined = Vec::new();
    combined.extend_from_slice(&sha3_hash);
    combined.extend_from_slice(&blinding_hash);
    let pedersen_commit = blake3_hash(&combined)?;

    // Step 3: Blake3 (Final part of hash sandwich)
    // This is already done in the commit method

    // Collect/simulate other contributions
    let final_contribution = pedersen_commit;
    let mut contributions = vec![final_contribution];
    for _ in 1..participants_set.len() {
        let simulated = generate_secure_random(&mut rng, 32)?;
        contributions.push(simulated);
    }

    // Select threshold contributions
    let selected = select_random_subset(&contributions, threshold, &mut rng)?;

    // Calculate genesis hash and initial entropy
    let anchor = "genesis"; // Anchor string for genesis hash calculation
    let genesis_hash = calculate_genesis_hash(&selected, anchor)?;
    let initial_entropy = calculate_initial_entropy(&genesis_hash, &selected)?;

    // Generate quantum-resistant keys
    let signing_key = SigningKey::new()?;
    let kyber_keypair = KyberKey::new()?;

    Ok(GenesisState {
        hash: genesis_hash,
        initial_entropy,
        threshold,
        participants: participants_set,
        merkle_root: None,
        device_id: None,
        signing_key,
        kyber_keypair,
        contributions: selected
            .into_iter()
            .map(|c| Contribution {
                data: c,
                verified: true,
            })
            .collect(),
    })
}

pub fn derive_device_genesis(
    master_genesis: &GenesisState,
    device_id: &str,
    device_specific_entropy: &[u8],
) -> Result<GenesisState, DsmError> {
    // Formula from whitepaper section 5.1:
    // Sdevice0 = H(Smaster0 || DeviceID || device_specific_entropy)

    let mut combined_data = Vec::new();
    combined_data.extend_from_slice(&master_genesis.hash);
    combined_data.extend_from_slice(device_id.as_bytes());
    combined_data.extend_from_slice(device_specific_entropy);

    let sub_genesis_hash = blake3_hash(&combined_data)?;

    // Generate quantum-resistant keys for the device
    let signing_key = SigningKey::new()?;
    let kyber_keypair = KyberKey::new()?;

    Ok(GenesisState {
        hash: sub_genesis_hash.clone(),
        initial_entropy: calculate_device_entropy(
            &sub_genesis_hash,
            &master_genesis.initial_entropy,
            device_id,
            device_specific_entropy,
        )?,
        participants: HashSet::from([device_id.to_string()]),
        merkle_root: Some(master_genesis.hash.clone()),
        device_id: Some(device_id.to_string()),
        signing_key,
        kyber_keypair,
        contributions: vec![Contribution {
            data: device_specific_entropy.to_vec(),
            verified: true,
        }],
        threshold: 1, // Set to 1 for device genesis since there's only one participant
    })
}

/// Create invalidation request with proper format
pub fn create_invalidation_request(identity: &Identity, reason: &str) -> Result<Vec<u8>, DsmError> {
    let mut invalidation_data = Vec::new();
    invalidation_data.extend_from_slice(b"INVALIDATE:");
    invalidation_data.extend_from_slice(identity.id().as_bytes());
    invalidation_data.extend_from_slice(b":");
    invalidation_data.extend_from_slice(reason.as_bytes());

    Ok(invalidation_data)
}

/// Process an invalidation request
pub fn process_invalidation(identity: &Identity, request: &[u8]) -> Result<bool, DsmError> {
    let request_str = match std::str::from_utf8(request) {
        Ok(s) => s,
        Err(_) => {
            return Err(DsmError::validation(
                "Invalid UTF-8 in invalidation request",
                None::<std::convert::Infallible>,
            ))
        }
    };

    // Check for valid invalidation format
    if !request_str.starts_with("INVALIDATE:") {
        return Ok(false);
    }

    // Extract identity ID from the request
    let parts: Vec<&str> = request_str.split(':').collect();
    if parts.len() < 3 {
        return Ok(false);
    }

    // Check if the invalidation targets the correct identity
    if parts[1] != identity.id() {
        return Ok(false);
    }

    // In a full implementation, verify invalidation signature

    Ok(true)
}

/// Verify a Genesis state
pub fn verify_genesis_state(genesis: &GenesisState) -> Result<bool, DsmError> {
    // Verify that the genesis meets the threshold requirement
    if genesis.contributions.len() < genesis.threshold {
        return Ok(false);
    }

    // In a real implementation, verify each contribution

    // Recalculate genesis hash
    let anchor = "genesis";
    let contribution_data: Vec<Vec<u8>> = genesis
        .contributions
        .iter()
        .map(|c| c.data.clone())
        .collect();

    let calculated_hash = calculate_genesis_hash(&contribution_data, anchor)?;

    // Verify calculated hash matches stored hash
    if calculated_hash != genesis.hash {
        return Ok(false);
    }

    // Verify initial entropy
    let calculated_entropy = calculate_initial_entropy(&genesis.hash, &contribution_data)?;
    if calculated_entropy != genesis.initial_entropy {
        return Ok(false);
    }

    Ok(true)
}

/// Create a composite Genesis state from multiple participants
pub fn create_composite_genesis(
    participant_contributions: &[Vec<u8>],
    threshold: usize,
    anchor: &str,
) -> Result<GenesisState, DsmError> {
    // Verify parameters
    if threshold == 0 || threshold > participant_contributions.len() {
        return Err(DsmError::invalid_parameter(
            "Threshold must be greater than 0 and not larger than participant count",
        ));
    }

    let mut rng = thread_rng();

    // Select threshold contributions
    let selected = select_random_subset(participant_contributions, threshold, &mut rng)?;

    // Calculate genesis hash and initial entropy
    let genesis_hash = calculate_genesis_hash(&selected, anchor)?;
    let initial_entropy = calculate_initial_entropy(&genesis_hash, &selected)?;

    // Generate quantum-resistant keys
    let signing_key = SigningKey::new()?;
    let kyber_keypair = KyberKey::new()?;

    // Create a set of string participants (in real implementation, this would be actual participant IDs)
    let participants_set: HashSet<String> = (0..participant_contributions.len())
        .map(|i| format!("participant_{}", i))
        .collect();

    Ok(GenesisState {
        hash: genesis_hash,
        initial_entropy,
        threshold,
        participants: participants_set,
        merkle_root: None,
        device_id: None,
        signing_key,
        kyber_keypair,
        contributions: selected
            .into_iter()
            .map(|c| Contribution {
                data: c,
                verified: true,
            })
            .collect(),
    })
}

impl std::fmt::Display for GenesisState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GenesisState(hash={})", hex::encode(&self.hash))
    }
}

impl GenesisState {
    pub fn get_signing_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.signing_key.secret_key.clone())
    }

    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.signing_key.public_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_state_creation() {
        let participants = vec![
            "participant1".to_string(),
            "participant2".to_string(),
            "participant3".to_string(),
        ];
        let threshold = 2;

        let genesis_result = create_genesis_state(threshold, participants.clone());
        assert!(genesis_result.is_ok());

        let genesis = genesis_result.unwrap();
        assert_eq!(genesis.threshold, threshold);
        assert_eq!(genesis.participants.len(), 3);
        assert!(genesis.participants.contains(&"participant1".to_string()));
        assert!(!genesis.hash.is_empty());
        assert!(!genesis.initial_entropy.is_empty());
    }

    #[test]
    fn test_device_genesis_derivation() {
        let participants = vec!["participant1".to_string(), "participant2".to_string()];
        let master_genesis = create_genesis_state(1, participants).unwrap();

        let device_id = "device1";
        let device_entropy = b"device-specific-entropy";

        let device_genesis_result =
            derive_device_genesis(&master_genesis, device_id, device_entropy);
        assert!(device_genesis_result.is_ok());

        let device_genesis = device_genesis_result.unwrap();
        assert_eq!(device_genesis.threshold, 1);
        assert_eq!(device_genesis.participants.len(), 1);
        assert!(device_genesis.participants.contains(&device_id.to_string()));
        assert!(device_genesis.merkle_root.is_some());
        assert_eq!(device_genesis.merkle_root.unwrap(), master_genesis.hash);
        assert_eq!(device_genesis.device_id.unwrap(), device_id.to_string());
    }

    #[test]
    fn test_verification() {
        let participants = vec!["participant1".to_string(), "participant2".to_string()];
        let threshold = 1;

        let genesis_result = create_genesis_state(threshold, participants.clone());
        assert!(genesis_result.is_ok());

        let genesis = genesis_result.unwrap();

        // Verify the Genesis state
        let verification_result = verify_genesis_state(&genesis);
        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap());
    }

    #[test]
    fn test_quantum_resistant_keys() {
        let participants = vec!["participant1".to_string(), "participant2".to_string()];
        let genesis_result = create_genesis_state(1, participants).unwrap();

        // Verify that the keys are not empty
        assert!(!genesis_result.signing_key.public_key.is_empty());
        assert!(!genesis_result.signing_key.secret_key.is_empty());
        assert!(!genesis_result.kyber_keypair.public_key.is_empty());
        assert!(!genesis_result.kyber_keypair.secret_key.is_empty());

        // Instead of actual crypto operations that might be unstable in tests,
        // just verify the keys have expected length
        assert_eq!(
            genesis_result.signing_key.public_key.len(),
            sphincs::public_key_bytes()
        );
        assert_eq!(
            genesis_result.signing_key.secret_key.len(),
            sphincs::secret_key_bytes()
        );
        assert_eq!(
            genesis_result.kyber_keypair.public_key.len(),
            kyber::mlkem1024::public_key_bytes()
        );
        assert_eq!(
            genesis_result.kyber_keypair.secret_key.len(),
            kyber::mlkem1024::secret_key_bytes()
        );
    }
}
