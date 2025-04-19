//! Token Factory
//!
//! Provides functionality for multiparty creation (genesis) of new tokens in DSM,
//! leveraging quantum-resistant Pedersen commitments, post-quantum keypairs,
//! and Content-Addressed Token Policy Anchors (CTPA) for token policy enforcement.

use std::collections::HashSet;

use blake3;
use rand::{rngs::OsRng, RngCore};
use sha3::{Digest, Sha3_512};

// Blake3 is imported directly from the crate
// Use the existing Pedersen implementation with correct types
use crate::crypto::pedersen::{PedersenCommitment, PedersenParams, SecurityLevel};
use crate::{
    crypto::{kyber::generate_kyber_keypair, sphincs::generate_sphincs_keypair},
    types::{
        error::DsmError,
        policy_types::{PolicyAnchor, PolicyFile},
        token_types::{Balance, Token, TokenStatus},
    },
};

/// Single partial share or partial commit from each participant
#[derive(Debug, Clone)]
pub struct TokenContribution {
    pub data: Vec<u8>,
    pub verified: bool,
}

/// Final "token genesis" record. Parallels your `GenesisState` but for tokens.
#[derive(Debug, Clone)]
pub struct TokenGenesis {
    pub token_hash: Vec<u8>,
    pub token_entropy: Vec<u8>,
    pub threshold: usize,
    pub participants: HashSet<String>,

    /// The SPHINCS+ public key
    pub signing_key_sphincs: Vec<u8>,

    /// The Kyber keypair (usually concatenated pubkey+secretkey bytes or separate fields)
    pub kyber_keypair: (Vec<u8>, Vec<u8>),

    /// Content-Addressed Token Policy Anchor (CTPA)
    pub policy_anchor: Option<PolicyAnchor>,

    /// The partial contributions that formed the final token
    pub contributions: Vec<TokenContribution>,

    /// The SPHINCS+ private key
    #[allow(dead_code)]
    signing_key: Vec<u8>,
}

/// Generate secure random bytes using OS entropy source
///
/// # Arguments
///
/// * `len` - The number of random bytes to generate
///
/// # Returns
///
/// * `Result<Vec<u8>, DsmError>` - The generated random bytes or an error
fn generate_secure_random(len: usize) -> Result<Vec<u8>, DsmError> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Combine partial commits with an anchor to produce a final token hash
fn combine_commits(commits: &[Vec<u8>], anchor: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(anchor);
    for c in commits {
        hasher.update(c);
    }
    hasher.finalize().to_vec()
}

/// Build token entropy by re-hashing final hash plus partial commits
fn build_token_entropy(token_hash: &[u8], commits: &[Vec<u8>]) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(token_hash);
    for c in commits {
        hasher.update(c);
    }
    hasher.finalize().to_vec()
}

/// Creates a new multiparty token genesis. Each participant produces a partial
/// Pedersen commit. Then we combine them into a final "token genesis hash" and
/// "token entropy."
pub fn create_token_genesis(
    threshold: usize,
    participants: impl IntoIterator<Item = String>,
    token_data: &[u8],
    policy_file: Option<&PolicyFile>,
) -> Result<TokenGenesis, DsmError> {
    let participants_set: HashSet<String> = participants.into_iter().collect();
    if threshold == 0 || threshold > participants_set.len() {
        return Err(DsmError::validation(
            format!(
                "Invalid threshold {} for {} participants",
                threshold,
                participants_set.len()
            ),
            None::<std::convert::Infallible>,
        ));
    }

    // Create Pedersen parameters with standard security level
    let params = PedersenParams::new(SecurityLevel::Standard128);
    let mut rng_thread = rand::thread_rng();

    // Implement the "hash sandwich" approach as described in whitepaper section 5.2.1
    // First hash with SHA-3 for quantum resistance
    let mut sha3_hasher = Sha3_512::new();
    sha3_hasher.update(token_data);
    let token_data_hash = sha3_hasher.finalize().to_vec();

    // Generate random data and create Pedersen commitment using the correct method
    // PedersenCommitment::commit returns (commitment, randomness)
    let (pedersen_commit, _) =
        PedersenCommitment::commit(&params, &token_data_hash, &mut rng_thread)?;

    // Final Blake3 hash to protect against future quantum attacks
    // The commitment_hash field is already properly implemented in PedersenCommitment
    let final_hash = blake3::hash(&pedersen_commit.commitment.to_bytes_be())
        .as_bytes()
        .to_vec();

    // Store the final hash as our first 'commit'
    let mut partials = vec![final_hash];

    // 3. Gather partial commits from other participants (simulate for now)
    for _ in 1..participants_set.len() {
        let sim_data = generate_secure_random(32)?;

        // Create hash sandwich for simulated participants too
        let mut sha3_hasher = Sha3_512::new();
        sha3_hasher.update(&sim_data);
        let sim_data_hash = sha3_hasher.finalize().to_vec();

        // Use the proper Pedersen commit method
        let (sim_commitment, _) =
            PedersenCommitment::commit(&params, &sim_data_hash, &mut rng_thread)?;
        let sim_final_hash = blake3::hash(&sim_commitment.commitment.to_bytes_be())
            .as_bytes()
            .to_vec();

        partials.push(sim_final_hash);
    }

    // 4. Select only threshold commits
    let selected = partials
        .into_iter()
        .take(threshold)
        .collect::<Vec<Vec<u8>>>();

    // 5. Combine them into final token hash + build token entropy
    let token_hash = combine_commits(&selected, token_data);
    let token_entropy = build_token_entropy(&token_hash, &selected);

    // 6. Generate post-quantum SPHINCS+ and Kyber keys
    let (sphincs_public_key, sphincs_private_key) = generate_sphincs_keypair();
    let (kyber_pub_key, kyber_secret_key) = generate_kyber_keypair()?;

    // 7. Process the policy file if provided
    let policy_anchor = if let Some(policy) = policy_file {
        Some(PolicyAnchor::from_policy(policy)?)
    } else {
        None
    };

    // 8. Build final record
    let genesis = TokenGenesis {
        token_hash,
        token_entropy,
        threshold,
        participants: participants_set,
        signing_key_sphincs: sphincs_public_key,
        // Store the kyber public/private as a tuple
        kyber_keypair: (kyber_pub_key, kyber_secret_key),
        policy_anchor,
        contributions: selected
            .into_iter()
            .map(|c| TokenContribution {
                data: c,
                verified: true,
            })
            .collect(),
        signing_key: sphincs_private_key,
    };

    Ok(genesis)
}

/// Derive a "sub-token genesis" from a parent token genesis.
pub fn derive_sub_token_genesis(
    parent: &TokenGenesis,
    sub_id: &str,
    sub_entropy: &[u8],
    policy_file: Option<&PolicyFile>,
) -> Result<TokenGenesis, DsmError> {
    // Combine parent hash + sub_id + sub_entropy
    let mut combined = Vec::new();
    combined.extend_from_slice(&parent.token_hash);
    combined.extend_from_slice(sub_id.as_bytes());
    combined.extend_from_slice(sub_entropy);

    // Hash to create sub-hash
    let sub_hash = blake3::hash(&combined).as_bytes().to_vec();

    // Combine with parent entropy to produce new token_entropy
    let mut hasher = Sha3_512::new();
    hasher.update(&parent.token_entropy);
    hasher.update(sub_id.as_bytes());
    hasher.update(sub_entropy);
    let derived_entropy = hasher.finalize().to_vec();

    // Create new quantum keys for the sub-genesis
    let (sphincs_public_key, sphincs_private_key) = generate_sphincs_keypair();
    let (kyber_pub_key, kyber_secret_key) = generate_kyber_keypair();

    // Process the policy file if provided, otherwise inherit from parent
    let policy_anchor = if let Some(policy) = policy_file {
        Some(PolicyAnchor::from_policy(policy)?)
    } else {
        parent.policy_anchor.clone()
    };

    Ok(TokenGenesis {
        token_hash: sub_hash,
        token_entropy: derived_entropy,
        threshold: 1, // single "owner" for sub
        participants: HashSet::from([sub_id.to_string()]),
        signing_key_sphincs: sphincs_public_key,
        kyber_keypair: (kyber_pub_key, kyber_secret_key),
        policy_anchor,
        contributions: vec![TokenContribution {
            data: sub_entropy.to_vec(),
            verified: true,
        }],
        signing_key: sphincs_private_key,
    })
}

/// Create a token from genesis data
pub fn create_token_from_genesis(
    genesis: &TokenGenesis,
    owner_id: &str,
    metadata: Vec<u8>,
    initial_balance: Balance,
) -> Token {
    if let Some(policy_anchor) = &genesis.policy_anchor {
        // Create token with policy anchor
        let mut anchor_bytes = [0u8; 32];
        anchor_bytes.copy_from_slice(&policy_anchor.0[..]);

        Token::new_with_policy(
            owner_id,
            genesis.token_hash.clone(),
            metadata,
            initial_balance,
            anchor_bytes,
        )
    } else {
        // Create token without policy anchor
        Token::new(
            owner_id,
            genesis.token_hash.clone(),
            metadata,
            initial_balance,
        )
    }
}

/// Create a token implementation directly without MPC
pub fn create_token_direct(
    owner_id: &str,
    token_hash: Vec<u8>,
    metadata: Vec<u8>,
    initial_balance: Balance,
) -> Token {
    Token::new(owner_id, token_hash, metadata, initial_balance)
}

/// Update token status based on state transition
pub fn update_token_status(token: &mut Token, status: TokenStatus) -> Result<(), DsmError> {
    token.set_status(status);
    Ok(())
}
