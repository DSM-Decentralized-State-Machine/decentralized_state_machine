use sha3::digest::Update;
use sha3::{
    digest::{ExtendableOutputReset, XofReader},
    Shake256,
};

/// SHA3 implementation for DSM protocol
/// Uses SHAKE256 in XOF mode for quantum resistance
pub fn hash_shake256_xof(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof_reset().read(&mut output);
    output
}

/// Combine multiple participant contributions with SHAKE256
pub fn combine_participant_contributions(contributions: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    // Add domain separation
    hasher.update(b"DSM.v1.shake.combine");
    for contribution in contributions {
        hasher.update(contribution);
    }
    let mut output = [0u8; 32];
    hasher.finalize_xof_reset().read(&mut output);
    output
}

/// Hash state information for pre-commitments using SHAKE256
pub fn hash_state_precommitment(state_hash: &[u8], operation: &[u8], entropy: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    // Add domain separation
    hasher.update(b"DSM.v1.shake.precommit");
    hasher.update(state_hash);
    hasher.update(operation);
    hasher.update(entropy);
    let mut output = [0u8; 32];
    hasher.finalize_xof_reset().read(&mut output);
    output
}

/// Process the first stage of the hash sandwich for Genesis MPC
pub fn preprocess_participant_contribution(contribution: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    // Add domain separation
    hasher.update(b"DSM.v1.shake.preprocess");
    hasher.update(contribution);
    let mut output = [0u8; 32];
    hasher.finalize_xof_reset().read(&mut output);
    output
}

/// Create a new incremental SHAKE256 hasher
pub fn new_shake256() -> Shake256 {
    Shake256::default()
}

/// Extend a SHAKE hasher with more data
pub fn extend_shake(hasher: &mut Shake256, data: &[u8]) {
    hasher.update(data);
}

/// Finalize a SHAKE hash with variable output length
pub fn finalize_shake_xof(mut hasher: Shake256, output_len: usize) -> Vec<u8> {
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof_reset().read(&mut output);
    output
}
