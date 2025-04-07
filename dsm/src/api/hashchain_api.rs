// Hash Chain API Implementation
//
// This module implements the straight hash chain verification mechanisms described in
// the DSM whitepaper Section 3. It provides the core verification primitives that
// enable the deterministic, quantum-resistant security guarantees of the system.

use crate::crypto::blake3::hash_blake3;
use crate::types::error::DsmError;
use crate::types::state_types::{MerkleProof, State};
use log::{debug, trace};
use std::collections::HashSet;

// Hash Chain Verification

/// Verify a straight hash chain between two consecutive states
///
/// This implements the core verification principle described in whitepaper Section 3.1,
/// where each state contains a cryptographic hash of its predecessor.
///
/// # Arguments
///
/// * `state1` - The predecessor state
/// * `state2` - The successor state
///
/// # Returns
///
/// * `Ok(())` if the hash chain is valid
/// * `Err(DsmError)` if the hash chain is invalid
pub fn verify_straight_hash_chain(state1: &State, state2: &State) -> Result<(), DsmError> {
    trace!(
        "Verifying hash chain between state {} and {}",
        state1.state_number,
        state2.state_number
    );

    // Verify sequential state numbers
    if state2.state_number != state1.state_number + 1 {
        debug!(
            "Hash chain verification failed: non-sequential state numbers ({} -> {})",
            state1.state_number, state2.state_number
        );
        return Err(DsmError::verification(format!(
            "Hash chain verification failed: non-sequential state numbers ({} -> {})",
            state1.state_number, state2.state_number
        )));
    }

    // Hash state1 for comparison
    let state1_hash = state1
        .hash()
        .map_err(|e| DsmError::serialization(format!("Failed to hash state1: {}", e), Some(e)))?;

    // Verify that state2's prev_state_hash matches the hash of state1
    if state1_hash != state2.prev_state_hash {
        debug!(
            "Hash chain verification failed: prev_state_hash mismatch between states {} and {}",
            state1.state_number, state2.state_number
        );
        return Err(DsmError::verification(format!(
            "Hash chain verification failed: prev_state_hash mismatch between states {} and {}",
            state1.state_number, state2.state_number
        )));
    }

    // Verify state2's hash is valid
    let computed_state2_hash = state2.compute_hash().map_err(|e| {
        DsmError::serialization(format!("Failed to compute state2 hash: {}", e), Some(e))
    })?;

    if state2.hash != computed_state2_hash {
        debug!(
            "Hash chain verification failed: invalid state2 hash for state {}",
            state2.state_number
        );
        return Err(DsmError::verification(format!(
            "Hash chain verification failed: invalid state2 hash for state {}",
            state2.state_number
        )));
    }

    trace!(
        "Hash chain verification successful between states {} and {}",
        state1.state_number,
        state2.state_number
    );
    Ok(())
}

/// Verify a chain of states using sparse index checkpoints as in whitepaper Section 3.2
///
/// This function efficiently verifies a long chain by using the sparse index checkpoints
/// to skip unnecessary verification steps.
///
/// # Arguments
///
/// * `states` - A slice of states representing the chain to verify
/// * `target_state` - The state at the end of the chain to verify
///
/// # Returns
///
/// * `Ok(true)` if the chain is valid
/// * `Ok(false)` if the chain is invalid
/// * `Err(DsmError)` if an error occurs during verification
pub fn verify_chain_with_sparse_index(
    states: &[State],
    target_state: &State,
) -> Result<bool, DsmError> {
    // Cannot verify empty chain
    if states.is_empty() {
        return Err(DsmError::state("Cannot verify empty chain"));
    }

    // Start verification from target state
    let mut current_state = target_state;

    // Track verified states to avoid re-verification
    let mut verified_states = HashSet::new();
    verified_states.insert(target_state.state_number);

    // Handle genesis state special case
    if current_state.state_number == 0 {
        return Ok(true);
    }

    // Continue until we reach genesis
    while current_state.state_number > 0 {
        // Get sparse indices from the sparse_index field
        let checkpoint = current_state.sparse_index.value();

        if checkpoint < current_state.state_number {
            // Find the state matching this checkpoint
            let checkpoint_state = states
                .iter()
                .find(|s| s.state_number == checkpoint)
                .ok_or_else(|| {
                    DsmError::state(format!(
                        "Checkpoint state {} not found in chain",
                        checkpoint
                    ))
                })?;

            // Find all states between checkpoint and current
            let intermediate_states: Vec<&State> = states
                .iter()
                .filter(|s| {
                    s.state_number > checkpoint && s.state_number < current_state.state_number
                })
                .collect();

            // Verify straight hash chain between checkpoint and intermediate states
            let mut prev = checkpoint_state;
            for state in intermediate_states {
                if !verified_states.contains(&state.state_number) {
                    verify_straight_hash_chain(prev, state)?;
                    verified_states.insert(state.state_number);
                }
                prev = state;
            }

            // Verify straight hash chain between last intermediate and current
            if prev.state_number != checkpoint_state.state_number {
                verify_straight_hash_chain(prev, current_state)?;
            } else {
                verify_straight_hash_chain(checkpoint_state, current_state)?;
            }

            // Move to checkpoint state and continue
            current_state = checkpoint_state;
            verified_states.insert(checkpoint_state.state_number);

            // If we've reached genesis, we're done
            if current_state.state_number == 0 {
                return Ok(true);
            }

            continue;
        }

        // No valid checkpoint found, fall back to direct predecessor
        let predecessor_state = states
            .iter()
            .find(|s| s.state_number == current_state.state_number - 1)
            .ok_or_else(|| {
                DsmError::state(format!(
                    "Predecessor state {} not found in chain",
                    current_state.state_number - 1
                ))
            })?;

        // Verify straight hash chain with direct predecessor
        verify_straight_hash_chain(predecessor_state, current_state)?;

        // Move to predecessor and continue
        current_state = predecessor_state;
        verified_states.insert(predecessor_state.state_number);
    }

    // We should have reached the genesis state
    Ok(current_state.state_number == 0)
}

/// Verify a Sparse Merkle Tree proof for a state as described in whitepaper Section 3.3
///
/// This function verifies that a state is included in a Sparse Merkle Tree with the given root hash.
///
/// # Arguments
///
/// * `root_hash` - The root hash of the Sparse Merkle Tree
/// * `state` - The state to verify inclusion for
/// * `proof` - The Merkle proof for the state
///
/// # Returns
///
/// * `Ok(true)` if the state is included in the tree
/// * `Ok(false)` if the state is not included in the tree
/// * `Err(DsmError)` if an error occurs during verification
pub fn verify_merkle_proof(
    root_hash: &[u8],
    state: &State,
    proof: &MerkleProof,
) -> Result<bool, DsmError> {
    // Compute the state hash
    let state_hash = state
        .hash()
        .map_err(|e| DsmError::serialization(format!("Failed to hash state: {}", e), Some(e)))?;

    // Convert the Hash to a vector
    let hash_vector = state_hash.to_vec();

    // Use the SparseMerkleTree structure's verify_proof method
    crate::types::state_types::SparseMerkleTree::verify_proof_static(
        &blake3::Hash::from_bytes(root_hash.try_into().map_err(|_| {
            DsmError::validation("Invalid root hash length", None::<std::convert::Infallible>)
        })?),
        &hash_vector,
        proof,
    )
}

/// Combined verification using both hash chain and Merkle tree as described in whitepaper Section 3
///
/// This comprehensive verification combines hash chain verification for temporal ordering
/// and Merkle proofs for inclusion verification.
///
/// # Arguments
///
/// * `states` - A slice of states representing the chain to verify
/// * `target_state` - The state at the end of the chain to verify
/// * `proof` - Optional Merkle proof for additional verification
/// * `root_hash` - Optional Merkle tree root hash for verification
///
/// # Returns
///
/// * `Ok(true)` if all verifications pass
/// * `Ok(false)` if any verification fails
/// * `Err(DsmError)` if an error occurs during verification
pub fn verify_state_comprehensive(
    states: &[State],
    target_state: &State,
    proof: Option<&MerkleProof>,
    root_hash: Option<&[u8]>,
) -> Result<bool, DsmError> {
    // First verify the hash chain
    let hash_chain_valid = verify_chain_with_sparse_index(states, target_state)?;

    // If hash chain verification fails, return early
    if !hash_chain_valid {
        return Ok(false);
    }

    // If no Merkle proof provided, we're done with hash chain verification
    if proof.is_none() || root_hash.is_none() {
        return Ok(true);
    }

    // Verify the Merkle proof if provided
    let merkle_valid = verify_merkle_proof(root_hash.unwrap(), target_state, proof.unwrap())?;

    // Both hash chain and Merkle proof must be valid
    Ok(merkle_valid)
}

/// TEE-Based Hash Chain Verification with random sampling as described in whitepaper Section 12
///
/// This function implements the TEE-based verification described in Section 12, where random
/// states are verified to ensure integrity without checking the entire chain.
///
/// # Arguments
///
/// * `states` - A slice of states representing the chain to verify
/// * `target_state` - The state at the end of the chain to verify
/// * `constant_entropy` - TEE-provided constant entropy
/// * `ephemeral_seed` - Ephemeral seed for this verification
/// * `num_samples` - Number of random samples to verify
///
/// # Returns
///
/// * `Ok(true)` if all sampled verifications pass
/// * `Ok(false)` if any verification fails
/// * `Err(DsmError)` if an error occurs during verification
pub fn verify_chain_with_tee_sampling(
    states: &[State],
    target_state: &State,
    constant_entropy: &[u8],
    ephemeral_seed: &[u8],
    num_samples: u32,
) -> Result<bool, DsmError> {
    // Generate seed for deterministic verification (Section 12)
    // seedTEE = H(constant entropy ∥ ephemeral seed)
    let mut seed_data = Vec::new();
    seed_data.extend_from_slice(constant_entropy);
    seed_data.extend_from_slice(ephemeral_seed);
    let seed_tee = hash_blake3(&seed_data).as_bytes().to_vec();

    // Start verification from target state
    let mut current_state = target_state;

    // Track verified states
    let mut verified_states = HashSet::new();
    verified_states.insert(target_state.state_number);

    // Perform deterministic random sampling verification
    for sample in 0..num_samples {
        // Create verification data for this iteration
        let mut verification_data = Vec::new();
        verification_data.extend_from_slice(&seed_tee);
        verification_data.extend_from_slice(&current_state.state_number.to_le_bytes());
        verification_data.extend_from_slice(&sample.to_le_bytes());

        // Generate deterministic random selection
        let current_hash = hash_blake3(&verification_data).as_bytes().to_vec();

        // Determine index to verify based on hash
        let index_to_verify = deterministic_select(&current_hash, current_state.state_number);

        // Skip if we've already verified this state
        if verified_states.contains(&index_to_verify) {
            continue;
        }

        // Find the state with this index
        let selected_state = states
            .iter()
            .find(|s| s.state_number == index_to_verify)
            .ok_or_else(|| {
                DsmError::state(format!(
                    "State with index {} not found in chain",
                    index_to_verify
                ))
            })?;

        // If selected state has sparse index checkpoint, verify that too
        let checkpoint = selected_state.sparse_index.value();
        if checkpoint < selected_state.state_number {
            // Find checkpoint state
            let checkpoint_state = states
                .iter()
                .find(|s| s.state_number == checkpoint)
                .ok_or_else(|| {
                    DsmError::state(format!(
                        "Checkpoint state {} not found in chain",
                        checkpoint
                    ))
                })?;

            // Verify hash chain between checkpoint and selected
            verify_straight_hash_chain(checkpoint_state, selected_state)?;
            verified_states.insert(checkpoint_state.state_number);
        }

        // Verify hash chain between selected state and current state
        if selected_state.state_number < current_state.state_number {
            // Find all states between selected and current
            let intermediate_states: Vec<&State> = states
                .iter()
                .filter(|s| {
                    s.state_number > selected_state.state_number
                        && s.state_number < current_state.state_number
                })
                .collect();

            // Verify straight hash chain for all intermediates
            let mut prev = selected_state;
            for state in intermediate_states {
                if !verified_states.contains(&state.state_number) {
                    verify_straight_hash_chain(prev, state)?;
                    verified_states.insert(state.state_number);
                }
                prev = state;
            }

            // Verify straight hash chain with current state
            if prev.state_number != selected_state.state_number {
                verify_straight_hash_chain(prev, current_state)?;
            } else {
                verify_straight_hash_chain(selected_state, current_state)?;
            }
        } else {
            // Find all states between current and selected
            let intermediate_states: Vec<&State> = states
                .iter()
                .filter(|s| {
                    s.state_number > current_state.state_number
                        && s.state_number < selected_state.state_number
                })
                .collect();

            // Verify straight hash chain for all intermediates
            let mut prev = current_state;
            for state in intermediate_states {
                if !verified_states.contains(&state.state_number) {
                    verify_straight_hash_chain(prev, state)?;
                    verified_states.insert(state.state_number);
                }
                prev = state;
            }

            // Verify straight hash chain with selected state
            if prev.state_number != current_state.state_number {
                verify_straight_hash_chain(prev, selected_state)?;
            } else {
                verify_straight_hash_chain(current_state, selected_state)?;
            }
        }

        // Update current state to the selected state
        current_state = selected_state;
    }

    // We've successfully verified all sampled states
    Ok(true)
}

/// Helper function to deterministically select a state index for verification
///
/// # Arguments
///
/// * `hash` - Hash bytes used for random selection
/// * `max_value` - Maximum state number (exclusive)
///
/// # Returns
///
/// * `u64` - Deterministically selected state number between 0 and max_value-1
fn deterministic_select(hash: &[u8], max_value: u64) -> u64 {
    if max_value <= 1 {
        return 0;
    }

    // Use first 8 bytes of hash as a u64
    let mut value_bytes = [0u8; 8];
    value_bytes[..std::cmp::min(8, hash.len())]
        .copy_from_slice(&hash[..std::cmp::min(8, hash.len())]);

    let value = u64::from_le_bytes(value_bytes);

    // Mod to get value within range
    value % max_value
}
