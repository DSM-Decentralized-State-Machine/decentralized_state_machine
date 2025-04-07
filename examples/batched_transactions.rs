//! Example demonstrating batched transactions in DSM
//!
//! This example shows how to:
//! 1. Create a batch of transactions
//! 2. Add multiple transitions to the batch
//! 3. Finalize the batch
//! 4. Commit the batch to the hash chain
//! 5. Verify transitions in the batch

use std::collections::HashMap;

use dsm::core::state_machine::hashchain::HashChain;
use dsm::core::state_machine::transition::StateTransition;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};

fn main() -> Result<(), DsmError> {
    println!("===== Batched Transactions Example =====");

    // Create a new hash chain
    let mut chain = HashChain::new();

    // Create a device
    let device_info = DeviceInfo::new("device_1", vec![1, 2, 3, 4]);

    // Create a genesis state
    let genesis_state = create_genesis_state(device_info.clone())?;
    println!("Created genesis state with ID: {}", genesis_state.id);

    // Add the genesis state to the chain
    chain.add_state(genesis_state.clone())?;

    // Create a batch for transactions
    let batch_id = chain.create_batch()?;
    println!("Created new batch with ID: {}", batch_id);

    // Store transitions locally
    let mut transitions = Vec::new();

    // Add multiple transitions to the batch
    let num_transactions = 5;
    for i in 0..num_transactions {
        // Create a transaction
        let transition =
            create_test_transition(&genesis_state, format!("tx_{}", i), vec![i as u8; 32])?;

        // Store transition locally
        transitions.push(transition.clone());

        // Add to batch
        let tx_index = chain.add_transition_to_batch(batch_id, transition)?;
        println!("Added transaction {} to batch at index {}", i, tx_index);
    }

    // Finalize the batch
    chain.finalize_batch(batch_id)?;
    println!("Batch {} finalized", batch_id);

    // Generate proof for a transition
    let proof = chain.generate_transition_proof(batch_id, 2)?;
    println!("Generated proof for transition 2 in batch {}", batch_id);

    // Verify a transition with its proof
    let verify_result = chain.verify_transition_in_batch(batch_id, 2, &transitions[2], &proof)?;

    println!("Transition verification result: {}", verify_result);

    // Commit the batch to the chain
    chain.commit_batch(batch_id)?;
    println!("Batch {} committed to the chain", batch_id);

    // Show the current chain state
    if let Some(current) = chain.get_latest_state().ok() {
        println!(
            "Current state: ID={}, Number={}",
            current.id, current.state_number
        );
    }

    println!("===== Example Completed Successfully =====");
    Ok(())
}

/// Create a genesis state
fn create_genesis_state(device_info: DeviceInfo) -> Result<State, DsmError> {
    let mut state = State::new_genesis(
        vec![0, 1, 2, 3], // Initial entropy
        device_info,
    );

    // Compute and set the hash
    let hash = state.compute_hash()?;
    state.hash = hash;

    Ok(state)
}

/// Create a test transition
fn create_test_transition(
    from_state: &State,
    op_name: String,
    entropy: Vec<u8>,
) -> Result<StateTransition, DsmError> {
    let transition = StateTransition {
        operation: Operation::Generic {
            operation_type: op_name,
            data: vec![1, 2, 3],
            message: format!("Transaction from state {}", from_state.state_number),
        },
        new_entropy: Some(entropy),
        encapsulated_entropy: None,
        device_id: from_state.device_info.device_id.clone(),
        flags: vec![],
        position_sequence: None,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DsmError::generic("Failed to get timestamp", Some(e)))?
            .as_secs(),
        token_balances: Some(HashMap::new()),
        forward_commitment: None,
        prev_state_hash: Some(from_state.hash.clone()),
        // Using empty signatures for example purposes
        entity_signature: Some(vec![]),
        counterparty_signature: Some(vec![]),
    };

    Ok(transition)
}
