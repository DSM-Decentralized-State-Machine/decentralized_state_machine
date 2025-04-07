// Direct State Verification Test for Hash Chain Integrity
//
// This test bypasses the StateMachine abstraction and directly tests
// the fundamental hash chain integrity mechanisms for DSM.

use dsm::core::state_machine::transition::{
    apply_transition, create_transition, verify_transition_integrity,
};
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State, StateFlag};

#[test]
fn test_direct_hash_chain_verification() -> Result<(), DsmError> {
    dsm::initialize();

    println!("Testing direct hash chain verification...");

    // Create genesis state
    let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![1, 2, 3, 4], device_info.clone());

    // Properly initialize flags for Genesis state
    genesis.flags.insert(StateFlag::Recovered);

    // Explicitly set state number for Genesis (should be 0)
    genesis.state_number = 0;

    // Set ID in canonical format
    genesis.id = format!("state_{}", genesis.state_number);

    // Compute and set hash
    let computed_hash = genesis.compute_hash()?;
    genesis.hash = computed_hash;

    // Create operation 1
    let op1 = Operation::Generic {
        operation_type: "test_operation".to_string(),
        data: vec![1, 2, 3, 4],
        message: "Generic operation: test".to_string(),
    };

    // Generate deterministic entropy for transition
    let entropy1 = dsm::crypto::blake3::generate_deterministic_entropy(
        &genesis.entropy,
        &bincode::serialize(&op1).unwrap_or_default(),
        genesis.state_number + 1,
    )
    .as_bytes()
    .to_vec();

    // Create transition 1
    let _transition1 = create_transition(&genesis, op1.clone(), &entropy1)?;

    // Apply transition to create state1
    let mut state1 = apply_transition(&genesis, &op1, &entropy1)?;

    // Ensure state ID is in canonical format
    state1.id = format!("state_{}", state1.state_number);

    // Recompute the hash to ensure cryptographic integrity
    let computed_hash = state1.compute_hash()?;
    state1.hash = computed_hash;

    // Verify transition integrity
    assert!(
        verify_transition_integrity(&genesis, &state1, &state1.operation)?,
        "Direct transition from genesis to state1 should verify"
    );

    // Create operation 2
    let op2 = Operation::Generic {
        operation_type: "second_operation".to_string(),
        data: vec![5, 6, 7, 8],
        message: "Second operation: test".to_string(),
    };

    // Generate deterministic entropy for second transition
    let entropy2 = dsm::crypto::blake3::generate_deterministic_entropy(
        &state1.entropy,
        &bincode::serialize(&op2).unwrap_or_default(),
        state1.state_number + 1,
    )
    .as_bytes()
    .to_vec();

    // Create transition 2
    let _transition2 = create_transition(&state1, op2.clone(), &entropy2)?;

    // Apply transition to create state2
    let mut state2 = apply_transition(&state1, &op2, &entropy2)?;

    // Ensure state ID is in canonical format
    state2.id = format!("state_{}", state2.state_number);

    // Recompute the hash to ensure cryptographic integrity
    let computed_hash = state2.compute_hash()?;
    state2.hash = computed_hash;

    // Verify state2's integrity
    assert!(
        verify_transition_integrity(&state1, &state2, &state2.operation)?,
        "Direct transition from state1 to state2 should verify"
    );

    // Verify the full chain's integrity
    assert_eq!(
        state1.prev_state_hash,
        genesis.hash()?,
        "State1 should reference genesis"
    );
    assert_eq!(
        state2.prev_state_hash,
        state1.hash()?,
        "State2 should reference state1"
    );

    // Verify state hashes match their computed values
    assert_eq!(
        genesis.hash()?,
        genesis.compute_hash()?,
        "Genesis hash integrity"
    );
    assert_eq!(
        state1.hash()?,
        state1.compute_hash()?,
        "State1 hash integrity"
    );
    assert_eq!(
        state2.hash()?,
        state2.compute_hash()?,
        "State2 hash integrity"
    );

    println!("Direct hash chain verification test passed!");
    Ok(())
}
