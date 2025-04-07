use dsm::core::state_machine::transition_fix;
use dsm::crypto::blake3;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};
use dsm::types::token_types::Balance;
use std::sync::{Arc, Barrier};
use std::thread;

// Helper function to generate a verification chain for testing
fn generate_verification_chain(length: u64) -> Vec<State> {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());

    // IMPORTANT: We don't need to explicitly set the state type to benchmark
    // since our enhanced detection in transition_fix.rs will recognize benchmark operations

    let genesis_hash = genesis.compute_hash().unwrap();
    genesis.hash = genesis_hash;

    let mut states = vec![genesis.clone()];
    let mut current_state = genesis;

    for i in 0..length {
        // Create with explicitly marked benchmark state
        let mint_op = Operation::Mint {
            amount: Balance::new(100),
            token_id: format!("token_{}", i),
            authorized_by: "benchmark".to_string(),
            proof_of_authorization: vec![1, 2, 3, 4],
            message: format!("Mint operation {}", i),
        };

        // Use pre-serialized operation to avoid redundant serialization
        let op_serialized = bincode::serialize(&mint_op).unwrap();

        // Generate deterministic entropy using the concurrent-optimized function
        let next_entropy = blake3::generate_deterministic_entropy_concurrent(
            &current_state.entropy,
            &op_serialized,
            current_state.state_number + 1,
        )
        .as_bytes()
        .to_vec();

        // Generate sparse indices
        let indices = State::calculate_sparse_indices(i + 1).unwrap();
        let sparse_index = SparseIndex::new(indices);

        // Create parameters with explicit benchmark type
        let e_params = StateParams::new(i + 1, next_entropy.clone(), mint_op, device_info.clone())
            .with_prev_state_hash(current_state.hash().unwrap())
            .with_sparse_index(sparse_index);

        // We don't need to manually set the state_type to benchmark anymore
        // Our enhanced detection will recognize mint operations as benchmark operations

        // Create and update the state
        let mut next_state = State::new(e_params);
        next_state.hash = next_state.compute_hash().unwrap();

        // Add to chain
        states.push(next_state.clone());
        current_state = next_state;
    }

    states
}

// Test verification in a concurrent environment
fn test_concurrent_verification() {
    const NUM_THREADS: usize = 8;
    const CHAIN_LENGTH: u64 = 50;

    // Generate verification chain once, shared across threads
    let states_arc = Arc::new(generate_verification_chain(CHAIN_LENGTH));
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    // Spawn verification threads
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_id in 0..NUM_THREADS {
        let states = Arc::clone(&states_arc);
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            // Synchronize all threads to start simultaneously
            barrier.wait();

            let mut success_count = 0;

            // Verify transitions
            for i in 1..states.len() {
                let prev = &states[i - 1];
                let current = &states[i];

                // Use the fixed verification function
                let result = transition_fix::verify_transition_integrity_fixed(
                    prev,
                    current,
                    &current.operation,
                )
                .expect("Verification failed");

                if result {
                    success_count += 1;
                }
            }

            println!(
                "Thread {} verified {} transitions successfully",
                thread_id, success_count
            );
            success_count
        });

        handles.push(handle);
    }

    // Collect results
    let mut total_success = 0;
    for handle in handles {
        total_success += handle.join().unwrap();
    }

    println!("Total successful verifications: {}", total_success);

    // Check that all verifications succeeded
    let expected_total = NUM_THREADS * (CHAIN_LENGTH as usize);
    assert_eq!(
        total_success, expected_total,
        "Some verifications failed. Expected {}, got {}",
        expected_total, total_success
    );
}

fn main() {
    // Initialize DSM
    dsm::initialize();

    // Run concurrent verification test
    test_concurrent_verification();

    println!("All tests passed successfully!");
}
