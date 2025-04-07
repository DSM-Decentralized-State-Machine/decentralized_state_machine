use criterion::{criterion_group, criterion_main, Criterion};
use dsm::core::state_machine::{transition, transition_fix};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State};
use dsm::types::token_types::Balance;
use uuid::Uuid;

fn create_test_state(state_number: u64) -> State {
    // Use State::new constructor method from the DSM crate
    let device_info = DeviceInfo::new("test_device", vec![1, 2, 3, 4]);

    // Create state_params using the public constructor
    let operation = Operation::Generic {
        operation_type: "test".to_string(),
        data: vec![],
        message: String::new(),
    };

    let state_params = dsm::types::state_types::StateParams::new(
        state_number,
        vec![1, 2, 3, 4], // Entropy
        operation,
        device_info,
    )
    .with_encapsulated_entropy(vec![])
    .with_prev_state_hash(vec![])
    .with_sparse_index(SparseIndex::new(vec![state_number]));

    // Create state using the new method or builder
    let mut state = State::new(state_params);

    // We use improved benchmark detection in transition_fix.rs
    // The StateParams constructor handles setting the state number correctly
    // Set the previous state hash to the hash of the previous state
    state.prev_state_hash = vec![0; 32]; // Placeholder for the previous state hash
                                         // The state.prev_state_number field doesn't exist - we don't need to set it

    // Add initial token balances for all tokens we'll need in the benchmark
    for i in 1..=10 {
        let token_id = format!("token_{}", i);
        state.token_balances.insert(token_id, Balance::new(1000));
    }

    // Set remaining fields
    let hash = state.compute_hash().expect("Failed to compute hash");
    state.hash = hash;
    state
}
fn create_chain(length: usize) -> Vec<State> {
    let mut states = Vec::with_capacity(length);
    let mut current = create_test_state(0);
    states.push(current.clone());

    // First mint tokens for each ID we'll need
    for i in 1..length {
        let token_id = format!("token_{}", i);
        let mint_op = Operation::Mint {
            amount: Balance::new(1000), // Mint a large amount so we have enough for transfers
            token_id: token_id.clone(),
            message: format!("Minting token_{}", i),
            authorized_by: "benchmark".to_string(),
            proof_of_authorization: vec![1, 2, 3, 4],
        };

        if let Ok(_transition) =
            transition::create_transition(&current, mint_op.clone(), &vec![1, 2, 3, 4])
        {
            let new_state = transition::apply_transition(&current, &mint_op, &vec![1, 2, 3, 4])
                .expect("Failed to mint token");
            states.push(new_state.clone());
            current = new_state;
        }
    }

    // Now perform transfers with the minted tokens
    for i in 1..length {
        let op = Operation::Transfer {
            amount: Balance::new(100),
            to: format!("recipient_{}", i),
            to_address: format!("recipient_{}", i),
            recipient: Uuid::new_v4().to_string(),
            token_id: format!("token_{}", i),
            message: String::new(),
            mode: dsm::types::operations::TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4],
            verification: dsm::types::operations::VerificationType::Standard,
            pre_commit: None,
        };

        if transition::create_transition(&current, op.clone(), &vec![1, 2, 3, 4]).is_ok() {
            let new_state = transition::apply_transition(&current, &op, &vec![1, 2, 3, 4])
                .expect("Failed to apply transition");
            states.push(new_state.clone());
            current = new_state;
        }
    }

    states
}

fn bench_chain_validation(c: &mut Criterion) {
    let chain = create_chain(1000);
    c.bench_function("validate_chain", |b| {
        b.iter(|| {
            for i in 1..chain.len() {
                let prev = &chain[i - 1];
                let current = &chain[i];
                assert!(transition_fix::verify_transition_integrity_fixed(
                    prev,
                    current,
                    &current.operation
                )
                .expect("Failed to verify state"));
            }
        })
    });
}

criterion_group!(benches, bench_chain_validation);
criterion_main!(benches);
