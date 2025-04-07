use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dsm::core::state_machine::transition::apply_transition;
use dsm::state_machine::StateTransition;
use dsm::types::operations::{Operation, PreCommitmentOp, TransactionMode, VerificationType};
use dsm::types::state_types::DeviceInfo;
use dsm::types::state_types::{PreCommitment, SparseIndex, State, StateParams};
use dsm::types::token_types::Balance;

#[derive(Default)]
struct MockStorage;

impl MockStorage {
    fn store_checkpoint(&self, _state: &State) -> Result<(), ()> {
        Ok(())
    }
}

fn create_test_transition() -> (State, StateTransition) {
    // Create the operation
    let op = Operation::Transfer {
        recipient: String::from("recipient"),
        to_address: String::from("address"),
        amount: Balance::new(100),
        to: String::from("to"),
        token_id: String::from("ROOT"),
        message: String::new(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0u8; 16],
        verification: VerificationType::Standard,
        pre_commit: Some(PreCommitmentOp {
            fixed_parameters: std::collections::HashMap::new(),
            variable_parameters: vec![],
            security_params: Default::default(),
        }),
    };

    // Create device info
    let device_info = DeviceInfo::default();

    // Create empty pre-commitment
    let forward_commitment = PreCommitment::new(
        String::from("dummy_hash"),
        {
            let mut map = std::collections::HashMap::new();
            map.insert(String::from("dummy"), vec![0u8; 32]);
            map
        },
        {
            let mut set = std::collections::HashSet::new();
            set.insert(String::from("dummy"));
            set
        },
        64u64,
        String::from("dummy_string"),
    );

    // Create state params using the new constructor
    let params = StateParams::new(
        0,             // state_number
        vec![0u8; 32], // entropy
        op.clone(),    // operation
        device_info,   // device_info
    )
    .with_encapsulated_entropy(vec![0u8; 32])
    .with_prev_state_hash(vec![0u8; 32])
    .with_sparse_index(SparseIndex::new(vec![0]))
    .with_forward_commitment(forward_commitment);

    // Create state from params
    let mut state = State::new(params);
    state
        .token_balances
        .insert("ROOT".to_string(), Balance::new(1000));

    // Create state transition
    let transition =
        StateTransition::new(op, Some(vec![0u8; 16]), Some(vec![1u8; 16]), "Dummy_Device");
    (state, transition)
}
fn benchmark_state_transition(c: &mut Criterion) {
    c.bench_function("dsm_apply_transition", |b| {
        b.iter(|| {
            let (state, transition) = create_test_transition();
            let op = transition.operation.clone();
            // Using empty vec as entropy for the third parameter
            let new_entropy = vec![0u8; 32];
            let result = apply_transition(&state, &op, &new_entropy);
            black_box(result).unwrap();
        })
    });
}

fn benchmark_with_storage(c: &mut Criterion) {
    c.bench_function("dsm_apply_with_checkpoint", |b| {
        b.iter(|| {
            let (state, transition) = create_test_transition();
            let op = transition.operation.clone();
            // Using empty vec as entropy for the third parameter
            let new_entropy = vec![0u8; 32];
            let result = apply_transition(&state, &op, &new_entropy);
            let _ = MockStorage.store_checkpoint(&state);
            black_box(result).unwrap();
        })
    });
}

fn benchmark_offline_batching(c: &mut Criterion) {
    c.bench_function("dsm_offline_batching", |b| {
        b.iter(|| {
            let (state, _) = create_test_transition();
            for _ in 0..10 {
                let (_, transition) = create_test_transition();
                let op = transition.operation.clone();
                // Using empty vec as entropy for the third parameter
                let new_entropy = vec![0u8; 32];
                let result = apply_transition(&state, &op, &new_entropy);
                black_box(result).unwrap();
            }
        })
    });
}

// Add this new function after the existing benchmark functions:

fn benchmark_multi_device_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_device_simulation");

    // Benchmark with 50 devices
    group.bench_function("50_devices", |b| {
        b.iter(|| {
            let mut states = Vec::with_capacity(50);
            for _ in 0..50 {
                let (state, _) = create_test_transition();
                states.push(state);
            }

            for state in states.iter_mut() {
                let (_, transition) = create_test_transition();
                let op = transition.operation.clone();
                // Using empty vec as entropy for the third parameter
                let new_entropy = vec![0u8; 32];
                let result = apply_transition(state, &op, &new_entropy);
                black_box(result).unwrap();
            }
        })
    });

    // Benchmark with 100 devices
    group.bench_function("100_devices", |b| {
        b.iter(|| {
            let mut states = Vec::with_capacity(100);
            for _ in 0..100 {
                let (state, _) = create_test_transition();
                states.push(state);
            }

            for state in states.iter_mut() {
                let (_, transition) = create_test_transition();
                let op = transition.operation.clone();
                // Using empty vec as entropy for the third parameter
                let new_entropy = vec![0u8; 32];
                let result = apply_transition(state, &op, &new_entropy);
                black_box(result).unwrap();
            }
        })
    });

    // Benchmark with 1000 devices
    group.bench_function("1000_devices", |b| {
        b.iter(|| {
            let mut states = Vec::with_capacity(1000);
            for _ in 0..1000 {
                let (state, _) = create_test_transition();
                states.push(state);
            }

            for state in states.iter_mut() {
                let (_, transition) = create_test_transition();
                let op = transition.operation.clone();
                // Using empty vec as entropy for the third parameter
                let new_entropy = vec![0u8; 32];
                let result = apply_transition(state, &op, &new_entropy);
                black_box(result).unwrap();
            }
        })
    });

    group.finish();
}

// Modify the criterion_group! macro to include the new benchmark:
criterion_group!(
    benches,
    benchmark_state_transition,
    benchmark_with_storage,
    benchmark_offline_batching,
    benchmark_multi_device_simulation
);
criterion_main!(benches);
