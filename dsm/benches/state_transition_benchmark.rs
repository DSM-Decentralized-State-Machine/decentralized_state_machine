use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dsm::core::state_machine::{self, transition};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};

mod bench;

// Implement memory pre-allocation and cache-warming to reduce variance
thread_local! {
    // Pre-allocate states for benchmarks to avoid memory allocation during measurements
    static BENCHMARK_STATES: std::cell::RefCell<Vec<State>> = std::cell::RefCell::new(Vec::with_capacity(128));
}

fn create_genesis_state() -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info);
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;
    genesis
}

fn transition_benchmark(c: &mut Criterion) {
    dsm::initialize();

    // Implement cache warming to minimize cold-cache outliers
    let mut state_machine = state_machine::StateMachine::new();
    let warm_state = create_genesis_state();
    state_machine.set_state(warm_state.clone());

    // Pre-warm CPU cache with operations that exercise the same code paths
    for _ in 0..1000 {
        let op = Operation::Generic {
            operation_type: "warmup_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: String::from("benchmark message"),
        };
        let _ = state_machine.execute_transition(op);
    }

    let mut group = c.benchmark_group("State Transitions");
    group.sample_size(150); // Increased sample size for better statistical analysis

    // Benchmark single transition execution
    group.bench_function("execute_transition", |b| {
        // Create state outside measurement to avoid allocation during benchmarking
        let genesis = create_genesis_state();

        // Pre-allocate the operation to avoid heap allocations during measurement
        let op_data = vec![9, 10, 11, 12];
        let op_type = "benchmark_op".to_string();

        b.iter_batched(
            // Setup: create a fresh state machine and genesis state for each iteration
            || {
                let mut state_machine = state_machine::StateMachine::new();
                state_machine.set_state(genesis.clone());
                (
                    state_machine,
                    Operation::Generic {
                        operation_type: op_type.clone(),
                        data: op_data.clone(),
                        message: String::from("benchmark message"),
                    },
                )
            },
            // Benchmark the operation with stable memory conditions
            |(mut state_machine, op)| black_box(state_machine.execute_transition(black_box(op))),
            // Use per-iteration batching for cache consistency
            criterion::BatchSize::SmallInput,
        )
    });

    // Benchmark transition creation and application separately
    group.bench_function("create_transition", |b| {
        // Pre-allocate objects outside of measurement
        let state = create_genesis_state();
        let op_data = vec![9, 10, 11, 12];
        let op_type = "benchmark_op".to_string();

        // Pre-compute serialized operation to avoid serialization during measurement
        let op = Operation::Generic {
            operation_type: op_type,
            data: op_data,
            message: "benchmark".to_string(),
        };
        let op_serialized = bincode::serialize(&op).unwrap();

        b.iter_batched(
            || {
                // Clone the operation to ensure each iteration has a fresh object
                (state.clone(), op.clone(), op_serialized.clone())
            },
            |(state, op, op_serialized)| {
                let entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                    &state.entropy,
                    &op_serialized,
                    state.state_number + 1,
                )
                .as_bytes()
                .to_vec();

                black_box(transition::create_transition(
                    black_box(&state),
                    black_box(op),
                    black_box(&entropy),
                ))
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Benchmark hash computation (critical for chain verification)
    group.bench_function("state_hash_computation", |b| {
        // Prepare state outside of measurement to avoid allocation noise
        let state = create_genesis_state();

        // Use prefetched state to ensure cache consistency
        b.iter_with_setup(|| state.clone(), |state| black_box(state.compute_hash()))
    });

    // Benchmark state verification
    group.bench_function("verify_transition", |b| {
        // Prepare test objects once outside of the measurement loop
        let genesis = create_genesis_state();

        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "benchmark message".to_string(),
        };

        let entropy = dsm::crypto::blake3::generate_deterministic_entropy(
            &genesis.entropy,
            &bincode::serialize(&op).unwrap(),
            genesis.state_number + 1,
        )
        .as_bytes()
        .to_vec();

        // Create the state directly without storing transition
        let state1 = transition::apply_transition(&genesis, &op, &entropy).unwrap();

        // Prefetch all memory structures to ensure cache locality
        let prefetch_refs = (&genesis, &state1, &op);
        std::hint::black_box(prefetch_refs);

        // Use a fixed state to eliminate allocation variance
        b.iter(|| {
            black_box(transition::verify_transition_integrity(
                black_box(&genesis),
                black_box(&state1),
                black_box(&op),
            ))
        })
    });

    // Benchmark transition application
    group.bench_function("apply_transition", |b| {
        // Prepare objects outside measurement loop
        let genesis = create_genesis_state();

        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "benchmark message".to_string(),
        };

        // Pre-compute entropy with proper memory alignment
        let op_serialized = bincode::serialize(&op).unwrap();
        let entropy = dsm::crypto::blake3::generate_deterministic_entropy(
            &genesis.entropy,
            &op_serialized,
            genesis.state_number + 1,
        )
        .as_bytes()
        .to_vec();

        // Use constant references to minimize memory operations
        let op_ref = &op;
        let genesis_ref = &genesis;
        let entropy_ref = &entropy;

        // Ensure data is in cache before measurement
        {
            let _warmup = transition::apply_transition(genesis_ref, op_ref, entropy_ref).unwrap();
        }

        b.iter(|| {
            black_box(transition::apply_transition(
                black_box(genesis_ref),
                black_box(op_ref),
                black_box(entropy_ref),
            ))
        })
    });

    group.finish();
}

fn chain_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash Chain Operations");
    // Increase sample size for better statistical significance
    group.sample_size(100);

    // Perform cache warming before benchmarking
    {
        let device_info = DeviceInfo::new("warmup_device", vec![1, 2, 3, 4]);
        let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
        genesis.hash = genesis.compute_hash().unwrap();

        let mut states = vec![genesis.clone()];
        let mut current_state = genesis;

        // Create a warmup chain to populate CPU caches
        for i in 0..200 {
            let operation = Operation::Generic {
                operation_type: format!("warmup_{}", i),
                data: vec![i as u8; 4],
                message: "benchmark".to_string(),
            };

            let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                &current_state.entropy,
                &bincode::serialize(&operation).unwrap(),
                current_state.state_number + 1,
            )
            .as_bytes()
            .to_vec();

            let indices = State::calculate_sparse_indices(i + 1).unwrap();
            let sparse_index = SparseIndex::new(indices);

            let state_params = StateParams::new(
                i + 1,               // state_number
                next_entropy,        // entropy
                operation,           // operation
                device_info.clone(), // device_info
            )
            .with_encapsulated_entropy(Vec::new())
            .with_prev_state_hash(current_state.hash().unwrap())
            .with_sparse_index(sparse_index);

            let mut next_state = State::new(state_params);
            next_state.hash = next_state.compute_hash().unwrap();

            // Verify chain to warm up verification code paths
            let _ = transition::verify_transition_integrity(
                &states[states.len() - 1],
                &next_state,
                &next_state.operation,
            );

            states.push(next_state.clone());
            current_state = next_state;
        }
    }

    // Benchmark hash chain verification with varying chain lengths
    for chain_length in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("verify_chain", chain_length),
            chain_length,
            |b, &n| {
                // Create a chain of length n with minimal allocation during measurement
                let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
                let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
                let computed_hash = genesis.compute_hash().unwrap();
                genesis.hash = computed_hash;

                // Pre-allocate vectors to prevent resizing during chain building
                let mut states = Vec::with_capacity(n as usize + 1);
                states.push(genesis.clone());

                // Pre-allocated buffer for operation data to prevent heap allocations
                let common_data = vec![0u8; 4];

                let mut current_state = genesis;

                // Create chain states outside of measurement phase
                for i in 0..n {
                    // Minimize allocations by reusing buffers
                    let mut data = common_data.clone();
                    for j in 0..4 {
                        if j < data.len() {
                            data[j] = i as u8;
                        }
                    }

                    let operation = Operation::Generic {
                        operation_type: format!("op_{}", i),
                        data,
                        message: "benchmark message".to_string(),
                    };

                    // Pre-serialize to avoid allocation during entropy derivation
                    let op_serialized = bincode::serialize(&operation).unwrap();
                    let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                        &current_state.entropy,
                        &op_serialized,
                        current_state.state_number + 1,
                    )
                    .as_bytes()
                    .to_vec();

                    let indices = State::calculate_sparse_indices(i + 1).unwrap();
                    let sparse_index = SparseIndex::new(indices);

                    let state_params = StateParams::new(
                        i + 1,               // state_number
                        next_entropy,        // entropy
                        operation,           // operation
                        device_info.clone(), // device_info
                    )
                    .with_encapsulated_entropy(Vec::new())
                    .with_prev_state_hash(current_state.hash().unwrap())
                    .with_sparse_index(sparse_index);
                    let mut next_state = State::new(state_params);
                    let computed_hash = next_state.compute_hash().unwrap();
                    next_state.hash = computed_hash.clone();

                    states.push(next_state.clone());
                    current_state.hash = computed_hash;
                }

                // Prefetch states into cache before measurement
                for state in &states {
                    std::hint::black_box(state);
                }

                // Ensure benchmark function captures states by reference
                let states_ref = &states;

                // Benchmark verification of the entire chain with stable memory
                b.iter(|| {
                    let mut verified = true;
                    for i in 1..states_ref.len() {
                        let prev_state = &states_ref[i - 1];
                        let curr_state = &states_ref[i];
                        verified = verified
                            && black_box(
                                transition::verify_transition_integrity(
                                    black_box(prev_state),
                                    black_box(curr_state),
                                    black_box(&curr_state.operation),
                                )
                                .unwrap(),
                            );
                    }
                    black_box(verified)
                })
            },
        );
    }

    group.finish();
}

fn precommitment_benchmark(c: &mut Criterion) {
    dsm::initialize();

    // Perform cache warming
    {
        let mut warm_machine = state_machine::StateMachine::new();
        warm_machine.set_state(create_genesis_state());

        // Generate multiple precommitments to warm CPU caches
        for i in 0..1000 {
            let op = Operation::Generic {
                operation_type: format!("warmup_{}", i),
                data: vec![i as u8; 4],
                message: "benchmark".to_string(),
            };
            let _ = warm_machine.generate_precommitment(&op);
        }
    }

    let mut group = c.benchmark_group("Precommitment Operations");
    group.sample_size(100); // Increased from 50 for better statistical power

    // Benchmark precommitment generation
    group.bench_function("generate_precommitment", |b| {
        // Create stable state environment outside measurement loop
        let mut state_machine = state_machine::StateMachine::new();
        let genesis = create_genesis_state();
        state_machine.set_state(genesis);

        // Pre-allocate operation data to minimize heap allocations
        let op_data = vec![9, 10, 11, 12];
        let op_type = "benchmark_op".to_string();

        // Use batch mode to ensure consistent state between iterations
        b.iter_batched(
            // Setup function creates consistent environment for each iteration
            || Operation::Generic {
                operation_type: op_type.clone(),
                data: op_data.clone(),
                message: "benchmark message".to_string(),
            },
            // Benchmark with minimal allocation noise
            |op| black_box(state_machine.generate_precommitment(black_box(&op))),
            criterion::BatchSize::SmallInput,
        )
    });

    // Benchmark precommitment verification
    group.bench_function("verify_precommitment", |b| {
        // Create stable state machine instance with deterministic state
        let mut state_machine = state_machine::StateMachine::new();
        let genesis = create_genesis_state();
        state_machine.set_state(genesis.clone());

        // Create reference operation with stable memory characteristics
        let op_data = vec![9, 10, 11, 12];
        let op_type = "benchmark_op".to_string();
        let op = Operation::Generic {
            operation_type: op_type.clone(),
            data: op_data.clone(),
            message: "benchmark message".to_string(),
        };

        // Generate positions once to avoid measuring generation time
        let (_, positions) = state_machine.generate_precommitment(&op).unwrap();

        // Create immutable references to minimize pointer manipulation
        let op_ref = &op;
        let positions_ref = &positions;

        // Perform one verification to ensure code paths are cached
        let _ = state_machine.verify_precommitment(op_ref, positions_ref);

        // Benchmark only the verification with stable memory access patterns
        b.iter(|| {
            black_box(
                state_machine.verify_precommitment(black_box(op_ref), black_box(positions_ref)),
            )
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = bench::configure_criterion("state_transition")();
    targets = transition_benchmark, chain_benchmark, precommitment_benchmark
}
criterion_main!(benches);
