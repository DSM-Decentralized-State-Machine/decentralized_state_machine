use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dsm::core::state_machine::transition;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

mod bench;

/// Benchmark parallel verification scalability for quantum-resistant hash chain validation.
///
/// This benchmark evaluates the parallel verification performance of the DSM system
/// across different thread counts, providing insights into horizontal scaling properties
/// for high-throughput deployment scenarios. The results directly inform optimal
/// thread pool configurations for verification nodes.
fn concurrent_verification_benchmark(c: &mut Criterion) {
    // Initialize DSM runtime environment
    dsm::initialize();

    // Create optimized benchmark group with thread-aware configuration
    let mut group = c.benchmark_group("Concurrent Verification");
    group.sample_size(50); // Reduced sample size due to thread coordination overhead
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(5));

    // Create verification workload that's representative of real-world validation
    // Longer chain produces more meaningful parallelization results
    let verification_chain = generate_verification_chain(1000);
    let arc_chain = Arc::new(verification_chain);

    // Test concurrency scaling across different thread counts
    // Note: Using powers of 2 to match common thread pool configurations
    for thread_count in [1, 2, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("parallel_verification", thread_count),
            thread_count,
            |b, &threads| {
                b.iter(|| {
                    // Clone Arc to pass chain data to threads safely
                    let shared_chain = Arc::clone(&arc_chain);
                    let chain_len = shared_chain.len();

                    // Compute block size for work distribution
                    let chunk_size = chain_len / threads as usize;

                    // Create synchronization barrier to ensure all threads start verification simultaneously
                    let barrier = Arc::new(Barrier::new(threads as usize));

                    // Create thread handles for joining later
                    let mut handles = Vec::with_capacity(threads as usize);

                    // Spawn verification threads with precise work distribution
                    for thread_id in 0..threads {
                        let thread_chain = Arc::clone(&shared_chain);
                        let thread_barrier = Arc::clone(&barrier);

                        // Calculate exact slice range for this thread
                        let start_idx = thread_id as usize * chunk_size;
                        let end_idx = if thread_id == threads - 1 {
                            chain_len
                        } else {
                            (thread_id as usize + 1) * chunk_size
                        };

                        let handle = thread::spawn(move || {
                            // Wait for all threads to reach this point before starting verification
                            thread_barrier.wait();

                            // Process assigned state transitions
                            let mut verified_count = 0;
                            for i in start_idx + 1..end_idx {
                                // Skip first state as it's genesis and has no previous state
                                if transition::verify_transition_integrity(
                                    &thread_chain[i - 1],
                                    &thread_chain[i],
                                    &thread_chain[i].operation,
                                )
                                .unwrap()
                                {
                                    verified_count += 1;
                                }
                            }

                            verified_count
                        });

                        handles.push(handle);
                    }

                    // Collect results from all threads
                    let verification_results: Vec<usize> =
                        handles.into_iter().map(|h| h.join().unwrap()).collect();

                    // Return total verified transitions for result validation
                    black_box(verification_results.iter().sum::<usize>())
                })
            },
        );
    }

    group.finish();
}

/// Benchmark distributed consensus verification patterns with isolated node simulation
fn distributed_verification_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Distributed Verification");

    // Create a verification chain with multiple forks for consensus evaluation
    let base_chain = generate_verification_chain(50);

    // Generate forked chains from the base chain
    let fork_points = [10, 20, 30, 40];
    let mut fork_chains = Vec::new();

    for &fork_point in &fork_points {
        let mut fork = base_chain[0..fork_point as usize].to_vec();

        // Create divergent chain from fork point
        let mut current_state = fork.last().unwrap().clone();

        for i in 0..10 {
            let operation = Operation::Generic {
                operation_type: format!("fork_{}_op_{}", fork_point, i),
                data: vec![i as u8; 4],
                message: format!("Fork operation {} at fork point {}", i, fork_point),
            };

            let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                &current_state.entropy,
                &bincode::serialize(&operation).unwrap(),
                current_state.state_number + 1,
            )
            .as_bytes()
            .to_vec();

            let indices = State::calculate_sparse_indices(current_state.state_number + 1).unwrap();
            let sparse_index = SparseIndex::new(indices);

            let device_info = DeviceInfo::new("fork_device", vec![1, 2, 3, 4]);

            let state_params = StateParams::new(
                current_state.state_number + 1,
                next_entropy,
                operation,
                device_info.clone(),
            )
            .with_encapsulated_entropy(vec![])
            .with_prev_state_hash(current_state.hash.clone())
            .with_sparse_index(sparse_index);
            // Remove forward_commitment as PreCommitment type is required

            let mut next_state = State::new(state_params);
            let computed_hash = next_state.compute_hash().unwrap();
            next_state.hash = computed_hash;

            fork.push(next_state.clone());
            current_state = next_state;
        }

        fork_chains.push(fork);
    }

    // Benchmark fork resolution performance
    group.bench_function("fork_resolution", |b| {
        b.iter(|| {
            // Simulate distributed consensus by verifying all forks and selecting the most valid
            let mut fork_validities = Vec::with_capacity(fork_chains.len());

            for fork in &fork_chains {
                let mut valid_transitions = 0;

                for i in 1..fork.len() {
                    if transition::verify_transition_integrity(
                        &fork[i - 1],
                        &fork[i],
                        &fork[i].operation,
                    )
                    .unwrap()
                    {
                        valid_transitions += 1;
                    }
                }

                fork_validities.push((valid_transitions, fork.len()));
            }

            // Return most valid fork based on verification ratio
            black_box(
                fork_validities
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| {
                        let ratio_a = a.0 as f64 / a.1 as f64;
                        let ratio_b = b.0 as f64 / b.1 as f64;
                        ratio_a.partial_cmp(&ratio_b).unwrap()
                    })
                    .map(|(idx, _)| idx)
                    .unwrap(),
            )
        })
    });

    group.finish();
}
/// Generate a chain of states for verification benchmarking
fn generate_verification_chain(length: u64) -> Vec<State> {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;

    let mut states = Vec::with_capacity(length as usize + 1);
    states.push(genesis.clone());

    let mut current_state = genesis;

    for i in 0..length {
        let operation = Operation::Generic {
            operation_type: format!("op_{}", i),
            data: vec![i as u8 % 255; 4],
            message: format!("Operation message {}", i),
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

        let state_params = StateParams::new(i + 1, next_entropy, operation, device_info.clone())
            .with_encapsulated_entropy(Vec::new())
            .with_prev_state_hash(current_state.hash().unwrap())
            .with_sparse_index(sparse_index);

        let mut next_state = State::new(state_params);
        let computed_hash = next_state.compute_hash().unwrap();
        next_state.hash = computed_hash;

        states.push(next_state.clone());
        current_state = next_state;
    }

    states
}

criterion_group! {
    name = benches;
    config = bench::configure_criterion("concurrent_verification")();
    targets = concurrent_verification_benchmark, distributed_verification_benchmark
}
criterion_main!(benches);
