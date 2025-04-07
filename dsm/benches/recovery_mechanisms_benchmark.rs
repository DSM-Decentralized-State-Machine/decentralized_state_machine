use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dsm::core::state_machine::transition;
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};
use std::time::Duration;

mod bench;

/// Benchmark DSM recovery mechanisms for various failure scenarios.
///
/// This benchmark suite evaluates the performance of DSM recovery mechanisms
/// across different failure scenarios and chain lengths, providing insights
/// into recovery time expectations, resource requirements, and scaling properties.
/// The results inform fault tolerance and recovery design decisions.
fn recovery_mechanisms_benchmark(c: &mut Criterion) {
    // Initialize DSM runtime environment
    dsm::initialize();

    let mut group = c.benchmark_group("Recovery Mechanisms");
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(10));

    // Benchmark chain lengths to test recovery performance at scale
    let chain_lengths = [10, 50, 100, 250];

    // Generate test chains for different lengths
    let test_chains = chain_lengths
        .iter()
        .map(|&length| (length, generate_test_chain(length)))
        .collect::<Vec<_>>();

    // Benchmark state reconstruction from partial chain
    for (length, chain) in &test_chains {
        // Determine sparse indices to keep (simulate fragmented chain)
        let sparse_indices = calculate_sparse_indices_for_chain(*length);
        let sparse_states: Vec<State> = chain
            .iter()
            .enumerate()
            .filter(|(idx, _)| sparse_indices.contains(idx))
            .map(|(_, state)| state.clone())
            .collect();

        // Keep approximately 20% of the chain to simulate partial data
        let retained_states = sparse_states;

        group.bench_with_input(
            BenchmarkId::new("state_reconstruction", length),
            length,
            |b, _| {
                b.iter(|| {
                    black_box(state_rebuild::reconstruct_missing_states(
                        black_box(retained_states.clone()),
                        black_box(*length as u64),
                    ))
                })
            },
        );
    }

    // Benchmark recovery from corrupted state
    for (length, chain) in &test_chains {
        // Create a chain with a corrupted state in the middle
        let mut corrupted_chain = chain.clone();
        let corrupt_idx = length / 2;

        // Corrupt the state (modify a hash that will break verification)
        let mut corrupted_state = corrupted_chain[corrupt_idx].clone();
        corrupted_state.hash = vec![0, 1, 2, 3];
        corrupted_chain[corrupt_idx] = corrupted_state;

        group.bench_with_input(
            BenchmarkId::new("corrupted_state_recovery", length),
            length,
            |b, _| {
                b.iter(|| {
                    black_box(mechanisms::repair_corrupted_chain(
                        black_box(corrupted_chain.clone()),
                        black_box(corrupt_idx),
                    ))
                })
            },
        );
    }

    // Benchmark entropy recovery (for cases where entropy might be lost)
    for (length, chain) in &test_chains {
        // Create a chain with missing entropy
        let mut missing_entropy_chain = chain.clone();
        let missing_idx = length / 2;

        // Remove entropy from a state
        let mut entropy_missing_state = missing_entropy_chain[missing_idx].clone();
        entropy_missing_state.entropy = vec![];
        missing_entropy_chain[missing_idx] = entropy_missing_state;

        group.bench_with_input(
            BenchmarkId::new("entropy_recovery", length),
            length,
            |b, _| {
                b.iter(|| {
                    black_box(mechanisms::recover_missing_entropy(
                        black_box(missing_entropy_chain.clone()),
                        black_box(missing_idx),
                    ))
                })
            },
        );
    }

    // Benchmark divergent chain reconciliation
    for (length, primary_chain) in &test_chains {
        // Create a divergent chain that splits from the main chain
        let fork_point = length / 3;
        let fork_length = *length - fork_point;

        // Generate a forked chain that diverges at fork_point
        let mut forked_chain = primary_chain[0..fork_point].to_vec();
        let mut fork_state = primary_chain[fork_point - 1].clone();

        for i in 0..fork_length {
            let operation = Operation::Generic {
                operation_type: format!("fork_op_{}", i),
                data: vec![(i % 255) as u8; 8],
                message: "Benchmark forked operation".to_string(),
            };

            let op_serialized = bincode::serialize(&operation).unwrap();
            let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                &fork_state.entropy,
                &op_serialized,
                fork_state.state_number + 1,
            )
            .as_bytes()
            .to_vec();

            let device_info = DeviceInfo::new("fork_device", vec![1, 2, 3, 4]);
            let indices = State::calculate_sparse_indices(fork_state.state_number + 1).unwrap();
            let sparse_index = SparseIndex::new(indices);

            let state_params = StateParams::new(
                fork_state.state_number + 1,
                next_entropy.clone(),
                operation,
                device_info,
            )
            .with_prev_state_hash(fork_state.hash().unwrap())
            .with_sparse_index(sparse_index);

            let mut next_state = State::new(state_params);
            let computed_hash = next_state.compute_hash().unwrap();
            next_state.hash = computed_hash;

            forked_chain.push(next_state.clone());
            fork_state = next_state;
        }

        group.bench_with_input(
            BenchmarkId::new("fork_reconciliation", length),
            length,
            |b, _| {
                b.iter(|| {
                    black_box(mechanisms::reconcile_divergent_chains(
                        black_box(primary_chain.clone()),
                        black_box(forked_chain.clone()),
                    ))
                })
            },
        );
    }

    // Benchmark full chain recovery from backup sources
    for (length, chain) in &test_chains {
        // Simulate backup data sources with varying completeness
        let backup1 = chain[0..(length * 3 / 4)].to_vec(); // 75% complete
        let backup2 = chain[0..(length / 2)].to_vec(); // 50% complete

        // Create sparse backup with only specific states
        let sparse_indices = calculate_sparse_indices_for_chain(*length);
        let backup3: Vec<State> = chain
            .iter()
            .enumerate()
            .filter(|(idx, _)| sparse_indices.contains(idx))
            .map(|(_, state)| state.clone())
            .collect();

        let backups = vec![backup1, backup2, backup3];

        group.bench_with_input(
            BenchmarkId::new("multi_source_recovery", length),
            length,
            |b, _| {
                b.iter(|| {
                    black_box(mechanisms::recover_from_multiple_sources(
                        black_box(backups.clone()),
                        black_box(*length as u64),
                    ))
                })
            },
        );
    }

    group.finish();
}

/// Generate a test chain of specified length for benchmarking
fn generate_test_chain(length: usize) -> Vec<State> {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;

    let mut states = Vec::with_capacity(length + 1);
    states.push(genesis.clone());

    let mut current_state = genesis;

    for i in 0..length {
        let operation = Operation::Generic {
            operation_type: format!("op_{}", i),
            data: vec![(i % 255) as u8; 4],
            message: "Benchmark operation".to_string(),
        };

        let op_serialized = bincode::serialize(&operation).unwrap();
        let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
            &current_state.entropy,
            &op_serialized,
            current_state.state_number + 1,
        )
        .as_bytes()
        .to_vec();

        let indices = State::calculate_sparse_indices(i as u64 + 1).unwrap();
        let sparse_index = SparseIndex::new(indices);

        let state_params = StateParams::new(
            i as u64 + 1,
            next_entropy.clone(),
            operation,
            device_info.clone(),
        )
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

/// Calculate sparse indices to simulate a partially available chain
fn calculate_sparse_indices_for_chain(length: usize) -> Vec<usize> {
    let mut indices = Vec::new();

    // Always include genesis
    indices.push(0);

    // Include checkpoints at powers of 2
    let mut power = 1;
    while power <= length {
        indices.push(power);
        power *= 2;
    }

    // Include a few random-ish states
    for i in 1..=5 {
        let idx = (length * i) / 6;
        if idx > 0 && idx < length && !indices.contains(&idx) {
            indices.push(idx);
        }
    }

    indices.sort();
    indices
}

/// Namespace placeholder for mechanisms module functions
mod mechanisms {
    use super::*;

    pub fn repair_corrupted_chain(chain: Vec<State>, corrupt_idx: usize) -> Result<Vec<State>, ()> {
        // In a real implementation, this would repair the corrupted state
        // by using the preceding and following states to reconstruct it

        let mut repaired_chain = chain.clone();
        if corrupt_idx > 0 && corrupt_idx < chain.len() - 1 {
            let prev_state = &chain[corrupt_idx - 1];
            let next_state = &chain[corrupt_idx + 1];

            // In a real implementation, we would regenerate the corrupted state
            // For benchmark purposes, we'll simulate the computational work

            // Hash the previous state to warm up caches
            let _ = prev_state.compute_hash();

            // Verify the next state's relationship to previous
            let _ = transition::verify_transition_integrity(
                prev_state,
                next_state,
                &next_state.operation,
            );

            // Simulate correcting the corrupted state
            repaired_chain[corrupt_idx] = chain[corrupt_idx - 1].clone();
        }

        Ok(repaired_chain)
    }

    pub fn recover_missing_entropy(
        chain: Vec<State>,
        missing_idx: usize,
    ) -> Result<Vec<State>, ()> {
        // In a real implementation, this would reconstruct missing entropy
        // using cryptographic derivation from neighboring states

        let mut repaired_chain = chain.clone();
        if missing_idx > 0 && missing_idx < chain.len() {
            let prev_state = &chain[missing_idx - 1];

            // Reconstruct the entropy (simulated for benchmark)
            let operation = &chain[missing_idx].operation;
            let op_serialized = bincode::serialize(operation).unwrap();

            let reconstructed_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                &prev_state.entropy,
                &op_serialized,
                prev_state.state_number + 1,
            )
            .as_bytes()
            .to_vec();

            // Update the state with recovered entropy
            let mut fixed_state = chain[missing_idx].clone();
            fixed_state.entropy = reconstructed_entropy;
            repaired_chain[missing_idx] = fixed_state;
        }

        Ok(repaired_chain)
    }

    pub fn reconcile_divergent_chains(
        primary: Vec<State>,
        fork: Vec<State>,
    ) -> Result<Vec<State>, ()> {
        // In a real implementation, this would merge two divergent chains
        // according to a consensus algorithm

        // Find the fork point
        let mut _fork_point = 0;
        for (i, (p_state, f_state)) in primary.iter().zip(fork.iter()).enumerate() {
            let p_hash = p_state.hash().unwrap_or_default();
            let f_hash = f_state.hash().unwrap_or_default();
            if p_hash != f_hash {
                _fork_point = i;
                break;
            }
        }

        // For benchmark purposes, simulate the work of evaluating both chains
        let primary_valid = validate_chain(&primary);
        let fork_valid = validate_chain(&fork);

        // Simulate choosing the longer valid chain
        if !primary_valid && fork_valid {
            Ok(fork)
        } else {
            Ok(primary)
        }
    }

    pub fn recover_from_multiple_sources(
        backups: Vec<Vec<State>>,
        target_length: u64,
    ) -> Result<Vec<State>, ()> {
        // Combine multiple partial backups to reconstruct a complete chain

        // Find the most complete chain to use as base
        let base_chain = backups
            .iter()
            .max_by_key(|chain| chain.len())
            .unwrap()
            .clone();

        // Identify missing states
        let mut missing_indices = Vec::new();
        for i in 0..=target_length {
            if !base_chain.iter().any(|state| state.state_number == i) {
                missing_indices.push(i);
            }
        }

        // Try to fill missing states from other backups
        let mut reconstructed_chain = base_chain.clone();

        for missing_idx in missing_indices {
            for backup in &backups {
                if let Some(state) = backup.iter().find(|s| s.state_number == missing_idx) {
                    reconstructed_chain.push(state.clone());
                    break;
                }
            }
        }

        // Sort by state number
        reconstructed_chain.sort_by_key(|state| state.state_number);

        Ok(reconstructed_chain)
    }

    // Helper to validate a chain
    fn validate_chain(chain: &[State]) -> bool {
        if chain.is_empty() {
            return false;
        }

        for i in 1..chain.len() {
            // We need to handle the result differently to avoid the comparison issue
            let result = transition::verify_transition_integrity(
                &chain[i - 1],
                &chain[i],
                &chain[i].operation,
            );

            // Check the result without direct comparison
            if result.is_err() || !result.unwrap() {
                return false;
            }
        }

        true
    }
}

/// Namespace placeholder for state_rebuild module functions
mod state_rebuild {
    use super::*;

    pub fn reconstruct_missing_states(
        sparse_states: Vec<State>,
        target_length: u64,
    ) -> Result<Vec<State>, ()> {
        // In a real implementation, this would rebuild missing states by
        // executing transitions between known sparse checkpoints

        if sparse_states.is_empty() {
            return Err(());
        }

        // Sort by state number
        let mut sorted_states = sparse_states.clone();
        sorted_states.sort_by_key(|state| state.state_number);

        let mut reconstructed_chain = Vec::new();
        reconstructed_chain.push(sorted_states[0].clone());

        // Identify gaps in the chain
        for i in 1..sorted_states.len() {
            let prev_state = &sorted_states[i - 1];
            let current_state = &sorted_states[i];

            if current_state.state_number > prev_state.state_number + 1 {
                // There's a gap to fill
                let mut rebuild_state = prev_state.clone();

                // Simulate regenerating the missing states
                for state_num in prev_state.state_number + 1..current_state.state_number {
                    // Create a synthetic operation
                    let operation = Operation::Generic {
                        operation_type: format!("rebuilt_op_{}", state_num),
                        data: vec![(state_num % 255) as u8; 4],
                        message: "Reconstructed operation".to_string(),
                    };

                    // Generate deterministic entropy
                    let op_serialized = bincode::serialize(&operation).unwrap();
                    let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                        &rebuild_state.entropy,
                        &op_serialized,
                        state_num,
                    )
                    .as_bytes()
                    .to_vec();

                    // Create the reconstructed state
                    let indices = State::calculate_sparse_indices(state_num).unwrap();
                    let sparse_index = SparseIndex::new(indices);

                    let device_info = rebuild_state.device_info.clone();

                    let state_params =
                        StateParams::new(state_num, next_entropy, operation, device_info)
                            .with_prev_state_hash(rebuild_state.hash().unwrap())
                            .with_sparse_index(sparse_index);

                    let mut next_state = State::new(state_params);
                    let computed_hash = next_state.compute_hash().unwrap();
                    next_state.hash = computed_hash;

                    reconstructed_chain.push(next_state.clone());
                    rebuild_state = next_state;
                }
            }
            reconstructed_chain.push(current_state.clone());
        }

        // Fill any remaining states to reach target_length
        if let Some(last_state) = reconstructed_chain.last().cloned() {
            let mut rebuild_state = last_state;

            for state_num in rebuild_state.state_number + 1..=target_length {
                // Create a synthetic operation
                let operation = Operation::Generic {
                    operation_type: format!("rebuilt_op_{}", state_num),
                    data: vec![(state_num % 255) as u8; 4],
                    message: "Reconstructed operation".to_string(),
                };

                // Generate deterministic entropy
                let op_serialized = bincode::serialize(&operation).unwrap();
                let next_entropy = dsm::crypto::blake3::generate_deterministic_entropy(
                    &rebuild_state.entropy,
                    &op_serialized,
                    state_num,
                )
                .as_bytes()
                .to_vec();

                // Create the reconstructed state
                let indices = State::calculate_sparse_indices(state_num).unwrap();
                let sparse_index = SparseIndex::new(indices);

                let device_info = rebuild_state.device_info.clone();

                let state_params =
                    StateParams::new(state_num, next_entropy, operation, device_info)
                        .with_prev_state_hash(rebuild_state.hash().unwrap())
                        .with_sparse_index(sparse_index);

                let mut next_state = State::new(state_params);
                let computed_hash = next_state.compute_hash().unwrap();
                next_state.hash = computed_hash;

                reconstructed_chain.push(next_state.clone());
                rebuild_state = next_state;
            }
        }

        Ok(reconstructed_chain)
    }
}

criterion_group! {
    name = recovery_benches;
    config = bench::configure_criterion("recovery_mechanisms")();
    targets = recovery_mechanisms_benchmark
}
criterion_main!(recovery_benches);
