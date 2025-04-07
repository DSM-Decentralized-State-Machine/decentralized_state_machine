// Path: /Users/cryptskii/Desktop/claude_workspace/self_evolving_cryptographic_identification/dsm/benches/performance_analysis.rs

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// Define the benchmark groups
criterion_group!(
    crypto_benchmarks,
    crypto_operations_benchmark,
    state_transition_benchmark,
    operation_complexity_benchmark
);
use dsm::core::state_machine::{self, generate_transition_entropy, transition};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State, StateParams};
// (Removed unresolved import)
use std::time::{Duration, Instant};

/// Create a properly initialized genesis state for benchmarking
fn create_benchmark_genesis() -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info);
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;
    genesis
}

/// Benchmark hash chain validation throughput
#[allow(dead_code)]
fn hash_chain_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash Chain Throughput");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(10));

    // Test different chain lengths to analyze scaling properties
    for chain_length in [10, 100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(*chain_length as u64));

        group.bench_with_input(
            BenchmarkId::new("chain_validation", chain_length),
            chain_length,
            |b, &n| {
                // Generate a chain of states of length n
                let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
                let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
                let computed_hash = genesis.compute_hash().unwrap();
                genesis.hash = computed_hash;

                let mut states = vec![genesis.clone()];
                let mut current_state = genesis;

                for i in 0..n {
                    let operation = Operation::Generic {
                        operation_type: format!("op_{}", i),
                        data: vec![i as u8; 4],
                        message: format!("Operation {}", i),
                    };

                    let next_entropy =
                        generate_transition_entropy(&current_state, &operation).unwrap();

                    let indices = State::calculate_sparse_indices(i + 1).unwrap();
                    let sparse_index = SparseIndex::new(indices);

                    let state_params =
                        StateParams::new(i + 1, next_entropy, operation, device_info.clone())
                            .with_prev_state_hash(current_state.hash().unwrap())
                            .with_sparse_index(sparse_index);

                    let mut next_state = State::new(state_params);
                    let computed_hash = next_state.compute_hash().unwrap();
                    next_state.hash = computed_hash;

                    states.push(next_state.clone());
                    current_state = next_state;
                }

                // Benchmark the entire chain validation
                b.iter(|| {
                    // Create a temporary copy for validation
                    let tmp_states = states.clone();

                    let mut verified = true;
                    for i in 1..tmp_states.len() {
                        verified = verified
                            && transition::verify_transition_integrity(
                                &tmp_states[i - 1],
                                &tmp_states[i],
                                &tmp_states[i].operation,
                            )
                            .unwrap();
                    }
                    verified
                });
            },
        );
    }

    group.finish();
}
/// Benchmark cryptographic operations
fn crypto_operations_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Cryptographic Operations");
    group.sample_size(100);

    // Benchmark Blake3 hash computation - critical for chain integrity
    group.bench_function("blake3_hash_computation", |b| {
        let data = vec![0u8; 1024]; // 1KB of data
        b.iter(|| {
            let hash = blake3::hash(&data);
            hash
        });
    });

    // Benchmark deterministic entropy generation - foundation for state evolution
    group.bench_function("deterministic_entropy_generation", |b| {
        let current_state = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: format!("Operation {}", 0),
        };
        b.iter(|| {
            let entropy = state_machine::generate_transition_entropy(&current_state, &op).unwrap();
            entropy
        });
    });

    // Benchmark precommitment generation - critical for random walk verification
    group.bench_function("precommitment_generation", |b| {
        let mut state_machine = state_machine::StateMachine::new();
        state_machine.set_state(create_benchmark_genesis());

        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: format!("Operation {}", 0),
        };
        b.iter(|| {
            let precommitment = state_machine.generate_precommitment(&op).unwrap();
            precommitment
        });
    });

    group.finish();
}

/// Benchmark state transition performance
fn state_transition_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("State Transition Performance");
    group.sample_size(100);

    // Benchmark transition creation performance
    group.bench_function("transition_creation", |b| {
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: format!("Operation {}", 0),
        };

        b.iter(|| {
            let entropy = state_machine::generate_transition_entropy(&genesis, &op).unwrap();
            transition::create_transition(&genesis, op.clone(), &entropy).unwrap()
        });
    });

    // Benchmark transition application performance
    group.bench_function("transition_application", |b| {
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "Operation 0".into(),
        };
        let entropy = state_machine::generate_transition_entropy(&genesis, &op).unwrap();
        let transition = transition::create_transition(&genesis, op.clone(), &entropy).unwrap();

        b.iter(|| transition::apply_transition(&genesis, &transition.operation, &entropy).unwrap());
    });

    // Benchmark full transition cycle
    group.bench_function("complete_transition_cycle", |b| {
        let mut state_machine = state_machine::StateMachine::new();
        state_machine.set_state(create_benchmark_genesis());

        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "benchmark message".into(),
        };
        b.iter(|| {
            let mut local_machine = state_machine.clone();
            local_machine.execute_transition(op.clone()).unwrap()
        });
    });

    group.finish();
}

/// Measure scalability with increasing operation complexity
fn operation_complexity_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Operation Complexity Scaling");
    group.sample_size(50);

    // Test data sizes from 1KB to 1MB
    for &size_kb in &[1, 10, 100, 1000] {
        let data_size = size_kb * 1024;
        group.throughput(Throughput::Bytes(data_size as u64));

        group.bench_with_input(
            BenchmarkId::new("operation_data_size", size_kb),
            &data_size,
            |b, &size| {
                let mut state_machine = state_machine::StateMachine::new();
                state_machine.set_state(create_benchmark_genesis());

                // Create operation with specified data size
                let data = vec![0u8; size];
                let op = Operation::Generic {
                    operation_type: format!("benchmark_op_{}_kb", size / 1024),
                    data,
                    message: format!("Operation with {}KB of data", size_kb),
                };

                b.iter(|| {
                    let mut local_machine = state_machine.clone();
                    local_machine.execute_transition(op.clone()).unwrap()
                });
            },
        );
    }
    group.finish();
}

/// Manual performance analysis without Criterion for more detailed metrics
#[allow(dead_code)]
fn manual_performance_analysis() {
    println!("\n=== Manual Performance Analysis ===\n");

    // Initialize DSM
    dsm::initialize();

    // Analyze state chain verification efficiency
    let chain_lengths = [100, 1000, 10000];
    println!("Hash Chain Verification Performance:");
    println!("Chain Length | Verification Time (ms) | Verifications/s");
    println!("------------------------------------------------------");

    for &length in &chain_lengths {
        // Build chain of specified length
        let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
        let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
        let computed_hash = genesis.compute_hash().unwrap();
        genesis.hash = computed_hash;

        let mut states = vec![genesis.clone()];
        let mut current_state = genesis;

        for i in 0..length {
            let operation = Operation::Generic {
                operation_type: format!("op_{}", i),
                data: vec![i as u8 % 255; 64], // 64-byte data
                message: format!("Operation {}", i),
            };

            let next_entropy = generate_transition_entropy(&current_state, &operation).unwrap();
            let indices = State::calculate_sparse_indices(i + 1).unwrap();
            let sparse_index = SparseIndex::new(indices);

            let state_params =
                StateParams::new(i + 1, next_entropy, operation, device_info.clone())
                    .with_encapsulated_entropy(vec![])
                    .with_prev_state_hash(current_state.hash().unwrap())
                    .with_sparse_index(sparse_index);
            let mut next_state = State::new(state_params);
            let computed_hash = next_state.compute_hash().unwrap();
            next_state.hash = computed_hash;

            states.push(next_state.clone());
            current_state = next_state;
        }

        // Measure verification time
        let iterations = if length < 1000 { 10 } else { 3 };
        let mut total_duration = Duration::from_secs(0);

        for _ in 0..iterations {
            let start = Instant::now();

            for i in 1..states.len() {
                transition::verify_transition_integrity(
                    &states[i - 1],
                    &states[i],
                    &states[i].operation,
                )
                .unwrap();
            }

            total_duration += start.elapsed();
        }

        let avg_duration = total_duration / iterations as u32;
        let ms_duration = avg_duration.as_millis();
        let verifications_per_sec = (length as f64 * 1000.0) / ms_duration as f64;

        println!(
            "{:11} | {:21} | {:.2}",
            length, ms_duration, verifications_per_sec
        );
    }

    println!("\nState Transition Performance:");
    let iterations = 100;
    let genesis = create_benchmark_genesis();
    let op = Operation::Generic {
        operation_type: "benchmark_op".to_string(),
        data: vec![9, 10, 11, 12],
        message: format!("Operation {}", 2),
    };

    // Measure entropy generation
    let mut entropy_total = Duration::from_secs(0);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = state_machine::generate_transition_entropy(&genesis, &op).unwrap();
        entropy_total += start.elapsed();
    }
    let entropy = state_machine::generate_transition_entropy(&genesis, &op).unwrap();
    let entropy_avg = entropy_total.as_micros() / iterations;
    println!("Entropy Generation| {}", entropy_avg);

    // Measure transition creation
    let mut transition_total = Duration::from_secs(0);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = transition::create_transition(&genesis, op.clone(), &entropy).unwrap();
        transition_total += start.elapsed();
    }
    let transition_avg = transition_total.as_micros() / iterations;
    println!("Create Transition| {}", transition_avg);

    // Measure transition application
    let mut apply_total = Duration::from_secs(0);
    let next_state = transition::create_transition(&genesis, op.clone(), &entropy).unwrap();

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = transition::apply_transition(&genesis, &next_state.operation, &entropy).unwrap();
        apply_total += start.elapsed();
    }
    let apply_avg = apply_total.as_micros() / iterations;
    println!("Apply Transition| {}", apply_avg);
    // Measure full cycle
    let mut full_cycle_total = Duration::from_secs(0);
    let mut state_machine = state_machine::StateMachine::new();
    state_machine.set_state(create_benchmark_genesis());

    for _ in 0..iterations {
        let mut local_machine = state_machine.clone();
        let start = Instant::now();
        let _ = local_machine.execute_transition(op.clone()).unwrap();
        full_cycle_total += start.elapsed();
    }
    let full_cycle_avg = full_cycle_total.as_micros() / iterations;
    println!("Complete Cycle  | {}", full_cycle_avg);

    println!("\n=== End Performance Analysis ===\n");
}

// Main entry point without function body
criterion_main!(crypto_benchmarks);
