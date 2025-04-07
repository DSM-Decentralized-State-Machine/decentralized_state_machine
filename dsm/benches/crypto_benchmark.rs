// DSM Cryptographic Primitives Benchmark
//
// This benchmark suite provides quantitative assessment of the core cryptographic
// operations that underpin DSM's security guarantees:
// 1. Blake3 hash computation - foundation of hash chain integrity
// 2. Entropy generation - essential for deterministic state evolution
// 3. Precommitment verification - enables quantum-resistant security model

use criterion::{criterion_group, criterion_main, Criterion};
use dsm::core::state_machine::{self, generate_transition_entropy};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};

/// Create a properly initialized genesis state for benchmarking
fn create_benchmark_genesis() -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info);
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;
    genesis
}

/// Benchmark core cryptographic operations with precise statistical analysis
fn crypto_operations_benchmark(c: &mut Criterion) {
    // Initialize DSM subsystems
    dsm::initialize();

    let mut group = c.benchmark_group("Cryptographic Primitives");

    // Configure benchmark parameters for statistical significance
    group.sample_size(20); // Balance between iteration count and variance analysis

    // 1. Blake3 hash computation - critical for hash chain integrity
    group.bench_function("blake3_hash_1kb", |b| {
        let data = vec![0u8; 1024]; // 1KB of data
        b.iter(|| blake3::hash(&data));
    });

    // 2. Deterministic entropy generation - foundation for state evolution
    group.bench_function("deterministic_entropy_generation", |b| {
        let current_state = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "Cryptographic benchmark operation".to_string(),
        };

        b.iter(|| generate_transition_entropy(&current_state, &op).unwrap());
    });

    // 3. Precommitment generation - critical for random walk verification
    group.bench_function("precommitment_generation", |b| {
        let mut state_machine = state_machine::StateMachine::new();
        state_machine.set_state(create_benchmark_genesis());

        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "Cryptographic benchmark operation".to_string(),
        };

        b.iter(|| state_machine.generate_precommitment(&op).unwrap());
    });

    group.finish();
}

// Register benchmark group with carefully calibrated sampling parameters
criterion_group!(
    name = crypto_benchmarks;
    config = Criterion::default().sample_size(20);
    targets = crypto_operations_benchmark
);

// Main entry point follows Criterion's canonical registration pattern
criterion_main!(crypto_benchmarks);
