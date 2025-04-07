// DSM State Transition Performance Benchmark
//
// This benchmark suite quantifies the performance characteristics of DSM's
// state transition operations, providing empirical metrics for:
// 1. Transition creation - measures cryptographic binding construction
// 2. Transition application - evaluates state evolution efficiency
// 3. Complete transition cycle - assesses full execution pathway
// 4. Verification throughput - analyzes security validation latency

use criterion::{criterion_group, criterion_main, Criterion};
use dsm::core::state_machine::{self, generate_transition_entropy, transition};
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

/// Benchmark state transition performance with detailed metrics
fn state_transition_benchmark(c: &mut Criterion) {
    // Initialize DSM subsystems
    dsm::initialize();

    let mut group = c.benchmark_group("State Transitions");

    // Configure benchmark parameters for statistical significance
    group.sample_size(20);

    // 1. Benchmark transition creation performance
    group.bench_function("transition_creation", |b| {
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "benchmark message".to_string(),
        };

        b.iter(|| {
            let entropy = generate_transition_entropy(&genesis, &op).unwrap();
            transition::create_transition(&genesis, op.clone(), &entropy).unwrap()
        });
    });

    // 2. Benchmark transition application performance
    group.bench_function("transition_application", |b| {
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "benchmark message".to_string(),
        };

        let entropy = generate_transition_entropy(&genesis, &op).unwrap();

        b.iter(|| transition::apply_transition(&genesis, &op, &entropy).unwrap());
    });

    // 3. Benchmark full transition cycle
    group.bench_function("complete_transition_cycle", |b| {
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "complete transition test".to_string(),
        };

        b.iter(|| {
            // Create new state machine for each iteration to ensure isolation
            let mut state_machine = state_machine::StateMachine::new();
            state_machine.set_state(genesis.clone());
            state_machine.execute_transition(op.clone()).unwrap()
        });
    });

    // 4. Benchmark state verification
    group.bench_function("state_verification", |b| {
        // Setup: Create two sequential states
        let genesis = create_benchmark_genesis();
        let op = Operation::Generic {
            operation_type: "benchmark_op".to_string(),
            data: vec![9, 10, 11, 12],
            message: "verification test".to_string(),
        };

        let entropy = generate_transition_entropy(&genesis, &op).unwrap();
        let state1 = transition::apply_transition(&genesis, &op, &entropy).unwrap();

        b.iter(|| transition::verify_transition_integrity(&genesis, &state1, &op).unwrap());
    });

    group.finish();
}

// Register benchmark group with appropriate sampling parameters
criterion_group!(
    name = transition_benchmarks;
    config = Criterion::default().sample_size(20);
    targets = state_transition_benchmark
);

// Main entry point follows idiomatic Criterion registration pattern
criterion_main!(transition_benchmarks);
