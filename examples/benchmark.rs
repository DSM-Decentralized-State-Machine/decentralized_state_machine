// Direct DSM performance benchmarking utility
// This implements precise measurements of core cryptographic primitives and state transitions
// without relying on external benchmarking frameworks

use dsm::core::state_machine::{self, generate_transition_entropy, transition};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};
use std::time::{Duration, Instant};

// Configuration parameters for benchmark precision
const WARMUP_ITERATIONS: usize = 10;
const BENCH_ITERATIONS: usize = 1000;
const CHAIN_LENGTH: usize = 100; // Length for hash chain verification tests

/// Create a properly initialized genesis state for benchmarking
fn create_benchmark_genesis() -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info);
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;
    genesis
}

/// Run a benchmark with proper warmup and measurement phases
fn run_benchmark<F, R>(name: &str, iterations: usize, f: F) -> (Duration, R)
where
    F: Fn() -> R,
    R: Clone,
{
    // Warmup phase to ensure instruction cache is primed and any JIT optimizations are applied
    let mut result = None;
    for _ in 0..WARMUP_ITERATIONS {
        result = Some(f());
    }

    // Measurement phase with precise timing
    let start = Instant::now();
    for _ in 0..iterations {
        result = Some(f());
    }
    let total = start.elapsed();

    // Calculate per-operation time
    let per_op = total / iterations as u32;
    println!(
        "{}: {:?} per operation ({} iterations)",
        name, per_op, iterations
    );

    (per_op, result.unwrap())
}

/// Generate a chain of states for hash chain verification benchmarks
fn generate_test_chain(length: usize) -> Vec<State> {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info.clone());
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;

    let mut states = vec![genesis.clone()];
    let mut current_state = genesis;

    for i in 0..length {
        let operation = Operation::Generic {
            operation_type: format!("op_{}", i),
            data: vec![i as u8 % 255; 4], // 4-byte data
            message: format!("Operation {} at state {}", i, current_state.state_number),
        };

        let next_entropy = generate_transition_entropy(&current_state, &operation).unwrap();

        let transition =
            transition::create_transition(&current_state, operation, &next_entropy).unwrap();
        let next_state = transition::apply_transition(&transition, &current_state).unwrap();

        states.push(next_state.clone());
        current_state = next_state;
    }

    states
}

fn main() {
    println!("\n=== DSM Performance Benchmarks ===\n");

    // Initialize DSM
    dsm::initialize();

    // ==== Core Cryptographic Primitives ====
    println!("Core Cryptographic Primitives:");

    // 1. Blake3 hashing (foundation of hash chain integrity)
    let data_1kb = vec![0u8; 1024];
    run_benchmark("Blake3 Hash (1KB)", BENCH_ITERATIONS, || {
        blake3::hash(&data_1kb)
    });

    // 2. Entropy generation (deterministic state evolution)
    let genesis = create_benchmark_genesis();
    let op = Operation::Generic {
        operation_type: "benchmark_op".to_string(),
        data: vec![1, 2, 3, 4],
        message: "Benchmark operation".to_string(),
    };

    run_benchmark("Entropy Generation", BENCH_ITERATIONS, || {
        generate_transition_entropy(&genesis, &op).unwrap()
    });

    // ==== State Transition Performance ====
    println!("\nState Transition Performance:");

    // 3. Transition creation
    run_benchmark("Transition Creation", BENCH_ITERATIONS / 2, || {
        let entropy = generate_transition_entropy(&genesis, &op).unwrap();
        transition::create_transition(&genesis, op.clone(), &entropy).unwrap()
    });

    // 4. Transition application
    let entropy = generate_transition_entropy(&genesis, &op).unwrap();
    let transition_obj = transition::create_transition(&genesis, op.clone(), &entropy).unwrap();

    run_benchmark("Transition Application", BENCH_ITERATIONS / 2, || {
        transition::apply_transition(&transition_obj, &genesis).unwrap()
    });

    // 5. Full transition cycle
    run_benchmark("Complete Transition Cycle", BENCH_ITERATIONS / 10, || {
        let mut state_machine = state_machine::StateMachine::new();
        state_machine.set_state(genesis.clone());
        state_machine.execute_transition(op.clone()).unwrap()
    });

    // ==== Hash Chain Verification ====
    println!("\nHash Chain Verification Performance:");

    // 6. Generate test chain
    println!("Generating test chain of {} states...", CHAIN_LENGTH);
    let states = generate_test_chain(CHAIN_LENGTH);
    println!("Chain generation completed, length: {}", states.len());

    // 7. Individual state transition verification
    run_benchmark(
        "Single Transition Verification",
        BENCH_ITERATIONS / 2,
        || {
            let idx = CHAIN_LENGTH / 2; // Check middle of chain
            transition::verify_transition_integrity(
                &states[idx - 1],
                &states[idx],
                &states[idx].operation,
            )
            .unwrap()
        },
    );

    // 8. Complete chain verification
    run_benchmark("Full Chain Verification", 5, || {
        let mut verified = true;
        for i in 1..states.len() {
            verified = verified
                && transition::verify_transition_integrity(
                    &states[i - 1],
                    &states[i],
                    &states[i].operation,
                )
                .unwrap();
        }
        verified
    });

    println!("\n=== End Performance Analysis ===\n");
}
