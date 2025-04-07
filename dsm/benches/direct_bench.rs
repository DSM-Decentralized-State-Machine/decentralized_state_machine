// Direct benchmark implementation that bypasses Criterion's macro system
// This ensures direct execution flow without relying on complex registration pathways

use dsm::core::state_machine::{self, generate_transition_entropy, transition};
use dsm::types::operations::Operation;
use dsm::types::state_types::{DeviceInfo, State};
use std::time::{Duration, Instant};

// Number of iterations for each benchmark to ensure statistical significance
const ITERATIONS: usize = 100;

/// Create a properly initialized genesis state for benchmarking
fn create_benchmark_genesis() -> State {
    let device_info = DeviceInfo::new("benchmark_device", vec![1, 2, 3, 4]);
    let mut genesis = State::new_genesis(vec![5, 6, 7, 8], device_info);
    let computed_hash = genesis.compute_hash().unwrap();
    genesis.hash = computed_hash;
    genesis
}

/// Run a benchmark with proper warmup and measurement
fn run_benchmark<F>(name: &str, iterations: usize, f: F) -> Duration
where
    F: Fn() -> (),
{
    // Warmup phase to ensure instruction cache is primed
    for _ in 0..5 {
        f();
    }

    // Actual measurement phase
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let total = start.elapsed();

    // Calculate per-operation time
    let per_op = total / iterations as u32;
    println!(
        "{}: {:?} per operation ({} iterations)",
        name, per_op, iterations
    );

    per_op
}

fn main() {
    println!("\n=== DSM Performance Benchmarks ===\n");

    // Initialize DSM
    dsm::initialize();

    // Benchmark Blake3 hashing (foundation of hash chain integrity)
    let data_1kb = vec![0u8; 1024];
    run_benchmark("Blake3 Hash (1KB)", ITERATIONS, || {
        blake3::hash(&data_1kb);
    });

    // Benchmark entropy generation (core of state evolution)
    let genesis = create_benchmark_genesis();
    let op = Operation::Generic {
        operation_type: "benchmark_op".to_string(),
        data: vec![1, 2, 3, 4],
        message: "Direct benchmark operation".to_string(),
    };

    run_benchmark("Entropy Generation", ITERATIONS, || {
        let _ = generate_transition_entropy(&genesis, &op).unwrap();
    });

    // Benchmark transition creation
    run_benchmark("Transition Creation", ITERATIONS, || {
        let entropy = generate_transition_entropy(&genesis, &op).unwrap();
        let _ = transition::create_transition(&genesis, op.clone(), &entropy).unwrap();
    });

    // Benchmark transition application
    let entropy = generate_transition_entropy(&genesis, &op).unwrap();

    run_benchmark("Transition Application", ITERATIONS, || {
        let _ = transition::apply_transition(&genesis, &op, &entropy).unwrap();
    });

    // Benchmark full transition cycle
    run_benchmark("Complete Transition Cycle", ITERATIONS / 2, || {
        let mut state_machine = state_machine::StateMachine::new();
        state_machine.set_state(genesis.clone());
        let _ = state_machine.execute_transition(op.clone()).unwrap();
    });

    // Benchmark state verification
    let new_state = transition::apply_transition(&genesis, &op, &entropy).unwrap();

    run_benchmark("State Verification", ITERATIONS, || {
        let _ = transition::verify_transition_integrity(&genesis, &new_state, &op).unwrap();
    });

    println!("\n=== End Performance Analysis ===\n");
}
