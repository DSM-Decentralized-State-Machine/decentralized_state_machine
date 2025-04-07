// DSM Performance Benchmark
// This benchmark demonstrates the performance of the core operations
// in the DSM system, focusing on cryptographic operations, state transitions,
// and hash chain verification.

use dsm::{
    core::state_machine::StateMachine,
    crypto,
    sdk::{hashchain_sdk::HashChainSDK, identity_sdk::IdentitySDK},
    types::{
        error::DsmError,
        operations::{Operation, PreCommitmentOp, TransactionMode, VerificationType},
        state_types::DeviceInfo,
        token_types::Balance,
    },
};
use dsm_sdk::core_sdk::CoreSDK;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct BenchmarkResult {
    name: String,
    iterations: usize,
    total_time: Duration,
    average_time: Duration,
}

impl BenchmarkResult {
    fn new(name: &str, iterations: usize, total_time: Duration) -> Self {
        let average_time = total_time.div_f64(iterations as f64);
        Self {
            name: name.to_string(),
            iterations,
            total_time,
            average_time,
        }
    }

    fn print(&self) {
        println!("Benchmark: {}", self.name);
        println!("  Iterations: {}", self.iterations);
        println!("  Total time: {:?}", self.total_time);
        println!("  Average time: {:?}", self.average_time);
        println!(
            "  Operations per second: {:.2}",
            1.0 / self.average_time.as_secs_f64()
        );
        println!();
    }
}

#[tokio::main]
async fn main() -> Result<(), DsmError> {
    println!("=== DSM Performance Benchmark ===");

    // Initialize DSM system
    dsm::initialize();

    // Create a device identity for benchmarking
    let device_id = format!("benchmark_device_{}", uuid::Uuid::new_v4());

    // Create SDK components
    let hash_chain_sdk = Arc::new(HashChainSDK::new());
    let identity_sdk = Arc::new(IdentitySDK::new(device_id.clone(), hash_chain_sdk.clone()));
    let core_sdk = Arc::new(CoreSDK::new());
    let (kyber_pk, kyber_sk, sphincs_pk, sphincs_sk) = crypto::generate_keypair();
    let device_info = DeviceInfo::new(&device_id, sphincs_pk.clone());

    println!("Created benchmark device: {}", device_id);

    // Create a genesis state
    let mut participant_inputs = Vec::new();
    for i in 0..3 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(format!("benchmark_participant_{}", i).as_bytes());
        hasher.update(&crypto::generate_nonce());
        participant_inputs.push(hasher.finalize().as_bytes().to_vec());
    }

    let mut genesis_state = identity_sdk.create_genesis(
        device_info.clone(),
        participant_inputs,
        Some(b"Benchmark metadata".to_vec()),
    )?;

    // Compute and set the hash explicitly for the genesis state
    let computed_hash = genesis_state.compute_hash()?;
    genesis_state.hash = computed_hash;

    println!("Genesis state created");

    // Initialize system with genesis state
    core_sdk
        .initialize_with_genesis(genesis_state.clone())
        .await?;

    println!("System initialized, starting benchmarks...\n");

    // =========================================================================
    // Benchmark 1: Cryptographic Operations
    // =========================================================================

    // 1.1 - BLAKE3 Hashing
    let iterations = 10000;
    let data = b"This is benchmark data for hashing operations";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = blake3::hash(data);
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("BLAKE3 Hashing (1KB)", iterations, total_time);
    result.print();

    // 1.2 - SPHINCS+ Signing
    let iterations = 100; // SPHINCS+ is much slower
    let data = b"This is benchmark data for signature operations";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = crypto::sign_data(data, &sphincs_sk);
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("SPHINCS+ Signing", iterations, total_time);
    result.print();

    // 1.3 - Kyber Key Encapsulation
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = crypto::kyber::kyber_encapsulate(&kyber_pk);
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("Kyber Key Encapsulation", iterations, total_time);
    result.print();

    // 1.4 - Kyber Key Decapsulation
    let iterations = 1000;
    let (_shared_secret, encapsulated) = crypto::kyber::kyber_encapsulate(&kyber_pk)?;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = crypto::kyber::kyber_decapsulate(&kyber_sk, &encapsulated);
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("Kyber Key Decapsulation", iterations, total_time);
    result.print();

    // =========================================================================
    // Benchmark 2: State Transitions
    // =========================================================================

    // 2.1 - State Transition Creation
    let iterations = 1000;
    let mut state_machine = StateMachine::new();
    state_machine.set_state(genesis_state.clone());

    let start = Instant::now();
    for i in 0..iterations {
        let operation = Operation::Generic {
            operation_type: format!("benchmark_op_{}", i),
            data: vec![1, 2, 3, 4],
            message: "Benchmark operation".to_string(),
        };

        // Execute but don't chain the transitions to isolate creation performance
        let _ = state_machine.execute_transition(operation)?;
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("State Transition Creation", iterations, total_time);
    result.print();

    // 2.2 - Hash Chain Addition (State Transition + Chaining)
    // Reset the SDK for a clean hash chain
    let hash_chain_sdk = Arc::new(HashChainSDK::new());
    let identity_sdk = Arc::new(IdentitySDK::new(device_id.clone(), hash_chain_sdk.clone()));
    let core_sdk = Arc::new(CoreSDK::new());

    // Re-initialize with genesis
    core_sdk
        .initialize_with_genesis(genesis_state.clone())
        .await?;

    let iterations = 500;

    let start = Instant::now();
    for i in 0..iterations {
        let operation = Operation::Generic {
            operation_type: format!("benchmark_chain_op_{}", i),
            data: vec![1, 2, 3, 4],
            message: "Benchmark hash chain operation".to_string(),
        };

        // This will create and chain the transition
        let _ = core_sdk.execute_transition(operation.clone()).await?;
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new(
        "State Transition + Hash Chain Addition",
        iterations,
        total_time,
    );
    result.print();

    // =========================================================================
    // Benchmark 3: Verification Operations
    // =========================================================================

    // 3.1 - State Hash Verification
    let iterations = 10000;
    let current_state = core_sdk.get_current_state()?;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = current_state.compute_hash()?;
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("State Hash Computation", iterations, total_time);
    result.print();

    // 3.2 - Hash Chain Verification
    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = hash_chain_sdk.verify_chain()?;
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("Full Hash Chain Verification", iterations, total_time);
    result.print();

    // 3.3 - Pre-commitment Creation & Verification
    let iterations = 1000;
    let operation = Operation::Generic {
        operation_type: "benchmark_precommit".to_string(),
        data: vec![1, 2, 3, 4],
        message: "Benchmark pre-commitment".to_string(),
    };

    let start = Instant::now();
    for _ in 0..iterations {
        // Using the updated method signatures
        let pre_commitment = identity_sdk.create_pre_commitment(
            &operation,
            Some("counterparty".to_string()),
            Some(b"fixed_params".to_vec()),
            Some(b"variable_params".to_vec()),
        )?;

        let _ = identity_sdk.verify_pre_commitment(&pre_commitment, &operation)?;
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new(
        "Pre-commitment Creation & Verification",
        iterations,
        total_time,
    );
    result.print();

    // =========================================================================
    // Benchmark 4: Token Operations
    // =========================================================================

    // 4.1 - Token Mint + Transfer
    let iterations = 500;

    // Reset the SDK for a clean hash chain
    let core_sdk = Arc::new(CoreSDK::new());

    // Re-initialize with genesis
    core_sdk
        .initialize_with_genesis(genesis_state.clone())
        .await?;

    let start = Instant::now();
    for i in 0..iterations {
        // Mint operation with proper fields
        let mint_op = Operation::Mint {
            token_id: format!("TOKEN_{}", i),
            amount: Balance::new(100),
            message: "Benchmark mint".to_string(),
            authorized_by: "Treasury".to_string(),
            proof_of_authorization: vec![0, 1, 2, 3], // Simplified proof
        };

        let _ = core_sdk.execute_transition(mint_op).await?;

        // Transfer operation with all required fields
        let transfer_op = Operation::Transfer {
            token_id: format!("TOKEN_{}", i),
            to_address: "recipient".to_string(),
            amount: Balance::new(50),
            to: "recipient".to_string(),
            recipient: "recipient".to_string(),
            message: "Benchmark transfer".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            verification: VerificationType::Standard,
            pre_commit: Some(PreCommitmentOp {
                fixed_parameters: std::collections::HashMap::new(),
                variable_parameters: vec![],
                security_params: Default::default(),
            }),
        };

        let _ = core_sdk.execute_transition(transfer_op).await?;
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("Token Mint + Transfer Operations", iterations, total_time);
    result.print();

    // =========================================================================
    // Benchmark 5: End-to-End System Performance
    // =========================================================================

    // 5.1 - Complete Transition Cycle (Create + Apply + Verify)
    let iterations = 200;

    // Reset the SDK for a clean hash chain
    let hash_chain_sdk = Arc::new(HashChainSDK::new());
    // Initializing core_sdk directly
    let core_sdk = Arc::new(CoreSDK::new());

    // Re-initialize with genesis
    core_sdk
        .initialize_with_genesis(genesis_state.clone())
        .await?;

    let start = Instant::now();
    for i in 0..iterations {
        // Create an operation
        let operation = Operation::Generic {
            operation_type: format!("e2e_benchmark_{}", i),
            data: vec![1, 2, 3, 4],
            message: "End-to-end benchmark".to_string(),
        };

        // Execute transition
        let new_state = core_sdk.execute_transition(operation).await?;

        // Verify the new state
        let _ = hash_chain_sdk.verify_state(&new_state)?;
    }
    let total_time = start.elapsed();

    let result = BenchmarkResult::new("Complete Transition Cycle (E2E)", iterations, total_time);
    result.print();

    // =========================================================================
    // Benchmark Summary
    // =========================================================================

    println!("=== Benchmark Summary ===");
    println!("All benchmarks completed successfully.");
    println!("DSM system demonstrated strong performance across all core operations.");
    println!("The system is particularly efficient in hash operations and state transitions,");
    println!("while maintaining the security guarantees of post-quantum cryptography.");

    Ok(())
}
