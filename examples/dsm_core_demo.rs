// DSM Core Demonstration
// This example demonstrates the fundamental state machine, cryptographic identity,
// and token operations in DSM working together as an integrated system.

use dsm::crypto;
use dsm::types::error::DsmError;
use dsm::types::operations::PreCommitmentOp;
use dsm::types::operations::VerificationType;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::state_types::DeviceInfo;
use dsm::types::token_types::Balance;
use dsm_sdk::core_sdk::CoreSDK;
use dsm_sdk::hashchain_sdk::HashChainSDK;
use dsm_sdk::identity_sdk::IdentitySDK;
use dsm_sdk::token_sdk::TokenSDK;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_sphincsplus::sphincssha2256fsimple;
use pqcrypto_traits::kem::PublicKey;
use pqcrypto_traits::kem::SecretKey as KemSecretKey;
use pqcrypto_traits::sign::PublicKey as SignPublicKey;
use pqcrypto_traits::sign::SecretKey as SignSecretKey;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), DsmError> {
    println!("=== DSM Core Demonstration ===");
    println!("Initializing DSM system...");

    // Initialize the DSM system
    dsm::initialize();

    // 1. Create a device identity

    let (sphincs_pk, sphincs_sk) = sphincssha2256fsimple::keypair();
    let (kyber_pk, kyber_sk) = mlkem1024::keypair();
    // Store the private key securely (in a real application, use a secure enclave or HSM)
    crypto::store_private_key("device_identity", sphincs_sk.as_bytes())?;
    // Store the Kyber private key securely
    crypto::store_private_key("kyber_private_key", kyber_sk.as_bytes())?;
    // Generate a unique device ID
    let device_id = format!("device_{}", hex::encode(&crypto::generate_nonce()[..8]));

    println!("Created device identity: {}", device_id);
    println!("Generated quantum-resistant keypair");
    println!(
        "  Kyber public key size: {} bytes",
        kyber_pk.as_bytes().len()
    );
    println!(
        "  SPHINCS+ public key size: {} bytes",
        sphincs_pk.as_bytes().len()
    );

    // Create a device info object
    let device_info = DeviceInfo::new(&device_id, sphincs_pk.as_bytes().to_vec());

    // 2. Initialize the Core SDK components
    println!("\n=== Step 2: Initializing SDK Components ===");
    let hash_chain_sdk = Arc::new(HashChainSDK::new());
    let core_sdk = Arc::new(CoreSDK::new());
    let identity_sdk = Arc::new(IdentitySDK::new(device_id.clone(), hash_chain_sdk.clone()));
    let _token_sdk = TokenSDK::new(core_sdk.clone());

    println!("SDK components initialized successfully");

    // 3. Create a Genesis State through multiparty computation
    println!("\n=== Step 3: Creating Genesis State ===");
    // Simulate blinded inputs from multiple parties
    let mut participant_inputs = Vec::new();
    for i in 0..3 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(format!("participant_{}_secret", i).as_bytes());
        hasher.update(&crypto::generate_nonce());
        participant_inputs.push(hasher.finalize().as_bytes().to_vec());
    }

    // Create a genesis state using the enhanced method
    let mut genesis_state = identity_sdk.create_genesis(
        device_info.clone(),
        participant_inputs,
        Some(b"Application metadata for device".to_vec()),
    )?;

    // Compute and set the hash explicitly for the genesis state
    let computed_hash = genesis_state.compute_hash()?;
    genesis_state.hash = computed_hash;

    println!(
        "Genesis state created with state number: {}",
        genesis_state.state_number
    );
    println!("Genesis hash: {}", hex::encode(&genesis_state.hash));

    // 4. Initialize the system with the genesis state
    println!("\n=== Step 4: Initializing System with Genesis State ===");
    core_sdk
        .initialize_with_genesis(genesis_state.clone())
        .await?;
    println!("System initialized with genesis state");

    // 5. Execute a state transition
    println!("\n=== Step 5: Executing State Transition ===");

    // Create operation with the updated struct fields
    let operation = Operation::Create {
        message: "Create initial state".to_string(),
        identity_data: Vec::new(),
        public_key: Vec::new(),
        metadata: Vec::new(),
        commitment: Vec::new(),
        proof: Vec::new(),
        mode: TransactionMode::Bilateral,
    };

    let new_state = core_sdk.execute_transition(operation).await?;
    println!("State transition executed successfully");
    println!("New state number: {}", new_state.state_number);
    println!("New state hash: {}", hex::encode(&new_state.hash));

    // 6. Verify the hash chain integrity
    println!("\n=== Step 6: Verifying Hash Chain Integrity ===");
    let chain_integrity = hash_chain_sdk.verify_chain()?;
    println!("Hash chain integrity: {}", chain_integrity);

    // 7. Create and execute a token operation
    println!("\n=== Step 7: Executing Token Operations ===");

    // First, mint some tokens to the device
    let mint_operation = Operation::Mint {
        token_id: "TEST_TOKEN".to_string(),
        amount: Balance::new(100),
        message: "Mint initial tokens".to_string(),
        authorized_by: "Treasury".to_string(),
        proof_of_authorization: vec![0, 1, 2, 3], // Simplified proof for example
    };

    let _state_after_mint = core_sdk.execute_transition(mint_operation).await?;
    println!("Tokens minted successfully");

    // Now transfer some tokens with all required fields
    let pre_commit_op = PreCommitmentOp {
        fixed_parameters: std::collections::HashMap::new(),
        variable_parameters: vec!["amount".to_string()],
        security_params: Default::default(),
    };

    let transfer_operation = Operation::Transfer {
        token_id: "TEST_TOKEN".to_string(),
        to_address: "recipient_device".to_string(),
        amount: Balance::new(50),
        to: "recipient_device".to_string(),
        recipient: "recipient_device".to_string(),
        message: "Transfer tokens".to_string(),
        mode: TransactionMode::Bilateral,
        nonce: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        verification: VerificationType::Standard,
        pre_commit: Some(pre_commit_op),
    };

    let state_after_transfer = core_sdk.execute_transition(transfer_operation).await?;
    println!("Tokens transferred successfully");
    println!("Final state number: {}", state_after_transfer.state_number);

    // 8. Create a pre-commitment for a future operation
    println!("\n=== Step 8: Creating Pre-Commitment ===");

    // Future operation with updated fields
    let future_op = Operation::Transfer {
        token_id: "TEST_TOKEN".to_string(),
        to_address: "future_recipient".to_string(),
        amount: Balance::new(10),
        to: "future_recipient".to_string(),
        recipient: "future_recipient".to_string(),
        message: "Future token transfer".to_string(),
        mode: TransactionMode::Bilateral,
        nonce: vec![16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
        verification: VerificationType::Standard,
        pre_commit: None, // No nested pre-commitment for this operation
    };

    // Use the identity_sdk to create a pre-commitment
    let pre_commitment = identity_sdk.create_pre_commitment(
        &future_op,
        Some("future_recipient".to_string()),
        Some(b"fixed_parameter_data".to_vec()),
        Some(b"variable_parameter_data".to_vec()),
    )?;

    println!(
        "Pre-commitment created: {}",
        hex::encode(&pre_commitment[0..16])
    );

    // 9. Verify the pre-commitment
    println!("\n=== Step 9: Verifying Pre-Commitment ===");
    let is_valid = identity_sdk.verify_pre_commitment(&pre_commitment, &future_op)?;
    println!("Pre-commitment verification: {}", is_valid);

    // 10. System integrity verification
    println!("\n=== Step 10: Verifying System Integrity ===");
    let system_integrity = core_sdk.verify_system_integrity().await?;
    println!("Overall system integrity: {}", system_integrity);

    println!("\n=== DSM Core Demonstration Complete ===");
    println!("All operations completed successfully, demonstrating the core DSM functionality.");

    Ok(())
}

// Create example operations
fn create_example_operations() -> Vec<Operation> {
    vec![
        Operation::Create {
            message: "Create identity".to_string(),
            identity_data: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            metadata: vec![7, 8, 9],
            commitment: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral,
        },
        Operation::AddRelationship {
            message: "Add relationship".to_string(),
            from_id: "alice".to_string(),
            to_id: "bob".to_string(), 
            relationship_type: "friend".to_string(),
            metadata: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral,
        },
        Operation::Generic {
            operation_type: "test".to_string(),
            data: vec![1,2,3],
            message: "Test generic operation".to_string()
        }
    ]
}
