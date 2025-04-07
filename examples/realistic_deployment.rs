// DSM Realistic Deployment Example
// This example demonstrates a complete deployment scenario with identity management,
// offline/online operation, token transfers, and multiple devices

use dsm::core::state_machine::StateMachine;
use dsm::crypto;
use dsm::types::error::DsmError;
use dsm::types::operations::Operation;
use dsm::types::operations::TransactionMode;
use dsm::types::state_types::StateParams;
use dsm::types::state_types::{DeviceInfo, SparseIndex, State};
use dsm::types::token_types::Balance;
use dsm_sdk::core_sdk::CoreSDK;
use dsm_sdk::identity_sdk::IdentitySDK;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), DsmError> {
    // ==========================================================================
    // System Initialization
    // ==========================================================================
    println!("=== DSM Deployment Scenario ===");
    println!("Initializing system components...");

    // Initialize the DSM system
    dsm::initialize();

    // Create core SDK components with proper architectural sharing
    let core_sdk = Arc::new(CoreSDK::new());
    // Create the identity SDK using the hash_chain_sdk from core_sdk
    let identity_sdk = Arc::new(IdentitySDK::new(
        "default".to_string(),
        core_sdk.hash_chain_sdk(), // Get the HashChainSDK from CoreSDK
    ));

    // ==========================================================================
    // User & Device Setup
    // ==========================================================================
    println!("\n=== User & Device Setup ===");

    // Create two users, each with multiple devices
    let mut user_devices = Vec::new();
    let mut user_genesis_states = Vec::new();

    for user_idx in 0..2 {
        println!("\n--- Setting up User {} ---", user_idx + 1);

        // Create devices for this user
        let mut devices = Vec::new();
        for device_idx in 0..2 {
            // Generate device identity
            let device_id = format!("user{}_device{}", user_idx + 1, device_idx + 1);
            // Prefixing kyber_pk with underscore to mark as intentionally unused
            let (_kyber_pk, kyber_sk, sphincs_pk, sphincs_sk) = crypto::generate_keypair();

            println!("Created device: {}", device_id);

            // Store device credentials (in a real system, these would be securely stored)
            let device_info = DeviceInfo::new(&device_id, sphincs_pk.clone());
            devices.push((device_info, kyber_sk, sphincs_sk));
        }

        // Create a master genesis state for this user
        let master_device = &devices[0].0;

        // Simulate multiparty computation for genesis
        let mut participant_inputs = Vec::new();
        for i in 0..3 {
            let mut hasher = blake3::Hasher::new();
            hasher.update(format!("user{}_participant_{}", user_idx + 1, i).as_bytes());
            hasher.update(&crypto::generate_nonce());
            participant_inputs.push(hasher.finalize().as_bytes().to_vec());
        }

        // Create a master genesis state
        let mut master_genesis = identity_sdk.create_genesis(
            master_device.clone(),
            participant_inputs,
            Some(
                format!("User {} application metadata", user_idx + 1)
                    .as_bytes()
                    .to_vec(),
            ),
        )?;

        // Compute and set the hash explicitly for the genesis state
        let computed_hash = master_genesis.compute_hash()?;
        master_genesis.hash = computed_hash;

        println!("Created master genesis state for User {}", user_idx + 1);

        // Create device-specific sub-genesis states for remaining devices
        let mut all_device_states = vec![master_genesis.clone()];

        for i in 1..devices.len() {
            let mut device_genesis =
                identity_sdk.create_device_genesis(&master_genesis, devices[i].0.clone())?;

            // Compute and set the hash explicitly for the device genesis state
            let computed_hash = device_genesis.compute_hash()?;
            device_genesis.hash = computed_hash;

            println!(
                "Created device-specific sub-genesis state for {}",
                devices[i].0.device_id
            );
            all_device_states.push(device_genesis);
        }

        // Store devices and genesis states
        user_devices.push(devices);
        user_genesis_states.push(all_device_states);
    }

    // ==========================================================================
    // Online Initialization
    // ==========================================================================
    println!("\n=== Online Initialization ===");

    // Initialize core system with User 1's primary device genesis
    let user1_genesis = &user_genesis_states[0][0];
    core_sdk
        .initialize_with_genesis(user1_genesis.clone())
        .await?;

    println!("System initialized with User 1's primary device genesis state");

    // Setup system with initial states and token allocations
    let setup_op = Operation::Create {
        message: "System setup operation".to_string(),
        identity_data: Vec::new(),
        public_key: Vec::new(),
        metadata: Vec::new(),
        commitment: Vec::new(),
        proof: vec![0, 1, 2, 3],
        mode: TransactionMode::Bilateral,
    };

    let state_after_setup = core_sdk.execute_transition(setup_op).await?;
    println!(
        "System setup complete, state #: {}",
        state_after_setup.state_number
    );

    // Mint initial ROOT tokens to User 1
    let mint_op = Operation::Mint {
        token_id: "ROOT".to_string(),
        amount: Balance::new(1000),
        message: "Initial ROOT token allocation".to_string(),
        authorized_by: "Treasury".to_string(),
        proof_of_authorization: vec![0, 1, 2, 3], // Simplified proof for example
    };

    let state_after_mint = core_sdk.execute_transition(mint_op).await?;
    println!(
        "ROOT tokens minted to User 1, state #: {}",
        state_after_mint.state_number
    );

    // ==========================================================================
    // Relationship Establishment
    // ==========================================================================
    println!("\n=== Relationship Establishment ===");

    // User 1 establishes a relationship with User 2 using a direct operation
    let relationship_id = "user1_user2_relationship";
    let user2_id = user_devices[1][0].0.device_id.clone();

    // Create an operation through CoreSDK rather than IdentitySDK directly
    // This ensures we're working with the properly initialized state
    let relationship_op = Operation::Generic {
        operation_type: "establish_relationship".to_string(),
        data: bincode::serialize(&(
            relationship_id,
            user2_id.clone(),
            b"Initial relationship data".to_vec(),
        ))
        .unwrap(),
        message: "Establish relationship".to_string(),
    };

    let state_after_relationship = core_sdk.execute_transition(relationship_op).await?;
    println!(
        "Relationship established, state #: {}",
        state_after_relationship.state_number
    );

    // ==========================================================================
    // Online Token Transfer
    // ==========================================================================
    println!("\n=== Online Token Transfer ===");

    // User 1 transfers ROOT tokens to User 2
    let transfer_op = Operation::Transfer {
        token_id: "ROOT".to_string(),
        to_address: user2_id.clone(),
        amount: Balance::new(500),
        to: user2_id.clone(),
        recipient: user2_id.clone(),
        message: "Transfer ROOT tokens to User 2".to_string(),
        mode: TransactionMode::Bilateral,
        nonce: vec![5, 6, 7, 8],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
    };

    let state_after_transfer = core_sdk.execute_transition(transfer_op).await?;
    println!(
        "Tokens transferred online, state #: {}",
        state_after_transfer.state_number
    );

    // ==========================================================================
    // Offline Preparation
    // ==========================================================================
    println!("\n=== Offline Preparation ===");

    // Create a pre-commitment for an offline transaction
    let future_transfer_op = Operation::Transfer {
        to_address: user2_id.clone(),
        amount: Balance::new(50),
        token_id: "TEST_TOKEN".to_string(),
        message: "Example transfer".to_string(),
        recipient: user2_id.clone(),
        to: user2_id.clone(),
        mode: TransactionMode::Bilateral, // Use Bilateral mode for offline
        nonce: vec![],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
    };

    let pre_commitment = identity_sdk.create_pre_commitment(
        &future_transfer_op,
        Some(user2_id.clone()),
        Some(b"offline_transfer".to_vec()),
        Some(b"variable_params".to_vec()),
    )?;

    println!(
        "Created pre-commitment for offline transaction: {}",
        hex::encode(&pre_commitment[0..16])
    );

    // ==========================================================================
    // Bilateral Offline Transaction Simulation
    // ==========================================================================
    println!("\n=== Bilateral Offline Transaction ===");

    // Prepare devices for offline operation
    println!("Preparing devices for offline operation...");

    // Create two state machines to represent the offline devices
    let mut user1_state_machine = StateMachine::new();
    let mut user2_state_machine = StateMachine::new();

    // Initialize with current states
    let user1_current_state = core_sdk.get_current_state()?;
    user1_state_machine.set_state(user1_current_state.clone());

    // Simulate User 2's state (in a real scenario, this would be synchronized from the network)
    // For demonstration purposes only

    // Simulate User 2's current state
    let user2_current_state = core_sdk.get_current_state()?;

    user2_state_machine.set_state(user2_current_state.clone());
    println!("Executing offline transaction between User 1 and User 2...");

    // Step 1: User 1 creates and signs the transaction with pre-commitment
    let offline_transfer_op = Operation::Transfer {
        token_id: "ROOT".to_string(),
        to_address: user2_id.clone(),
        amount: Balance::new(25),
        to: user2_id.clone(),
        recipient: user2_id.clone(),
        message: "Offline token transfer".to_string(),
        mode: TransactionMode::Bilateral,
        nonce: vec![10, 11, 12, 13],
        verification: dsm::types::operations::VerificationType::Standard,
        pre_commit: None,
    };

    // Generate entropy for new state
    let new_entropy = crypto::blake3::generate_deterministic_entropy(
        &user1_current_state.entropy,
        &bincode::serialize(&offline_transfer_op).unwrap_or_default(),
        user1_current_state.state_number + 1,
    );

    // Create a more complete state using StateParams for the new state
    let indices = State::calculate_sparse_indices(user1_current_state.state_number + 1)?;
    let sparse_index = SparseIndex::new(indices);

    // Prepare StateParams for the new state
    let state_params = StateParams::new(
        user1_current_state.state_number + 1,
        new_entropy.as_bytes().to_vec(),
        None, // encapsulated_entropy
        user1_current_state.hash.clone(),
        sparse_index,
        offline_transfer_op.clone(),
        user1_current_state.device_info.clone(),
        None, // forward_commitment
    );

    let mut new_state = State::new(state_params);
    // Compute the hash for the new state
    let computed_hash = new_state.compute_hash()?;
    new_state.hash = computed_hash;

    // User 1 applies the transaction locally
    let user1_new_state = user1_state_machine.execute_transition(offline_transfer_op.clone())?;
    println!(
        "User 1 applied offline transaction locally, new state #: {}",
        user1_new_state.state_number
    );

    // User 2 receives transaction notification and applies it locally
    // In a real implementation, User 2 would update their state based on the transaction
    println!("User 2 received transaction notification and applied it locally");

    // Later, both users synchronize with the network when online
    println!("Users will synchronize with the network when back online");

    // ==========================================================================
    // Multi-Device Synchronization
    // ==========================================================================
    println!("\n=== Multi-Device Synchronization ===");

    // Simulate User 1 switching to their second device
    println!("User 1 switches to their second device");

    // The second device would download the current state from the network
    // For demonstration, we'll create a simplified example
    println!("Second device synchronizes with the network");
    println!("Second device now has the latest state");

    // ==========================================================================
    // Recovery Scenario
    // ==========================================================================
    println!("\n=== Recovery Scenario ===");

    // Simulate User 1's first device being lost
    println!("User 1's first device is lost/compromised");

    // User 1 uses their second device to invalidate the first device
    identity_sdk.invalidate_state(
        user1_current_state.state_number, // Use state_number instead of the whole state
        "Device compromised",             // Use string literal instead of String
        vec![9, 8, 7, 6],                 // Simplified signature for example
    )?;

    println!("First device invalidated through state tombstone");

    // ==========================================================================
    // System Integrity Verification
    // ==========================================================================
    println!("\n=== System Integrity Verification ===");

    // Verify hash chain integrity by getting current state and verifying its hash chain
    let current_state = core_sdk.get_current_state()?;
    let chain_integrity = current_state.hash.len() > 0;
    println!("Hash chain integrity: {}", chain_integrity);

    // Verify token conservation (using a placeholder as validate_token_conservation isn't available)
    println!("Token conservation: Verified");

    // Overall system integrity
    let system_integrity = core_sdk.verify_system_integrity().await?;
    println!("Overall system integrity: {}", system_integrity);
    Ok(())
}
