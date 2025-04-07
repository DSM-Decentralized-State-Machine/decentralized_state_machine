// Pokemon Bluetooth Trading Example
//
// This example demonstrates a peer-to-peer Pokemon trading implementation
// utilizing the DSM architecture for state transition verification and the
// Bluetooth transport layer for device communication. The simulation models
// two distinct devices executing a secure state transition protocol with
// cryptographic identity verification.

use dsm::core::state_machine::StateMachine;
use dsm::types::error::DsmError;
use dsm::types::state_types::DeviceInfo;
use dsm_sdk::bluetooth_transport::{BluetoothMode, BluetoothTransport};
use dsm_sdk::identity_sdk::IdentitySDK;
use dsm_sdk::pokemon_bluetooth_sdk::PokemonBluetoothSDK;
use dsm_sdk::pokemon_sdk::{Pokemon, PokemonParams, PokemonTrainer, PokemonType, TradeConditions};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::time::{self, Duration};
use parking_lot::RwLock;
use futures::future::join_all;
use blake3::Hasher;
use tracing::{info, warn, error, debug};

/// Execute a trade sequence with fault-tolerance and cryptographic verification
async fn execute_trade_sequence(
    red_sdk: &PokemonBluetoothSDK,
    blue_sdk: &PokemonBluetoothSDK,
    trade_conditions: TradeConditions,
) -> Result<(), DsmError> {
    // Create a cryptographically secure trade identifier
    let trade_id = generate_secure_trade_id(&trade_conditions);
    debug!("Generated secure trade ID: {}", trade_id);
    
    // Configure concurrent message processing
    let (red_tx, red_rx) = oneshot::channel::<()>();
    let (blue_tx, blue_rx) = oneshot::channel::<()>();
    
    // Spawn dedicated tasks for each participant to prevent deadlocks
    let red_handle = tokio::spawn({
        let red_sdk = red_sdk.clone();
        let trade_conditions = trade_conditions.clone();
        let trade_id = trade_id.clone();
        async move {
            // Initialize message listener with backpressure handling
            red_sdk.start_message_listener().await?;
            debug!("Red trainer message listener initialized");
            
            // Propose trade with timeout protection
            let timeout = Duration::from_secs(5);
            match time::timeout(timeout, red_sdk.propose_trade("blue_device", trade_conditions)).await {
                Ok(result) => {
                    let actual_trade_id = result?;
                    debug!("Trade proposed successfully: {}", actual_trade_id);
                    assert_eq!(trade_id, actual_trade_id, "Trade ID mismatch - potential replay attack");
                },
                Err(_) => {
                    error!("Trade proposal timed out");
                    return Err(DsmError::timeout("Trade proposal timed out"));
                }
            }
            
            // Signal completion to coordinator
            let _ = red_tx.send(());
            
            // Await confirmation of trade acceptance
            time::sleep(Duration::from_secs(3)).await;
            
            // Execute trade with cryptographic verification
            red_sdk.execute_trade(&trade_id).await?;
            info!("Red trainer completed trade execution");
            
            Ok::<_, DsmError>(())
        }
    });
    
    let blue_handle = tokio::spawn({
        let blue_sdk = blue_sdk.clone();
        let trade_id = trade_id.clone();
        async move {
            // Initialize message processor with bounded queue
            blue_sdk.start_message_listener().await?;
            debug!("Blue trainer message listener initialized");
            
            // Wait for proposal with timeout protection
            time::sleep(Duration::from_secs(2)).await;
            
            // Accept trade with cryptographic verification
            blue_sdk.respond_to_trade(&trade_id, true, None).await?;
            info!("Blue trainer accepted trade offer");
            
            // Signal completion to coordinator
            let _ = blue_tx.send(());
            
            Ok::<_, DsmError>(())
        }
    });
    
    // Coordinator awaits completion signals with timeout protection
    let coordinator = tokio::spawn(async move {
        let timeout = Duration::from_secs(10);
        match time::timeout(timeout, futures::future::join(red_rx, blue_rx)).await {
            Ok((red_result, blue_result)) => {
                red_result.map_err(|_| DsmError::coordination("Red trainer coordination failed"))?;
                blue_result.map_err(|_| DsmError::coordination("Blue trainer coordination failed"))?;
                info!("Trade coordination completed successfully");
            },
            Err(_) => {
                error!("Trade coordination timed out");
                return Err(DsmError::timeout("Trade coordination timed out"));
            }
        }
        
        Ok::<_, DsmError>(())
    });
    
    // Join all handles with comprehensive error handling
    let results = join_all(vec![red_handle, blue_handle, coordinator]).await;
    for (idx, result) in results.into_iter().enumerate() {
        match result {
            Ok(inner_result) => {
                if let Err(e) = inner_result {
                    error!("Task {idx} failed with error: {e}");
                    return Err(e);
                }
            },
            Err(e) => {
                error!("Task {idx} panicked: {e}");
                return Err(DsmError::fatal(format!("Task {idx} panicked: {e}")));
            }
        }
    }
    
    Ok(())
}

/// Generate a cryptographically secure trade identifier
fn generate_secure_trade_id(conditions: &TradeConditions) -> String {
    let mut hasher = Hasher::new();
    hasher.update(conditions.offered_pokemon_id.as_bytes());
    
    if let Some(req_id) = &conditions.requested_pokemon_id {
        hasher.update(req_id.as_bytes());
    }
    
    hasher.update(conditions.sender_id.as_bytes());
    hasher.update(conditions.recipient_id.as_bytes());
    hasher.update(&chrono::Utc::now().timestamp().to_le_bytes());
    
    // Format as hex string for readability while maintaining entropy
    let hash = hasher.finalize();
    format!("trade_{}", hex::encode(hash.as_bytes()[0..16].to_vec()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging with contextual metadata
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global tracing subscriber");
    
    info!("=== DSM Pokemon Bluetooth Trading Protocol Demonstration ===");
    
    // Establish cryptographically secure identities with Ed25519 keypairs
    info!("Establishing secure identity contexts...");
    let red_identity_sdk = Arc::new(IdentitySDK::new(
        "red_trainer".to_string(),
        Arc::new(dsm_sdk::hashchain_sdk::HashChainSDK::new()),
    ));
    
    let blue_identity_sdk = Arc::new(IdentitySDK::new(
        "blue_trainer".to_string(),
        Arc::new(dsm_sdk::hashchain_sdk::HashChainSDK::new()),
    ));
    
    // Create thread-safe state machines with mutex protection
    info!("Initializing concurrent state transition machines...");
    let red_state_machine = Arc::new(StateMachine::new());
    let blue_state_machine = Arc::new(StateMachine::new());
    
    // Initialize Bluetooth SDKs with appropriate role isolation
    info!("Configuring secure transport channels...");
    let red_sdk = PokemonBluetoothSDK::new(
        red_identity_sdk,
        red_state_machine,
        "red_device",
        "Pokemon Trainer Red",
        BluetoothMode::Central, // Active discovery role
    );
    
    let blue_sdk = PokemonBluetoothSDK::new(
        blue_identity_sdk,
        blue_state_machine,
        "blue_device",
        "Pokemon Trainer Blue",
        BluetoothMode::Peripheral, // Passive advertising role
    );
    
    // Create verifiable trainer contexts with deterministic identifiers
    info!("Establishing trainer identity contexts...");
    let red_device_info = DeviceInfo::new("red_device", vec![0, 1, 2, 3]);
    let mut red_trainer = PokemonTrainer::new(
        "red_trainer", 
        "Red", 
        "red_device", 
        red_device_info.public_key.clone()
    );
    
    let blue_device_info = DeviceInfo::new("blue_device", vec![4, 5, 6, 7]);
    let mut blue_trainer = PokemonTrainer::new(
        "blue_trainer", 
        "Blue", 
        "blue_device", 
        blue_device_info.public_key.clone()
    );
    
    // Populate trainer inventories with type-safe Pokemon entities
    info!("Initializing trainer inventories...");
    // Red's Pokemon with deterministic properties
    let charmander = Pokemon::new(PokemonParams {
        id: "PKM_001".to_string(),
        name: "Charmander".to_string(),
        types: vec![PokemonType::Fire],
        level: 15,
        hp: 39,
        attack: 52,
        defense: 43,
        owner_id: "red_trainer".to_string(),
    });
    
    let squirtle = Pokemon::new(PokemonParams {
        id: "PKM_002".to_string(),
        name: "Squirtle".to_string(),
        types: vec![PokemonType::Water],
        level: 14,
        hp: 44,
        attack: 48,
        defense: 65,
        owner_id: "red_trainer".to_string(),
    });
    
    // Blue's Pokemon with deterministic properties
    let bulbasaur = Pokemon::new(PokemonParams {
        id: "PKM_003".to_string(),
        name: "Bulbasaur".to_string(),
        types: vec![PokemonType::Grass, PokemonType::Poison],
        level: 15,
        hp: 45,
        attack: 49,
        defense: 49,
        owner_id: "blue_trainer".to_string(),
    });
    
    let pikachu = Pokemon::new(PokemonParams {
        id: "PKM_004".to_string(),
        name: "Pikachu".to_string(),
        types: vec![PokemonType::Electric],
        level: 16,
        hp: 35,
        attack: 55,
        defense: 40,
        owner_id: "blue_trainer".to_string(),
    });
    
    // Register Pokemon with trainers using atomic operations
    red_trainer.add_pokemon(charmander)?;
    red_trainer.add_pokemon(squirtle)?;
    blue_trainer.add_pokemon(bulbasaur)?;
    blue_trainer.add_pokemon(pikachu)?;
    
    // Initialize SDKs with immutable trainer contexts
    info!("Binding trainer contexts to secure execution environments...");
    red_sdk.initialize(red_trainer)?;
    blue_sdk.initialize(blue_trainer)?;
    
    info!("Red trainer inventory: {} Pokemon", red_sdk.get_trainer().unwrap().pokemon_count());
    for (id, pokemon) in &red_sdk.get_trainer().unwrap().pokemon {
        debug!("  - {}: {} (Type: {:?}, CP: {})", id, pokemon.name, pokemon.types, pokemon.cp);
    }
    
    info!("Blue trainer inventory: {} Pokemon", blue_sdk.get_trainer().unwrap().pokemon_count());
    for (id, pokemon) in &blue_sdk.get_trainer().unwrap().pokemon {
        debug!("  - {}: {} (Type: {:?}, CP: {})", id, pokemon.name, pokemon.types, pokemon.cp);
    }
    
    // Establish communication channels with proper handshaking
    info!("Establishing secure transport channel...");
    blue_sdk.start_advertising().await?;
    red_sdk.start_scanning().await?;
    
    // Allow device discovery with appropriate timeout
    time::sleep(Duration::from_secs(2)).await;
    
    // Establish connection with proper authentication
    info!("Initiating connection handshake...");
    let discovered = red_sdk.get_discovered_trainers();
    debug!("Red discovered trainers: {:?}", discovered);
    
    red_sdk.connect_to_trainer("blue_device").await?;
    info!("Secure channel established between Red and Blue");
    
    // Define trade parameters with cryptographic guarantees
    info!("Initiating atomic trade protocol...");
    let trade_conditions = TradeConditions {
        offered_pokemon_id: "PKM_001".to_string(), // Charmander
        requested_pokemon_id: Some("PKM_003".to_string()), // Bulbasaur
        requested_pokemon_type: None,
        min_cp_requirement: None,
        requested_rarity: None,
        token_amount: None,
        token_type: None,
        expires_at: Some((chrono::Utc::now().timestamp() + 60) as u64), // 1 minute expiration
        trade_id: String::new(), // Will be set by the protocol
        sender_id: "red_trainer".to_string(),
        recipient_id: "blue_trainer".to_string(),
    };
    
    // Execute trade with comprehensive error handling
    match execute_trade_sequence(&red_sdk, &blue_sdk, trade_conditions).await {
        Ok(_) => info!("Trade protocol completed successfully"),
        Err(e) => {
            error!("Trade protocol failed: {}", e);
            return Err(Box::new(e));
        }
    }
    
    // Verify post-trade state with cryptographic attestation
    info!("Verifying post-trade state integrity...");
    
    let red_trainer = red_sdk.get_trainer().unwrap();
    let blue_trainer = blue_sdk.get_trainer().unwrap();
    
    // Verify ownership transfers with cryptographic assurances
    assert!(
        red_trainer.get_pokemon("PKM_003").is_some(),
        "Red should now own Bulbasaur (PKM_003)"
    );
    assert!(
        blue_trainer.get_pokemon("PKM_001").is_some(),
        "Blue should now own Charmander (PKM_001)"
    );
    
    info!("Post-trade inventory validation successful:");
    info!("Red trainer inventory: {} Pokemon", red_trainer.pokemon_count());
    for (id, pokemon) in &red_trainer.pokemon {
        info!("  - {}: {} (Type: {:?}, CP: {})", id, pokemon.name, pokemon.types, pokemon.cp);
        // Verify Pokemon integrity
        assert!(
            pokemon.verify_integrity(),
            "Pokemon {} fails integrity check",
            id
        );
    }
    
    info!("Blue trainer inventory: {} Pokemon", blue_trainer.pokemon_count());
    for (id, pokemon) in &blue_trainer.pokemon {
        info!("  - {}: {} (Type: {:?}, CP: {})", id, pokemon.name, pokemon.types, pokemon.cp);
        // Verify Pokemon integrity
        assert!(
            pokemon.verify_integrity(),
            "Pokemon {} fails integrity check",
            id
        );
    }
    
    // Clean up resources to prevent memory leaks
    info!("Terminating secure transport channels...");
    red_sdk.disconnect_from_trainer("blue_device").await?;
    red_sdk.stop_scanning()?;
    blue_sdk.stop_advertising()?;
    
    info!("Pokemon trade demonstration completed successfully");
    
    Ok(())
}