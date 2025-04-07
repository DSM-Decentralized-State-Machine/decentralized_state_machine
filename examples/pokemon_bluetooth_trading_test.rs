use dsm::core::state_machine::StateMachine;
use dsm::types::state_types::DeviceInfo;
use dsm_sdk::identity_sdk::IdentitySDK;
use dsm_sdk::pokemon_bluetooth_sdk::{BluetoothPokemonTrading, PokemonBluetoothSDK};
use dsm_sdk::pokemon_sdk::{Pokemon, PokemonParams, PokemonRarity, PokemonTrainer, PokemonType, TradeConditions};
use dsm_sdk::BluetoothMode;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// Test the Pokemon Bluetooth trading functionality
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize trader 1 with a state machine and identity
    let device_id1 = "device_1";
    let device_name1 = "Trainer Alice";
    let trainer_id1 = "trainer_alice";
    let trainer_name1 = "Alice";
    
    // Create state machine and identity SDK
    let state_machine1 = Arc::new(StateMachine::new());
    let identity_sdk1 = Arc::new(IdentitySDK::new(device_id1.to_string(), state_machine1.clone()));
    
    // Initialize identity
    identity_sdk1.initialize()?;
    
    // Create Bluetooth SDK for trader 1 (Central mode - initiates connections)
    let bluetooth_sdk1 = PokemonBluetoothSDK::new(
        identity_sdk1.clone(),
        state_machine1.clone(),
        device_id1,
        device_name1,
        BluetoothMode::Central,
    );
    
    // Initialize trainer data
    let trainer1 = PokemonTrainer::new(
        trainer_id1,
        trainer_name1,
        device_id1,
        vec![1, 2, 3, 4], // Mock public key
    );
    
    // Add Pokemon to trainer 1
    let mut trainer1_with_pokemon = trainer1.clone();
    let pokemon1 = Pokemon::new(PokemonParams {
        id: "001".to_string(),
        name: "Pikachu".to_string(),
        types: vec![PokemonType::Electric],
        level: 25,
        hp: 60,
        attack: 55,
        defense: 40,
        owner_id: trainer_id1.to_string(),
    });
    
    trainer1_with_pokemon.add_pokemon(pokemon1.clone())?;
    
    // Initialize the Bluetooth SDK with trainer data
    bluetooth_sdk1.initialize(trainer1_with_pokemon)?;

    // Initialize trader 2 with a state machine and identity
    let device_id2 = "device_2";
    let device_name2 = "Trainer Bob";
    let trainer_id2 = "trainer_bob";
    let trainer_name2 = "Bob";
    
    // Create state machine and identity SDK
    let state_machine2 = Arc::new(StateMachine::new());
    let identity_sdk2 = Arc::new(IdentitySDK::new(device_id2.to_string(), state_machine2.clone()));
    
    // Initialize identity
    identity_sdk2.initialize()?;
    
    // Create Bluetooth SDK for trader 2 (Peripheral mode - accepts connections)
    let bluetooth_sdk2 = PokemonBluetoothSDK::new(
        identity_sdk2.clone(),
        state_machine2.clone(),
        device_id2,
        device_name2,
        BluetoothMode::Peripheral,
    );
    
    // Initialize trainer data
    let trainer2 = PokemonTrainer::new(
        trainer_id2,
        trainer_name2,
        device_id2,
        vec![5, 6, 7, 8], // Mock public key
    );
    
    // Add Pokemon to trainer 2
    let mut trainer2_with_pokemon = trainer2.clone();
    let pokemon2 = Pokemon::new(PokemonParams {
        id: "004".to_string(),
        name: "Charmander".to_string(),
        types: vec![PokemonType::Fire],
        level: 20,
        hp: 52,
        attack: 52,
        defense: 43,
        owner_id: trainer_id2.to_string(),
    });
    
    trainer2_with_pokemon.add_pokemon(pokemon2.clone())?;
    
    // Initialize the Bluetooth SDK with trainer data
    bluetooth_sdk2.initialize(trainer2_with_pokemon)?;

    // Start advertising for trader 2 (Peripheral)
    println!("Trainer 2 ({}) starts advertising...", trainer_name2);
    bluetooth_sdk2.start_advertising().await?;

    // Start scanning for trader 1 (Central)
    println!("Trainer 1 ({}) starts scanning...", trainer_name1);
    bluetooth_sdk1.start_scanning().await?;
    
    // Wait for discovery
    println!("Waiting for device discovery...");
    sleep(Duration::from_secs(2)).await;
    
    // Get discovered devices
    let discovered = bluetooth_sdk1.get_discovered_trainers();
    println!("Discovered trainers: {:?}", discovered);
    
    // Connect trainer 1 to trainer 2
    println!("Connecting to {}", device_name2);
    bluetooth_sdk1.connect_to_trainer(device_id2).await?;
    
    // Start message listeners for both trainers
    bluetooth_sdk1.start_message_listener().await?;
    bluetooth_sdk2.start_message_listener().await?;
    
    // Wait for connection to establish
    sleep(Duration::from_secs(1)).await;
    
    // Create trade conditions
    let trade_conditions = TradeConditions {
        offered_pokemon_id: "001".to_string(), // Pikachu
        requested_pokemon_id: Some("004".to_string()), // Charmander
        requested_pokemon_type: None,
        min_cp_requirement: None,
        requested_rarity: None,
        token_amount: None,
        token_type: None,
        expires_at: None,
        trade_id: "trade_1".to_string(),
        sender_id: trainer_id1.to_string(),
        recipient_id: trainer_id2.to_string(),
    };
    
    // Propose trade from trader 1 to trader 2
    println!("Trainer 1 proposes a trade of Pikachu for Charmander");
    let trade_id = bluetooth_sdk1.propose_trade(device_id2, trade_conditions).await?;
    println!("Trade proposed with ID: {}", trade_id);
    
    // Wait for trade proposal to be received
    sleep(Duration::from_secs(1)).await;
    
    // Trader 2 accepts the trade
    println!("Trainer 2 accepts the trade");
    bluetooth_sdk2.respond_to_trade(&trade_id, true, None).await?;
    
    // Wait for trade acceptance to be processed
    sleep(Duration::from_secs(1)).await;
    
    // Execute the trade - both trainers send their Pokemon
    println!("Trainer 1 executes the trade");
    bluetooth_sdk1.execute_trade(&trade_id).await?;
    
    // Wait for trade to complete
    sleep(Duration::from_secs(1)).await;
    
    println!("Trainer 2 executes the trade");
    bluetooth_sdk2.execute_trade(&trade_id).await?;
    
    // Wait for trade to complete
    sleep(Duration::from_secs(2)).await;
    
    // Verify the trade results
    if let Some(trainer1_after) = bluetooth_sdk1.get_trainer() {
        println!("Trainer 1 now has {} Pokemon", trainer1_after.pokemon_count());
        if let Some(received_pokemon) = trainer1_after.get_pokemon("004") {
            println!("Trainer 1 now has: {} ({})", received_pokemon.name, received_pokemon.id);
        } else {
            println!("Error: Trainer 1 did not receive Charmander!");
        }
    }
    
    if let Some(trainer2_after) = bluetooth_sdk2.get_trainer() {
        println!("Trainer 2 now has {} Pokemon", trainer2_after.pokemon_count());
        if let Some(received_pokemon) = trainer2_after.get_pokemon("001") {
            println!("Trainer 2 now has: {} ({})", received_pokemon.name, received_pokemon.id);
        } else {
            println!("Error: Trainer 2 did not receive Pikachu!");
        }
    }
    
    // Disconnect
    println!("Disconnecting...");
    bluetooth_sdk1.disconnect_from_trainer(device_id2).await?;
    
    // Clean up
    bluetooth_sdk1.stop_scanning()?;
    bluetooth_sdk2.stop_advertising()?;
    
    println!("Test complete!");
    Ok(())
}
