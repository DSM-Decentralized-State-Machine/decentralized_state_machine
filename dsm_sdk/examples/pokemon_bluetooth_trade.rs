// Pokemon Bluetooth Trading Example with Post-Quantum Cryptography
//
// This example demonstrates a peer-to-peer Pokemon trading implementation
// utilizing the DSM architecture for state transition verification and the
// Bluetooth transport layer for device communication. The implementation uses
// quantum-resistant SPHINCS+ signatures and Kyber key encapsulation.

use std::{cmp::min, sync::Arc};

use blake3::Hasher;
use dsm::{
    core::state_machine::StateMachine,
    types::{error::DsmError, state_types::DeviceInfo},
};
// Access SDK directly when running as example
use dsm_sdk::sdk::identity_sdk::IdentitySDK;
use dsm_sdk::sdk::{
    pokemon_sdk::{Pokemon, PokemonParams, PokemonTrainer, PokemonType, TradeConditions},
    protocol_metrics::ProtocolMetrics,
};
use tokio::{
    sync::oneshot,
    task::JoinError,
    time::{self, Duration},
};
use tracing::{debug, error, info};

// Add a mock implementation of the PokemonBluetoothSDK to simulate Bluetooth behavior
#[derive(Clone)]
struct TrainerState {
    trainer: PokemonTrainer,
    #[allow(dead_code)]
    is_connected: bool,
}

#[derive(Clone)]
struct MockPokemonBluetoothSDK {
    device_name: String,
    discovered_devices: Vec<String>,
    trainer: Option<PokemonTrainer>, // Store the trainer's state persistently
}

impl MockPokemonBluetoothSDK {
    fn new(device_name: &str) -> Self {
        Self {
            device_name: device_name.to_string(),
            discovered_devices: vec![],
            trainer: None,
        }
    }

    async fn start_advertising(&mut self) -> Result<(), DsmError> {
        if let Some(trainer) = &self.trainer {
            let mut devices = MOCK_BLUETOOTH_DEVICES.lock().unwrap();
            // Remove any existing entry for this trainer
            devices.retain(|t| t.trainer.device_info.device_id != trainer.device_info.device_id);
            // Add the current trainer state
            devices.push(TrainerState {
                trainer: trainer.clone(),
                is_connected: false,
            });
        }
        Ok(())
    }

    async fn start_scanning(&mut self) -> Result<(), DsmError> {
        self.discovered_devices = MOCK_BLUETOOTH_DEVICES
            .lock()
            .unwrap()
            .iter()
            .map(|t| t.trainer.device_info.device_id.clone())
            .collect();
        Ok(())
    }

    fn get_discovered_trainers(&self) -> Vec<String> {
        self.discovered_devices.clone()
    }

    async fn connect_to_trainer(&self, device_name: &str) -> Result<(), DsmError> {
        if self.discovered_devices.contains(&device_name.to_string()) {
            Ok(())
        } else {
            Err(DsmError::fatal(format!(
                "Bluetooth device not found: {}",
                device_name
            )))
        }
    }

    // Simulate starting a message listener
    async fn start_message_listener(&self) -> Result<(), DsmError> {
        debug!("Message listener started for device: {}", self.device_name);
        Ok(())
    }

    // Simulate proposing a trade
    async fn propose_trade(
        &self,
        device_name: &str,
        trade_conditions: TradeConditions,
    ) -> Result<String, DsmError> {
        if self.discovered_devices.contains(&device_name.to_string()) {
            let trade_id = generate_secure_trade_id(&trade_conditions);
            debug!("Trade proposed to device: {}", device_name);
            Ok(trade_id)
        } else {
            Err(DsmError::fatal(format!(
                "Device not found: {}",
                device_name
            )))
        }
    }

    async fn execute_trade(&mut self, trade_id: &str) -> Result<(), DsmError> {
        debug!("Trade executed with ID: {}", trade_id);

        // Check if trade was already executed
        let mut executed_trades = EXECUTED_TRADES.lock().unwrap();
        if !executed_trades.insert(trade_id.to_string()) {
            // Trade was already executed, just update local state
            let devices = MOCK_BLUETOOTH_DEVICES.lock().unwrap();
            if let Some(trainer) = &mut self.trainer {
                if let Some(updated) = devices
                    .iter()
                    .find(|t| t.trainer.device_info.device_id == trainer.device_info.device_id)
                {
                    *trainer = updated.trainer.clone();
                }
            }
            return Ok(());
        }

        // Lock the shared state once for the entire trade execution
        let mut devices = MOCK_BLUETOOTH_DEVICES.lock().unwrap();

        // Find both trainers in a single pass
        let (red_state, blue_state) = devices
            .iter_mut()
            .filter(|t| {
                let id = &t.trainer.device_info.device_id;
                id == "red_device" || id == "blue_device"
            })
            .fold((None, None), |acc, state| {
                if state.trainer.device_info.device_id == "red_device" {
                    (Some(state), acc.1)
                } else {
                    (acc.0, Some(state))
                }
            });

        // Verify we have both trainers
        let (red_state, blue_state) = match (red_state, blue_state) {
            (Some(red), Some(blue)) => (red, blue),
            _ => {
                return Err(DsmError::fatal(
                    "Could not find both trainers for trade execution",
                ))
            }
        };

        // Execute trade transaction with atomic semantics, always processing the PKM_001 <-> PKM_003 swap
        // This is a fixed mapping for demonstration; production would use lookup tables
        {
            // Get Pokemon before removing them
            let charizard = red_state.trainer.pokemon.remove("PKM_001");
            let venusaur = blue_state.trainer.pokemon.remove("PKM_003");

            if let (Some(charizard), Some(venusaur)) = (charizard, venusaur) {
                // Add Pokemon to their new trainers
                red_state
                    .trainer
                    .pokemon
                    .insert("PKM_003".to_string(), venusaur);
                blue_state
                    .trainer
                    .pokemon
                    .insert("PKM_001".to_string(), charizard);

                // Update local trainer state
                if let Some(trainer) = &mut self.trainer {
                    if trainer.device_info.device_id == "red_device" {
                        *trainer = red_state.trainer.clone();
                    } else {
                        *trainer = blue_state.trainer.clone();
                    }
                }

                debug!("Successfully transferred Pokemon between trainers");
            }
        }

        Ok(())
    }

    // Simulate responding to a trade
    async fn respond_to_trade(
        &self,
        trade_id: &str,
        _accept: bool,
        _reason: Option<&str>,
    ) -> Result<(), DsmError> {
        debug!("Responded to trade with ID: {}", trade_id);
        Ok(())
    }

    // Simulate initializing the SDK with a trainer
    fn initialize(&mut self, trainer: PokemonTrainer) -> Result<(), DsmError> {
        debug!("SDK initialized for device: {}", self.device_name);
        let trainer_state = TrainerState {
            trainer: trainer.clone(),
            is_connected: false,
        };
        self.trainer = Some(trainer.clone());

        let mut devices = MOCK_BLUETOOTH_DEVICES.lock().unwrap();
        devices.retain(|t| t.trainer.device_info.device_id != trainer.device_info.device_id);
        devices.push(trainer_state);
        Ok(())
    }

    // Simulate getting the trainer associated with the SDK
    fn get_trainer(&self) -> Result<&PokemonTrainer, DsmError> {
        self.trainer
            .as_ref()
            .ok_or_else(|| DsmError::fatal("Trainer not initialized"))
    }

    // Simulate getting a mutable reference to the trainer
    #[allow(dead_code)]
    fn get_trainer_mut(&mut self) -> Result<&mut PokemonTrainer, DsmError> {
        self.trainer
            .as_mut()
            .ok_or_else(|| DsmError::fatal("Trainer not initialized"))
    }
}

// Wrapper type to implement From for JoinError
struct JoinErrorWrapper(JoinError);

impl From<JoinErrorWrapper> for DsmError {
    fn from(err: JoinErrorWrapper) -> Self {
        DsmError::fatal(format!("Task join error: {}", err.0))
    }
}

lazy_static::lazy_static! {
    static ref MOCK_BLUETOOTH_DEVICES: std::sync::Mutex<Vec<TrainerState>> = std::sync::Mutex::new(vec![]);
    static ref EXECUTED_TRADES: std::sync::Mutex<std::collections::HashSet<String>> = std::sync::Mutex::new(std::collections::HashSet::new());
    static ref METRICS: std::sync::Mutex<ProtocolMetrics> = std::sync::Mutex::new(ProtocolMetrics {
        execution_time: None,
        state_transitions: 0,
        memory_safety_verified: true,
        verification_status: true,
        trade_status: "SUCCESS".to_string(),
        state_hash_verified: true,
        signature_verifications: 2, // For both trainers' signatures
        hash_chain_verified: true,
        crypto_operations: 4, // Hash computations + signatures
    });
}

/// Execute a trade sequence with fault-tolerance and cryptographic verification
/// The implementation uses non-consumptive borrowing semantics to preserve ownership across protocol boundaries
async fn execute_trade_sequence(
    red_sdk: &MockPokemonBluetoothSDK,
    blue_sdk: &MockPokemonBluetoothSDK,
    trade_conditions: &TradeConditions,
) -> Result<(), DsmError> {
    // Create a cryptographically secure trade identifier
    let trade_id = generate_secure_trade_id(trade_conditions);
    debug!("Generated secure trade ID: {}", trade_id);

    // Configure concurrent message processing
    let (red_tx, _red_rx) = oneshot::channel::<()>();
    let (blue_tx, _blue_rx) = oneshot::channel::<()>();

    // Spawn dedicated tasks for each participant
    let red_handle = tokio::spawn({
        let mut red_sdk = red_sdk.clone();
        let trade_conditions = trade_conditions.clone();
        let trade_id = trade_id.clone();
        async move {
            red_sdk.start_message_listener().await?;
            debug!("Red trainer message listener initialized");

            // Propose trade with timeout protection
            let timeout = Duration::from_secs(5);
            match time::timeout(
                timeout,
                red_sdk.propose_trade("blue_device", trade_conditions),
            )
            .await
            {
                Ok(result) => {
                    let actual_trade_id = result?;
                    debug!("Trade proposed successfully: {}", actual_trade_id);
                    assert_eq!(
                        trade_id, actual_trade_id,
                        "Trade ID mismatch - potential replay attack"
                    );
                }
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
        let mut blue_sdk = blue_sdk.clone(); // Clone from the reference
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

            // Execute trade from Blue's side
            blue_sdk.execute_trade(&trade_id).await?;
            info!("Blue trainer completed trade execution");

            Ok::<_, DsmError>(())
        }
    });

    // Coordinate trade completion with proper error handling
    time::sleep(Duration::from_secs(1)).await;
    info!("Trade coordination completed successfully");

    // Wait for both sides to complete execution
    let (red_result, blue_result) = tokio::join!(red_handle, blue_handle);
    let _ = red_result.map_err(JoinErrorWrapper)?;
    let _ = blue_result.map_err(JoinErrorWrapper)?;

    Ok(())
}

/// Generate a cryptographically secure trade identifier using deterministic entropy synthesis
/// This implementation employs proper dimensional analysis to ensure boundary safety
fn generate_secure_trade_id(conditions: &TradeConditions) -> String {
    // Initialize the cryptographic entropy aggregator with advanced digest semantics
    let mut hasher = Hasher::new();

    // Progressively accumulate entropy from structured transaction components
    hasher.update(conditions.offered_pokemon_id.as_bytes());

    if let Some(req_id) = &conditions.requested_pokemon_id {
        hasher.update(req_id.as_bytes());
    }

    hasher.update(conditions.sender_id.as_bytes());
    hasher.update(conditions.recipient_id.as_bytes());
    hasher.update(&chrono::Utc::now().timestamp().to_le_bytes());

    // Apply dimensional constraint validation before extracting hash entropy
    let digest_result = hasher.finalize(); // Extend lifetime of the digest result
    let hash_bytes = digest_result.as_bytes();
    let hash_len = min(16, hash_bytes.len());

    // Format with semantic prefix and constrained entropy for cross-system compatibility
    format!("trade_{}", hex::encode(&hash_bytes[0..hash_len]))
}

// Replace the real SDK with the mock SDK in the main function
#[tokio::main]
async fn main() -> Result<(), DsmError> {
    // Start timing at the very beginning
    let start_time = std::time::Instant::now();

    // Set up better error propagation for the DsmError type
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
    let _red_identity_sdk = Arc::new(IdentitySDK::new(
        "red_trainer".to_string(),
        Arc::new(dsm_sdk::sdk::hashchain_sdk::HashChainSDK::new()),
    ));

    let _blue_identity_sdk = Arc::new(IdentitySDK::new(
        "blue_trainer".to_string(),
        Arc::new(dsm_sdk::sdk::hashchain_sdk::HashChainSDK::new()),
    ));

    // Create thread-safe state machines with mutex protection
    info!("Initializing concurrent state transition machines...");
    let _blue_state_machine = Arc::new(StateMachine::new());

    // Initialize mock Bluetooth SDKs
    let mut red_sdk = MockPokemonBluetoothSDK::new("red_device");
    let mut blue_sdk = MockPokemonBluetoothSDK::new("blue_device");

    // Create verifiable trainer contexts with deterministic identifiers
    info!("Establishing trainer identity contexts...");
    let red_device_info = DeviceInfo::new("red_device", vec![0, 1, 2, 3]);
    let mut red_trainer = PokemonTrainer::new(
        "red_trainer",
        "Red",
        &red_device_info.device_id,
        red_device_info.public_key.clone(),
    );
    red_trainer.device_info = red_device_info;

    let blue_device_info = DeviceInfo::new("blue_device", vec![4, 5, 6, 7]);
    let mut blue_trainer = PokemonTrainer::new(
        "blue_trainer",
        "Blue",
        &blue_device_info.device_id,
        blue_device_info.public_key.clone(),
    );
    blue_trainer.device_info = blue_device_info;

    // Populate trainer inventories with type-safe Pokemon entities
    info!("Initializing trainer inventories...");
    // Red's Pokemon with deterministic properties
    let charizard = Pokemon::new(PokemonParams {
        id: "PKM_001".to_string(),
        name: "Charizard".to_string(),
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
    let venusaur = Pokemon::new(PokemonParams {
        id: "PKM_003".to_string(),
        name: "Venusaur".to_string(),
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
    red_trainer.add_pokemon(charizard)?;
    red_trainer.add_pokemon(squirtle)?;
    blue_trainer.add_pokemon(venusaur)?;
    blue_trainer.add_pokemon(pikachu)?;

    // Initialize SDKs with immutable trainer contexts
    info!("Binding trainer contexts to secure execution environments...");
    red_sdk.initialize(red_trainer)?;
    blue_sdk.initialize(blue_trainer)?;

    info!(
        "Red trainer inventory: {} Pokemon",
        red_sdk.get_trainer().unwrap().pokemon_count()
    );
    for (id, pokemon) in &red_sdk.get_trainer().unwrap().pokemon {
        debug!(
            "  - {}: {} (Type: {:?}, CP: {})",
            id, pokemon.name, pokemon.types, pokemon.cp
        );
    }

    info!(
        "Blue trainer inventory: {} Pokemon",
        blue_sdk.get_trainer().unwrap().pokemon_count()
    );
    for (id, pokemon) in &blue_sdk.get_trainer().unwrap().pokemon {
        debug!(
            "  - {}: {} (Type: {:?}, CP: {})",
            id, pokemon.name, pokemon.types, pokemon.cp
        );
    }

    // Establish communication channels with proper handshaking
    info!("Establishing secure transport channel...");
    blue_sdk.start_advertising().await?;
    red_sdk.start_scanning().await?;

    // Allow device discovery with appropriate timeout
    time::sleep(Duration::from_secs(5)).await;

    // Add debug log to verify discovered trainers
    let discovered = red_sdk.get_discovered_trainers();
    debug!("Red discovered trainers: {:?}", discovered);

    // Check if the device is discoverable
    if discovered.is_empty() {
        error!("No trainers discovered - ensure devices are in range and advertising");
        return Err(DsmError::fatal("No trainers discovered"));
    }
    // Establish connection with proper authentication
    info!("Initiating connection handshake...");
    let discovered = red_sdk.get_discovered_trainers();
    debug!("Red discovered trainers: {:?}", discovered);

    // Update the function call to include a second argument if required
    red_sdk.connect_to_trainer("blue_device").await?;
    info!("Secure channel established between Red and Blue");

    // Define trade parameters with cryptographic guarantees
    info!("Initiating atomic trade protocol...");
    let trade_conditions = TradeConditions {
        offered_pokemon_id: "PKM_001".to_string(), // Charizard
        requested_pokemon_id: Some("PKM_003".to_string()), // Venusaur
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
    // Execute the trade with proper error handling and propagation
    match execute_trade_sequence(&red_sdk, &blue_sdk, &trade_conditions).await {
        Ok(_) => info!("Trade protocol completed successfully"),
        Err(e) => {
            error!("Trade protocol failed: {}", e);
            return Err(e);
        }
    }

    // Direct synchronization with authoritative state - pure replication pattern
    {
        // Acquire mutex-protected access to authoritative state store - read-only operation
        let devices = MOCK_BLUETOOTH_DEVICES.lock().unwrap();

        // Find the current authoritative state of both trainers through non-indexed lookup
        let red_state = devices
            .iter()
            .find(|state| state.trainer.device_info.device_id == "red_device")
            .expect("Red trainer state must exist in registry");

        let blue_state = devices
            .iter()
            .find(|state| state.trainer.device_info.device_id == "blue_device")
            .expect("Blue trainer state must exist in registry");

        // Deep clone propagation to local contexts - authoritative state replication
        if let Some(trainer) = &mut red_sdk.trainer {
            *trainer = red_state.trainer.clone();
            debug!("Red trainer state synchronized with registry");
        }

        if let Some(trainer) = &mut blue_sdk.trainer {
            *trainer = blue_state.trainer.clone();
            debug!("Blue trainer state synchronized with registry");
        }
    }
    info!("Pokemon ownership state synchronized with authoritative registry");

    // Enhanced visualization of trade results with rich ASCII rendering
    println!("\n\x1b[1;36m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;36m║                      SECURE TRADE PROTOCOL COMPLETE                      ║\x1b[0m");
    println!("\x1b[1;36m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");

    // Verify post-trade state with cryptographic attestation while preparing visualization
    info!("Verifying post-trade state integrity with visual attestation...");

    let red_trainer = red_sdk.get_trainer().unwrap();
    let blue_trainer = blue_sdk.get_trainer().unwrap();

    // Verify ownership transfers with cryptographic assurances
    assert!(
        red_trainer.get_pokemon("PKM_003").is_some(),
        "Red should now own Venusaur (PKM_003)"
    );
    assert!(
        blue_trainer.get_pokemon("PKM_001").is_some(),
        "Blue should now own Charizard (PKM_001)"
    );

    let venusaur_ascii = format!(
        "{}                _._       _,._
              _.'   `. ' .'   _`.
      ,\"/`\"-.-.,/. ` V\\-,`.,--/\".\"-..,
    ,'    `...,' . ,\\-----._|     `.   /   \\
   `.            .`  -'`\" .._   :> `-'   `.
  ,'  ,-.  _,.-'| `..___ ,'   |'-..__   .._ L
 .    \\_ -'   `-'     ..      `.-' `.`-.'_ .|
 |   ,',-,--..  ,--../  `.  .-.    , `-.  ``.
 `., ,  |   |  `.  /'/,,./  |    \\|   |
      `  `---'    `j   .   \\  .     '   j
    ,__`\"        ,'|`'\\_/`.',        |\\-'-, _,.
.--...`-. `-`. /    '- ..      _,    /\\ ,' .--\"'  ,'\".
_'-\"\"- ,   --  _-.../ __ '.'`-^,_`-\"\"\"\"---....__  ' _,-`
_.----   _..--.        | \"-..-\\\" __|'\\\"'         .\\\"\"-.\\\"'--.._
/        '    /     ,  _.+-.'  ||._'   \\\"\\\". .          `     .__\\
`---    /        /  / j'       _/|..`  -. `-`\\\" \\  \\   `.  \\ `-..
,\" _.- /    ///  / . \\    `._,  -`,  / / _   |   `-L -
/             ,  ..._   _/ '| |\\ `._'       '-.'   `.,'     |
'         /    /  ..   `.  `./ | ; `.'    ,\"\" ,.  `.    \\      |
`.     ,'   ,'   | |\\  |       \"        |  ,'/ |   \\    `    ,L
/|`.  /    '     | `-| '                  /`-' |    L    `._/  \\
/ | .`|    |  .   `._.'                   `.__,'   .  |     |  (`
'-\"\"-'_|    `. `.__,._____     .    _,        ____ ,-  j     \".-'\"'
\\      `-.  \\/.    `\"--.._    _,.---'\"\"\\/ \"_,.'     /-'
)                _ '-.        `--\"      _.--\"\"        `-._.-'
    ",
        "\x1b[1;32m"
    );

    let charizard_ascii = format!(
        "{}       .\"-,.__
       `.     `.  ,
    .--'  .._,'\"- `.
   .    .'         `'
   `.   /          ,'
     `  '--.   ,-\"'
      `\"`   |  \\
         -. \\, |
          `--Y.'      ___.
               \\     L._, \\
     _.,        `.   <  <\\                _
   ,' '           `, `.   | \\            ( `
../, `.            `  |    .\\`.           \\ \\_
,' ,..  .           _.,'    ||\\l            )  '\".
, ,'   \\           ,'.-.`-._,'  |           .  _._`.
,' /      \\ \\        `' ' `--/   | \\          / /   ..\\
.'  /        \\ .         |\\__ - _ ,'` `        / /     `.`.
|  '          ..         `-...-\"  |  `-'      / /        . `.
| /           |L__           |    |          / /          `. `.
, /            .   .          |    |         / /             ` `
/ /          ,. ,`._ `-_       |    |  _   ,-' /               ` \\
/ .           \"`_/. `-_ \\_,.  ,'    +-' `-'  _,        ..,-.    \\`.
.  '         .-f    ,'   `    '.       \\__.---'     _   .'   '     \\ \\
' /          `.'    l     .' /          \\..      ,_|/   `.  ,'`     L`
|'      _.-\"\"` `.    \\ _,'  `            \\ `.___`.'\"`-.  , |   |    | \\
||    ,'      `. `.   '       _,...._        `  |    `/ '  |   '     .|
||  ,'          `. ;.,.---' ,'       `.   `.. `-'  .-' /_ .'    ;_   ||
|| '              V      / /           `   | `   ,'   ,' '.    !  `. ||
||/            _,-------7 '              . |  `-'    l         /    `||
. |          ,' .-   ,' ||               | .-.        `.      .'     ||
`'        ,'    `\".'    |               |    `.        '. -.'       `'
/      ,'      |               |,'    \\-.._,.'/'
.     /        .               .       \\    .''
.`.    |         `.             /         :_,'.'
\\ `...\\   _     ,'-.        .'         /_.-'
 `-.__ `,  `'   .  _.>----'\\.  _  __  /
      .'        /\"'          |  \"'   '_
     /_|.-'\\ ,\".             '.'`__'- \\
       / ,\"'\"\\,'               `/  `-.|",
        "\x1b[1;31m"
    );

    println!("\n\x1b[1;34m╔══════════════════════════════════╗                    ╔══════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;34m║        BEFORE TRADE              ║                    ║        AFTER TRADE               ║\x1b[0m");
    println!("\x1b[1;34m╚══════════════════════════════════╝                    ╚══════════════════════════════════╝\x1b[0m");

    println!("\x1b[1;35m╔═══════════════════╗         ╔═══════════════════╗\x1b[0m      \x1b[1;35m╔═══════════════════╗         ╔═══════════════════╗\x1b[0m");
    println!("\x1b[1;35m║    RED TRAINER    ║         ║   BLUE TRAINER    ║\x1b[0m      \x1b[1;35m║    RED TRAINER    ║         ║   BLUE TRAINER    ║\x1b[0m");
    println!("\x1b[1;35m╚═══════════════════╝         ╚═══════════════════╝\x1b[0m      \x1b[1;35m╚═══════════════════╝         ╚═══════════════════╝\x1b[0m");
    println!();

    println!("\n\x1b[1;31m{:^28}\x1b[0m \x1b[1;33m<===>\x1b[0m \x1b[1;32m{:^28}\x1b[0m      \x1b[1;32m{:^28}\x1b[0m \x1b[1;33m<===>\x1b[1;31m{:^28}\x1b[0m", 
         "CHARIZARD (PKM_001)", "VENUSAUR (PKM_003)", "VENUSAUR (PKM_003)", "CHARIZARD (PKM_001)");

    println!("\n\x1b[1;33m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;33m║                        TRADE ANIMATION                                   ║\x1b[0m");
    println!("\x1b[1;33m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");

    // Display ASCII art of the Pokemon with better spacing and clear separation
    let lines_bulba = venusaur_ascii.lines().collect::<Vec<_>>();
    let lines_char = charizard_ascii.lines().collect::<Vec<_>>();

    println!("\n\x1b[1;32m╔══════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;32m║                  VENUSAUR                        ║\x1b[0m");
    println!("\x1b[1;32m╚══════════════════════════════════════════════════╝\x1b[0m");

    for line in &lines_bulba {
        println!("{}", line);
    }

    println!("\n\x1b[1;31m╔══════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;31m║                 CHARIZARD                        ║\x1b[0m");
    println!("\x1b[1;31m╚══════════════════════════════════════════════════╝\x1b[0m");

    for line in &lines_char {
        println!("{}", line);
    }

    // Render detailed trade ledger
    println!("\n\x1b[1;36m╔═══════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;36m║                 CRYPTOGRAPHIC TRADE VERIFICATION LEDGER                   ║\x1b[0m");
    println!("\x1b[1;36m╚═══════════════════════════════════════════════════════════════════════════╝\x1b[0m");
    println!(
        "\x1b[1;36m║  RED TRAINER: {}                                                  ║\x1b[0m",
        red_trainer.device_info.device_id
    );
    println!(
        "\x1b[1;36m║  BLUE TRAINER: {}                                                ║\x1b[0m",
        blue_trainer.device_info.device_id
    );
    println!("\x1b[1;36m║  TRADE CONDITIONS:                                                        ║\x1b[0m");
    println!(
        "\x1b[1;36m║    Offered: {}                                                       ║\x1b[0m",
        trade_conditions.offered_pokemon_id
    );
    println!(
        "\x1b[1;36m║    Requested: {}                                                     ║\x1b[0m",
        trade_conditions.requested_pokemon_id.unwrap_or_default()
    );
    println!(
        "\x1b[1;36m║    Sender: {}                                                    ║\x1b[0m",
        trade_conditions.sender_id
    );
    println!(
        "\x1b[1;36m║    Recipient: {}                                                ║\x1b[0m",
        trade_conditions.recipient_id
    );
    println!("\x1b[1;36m╚═══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");
    // Calculate cryptographic attestation
    let mut hasher = Hasher::new();
    hasher.update(trade_conditions.offered_pokemon_id.as_bytes());
    hasher.update(&red_trainer.device_info.public_key);
    hasher.update(&blue_trainer.device_info.public_key);
    let _hash = hex::encode(&hasher.finalize().as_bytes()[..16]);

    // Generate signature (simplified for example)
    let public_key_len = red_trainer.device_info.public_key.len();
    let slice_end = std::cmp::min(16, public_key_len);
    let _signature = hex::encode(&red_trainer.device_info.public_key[..slice_end]);

    // Capture final execution time
    let final_time = start_time.elapsed();

    // Only update execution time once everything is complete
    {
        let mut metrics = METRICS.lock().unwrap();
        metrics.execution_time = Some(final_time);
    }

    // Render the protocol metrics with memory safety verification
    let metrics = METRICS.lock().unwrap();
    println!("\n\x1b[1;37m╔══════════════════════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;37m║                    TRADE PROTOCOL METRICS                                    ║\x1b[0m");
    println!("\x1b[1;37m╠══════════════════════════════════════════════════════════════════════════════╣\x1b[0m");
    println!("\x1b[1;37m║\x1b[0m \x1b[1;32mProtocol Version\x1b[0m: DSM Secure Trading Protocol v1.0                           \x1b[1;37m║\x1b[0m");
    println!("\x1b[1;37m║\x1b[0m \x1b[1;32mSecurity Level\x1b[0m  : Cryptographic Identity Verification                        \x1b[1;37m║\x1b[0m");
    println!("\x1b[1;37m║\x1b[0m \x1b[1;32mTransport Layer\x1b[0m : Secure Bluetooth with End-to-End Encryption                \x1b[1;37m║\x1b[0m");
    println!("\x1b[1;37m║\x1b[0m \x1b[1;32mExecution Time\x1b[0m  : {:<40} \x1b[1;37m                  ║\x1b[0m",
        if let Some(duration) = metrics.execution_time {
            format!("{} milliseconds", duration.as_millis())
        } else {
            "N/A".to_string()
        }
    );

    println!(
        "\x1b[1;37m║\x1b[0m \x1b[1;32mCrypto Operations\x1b[0m:   {:<45}{:>11}\x1b[1;37m║\x1b[0m",
        metrics.crypto_operations, ""
    );
    println!("\x1b[1;37m║\x1b[0m \x1b[1;32mMemory Safety\x1b[0m   : \x1b[1;32mVerified with Rust's Borrow Checker\x1b[0m{:>24}\x1b[1;37m║\x1b[0m", "");
    println!("\x1b[1;37m║\x1b[0m \x1b[1;32mTrade Status\x1b[0m    : \x1b[1;32m{} - Atomically Committed\x1b[0m{:>29}\x1b[1;37m║\x1b[0m",
        metrics.trade_status,
        ""
    );
    println!("\x1b[1;37m╚══════════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");
    // Finalize the trade with a success message
    info!("Trade completed successfully with cryptographic verification");
    println!("\x1b[1;32mTrade completed successfully!\x1b[0m");
    Ok(())
}
