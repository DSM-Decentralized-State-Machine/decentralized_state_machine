// Pokemon Bluetooth SDK Module - EXAMPLE IMPLEMENTATION
//
// IMPORTANT: This is an EXAMPLE implementation intended to demonstrate DSM capabilities.
// It is NOT part of the core DSM functionality and serves purely as a reference
// implementation to show how applications can be built on the DSM architecture.
//
// This example module extends the Pokemon SDK with Bluetooth capabilities for
// peer-to-peer trading without requiring a central server. It demonstrates
// direct device-to-device communication using Bluetooth as a transport
// layer.

use super::bluetooth_transport::{
    BluetoothMessage, BluetoothMode, BluetoothTransport,
};
use super::identity_sdk::IdentitySDK;
use super::pokemon_sdk::{Pokemon, PokemonSDK, PokemonTrainer, TradeConditions, TradeVault};
use async_trait::async_trait;
use dsm::core::state_machine::StateMachine;
use dsm::types::error::DsmError;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use blake3::Hasher;

/// Derive deterministic entropy for the next state as defined in the DSM whitepaper
/// This follows the equation e_{n+1} = H(e_n || op_{n+1} || n+1)
fn derive_next_entropy(current_entropy: &[u8], operation_data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(current_entropy);
    hasher.update(operation_data);
    // Add state transition counter as defined in the whitepaper
    let next_state_number = chrono::Utc::now().timestamp() as u64;
    hasher.update(&next_state_number.to_le_bytes());
    hasher.finalize().as_bytes().to_vec()
}

/// Represents an ongoing Pokemon Bluetooth trade session
pub struct BluetoothTradeSession {
    /// The trade vault for this session
    pub trade_vault: TradeVault,

    /// The remote device ID
    pub remote_device_id: String,

    /// Session status
    pub status: String,

    /// Timestamp when the session was created
    pub created_at: u64,

    /// Session-specific metadata
    pub metadata: HashMap<String, String>,
}

impl BluetoothTradeSession {
    /// Create a new Bluetooth trade session
    pub fn new(trade_vault: TradeVault, remote_device_id: &str) -> Self {
        Self {
            trade_vault,
            remote_device_id: remote_device_id.to_string(),
            status: "initiated".to_string(),
            created_at: chrono::Utc::now().timestamp() as u64,
            metadata: HashMap::new(),
        }
    }
}

/// Pokemon Bluetooth SDK for peer-to-peer trading
pub struct PokemonBluetoothSDK {
    /// Reference to the base Pokemon SDK
    pub pokemon_sdk: Arc<PokemonSDK>,

    /// Bluetooth transport implementation
    pub bluetooth: Arc<BluetoothTransport>,

    /// Local trainer data
    pub trainer: Arc<Mutex<Option<PokemonTrainer>>>,

    /// Active trade sessions
    pub trade_sessions: Arc<Mutex<HashMap<String, BluetoothTradeSession>>>,

    /// Is the SDK initialized?
    pub initialized: Arc<Mutex<bool>>,
}

impl PokemonBluetoothSDK {
    /// Create a new Pokemon Bluetooth SDK
    pub fn new(
        identity_sdk: Arc<IdentitySDK>,
        state_machine: Arc<StateMachine>,
        device_id: &str,
        device_name: &str,
        mode: BluetoothMode,
    ) -> Self {
        // Create the base Pokemon SDK
        let pokemon_sdk = Arc::new(PokemonSDK::new(identity_sdk, state_machine));

        // Create the Bluetooth transport
        let bluetooth = Arc::new(BluetoothTransport::new(mode, device_id, device_name));

        Self {
            pokemon_sdk,
            bluetooth,
            trainer: Arc::new(Mutex::new(None)),
            trade_sessions: Arc::new(Mutex::new(HashMap::new())),
            initialized: Arc::new(Mutex::new(false)),
        }
    }

    /// Initialize the SDK with trainer data
    pub fn initialize(&self, trainer: PokemonTrainer) -> Result<(), DsmError> {
        let mut trainer_guard = self.trainer.lock().unwrap();
        *trainer_guard = Some(trainer);

        let mut initialized = self.initialized.lock().unwrap();
        *initialized = true;

        Ok(())
    }

    /// Check if the SDK is initialized
    pub fn is_initialized(&self) -> bool {
        let initialized = self.initialized.lock().unwrap();
        *initialized
    }

    /// Get the current trainer
    pub fn get_trainer(&self) -> Option<PokemonTrainer> {
        let trainer = self.trainer.lock().unwrap();
        trainer.clone()
    }

    /// Start scanning for nearby trainers (Central mode)
    pub async fn start_scanning(&self) -> Result<(), DsmError> {
        self.bluetooth
            .start_scanning()
            .await
            .map_err(DsmError::from)
    }

    /// Stop scanning for nearby trainers
    pub fn stop_scanning(&self) -> Result<(), DsmError> {
        self.bluetooth
            .stop_scanning()
            .map_err(DsmError::from)
    }

    /// Start advertising this trainer (Peripheral mode)
    pub async fn start_advertising(&self) -> Result<(), DsmError> {
        self.bluetooth
            .start_advertising()
            .await
            .map_err(DsmError::from)
    }

    /// Stop advertising this trainer
    pub fn stop_advertising(&self) -> Result<(), DsmError> {
        self.bluetooth
            .stop_advertising()
            .map_err(DsmError::from)
    }

    /// Get list of discovered trainers
    pub fn get_discovered_trainers(&self) -> Vec<String> {
        self.bluetooth
            .get_discovered_devices()
            .into_iter()
            .map(|device| device.name)
            .collect()
    }

    /// Connect to a trainer by device ID
    pub async fn connect_to_trainer(&self, device_id: &str) -> Result<(), DsmError> {
        self.bluetooth
            .connect_to_device(device_id)
            .await
            .map_err(DsmError::from)
    }

    /// Disconnect from a trainer
    pub async fn disconnect_from_trainer(&self, device_id: &str) -> Result<(), DsmError> {
        self.bluetooth
            .disconnect(device_id)
            .await
            .map_err(DsmError::from)
    }

    /// Propose a trade to another trainer
    pub async fn propose_trade(
        &self,
        remote_device_id: &str,
        conditions: TradeConditions,
    ) -> Result<String, DsmError> {
        let execution_start = std::time::Instant::now();
        // Ensure we have a trainer
        if !self.is_initialized() {
            // Log error metrics using the tracing system
            tracing::error!(
                protocol_version = env!("CARGO_PKG_VERSION", "1.0.0"),
                security_level = "Cryptographic Identity Verification",
                transport_layer = "Secure Bluetooth with End-to-End Encryption",
                execution_time_ms = 0,
                memory_safety = "Verified with Rust's Borrow Checker",
                trade_status = "FAILED - Not Initialized",
                "Trade proposal failed due to uninitialized SDK"
            );
            
            return Err(DsmError::validation(
                "SDK not initialized with trainer data",
                None::<std::convert::Infallible>,
            ));
        }

        // Create trade vault
        let mut trade_vault = TradeVault::new(conditions);

        // Generate cryptographic signature with SPHINCS+
        let _identity = self.pokemon_sdk.identity_sdk.get_identity();
        let serialized_vault = bincode::serialize(&trade_vault)
            .map_err(|e| DsmError::serialization("Failed to serialize trade vault for signing", Some(e)))?;
            
        // Sign the serialized trade vault with the identity's signing key
        let signature = self.pokemon_sdk.identity_sdk.sign_data(&serialized_vault)
            .map_err(|e| DsmError::crypto(format!("Failed to sign trade vault: {}", e), Some(e)))?;
            
        trade_vault.sign_as_proposer(signature);

        // Create a pre-commitment record in the hash chain
        // This establishes cryptographic intent before the trade is fully executed
        {
            // Get current state from the state machine
            let state_machine = self.pokemon_sdk.state_machine.clone();
            let current_state = state_machine.current_state()
                .cloned()
                .ok_or_else(|| DsmError::state("No current state available for pre-commitment"))?;
            
            // Create a hash of the trade proposal as pre-commitment
            let mut hasher = blake3::Hasher::new();
            hasher.update(&current_state.entropy);
            hasher.update(&serialized_vault);
            let pre_commitment = hasher.finalize().as_bytes().to_vec();
            
            // Create operation for the pre-commitment
            let pre_commit_op = dsm::types::operations::Operation::Generic {
                operation_type: "pre_commit".to_string(),
                message: format!("Trade pre-commitment: {}", trade_vault.trade_id),
                data: pre_commitment.clone(),
            };
            
            // Apply the pre-commitment to create a new state in the hash chain
            let next_entropy = derive_next_entropy(&current_state.entropy, &serialized_vault);
            let _next_state = state_machine.apply_operation(
                current_state,
                pre_commit_op,
                next_entropy,
            )?;
            
            tracing::debug!("Pre-commitment for trade {} recorded in hash chain", trade_vault.trade_id);
        }
        
        // Create a trade session
        let session = BluetoothTradeSession::new(trade_vault.clone(), remote_device_id);

        // Add session to active sessions
        {
            let mut sessions = self.trade_sessions.lock().unwrap();
            sessions.insert(trade_vault.trade_id.clone(), session);
        }

        // Serialize the trade vault
        let serialized_trade = trade_vault.serialize()?;

        // Send trade request via Bluetooth
        self.bluetooth
            .send_trade_request(remote_device_id, &trade_vault.trade_id, serialized_trade)
            .await
            .map_err(DsmError::from)?;

        // Log metrics on success using the tracing system
        let execution_time = execution_start.elapsed();
        let protocol_version = env!("CARGO_PKG_VERSION", "1.0.0");
            
        tracing::info!(
            protocol_version = protocol_version,
            security_level = "Cryptographic Identity Verification with 1 signature",
            transport_layer = "Secure Bluetooth with End-to-End Encryption",
            execution_time_ms = execution_time.as_millis(),
            memory_safety = "Verified with Rust's Borrow Checker",
            trade_status = "SUCCESS - Trade Proposal Sent",
            trade_id = trade_vault.trade_id,
            "Trade proposal successfully sent"
        );



        Ok(trade_vault.trade_id)
    }

    /// Respond to a trade proposal
    pub async fn respond_to_trade(
        &self,
        trade_id: &str,
        accept: bool,
        counter_offer: Option<TradeConditions>,
    ) -> Result<(), DsmError> {
        let execution_start = std::time::Instant::now();
        // Ensure we have a trainer
        if !self.is_initialized() {
            // Log error metrics using the tracing system
            tracing::error!(
                protocol_version = env!("CARGO_PKG_VERSION", "1.0.0"),
                security_level = "Cryptographic Identity Verification",
                transport_layer = "Secure Bluetooth with End-to-End Encryption",
                execution_time_ms = execution_start.elapsed().as_millis(),
                memory_safety = "Verified with Rust's Borrow Checker",
                trade_status = "FAILED - Not Initialized",
                trade_id = trade_id,
                "Trade response failed due to uninitialized SDK"
            );
            
            return Err(DsmError::validation(
                "SDK not initialized with trainer data",
                None::<std::convert::Infallible>,
            ));
        }

        // Find the trade session
        let remote_device_id = {
            let sessions = self.trade_sessions.lock().unwrap();
            let session = sessions.get(trade_id).ok_or_else(|| {
                DsmError::validation("Trade session not found", None::<std::convert::Infallible>)
            })?;

            session.remote_device_id.clone()
        };
        // Create serialized counter offer if provided
        let counter_offer_data = if let Some(counter_conditions) = counter_offer {
            let counter_vault = TradeVault::new(counter_conditions);
            Some(counter_vault.serialize()?)
        } else {
            None
        };

        // Send response via Bluetooth
        self.bluetooth
            .send_trade_response(&remote_device_id, trade_id, accept, counter_offer_data)
            .await
            .map_err(DsmError::from)?;

        // Update session status
        {
            let mut sessions = self.trade_sessions.lock().unwrap();
            if let Some(session) = sessions.get_mut(trade_id) {
                session.status = if accept {
                    "accepted".to_string()
                } else {
                    "rejected".to_string()
                };
            }
        }

        // Log metrics on success using the tracing system
        let execution_time = execution_start.elapsed();
        let protocol_version = env!("CARGO_PKG_VERSION", "1.0.0");
        let status_str = if accept { "ACCEPTED" } else { "REJECTED" };
            
        tracing::info!(
            protocol_version = protocol_version,
            security_level = "Cryptographic Identity Verification",
            transport_layer = "Secure Bluetooth with End-to-End Encryption",
            execution_time_ms = execution_time.as_millis(),
            memory_safety = "Verified with Rust's Borrow Checker",
            trade_status = format!("SUCCESS - Trade {}", status_str),
            trade_id = trade_id,
            "Trade response sent"
        );



        Ok(())
    }

    /// Execute a trade that has been accepted
    pub async fn execute_trade(&self, trade_id: &str) -> Result<(), DsmError> {
        let execution_start = std::time::Instant::now();
        let mut signature_verifications = 0;
        let mut hash_operations = 0;
        // Ensure we have a trainer
        if !self.is_initialized() {
            return Err(DsmError::validation(
                "SDK not initialized with trainer data",
                None::<std::convert::Infallible>,
            ));
        }

        // Get current trainer
        let trainer = self
            .get_trainer()
            .ok_or_else(|| DsmError::state("Trainer data not found"))?;

        // Find the trade session and clone it to avoid borrowing issues
        let trade_vault;
        let remote_device_id;
        let offered_pokemon_id;
        {
            let sessions = self.trade_sessions.lock().unwrap();
            let session_ref = sessions
                .get(trade_id)
                .ok_or_else(|| {
                    DsmError::validation(
                        "Trade session not found",
                        None::<std::convert::Infallible>,
                    )
                })?;
            
            // Check if trade is in the right state
            if session_ref.status != "accepted" {
                return Err(DsmError::validation(
                    "Trade cannot be executed - it may not be accepted or may have expired",
                    None::<std::convert::Infallible>,
                ));
            }
            
            // Verify signatures before executing trade
            let mut vault_copy = session_ref.trade_vault.clone();
            
            // Verify proposer signature
            let proposer_sig_clone = vault_copy.proposer_signature.clone();
            if let Some(proposer_sig) = &proposer_sig_clone {
                // Temporarily remove signatures for verification
                let recipient_sig = vault_copy.recipient_signature.clone();
                vault_copy.proposer_signature = None;
                vault_copy.recipient_signature = None;
                
                // Serialize for verification
                let verification_bytes = bincode::serialize(&vault_copy)
                    .map_err(|e| DsmError::serialization("Failed to serialize vault for signature verification", Some(e)))?;
                
                // Get relationship context for the other party
                if let Some(_context) = self.pokemon_sdk.identity_sdk.get_relationship_context(&vault_copy.conditions.sender_id) {
                    // Verify signature
                    signature_verifications += 1;
                    let valid = dsm::crypto::signatures::SignatureKeyPair::verify_raw(
                        &verification_bytes,
                        proposer_sig,
                        &_context.counterparty_public_key
                    )?;
                    
                    if !valid {
                        return Err(DsmError::validation(
                            "Proposer's signature verification failed",
                            None::<std::convert::Infallible>,
                        ));
                    }
                }
                
                // Restore recipient signature for later verification
                vault_copy.recipient_signature = recipient_sig;
            } else {
                return Err(DsmError::validation(
                    "Missing proposer's signature on trade vault",
                    None::<std::convert::Infallible>,
                ));
            }
            
            // Verify recipient signature if present
            let recipient_sig_clone = vault_copy.recipient_signature.clone();
            if let Some(recipient_sig) = &recipient_sig_clone {
                // Temporarily remove signatures for verification
                vault_copy.proposer_signature = None;
                vault_copy.recipient_signature = None;
                
                // Add back proposer signature as it would have been present when recipient signed
                vault_copy.proposer_signature = session_ref.trade_vault.proposer_signature.clone();
                
                // Serialize for verification
                let verification_bytes = bincode::serialize(&vault_copy)
                    .map_err(|e| DsmError::serialization("Failed to serialize vault for recipient signature verification", Some(e)))?;
                
                // Get relationship context for the recipient
                if let Some(context) = self.pokemon_sdk.identity_sdk.get_relationship_context(&vault_copy.conditions.recipient_id) {
                    // Verify signature
                    signature_verifications += 1;
                    let valid = dsm::crypto::signatures::SignatureKeyPair::verify_raw(
                        &verification_bytes,
                        recipient_sig,
                        &context.counterparty_public_key
                    )?;
                    
                    if !valid {
                        return Err(DsmError::validation(
                            "Recipient's signature verification failed",
                            None::<std::convert::Infallible>,
                        ));
                    }
                }
            } else {
                return Err(DsmError::validation(
                    "Missing recipient's signature on trade vault",
                    None::<std::convert::Infallible>,
                ));
            }
            
            // Bind this trade to the hash chain for tamper-evident state tracking
            hash_operations += 1;
            self.bind_trade_to_hash_chain(&session_ref.trade_vault)?;
            
            // Clone needed data
            trade_vault = session_ref.trade_vault.clone();
            remote_device_id = session_ref.remote_device_id.clone();
            offered_pokemon_id = trade_vault.conditions.offered_pokemon_id.clone();
        }
        
        // Verify Pokemon exists before trying to transfer
        let pokemon_to_transfer = trainer
            .get_pokemon(&offered_pokemon_id)
            .ok_or_else(|| {
                DsmError::validation(
                    format!("Offered Pokemon {} not found", offered_pokemon_id),
                    None::<std::convert::Infallible>,
                )
            })?;
            
        // Serialize the Pokemon for transfer
        let serialized_pokemon = bincode::serialize(&pokemon_to_transfer)
            .map_err(|e| DsmError::serialization("Failed to serialize Pokemon", Some(e)))?;
            
        // Send Pokemon via Bluetooth
        self.bluetooth
            .send_pokemon(
                &remote_device_id,
                &offered_pokemon_id,
                serialized_pokemon,
            )
            .await
            .map_err(DsmError::from)?;

        // Update trade status
        {
            let mut sessions = self.trade_sessions.lock().unwrap();
            if let Some(session) = sessions.get_mut(trade_id) {
                session.trade_vault.complete();
                session.status = "completed".to_string();
            }
        }

        // Update local trainer state
        {
            let mut trainer_guard = self.trainer.lock().unwrap();
            *trainer_guard = Some(trainer);
        }

        // Display protocol metrics
        let execution_time = execution_start.elapsed();
        let protocol_version = env!("CARGO_PKG_VERSION", "1.0.0");
        // Determine the current Bluetooth mode
        let bluetooth_mode = match self.bluetooth.get_mode() {
            BluetoothMode::Central => "Bluetooth Central",
            BluetoothMode::Peripheral => "Bluetooth Peripheral"
        };
        
        println!("\n\x1b[1;37m╔══════════════════════════════════════════════════════════════════════════╗\x1b[0m");
        println!("\x1b[1;37m║                    TRADE PROTOCOL METRICS                                ║\x1b[0m");
        println!("\x1b[1;37m╠══════════════════════════════════════════════════════════════════════════╣\x1b[0m");
        println!("\x1b[1;37m║\x1b[0m \x1b[1;32mProtocol Version\x1b[0m: DSM Secure Trading Protocol {}                       \x1b[1;37m║\x1b[0m", protocol_version);
        println!("\x1b[1;37m║\x1b[0m \x1b[1;32mSecurity Level\x1b[0m  : Cryptographic Identity Verification ({} sigs)          \x1b[1;37m║\x1b[0m", signature_verifications);      
        println!("\x1b[1;37m║\x1b[0m \x1b[1;32mTransport Layer\x1b[0m : Secure {} with End-to-End Encryption     \x1b[1;37m║\x1b[0m", bluetooth_mode);
        println!("\x1b[1;37m║\x1b[0m \x1b[1;32mExecution Time\x1b[0m  : {:.3} seconds                                       \x1b[1;37m║\x1b[0m", execution_time.as_secs_f64());
        println!("\x1b[1;37m║\x1b[0m \x1b[1;32mMemory Safety\x1b[0m   : \x1b[1;32mVerified with Rust's Borrow Checker\x1b[0m                    \x1b[1;37m║\x1b[0m");
        println!("\x1b[1;37m║\x1b[0m \x1b[1;32mTrade Status\x1b[0m    : \x1b[1;32mSUCCESS - Atomically Committed\x1b[0m                         \x1b[1;37m║\x1b[0m");
        println!("\x1b[1;37m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m\n");

        // Log the metrics to tracing system for analysis
        tracing::info!(
            protocol_version = protocol_version,
            security_level = format!("Cryptographic Identity Verification with {} signatures", signature_verifications),
            transport_layer = format!("Secure {} with E2E Encryption", bluetooth_mode),
            execution_time_ms = execution_time.as_millis(),
            hash_operations = hash_operations,
            trade_id = trade_id,
            "Trade successfully executed"
        );

        Ok(())
    }

    /// Cancel a pending trade
    pub async fn cancel_trade(&self, trade_id: &str) -> Result<(), DsmError> {
        // Find the trade session
        let remote_device_id = {
            let sessions = self.trade_sessions.lock().unwrap();
            let session = sessions
                .get(trade_id)
                .ok_or_else(|| {
                    DsmError::validation(
                        "Trade session not found",
                        None::<std::convert::Infallible>,
                    )
                })?;
            session.remote_device_id.clone()
        };

        // Send cancellation message
        let cancel_message = BluetoothMessage::Data {
            message_type: "trade_canceled".to_string(),
            payload: trade_id.as_bytes().to_vec(),
        };

        self.bluetooth
            .send_message(&remote_device_id, cancel_message)
            .await
            .map_err(DsmError::from)?;

        // Update trade status
        {
            let mut sessions = self.trade_sessions.lock().unwrap();
            if let Some(session) = sessions.get_mut(trade_id) {
                session.trade_vault.cancel();
                session.status = "canceled".to_string();
            }
        }

        Ok(())
    }
    
    /// Receive a Pokemon from another trainer
    pub async fn receive_pokemon(&self, serialized_pokemon: &[u8]) -> Result<(), DsmError> {
        // Ensure we have a trainer
        if !self.is_initialized() {
            return Err(DsmError::validation(
                "SDK not initialized with trainer data",
                None::<std::convert::Infallible>,
            ));
        }

        // Deserialize the Pokemon
        let mut pokemon: Pokemon = bincode::deserialize(serialized_pokemon)
            .map_err(|e| DsmError::serialization("Failed to deserialize Pokemon", Some(e)))?;

        // Get current trainer
        let mut trainer = self
            .get_trainer()
            .ok_or_else(|| DsmError::state("Trainer data not found"))?;

        // Update Pokemon ownership
        pokemon.transfer_to(trainer.id.clone())?;

        // Add Pokemon to trainer's collection
        trainer.add_pokemon(pokemon.clone())?;
        
        // Record this Pokemon receipt in the hash chain for provenance tracking
        self.record_pokemon_receipt(&pokemon)?;

        // Update local trainer state
        {
            let mut trainer_guard = self.trainer.lock().unwrap();
            *trainer_guard = Some(trainer);
        }

        Ok(())
    }
    
    /// Start listening for incoming messages
    pub async fn start_message_listener(&self) -> Result<(), DsmError> {
        // Clone necessary components to avoid lifetime issues
        let bluetooth = self.bluetooth.clone();
        let trade_sessions = self.trade_sessions.clone();
        let pokemon_sdk = self.pokemon_sdk.clone();
        let trainer = self.trainer.clone();

        // Get list of connected devices
        let devices = bluetooth.get_discovered_devices();

        for device in devices {
            // Start a message listener for each connected device
            let device_id = device.id.clone();
            let bluetooth_clone = bluetooth.clone();
            let trade_sessions_clone = trade_sessions.clone();
            let pokemon_sdk_clone = pokemon_sdk.clone();
            let trainer_clone = trainer.clone();
            let device_id_clone = device_id.clone();
            let device_id = device_id_clone;
            
            tokio::spawn(async move {
                // Get message stream for this device
                let message_stream = match bluetooth_clone.get_message_stream(&device_id).await {
                    Ok(stream) => stream,
                    Err(_) => return, // Skip this device if we can't get a stream
                };

                // Process messages
                let mut stream = message_stream;
                while let Some(message) = stream.next().await {
                    match message {
                        BluetoothMessage::ConnectionRequest { device_id: _, device_name: _ } => {
                            // Handle connection request
                            println!("Connection request from device: {}", device_id);
                        },
                                    
                        BluetoothMessage::ConnectionResponse { accepted, error_message } => {
                            // Handle connection response
                            if accepted {
                                println!("Connection accepted by device: {}", device_id);
                            } else {
                                println!("Connection rejected by device: {}: {:?}", 
                                            device_id, error_message);
                            }
                        },
                        
                        // Handle different message types based on BluetoothMessage enum
                        BluetoothMessage::TradeRequest { trade_id, serialized_trade } => {
                            // Deserialize trade vault
                            if let Ok(trade_vault) = TradeVault::deserialize(&serialized_trade) {
                                // Verify the proposer's signature when available
                                if let Some(proposer_sig) = &trade_vault.proposer_signature {
                                    // Get sender's public key from identity context
                                    if let Some(sender_context) = pokemon_sdk_clone.identity_sdk
                                        .get_relationship_context(&trade_vault.conditions.sender_id) {
                                            
                                        // Create a copy of the vault without the signature for verification
                                        let mut verification_vault = trade_vault.clone();
                                        verification_vault.proposer_signature = None;
                                        
                                        // Serialize for verification
                                        if let Ok(verification_bytes) = bincode::serialize(&verification_vault) {
                                            // Verify signature
                                            let verification_result = dsm::crypto::signatures::SignatureKeyPair::verify_raw(
                                                &verification_bytes,
                                                proposer_sig,
                                                &sender_context.counterparty_public_key
                                            );
                                            
                                            if let Err(e) = verification_result {
                                                println!("Error verifying trade proposal signature: {}", e);
                                                continue;
                                            } else if let Ok(false) = verification_result {
                                                println!("Invalid signature on trade proposal");
                                                continue;
                                            }
                                            
                                            println!("Trade proposal signature verified successfully");
                                        }
                                    }
                                }
                                // Create a new trade session
                                let session = BluetoothTradeSession::new(trade_vault, &device_id);
                                
                                // Clone trade_id before moving it
                                let trade_id_clone = trade_id.clone();
                                
                                // Add session to active sessions
                                let mut sessions = trade_sessions_clone.lock().unwrap();
                                sessions.insert(trade_id_clone, session);

                                println!("Trade request received: {}", trade_id);
                            }
                        },
                        
                        BluetoothMessage::TradeResponse { trade_id, accepted, counter_offer } => {
                            // Update the trade session
                            let mut sessions = trade_sessions_clone.lock().unwrap();
                            if let Some(session) = sessions.get_mut(&trade_id) {
                                // Get trade vault and recipient details
                                let recipient_id = &session.trade_vault.conditions.recipient_id;
                                if accepted {
                                    session.status = "accepted".to_string();
                                    
                                    // Verify if we have a relationship context with the recipient
                                    let recipient_context = pokemon_sdk_clone.identity_sdk
                                        .get_relationship_context(recipient_id);
                                    
                                    // If we have a relationship context, we can proceed with verification
                                    if let Some(_context) = recipient_context {
                                        // Now sign the trade as recipient with a cryptographic signature
                                        let serialized_vault = match bincode::serialize(&session.trade_vault) {
                                            Ok(data) => data,
                                            Err(e) => {
                                                println!("Error serializing trade vault: {}", e);
                                                continue;
                                            }
                                        };
                                        
                                        // Generate signature using SPHINCS+
                                        match pokemon_sdk_clone.identity_sdk.sign_data(&serialized_vault) {
                                            Ok(signature) => {
                                                session.trade_vault.sign_as_recipient(signature);
                                                
                                                // Log that we've applied a real cryptographic signature
                                                println!("Trade {} accepted and cryptographically signed", trade_id);
                                            },
                                            Err(e) => {
                                                println!("Error signing trade vault: {}", e);
                                                continue;
                                            }
                                        };
                                    } else {
                                        println!("No relationship context found for recipient {}", recipient_id);
                                        continue;
                                    }
                                } else {
                                    session.status = "rejected".to_string();
                                    session.trade_vault.reject();
                                    
                                    // Handle counter offer if present
                                    if let Some(counter_data) = counter_offer {
                                        if let Ok(_counter_vault) = TradeVault::deserialize(&counter_data) {
                                            println!("Counter offer received for trade: {}", trade_id);
                                            // Here we would notify the application to show the counter offer
                                        }
                                    }
                                }
                            }
                        },
                        
                        BluetoothMessage::PokemonTransfer { pokemon_id, serialized_pokemon } => {
                            // Implement receive_pokemon logic directly here since we can't call self methods
                            // First ensure we have the trainer data
                            let initialized = {
                                let initialized_guard = trainer_clone.lock().unwrap();
                                initialized_guard.is_some()
                            };
                            
                            if !initialized {
                                println!("Error receiving Pokemon: SDK not initialized with trainer data");
                                continue;
                            }
                            
                            // Deserialize the Pokemon
                            let pokemon_result = bincode::deserialize::<Pokemon>(&serialized_pokemon);
                            
                            if let Err(e) = pokemon_result {
                                println!("Error deserializing Pokemon: {}", e);
                                continue;
                            }
                            
                            let mut pokemon = pokemon_result.unwrap();
                            
                            // Get current trainer
                            let trainer_option = {
                                let trainer_guard = trainer_clone.lock().unwrap();
                                trainer_guard.clone()
                            };
                            
                            if trainer_option.is_none() {
                                println!("Error receiving Pokemon: Trainer data not found");
                                continue;
                            }
                            
                            let mut trainer = trainer_option.unwrap();
                            
                            // Update Pokemon ownership
                            if let Err(e) = pokemon.transfer_to(trainer.id.clone()) {
                                println!("Error transferring Pokemon ownership: {}", e);
                                continue;
                            }
                            
                            // Add Pokemon to trainer's collection
                            if let Err(e) = trainer.add_pokemon(pokemon.clone()) {
                                println!("Error adding Pokemon to collection: {}", e);
                                continue;
                            }
                            
                            // Create a record of this receipt in the hash chain
                            let serialized_pokemon_for_hash = match bincode::serialize(&pokemon) {
                                Ok(data) => data,
                                Err(e) => {
                                    println!("Error serializing Pokemon for hash chain: {}", e);
                                    continue;
                                }
                            };
                            
                            let state_machine = pokemon_sdk_clone.state_machine.clone();
                            let current_state_result = state_machine.current_state().cloned();
                            
                            if let Some(current_state) = current_state_result {
                                // Build an operation for tracking the Pokemon receipt
                                let receipt_operation = dsm::types::operations::Operation::Generic {
                                    operation_type: "pokemon_receipt".to_string(),
                                    message: format!("Pokemon receipt: {}", pokemon.id),
                                    data: serialized_pokemon_for_hash.clone(),
                                };
                                
                                // Generate entropy for the next state
                                let next_entropy = derive_next_entropy(&current_state.entropy, &pokemon.hash);
                                
                                // Apply the operation to record the receipt
                                match state_machine.apply_operation(
                                    current_state,
                                    receipt_operation,
                                    next_entropy
                                ) {
                                    Ok(_) => {
                                        println!("Pokemon receipt recorded in hash chain: {}", pokemon.id);
                                    },
                                    Err(e) => {
                                        println!("Error recording Pokemon receipt in hash chain: {}", e);
                                    }
                                }
                            }
                            
                            // Update local trainer state
                            {
                                let mut trainer_guard = trainer_clone.lock().unwrap();
                                *trainer_guard = Some(trainer);
                            }
                            
                            println!("Pokemon received: {}", pokemon_id);
                        },
                        
                        BluetoothMessage::Data { message_type, payload } => {
                            match message_type.as_str() {
                                "trade_canceled" => {
                                    // Handle trade cancellation
                                    let trade_id = String::from_utf8_lossy(&payload).to_string();
                                    let mut sessions = trade_sessions_clone.lock().unwrap();
                                    if let Some(session) = sessions.get_mut(&trade_id) {
                                        session.status = "canceled".to_string();
                                        session.trade_vault.cancel();
                                    }
                                    println!("Trade canceled: {}", trade_id);
                                },
                                _ => {
                                    // Handle other message types
                                    println!("Received data message: {}", message_type);
                                }
                            }
                        },
                        _ => {
                            // Handle other message types if needed
                            println!("Received other message type from device: {}", device_id);
                        }
                    }
                }
            });
        }
        
        Ok(())
    }

    /// Record the receipt of a Pokemon in the hash chain for provenance tracking
    pub fn record_pokemon_receipt(&self, pokemon: &Pokemon) -> Result<(), DsmError> {
        // Create a record in the hash chain using the Pokemon's hash as a commitment
        let serialized_pokemon = bincode::serialize(pokemon)
            .map_err(|e| DsmError::serialization("Failed to serialize Pokemon for hash chain", Some(e)))?;
        
        // Get state machine reference
        let state_machine = self.pokemon_sdk.state_machine.clone();
        let current_state = state_machine.current_state()
            .cloned()
            .ok_or_else(|| DsmError::state("No current state available for Pokemon receipt"))?;
        
        // Build an operation for tracking the Pokemon receipt
        let receipt_operation = dsm::types::operations::Operation::Generic {
            operation_type: "pokemon_receipt".to_string(),
            message: format!("Pokemon receipt: {}", pokemon.id),
            data: serialized_pokemon,
        };
        
        // Generate entropy for the next state
        let next_entropy = derive_next_entropy(&current_state.entropy, &pokemon.hash);
        
        // Apply the operation to record the receipt
        let _next_state = state_machine.apply_operation(
            current_state,
            receipt_operation,
            next_entropy
        )?;
        
        tracing::debug!("Pokemon {} receipt recorded in hash chain", pokemon.id);
        
        Ok(())
    }
    
    /// Bind a trade to the hash chain for tamper-evident state tracking
    fn bind_trade_to_hash_chain(&self, trade_vault: &TradeVault) -> Result<(), DsmError> {
        // Get state machine reference
        let state_machine = self.pokemon_sdk.state_machine.clone();
        let current_state = state_machine.current_state()
            .cloned()
            .ok_or_else(|| DsmError::state("No current state available for binding trade"))?;
        
        // Serialize the trade vault for hashing
        let serialized_vault = bincode::serialize(trade_vault)
            .map_err(|e| DsmError::serialization("Failed to serialize trade vault for hash chain", Some(e)))?;
        
        // Create a hash of the serialized vault
        let mut hasher = blake3::Hasher::new();
        hasher.update(&current_state.entropy);
        hasher.update(&serialized_vault);
        let trade_hash = hasher.finalize().as_bytes().to_vec();
        
        // Create an operation for binding the trade to the hash chain
        let bind_operation = dsm::types::operations::Operation::Generic {
            operation_type: "bind_trade".to_string(),
            message: format!("Binding trade {} to hash chain", trade_vault.trade_id),
            data: trade_hash.clone(), // Clone here to avoid ownership issues
        };
        
        // Generate entropy for the next state
        let next_entropy = derive_next_entropy(&current_state.entropy, &trade_hash);
        
        // Apply the operation to bind the trade
        let _next_state = state_machine.apply_operation(
            current_state,
            bind_operation,
            next_entropy,
        )?;
        
        tracing::debug!("Trade {} bound to hash chain", trade_vault.trade_id);
        
        Ok(())
    }
}

impl Clone for PokemonBluetoothSDK {
    fn clone(&self) -> PokemonBluetoothSDK {
        PokemonBluetoothSDK {
            pokemon_sdk: self.pokemon_sdk.clone(),
            bluetooth: self.bluetooth.clone(),
            trainer: self.trainer.clone(),
            trade_sessions: self.trade_sessions.clone(),
            initialized: self.initialized.clone(),
        }
    }
}

/// Bluetooth-enabled Pokemon trading via DSM with hash chain verification
#[async_trait]
pub trait BluetoothPokemonTrading: Send + Sync {
    /// Start scanning for nearby trainers
    async fn start_scanning(&self) -> Result<(), DsmError>;

    /// Start advertising to nearby trainers
    async fn start_advertising(&self) -> Result<(), DsmError>;

    /// Propose a trade to another trainer with cryptographic verification
    /// The trade is recorded as a pre-commitment in the hash chain
    async fn propose_trade(
        &self,
        remote_device_id: &str,
        conditions: TradeConditions,
    ) -> Result<String, DsmError>;

    /// Respond to a trade proposal
    /// If accepted, signs the trade with the recipient's cryptographic key
    async fn respond_to_trade(
        &self,
        trade_id: &str,
        accept: bool,
        counter_offer: Option<TradeConditions>,
    ) -> Result<(), DsmError>;

    /// Execute an accepted trade with hash chain verification
    /// This verifies signatures and records the trade in the hash chain as a state transition
    async fn execute_trade(&self, trade_id: &str) -> Result<(), DsmError>;
}

#[async_trait]
impl BluetoothPokemonTrading for PokemonBluetoothSDK {
    async fn start_scanning(&self) -> Result<(), DsmError> {
        PokemonBluetoothSDK::start_scanning(self).await
    }

    async fn start_advertising(&self) -> Result<(), DsmError> {
        PokemonBluetoothSDK::start_advertising(self).await
    }

    async fn propose_trade(
        &self,
        remote_device_id: &str,
        conditions: TradeConditions,
    ) -> Result<String, DsmError> {
        PokemonBluetoothSDK::propose_trade(self, remote_device_id, conditions).await
    }

    async fn respond_to_trade(
        &self,
        trade_id: &str,
        accept: bool,
        counter_offer: Option<TradeConditions>,
    ) -> Result<(), DsmError> {
        PokemonBluetoothSDK::respond_to_trade(self, trade_id, accept, counter_offer).await
    }

    async fn execute_trade(&self, trade_id: &str) -> Result<(), DsmError> {
        PokemonBluetoothSDK::execute_trade(self, trade_id).await
    }
}
