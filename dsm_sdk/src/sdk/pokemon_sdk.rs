//! Pokemon SDK Module - EXAMPLE IMPLEMENTATION
//!
//! IMPORTANT: This is an EXAMPLE implementation intended to demonstrate DSM capabilities.
//! It is NOT part of the core DSM functionality and serves purely as a reference
//! implementation to show how applications can be built on the DSM architecture.
//!
//! This example module implements a comprehensive Pokemon trading and management
//! system on top of the DSM architecture. It demonstrates how applications
//! can leverage DSM's secure state transitions, offline capabilities, and
//! cryptographic guarantees for gaming use cases.
//!
//! The implementation provides full support for both online and offline
//! trading scenarios, vault-based conditional trades, and integration with
//! the DSM hash chain verification system.

use super::core_sdk::CoreSDK;
use super::identity_sdk::IdentitySDK;
use blake3;
use chrono;
use dsm::core::state_machine::StateMachine;
use dsm::types::error::DsmError;
use dsm::types::state_types::DeviceInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug)]
pub struct PokemonSDK {
    pub identity_sdk: Arc<IdentitySDK>,
    pub state_machine: Arc<StateMachine>,
}

impl PokemonSDK {
    pub fn new(identity_sdk: Arc<IdentitySDK>, state_machine: Arc<StateMachine>) -> Self {
        Self {
            identity_sdk,
            state_machine,
        }
    }
}

/// Simplified SmartCommitmentSDK definition for Pokemon SDK
#[allow(dead_code)]
pub struct SmartCommitmentSDK {
    core_sdk: Arc<CoreSDK>,
}

impl SmartCommitmentSDK {
    pub fn new(core_sdk: Arc<CoreSDK>) -> Self {
        Self { core_sdk }
    }
}

/// Pokemon elemental types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PokemonType {
    Normal,
    Fire,
    Water,
    Electric,
    Grass,
    Ice,
    Fighting,
    Poison,
    Ground,
    Flying,
    Psychic,
    Bug,
    Rock,
    Ghost,
    Dragon,
    Dark,
    Steel,
    Fairy,
}

/// Pokemon rarity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PokemonRarity {
    Common,
    Uncommon,
    Rare,
    VeryRare,
    UltraRare,
    Legendary,
    Mythical,
}

/// Represents a unique Pokemon with attributes and ownership information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pokemon {
    /// Unique identifier for this Pokemon
    pub id: String,

    /// Pokemon species name
    pub name: String,

    /// Pokemon elemental type(s)
    pub types: Vec<PokemonType>,

    /// Combat power level
    pub cp: u32,

    /// Health points
    pub hp: u32,

    /// Rarity classification
    pub rarity: PokemonRarity,

    /// Evolution stage (1 = base form)
    pub evolution_stage: u8,

    /// Owner's unique identifier
    pub owner_id: String,

    /// Timestamp when this Pokemon was caught/created
    pub timestamp: u64,

    /// Unique hash of this Pokemon's attributes
    pub hash: Vec<u8>,

    /// Optional additional attributes
    pub attributes: HashMap<String, String>,
}

pub struct PokemonParams {
    pub id: String,
    pub name: String,
    pub types: Vec<PokemonType>,
    pub level: u32,
    pub hp: u32,
    pub attack: u32,
    pub defense: u32,
    pub owner_id: String,
}

impl Pokemon {
    /// Create a new Pokemon instance
    pub fn new(params: PokemonParams) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let mut pokemon = Self {
            id: params.id,
            name: params.name,
            types: params.types,
            cp: params.level * 10, // Simple CP calculation based on level
            hp: params.hp,
            rarity: PokemonRarity::Common, // Default rarity
            evolution_stage: 1,            // Base form
            owner_id: params.owner_id,
            timestamp,
            hash: Vec::new(),
            attributes: HashMap::new(),
        };

        // Add attack and defense as attributes
        pokemon
            .attributes
            .insert("attack".to_string(), params.attack.to_string());
        pokemon
            .attributes
            .insert("defense".to_string(), params.defense.to_string());

        // Compute hash after setting all fields
        pokemon.hash = pokemon.compute_hash();

        pokemon
    }

    /// Compute a deterministic hash for this Pokemon
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();

        // Add core attributes in deterministic order
        hasher.update(self.id.as_bytes());
        hasher.update(self.name.as_bytes());

        // Serialize and add types in deterministic order
        let types_bytes = bincode::serialize(&self.types).unwrap_or_default();
        hasher.update(&types_bytes);

        // Add numeric attributes
        hasher.update(&self.cp.to_le_bytes());
        hasher.update(&self.hp.to_le_bytes());

        // Add rarity and evolution stage
        let rarity_bytes = bincode::serialize(&self.rarity).unwrap_or_default();
        hasher.update(&rarity_bytes);
        hasher.update(&[self.evolution_stage]);

        // Include owner and timestamp
        hasher.update(self.owner_id.as_bytes());
        hasher.update(&self.timestamp.to_le_bytes());

        // Include all attributes in sorted order for determinism
        let mut sorted_keys: Vec<&String> = self.attributes.keys().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            if let Some(value) = self.attributes.get(key) {
                hasher.update(key.as_bytes());
                hasher.update(value.as_bytes());
            }
        }

        hasher.finalize().as_bytes().to_vec()
    }

    /// Transfer ownership to a new trainer
    pub fn transfer_to(&mut self, new_owner_id: String) -> Result<(), DsmError> {
        // Update owner
        self.owner_id = new_owner_id;

        // Add transfer timestamp to attributes
        self.attributes
            .insert("last_transfer".to_string(), chrono::Utc::now().to_rfc3339());

        // Recalculate hash after ownership change
        self.hash = self.compute_hash();

        Ok(())
    }

    /// Verify the integrity of this Pokemon
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = self.compute_hash();
        computed_hash == self.hash
    }
}

/// Represents a Pokemon Trainer with state chain integration
#[derive(Debug, Clone)]
pub struct PokemonTrainer {
    /// Trainer's unique identifier
    pub id: String,

    /// Trainer's display name
    pub name: String,

    /// Collection of owned Pokemon (by Pokemon ID)
    pub pokemon: HashMap<String, Pokemon>,

    /// State chain representing the trainer's history
    pub state_chain: Vec<String>,

    /// Device information for this trainer
    pub device_info: DeviceInfo,

    /// Token balance (coins, stardust, etc.)
    pub tokens: HashMap<String, u64>,
}

impl PokemonTrainer {
    /// Create a new Pokemon trainer
    pub fn new(id: &str, name: &str, device_id: &str, public_key: Vec<u8>) -> Self {
        // Create device info
        let device_info = DeviceInfo::new(device_id, public_key);

        Self {
            id: id.to_string(),
            name: name.to_string(),
            pokemon: HashMap::new(),
            state_chain: vec!["genesis".to_string()],
            device_info,
            tokens: HashMap::new(),
        }
    }

    /// Add a new Pokemon to the trainer's collection
    pub fn add_pokemon(&mut self, pokemon: Pokemon) -> Result<(), DsmError> {
        // Verify ownership
        if pokemon.owner_id != self.id {
            return Err(DsmError::validation(
                format!("Pokemon {} is not owned by this trainer", pokemon.id),
                None::<std::convert::Infallible>,
            ));
        }

        // Verify Pokemon integrity
        if !pokemon.verify_integrity() {
            return Err(DsmError::validation(
                format!("Pokemon {} has invalid hash", pokemon.id),
                None::<std::convert::Infallible>,
            ));
        }

        // Get Pokemon ID before moving
        let pokemon_id = pokemon.id.clone();

        // Add Pokemon to collection
        self.pokemon.insert(pokemon_id.clone(), pokemon);

        // Update state chain
        let state_entry = format!(
            "add_pokemon:{}:{}",
            self.state_chain.last().unwrap_or(&"genesis".to_string()),
            pokemon_id
        );
        self.state_chain.push(state_entry);

        Ok(())
    }

    /// Remove a Pokemon from the trainer's collection
    pub fn remove_pokemon(&mut self, pokemon_id: &str) -> Result<Pokemon, DsmError> {
        // Check if the trainer has this Pokemon
        if !self.pokemon.contains_key(pokemon_id) {
            return Err(DsmError::validation(
                format!("Pokemon {} not found in trainer's collection", pokemon_id),
                None::<std::convert::Infallible>,
            ));
        }

        // Remove Pokemon from collection
        let pokemon = self.pokemon.remove(pokemon_id).unwrap();

        // Update state chain
        let state_entry = format!(
            "remove_pokemon:{}:{}",
            self.state_chain.last().unwrap_or(&"genesis".to_string()),
            pokemon_id
        );
        self.state_chain.push(state_entry);

        Ok(pokemon)
    }

    /// Transfer a Pokemon to another trainer
    pub fn transfer_pokemon(
        &mut self,
        pokemon_id: &str,
        recipient_id: &str,
    ) -> Result<Pokemon, DsmError> {
        // Get the Pokemon
        let mut pokemon = self.remove_pokemon(pokemon_id)?;

        // Update ownership
        pokemon.transfer_to(recipient_id.to_string())?;

        // Update state chain
        let state_entry = format!(
            "transfer_pokemon:{}:{}:{}",
            self.state_chain.last().unwrap_or(&"genesis".to_string()),
            pokemon_id,
            recipient_id
        );
        self.state_chain.push(state_entry);

        Ok(pokemon)
    }

    /// Get Pokemon by ID
    pub fn get_pokemon(&self, pokemon_id: &str) -> Option<&Pokemon> {
        self.pokemon.get(pokemon_id)
    }

    /// Count Pokemon by type
    pub fn count_by_type(&self, pokemon_type: &PokemonType) -> usize {
        self.pokemon
            .values()
            .filter(|p| p.types.contains(pokemon_type))
            .count()
    }

    /// Count Pokemon by rarity
    pub fn count_by_rarity(&self, rarity: &PokemonRarity) -> usize {
        self.pokemon
            .values()
            .filter(|p| p.rarity == *rarity)
            .count()
    }

    /// Add tokens to the trainer's balance
    pub fn add_tokens(&mut self, token_type: &str, amount: u64) {
        let current = self.tokens.get(token_type).cloned().unwrap_or(0);
        self.tokens.insert(token_type.to_string(), current + amount);

        // Update state chain
        let state_entry = format!(
            "add_tokens:{}:{}:{}",
            self.state_chain.last().unwrap_or(&"genesis".to_string()),
            token_type,
            amount
        );
        self.state_chain.push(state_entry);
    }

    /// Remove tokens from the trainer's balance
    pub fn remove_tokens(&mut self, token_type: &str, amount: u64) -> Result<(), DsmError> {
        let current = self.tokens.get(token_type).cloned().unwrap_or(0);

        if current < amount {
            return Err(DsmError::validation(
                format!("Insufficient {} balance", token_type),
                None::<std::convert::Infallible>,
            ));
        }

        self.tokens.insert(token_type.to_string(), current - amount);

        // Update state chain
        let state_entry = format!(
            "remove_tokens:{}:{}:{}",
            self.state_chain.last().unwrap_or(&"genesis".to_string()),
            token_type,
            amount
        );
        self.state_chain.push(state_entry);

        Ok(())
    }

    /// Get trainer's token balance
    pub fn get_token_balance(&self, token_type: &str) -> u64 {
        *self.tokens.get(token_type).unwrap_or(&0)
    }

    /// Get all Pokemon by type
    pub fn get_pokemon_by_type(&self, pokemon_type: &PokemonType) -> Vec<&Pokemon> {
        self.pokemon
            .values()
            .filter(|p| p.types.contains(pokemon_type))
            .collect()
    }

    /// Get all Pokemon by rarity
    pub fn get_pokemon_by_rarity(&self, rarity: &PokemonRarity) -> Vec<&Pokemon> {
        self.pokemon
            .values()
            .filter(|p| p.rarity == *rarity)
            .collect()
    }

    /// Get the current state
    pub fn get_current_state(&self) -> Option<&String> {
        self.state_chain.last()
    }

    /// Get number of states in the chain
    pub fn state_count(&self) -> usize {
        self.state_chain.len()
    }

    /// Get number of Pokemon owned
    pub fn pokemon_count(&self) -> usize {
        self.pokemon.len()
    }
}

/// Represents the conditions of a Pokemon trade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeConditions {
    /// Pokemon to be exchanged (sender offers this)
    pub offered_pokemon_id: String,

    /// Pokemon requested in return (sender wants this)
    pub requested_pokemon_id: Option<String>,

    /// Requested Pokemon type (if any specific type is desired)
    pub requested_pokemon_type: Option<PokemonType>,

    /// Minimum CP requirement for the requested Pokemon
    pub min_cp_requirement: Option<u32>,

    /// The rarity of Pokemon requested
    pub requested_rarity: Option<PokemonRarity>,

    /// Optional token amount included in the trade
    pub token_amount: Option<u64>,

    /// Token type (if tokens are included)
    pub token_type: Option<String>,

    /// Timeout for the trade offer (Unix timestamp)
    pub expires_at: Option<u64>,

    /// Trade identifier
    pub trade_id: String,

    /// Sender's ID
    pub sender_id: String,

    /// Recipient's ID
    pub recipient_id: String,
}

/// Trade status enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TradeStatus {
    /// Trade has been proposed but not yet accepted or rejected
    Pending,

    /// Trade has been accepted by the recipient
    Accepted,

    /// Trade has been rejected by the recipient
    Rejected,

    /// Trade has expired
    Expired,

    /// Trade has been completed successfully
    Completed,

    /// Trade has been canceled by the proposer
    Canceled,
}

/// Trade vault for holding Pokemon trade data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeVault {
    /// Unique identifier for this trade
    pub trade_id: String,

    /// Detailed trade conditions
    pub conditions: TradeConditions,

    /// Current status of the trade
    pub status: TradeStatus,

    /// Timestamp when this trade was created
    pub created_at: u64,

    /// Hash of the trade vault (computed from all fields)
    pub hash: Vec<u8>,

    /// Proposer's signature
    pub proposer_signature: Option<Vec<u8>>,

    /// Recipient's signature (when accepted)
    pub recipient_signature: Option<Vec<u8>>,
}

impl TradeVault {
    /// Create a new trade vault
    pub fn new(conditions: TradeConditions) -> Self {
        let created_at = chrono::Utc::now().timestamp() as u64;
        let trade_id = if conditions.trade_id.is_empty() {
            format!("trade_{}", created_at)
        } else {
            conditions.trade_id.clone()
        };

        // Create trade vault without hash initially
        let mut trade_vault = Self {
            trade_id,
            conditions,
            status: TradeStatus::Pending,
            created_at,
            hash: Vec::new(),
            proposer_signature: None,
            recipient_signature: None,
        };

        // Compute hash
        trade_vault.hash = trade_vault.compute_hash();

        trade_vault
    }

    /// Compute a deterministic hash for this trade vault
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();

        // Add trade ID and timestamps
        hasher.update(self.trade_id.as_bytes());
        hasher.update(&self.created_at.to_le_bytes());

        // Add conditions
        let conditions_bytes = bincode::serialize(&self.conditions).unwrap_or_default();
        hasher.update(&conditions_bytes);

        // Add status
        let status_bytes = bincode::serialize(&self.status).unwrap_or_default();
        hasher.update(&status_bytes);

        hasher.finalize().as_bytes().to_vec()
    }

    /// Sign the trade vault as the proposer
    pub fn sign_as_proposer(&mut self, signature: Vec<u8>) {
        self.proposer_signature = Some(signature);
    }

    /// Sign the trade vault as the recipient
    pub fn sign_as_recipient(&mut self, signature: Vec<u8>) {
        self.recipient_signature = Some(signature);
        self.status = TradeStatus::Accepted;
        self.hash = self.compute_hash();
    }

    /// Reject the trade
    pub fn reject(&mut self) {
        self.status = TradeStatus::Rejected;
        self.hash = self.compute_hash();
    }

    /// Cancel the trade
    pub fn cancel(&mut self) {
        self.status = TradeStatus::Canceled;
        self.hash = self.compute_hash();
    }

    /// Complete the trade
    pub fn complete(&mut self) {
        self.status = TradeStatus::Completed;
        self.hash = self.compute_hash();
    }

    /// Check if the trade has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.conditions.expires_at {
            let now = chrono::Utc::now().timestamp() as u64;
            if now > expires_at {
                return true;
            }
        }
        false
    }

    /// Check if the trade can be executed
    pub fn can_execute(&self) -> bool {
        self.status == TradeStatus::Accepted
            && !self.is_expired()
            && self.proposer_signature.is_some()
            && self.recipient_signature.is_some()
    }

    /// Verify the integrity of this trade vault
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = self.compute_hash();
        computed_hash == self.hash
    }

    /// Serialize the trade vault for transmission
    pub fn serialize(&self) -> Result<Vec<u8>, DsmError> {
        bincode::serialize(self)
            .map_err(|e| DsmError::serialization("Failed to serialize trade vault", Some(e)))
    }

    /// Deserialize a trade vault from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DsmError> {
        bincode::deserialize(bytes)
            .map_err(|e| DsmError::serialization("Failed to deserialize trade vault", Some(e)))
    }
}

/// Counter-offer for a trade
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradeCounterOffer {
    /// ID of the original trade
    pub original_trade_id: String,

    /// Counter offer conditions
    pub counter_conditions: TradeConditions,

    /// Explanation for the counter offer
    pub explanation: Option<String>,

    /// Timestamp when this counter was created
    pub created_at: u64,

    /// Hash of the counter offer (computed from all fields)
    pub hash: Vec<u8>,

    /// Counter-proposer's signature
    pub proposer_signature: Option<Vec<u8>>,
}

impl TradeCounterOffer {
    /// Create a new counter offer
    pub fn new(
        original_trade_id: String,
        counter_conditions: TradeConditions,
        explanation: Option<String>,
    ) -> Self {
        let created_at = chrono::Utc::now().timestamp() as u64;

        // Create counter offer without hash initially
        let mut counter_offer = Self {
            original_trade_id,
            counter_conditions,
            explanation,
            created_at,
            hash: Vec::new(),
            proposer_signature: None,
        };

        // Compute hash
        counter_offer.hash = counter_offer.compute_hash();

        counter_offer
    }

    /// Compute a deterministic hash for this counter offer
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();

        // Add original trade ID
        hasher.update(self.original_trade_id.as_bytes());

        // Add counter conditions
        let conditions_bytes = bincode::serialize(&self.counter_conditions).unwrap_or_default();
        hasher.update(&conditions_bytes);

        // Add explanation if present
        if let Some(explanation) = &self.explanation {
            hasher.update(explanation.as_bytes());
        }

        // Add timestamp
        hasher.update(&self.created_at.to_le_bytes());

        hasher.finalize().as_bytes().to_vec()
    }

    /// Sign the counter offer
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.proposer_signature = Some(signature);
    }

    /// Verify the integrity of this counter offer
    pub fn verify_integrity(&self) -> bool {
        let computed_hash = self.compute_hash();
        computed_hash == self.hash
    }
}

/// Represents a location-based vault for storing Pokemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationBasedVault {
    /// Unique vault identifier
    pub vault_id: String,

    /// Description of the lock condition
    pub lock_description: String,

    /// Creator of the vault
    pub creator_id: String,

    /// Hash commitment of the payload
    pub commitment_hash: Vec<u8>,

    /// Timestamp when the vault was created
    pub timestamp_created: u64,

    /// Current status of the vault
    pub status: String, // "unresolved" or "resolved"

    /// Metadata for the vault
    pub metadata: HashMap<String, String>,

    /// The Pokemon offered in this location-based trade
    pub offered_pokemon_id: String,

    /// The Pokemon requested in exchange
    pub requested_pokemon_id: Option<String>,

    /// Location data for the vault to be unlocked
    pub required_latitude: f64,

    /// Location data for the vault to be unlocked
    pub required_longitude: f64,

    /// Proximity radius in meters required to unlock
    pub required_proximity_meters: u32,

    /// Vault payload (encrypted until conditions are met)
    pub payload: Option<Vec<u8>>,
}

impl LocationBasedVault {
    /// Create a new location-based vault for Pokemon trading
    pub fn new(
        creator_id: &str,
        offered_pokemon_id: &str,
        requested_pokemon_id: Option<&str>,
        required_latitude: f64,
        required_longitude: f64,
        required_proximity_meters: u32,
        payload: Vec<u8>,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let vault_id = format!("location_vault_{}_{}", creator_id, timestamp);

        // Create commitment hash for the payload
        let mut hasher = blake3::Hasher::new();
        hasher.update(&payload);
        hasher.update(&required_latitude.to_le_bytes());
        hasher.update(&required_longitude.to_le_bytes());
        hasher.update(&required_proximity_meters.to_le_bytes());
        let commitment_hash = hasher.finalize().as_bytes().to_vec();

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("purpose".to_string(), "pokemon_location_trade".to_string());
        metadata.insert("expiration".to_string(), (timestamp + 86400).to_string()); // 24 hour expiration by default

        Self {
            vault_id,
            lock_description: format!(
                "Pokemon trade at location {},{} within {}m radius",
                required_latitude, required_longitude, required_proximity_meters
            ),
            creator_id: creator_id.to_string(),
            commitment_hash,
            timestamp_created: timestamp,
            status: "unresolved".to_string(),
            metadata,
            offered_pokemon_id: offered_pokemon_id.to_string(),
            requested_pokemon_id: requested_pokemon_id.map(|s| s.to_string()),
            required_latitude,
            required_longitude,
            required_proximity_meters,
            payload: Some(payload),
        }
    }
}
