//! Token types for DSM
//!
//! This module defines the comprehensive token system for DSM, including:
//! - Native ROOT token and created tokens
//! - Token balance management with atomic state integration
//! - Token registry and supply tracking
//! - Advanced token operations (transfer, mint, burn, lock)
//! - Quantum-resistant token state evolution
use crate::types::error::DsmError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
/// Token type representing the nature and properties of a token
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TokenType {
    /// Native token for the DSM system (ROOT)
    Native,
    /// User-created tokens through token factory
    Created,
    /// Special-purpose tokens with restricted operations
    Restricted,
    /// Tokens that represent external assets
    Wrapped,
}

/// Token supply management parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenSupply {
    /// Total fixed supply
    pub total_supply: i64,
    /// Current circulating supply
    pub circulating_supply: i64,
    /// Maximum allowed supply (can be None for unlimited)
    pub max_supply: Option<i64>,
    /// Minimum allowed supply (cannot go below this value)
    pub min_supply: Option<i64>,
}

impl TokenSupply {
    /// Create a new TokenSupply with fixed total supply
    pub fn new(total_supply: i64) -> Self {
        Self {
            total_supply,
            circulating_supply: total_supply,
            max_supply: Some(total_supply),
            min_supply: Some(0),
        }
    }

    /// Create a TokenSupply with flexible minting/burning parameters
    pub fn with_limits(
        total_supply: i64,
        max_supply: Option<i64>,
        min_supply: Option<i64>,
    ) -> Self {
        Self {
            total_supply,
            circulating_supply: total_supply,
            max_supply,
            min_supply,
        }
    }

    /// Check if a supply change is within allowed limits
    pub fn is_valid_supply_change(&self, change: i64) -> bool {
        let new_supply = self.circulating_supply + change;
        match (self.min_supply, self.max_supply) {
            (Some(min), Some(max)) => new_supply >= min && new_supply <= max,
            (Some(min), None) => new_supply >= min,
            (None, Some(max)) => new_supply <= max,
            (None, None) => true,
        }
    }
}

/// Token identity and metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// Unique identifier for this token
    pub token_id: String,
    /// Name of the token
    pub name: String,
    /// Symbol for the token (e.g., "ROOT")
    pub symbol: String,
    /// Number of decimal places for token precision
    pub decimals: u8,
    /// Token type (Native, Created, etc.)
    pub token_type: TokenType,
    /// Owner of the token (creator's identity)
    pub owner_id: String,
    /// Creation timestamp
    pub creation_timestamp: u64,
    /// Optional URI for token metadata
    pub metadata_uri: Option<String>,
    /// Description of the token
    pub description: Option<String>,
    /// Token icon URL
    pub icon_url: Option<String>,
    /// Content-Addressed Token Policy Anchor (CTPA) hash
    pub policy_anchor: Option<String>,
    /// Additional metadata fields
    pub fields: HashMap<String, String>,
}

impl TokenMetadata {
    /// Create new token metadata
    pub fn new(
        token_id: &str,
        name: &str,
        symbol: &str,
        decimals: u8,
        token_type: TokenType,
        owner_id: &str,
    ) -> Self {
        Self {
            token_id: token_id.to_string(),
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            token_type,
            owner_id: owner_id.to_string(),
            creation_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata_uri: None,
            description: None,
            icon_url: None,
            policy_anchor: None,
            fields: HashMap::new(),
        }
    }

    /// Add metadata URI
    pub fn with_metadata_uri(mut self, uri: &str) -> Self {
        self.metadata_uri = Some(uri.to_string());
        self
    }

    /// Add description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Add icon URL
    pub fn with_icon_url(mut self, url: &str) -> Self {
        self.icon_url = Some(url.to_string());
        self
    }

    /// Add custom metadata field
    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
        self
    }
    
    /// Add policy anchor
    pub fn with_policy_anchor(mut self, anchor: &str) -> Self {
        self.policy_anchor = Some(anchor.to_string());
        self
    }

    /// Generate canonical token identifier for balance mapping
    pub fn canonical_id(&self) -> String {
        format!("{}.{}", self.owner_id, self.token_id)
    }
}

/// Core token balance type
///
/// This implementation uses signed integers to represent balances,
/// enabling both positive and negative delta values during state transitions.
/// This is crucial for implementing the conservation of value invariant
/// described in the whitepaper Section 10.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Balance {
    /// Token value
    value: i64,
    /// Locked portion of balance that cannot be spent
    locked: i64,
    /// Last update timestamp
    last_updated: u64,
    /// Ledger state hash referencing the last update
    state_hash: Option<Vec<u8>>,
    pub(crate) amount: u64,
}

impl Balance {
    /// Create a new Balance
    pub fn new(value: i64) -> Self {
        Self {
            value,
            locked: 0,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            state_hash: None,
            amount: if value >= 0 { value as u64 } else { 0 },
        }
    }

    /// Create a balance from a state
    pub fn from_state(value: i64, state_hash: Vec<u8>) -> Self {
        Self {
            value,
            locked: 0,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            state_hash: Some(state_hash),
            amount: if value >= 0 { value as u64 } else { 0 },
        }
    }

    /// Get the available balance (total minus locked)
    pub fn available(&self) -> i64 {
        self.value - self.locked
    }

    /// Get the total balance value
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Get the locked balance
    pub fn locked(&self) -> i64 {
        self.locked
    }

    /// Lock a portion of the balance
    pub fn lock(&mut self, amount: i64) -> Result<(), DsmError> {
        if amount <= 0 {
            return Err(DsmError::validation(
                "Lock amount must be positive",
                None::<std::convert::Infallible>,
            ));
        }
        if amount > self.available() {
            return Err(DsmError::validation(
                "Insufficient available balance to lock",
                None::<std::convert::Infallible>,
            ));
        }
        self.locked += amount;
        self.update_timestamp();
        Ok(())
    }

    /// Unlock a portion of the locked balance
    pub fn unlock(&mut self, amount: i64) -> Result<(), DsmError> {
        if amount <= 0 {
            return Err(DsmError::validation(
                "Unlock amount must be positive",
                None::<std::convert::Infallible>,
            ));
        }
        if amount > self.locked {
            return Err(DsmError::validation(
                "Unlock amount exceeds locked balance",
                None::<std::convert::Infallible>,
            ));
        }
        self.locked -= amount;
        self.update_timestamp();
        Ok(())
    }

    /// Update the balance
    pub fn update(&mut self, delta: i64) {
        self.value += delta;
        // Critical: Ensure amount field stays in sync with value
        self.amount = if self.value >= 0 {
            self.value as u64
        } else {
            0
        };
        self.update_timestamp();
    }

    /// Update the timestamp
    fn update_timestamp(&mut self) {
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Format balance with appropriate decimals
    pub fn formatted(&self, decimals: u8) -> String {
        let factor = 10i64.pow(decimals as u32) as f64;
        format!(
            "{:.precision$}",
            self.value as f64 / factor,
            precision = decimals as usize
        )
    }

    /// Set state hash reference
    pub fn with_state_hash(mut self, hash: Vec<u8>) -> Self {
        self.state_hash = Some(hash);
        self
    }

    /// Convert to little-endian bytes for hashing
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(24); // 8 bytes for each i64, 8 for timestamp
        result.extend_from_slice(&self.value.to_le_bytes());
        result.extend_from_slice(&self.locked.to_le_bytes());
        result.extend_from_slice(&self.last_updated.to_le_bytes());
        if let Some(hash) = &self.state_hash {
            result.extend_from_slice(hash);
        }
        result
    }
}

/// Token Registry for managing token metadata and supply information
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TokenRegistry {
    /// Map of token IDs to their metadata
    pub tokens: HashMap<String, TokenMetadata>,
    /// Map of token IDs to their supply information
    pub supplies: HashMap<String, TokenSupply>,
    /// Native token ID (ROOT)
    pub native_token_id: String,
}

impl TokenRegistry {
    /// Create a new empty TokenRegistry
    pub fn new() -> Self {
        let native_token_id = "ROOT".to_string();
        let mut tokens = HashMap::new();
        let mut supplies = HashMap::new();

        // Initialize ROOT token
        let root_metadata = TokenMetadata::new(
            &native_token_id,
            "ROOT",
            "ROOT",
            18, // 18 decimals like ETH
            TokenType::Native,
            "system", // System-owned
        );

        // Initialize with a fixed supply of 100 million tokens
        let root_supply = TokenSupply::new(100_000_000 * 10i64.pow(18));

        tokens.insert(native_token_id.clone(), root_metadata);
        supplies.insert(native_token_id.clone(), root_supply);

        Self {
            tokens,
            supplies,
            native_token_id,
        }
    }

    /// Register a new token
    pub fn register_token(
        &mut self,
        metadata: TokenMetadata,
        supply: TokenSupply,
    ) -> Result<(), DsmError> {
        let token_id = metadata.token_id.clone();

        // Check if token already exists
        if self.tokens.contains_key(&token_id) {
            return Err(DsmError::validation(
                format!("Token {} already exists", token_id),
                None::<std::convert::Infallible>,
            ));
        }

        // Register the token
        self.tokens.insert(token_id.clone(), metadata);
        self.supplies.insert(token_id, supply);

        Ok(())
    }

    /// Get token metadata by ID
    pub fn get_token(&self, token_id: &str) -> Option<&TokenMetadata> {
        self.tokens.get(token_id)
    }

    /// Get token supply information by ID
    pub fn get_supply(&self, token_id: &str) -> Option<&TokenSupply> {
        self.supplies.get(token_id)
    }

    /// Update token supply
    pub fn update_supply(&mut self, token_id: &str, delta: i64) -> Result<(), DsmError> {
        let supply = self.supplies.get_mut(token_id).ok_or_else(|| {
            DsmError::validation(
                format!("Token {} not found", token_id),
                None::<std::convert::Infallible>,
            )
        })?;

        if !supply.is_valid_supply_change(delta) {
            return Err(DsmError::validation(
                format!("Invalid supply change for token {}", token_id),
                None::<std::convert::Infallible>,
            ));
        }

        supply.circulating_supply += delta;
        Ok(())
    }

    /// Check if a token is native (ROOT)
    pub fn is_native_token(&self, token_id: &str) -> bool {
        token_id == self.native_token_id
    }

    /// Get canonical token ID combining owner ID and token ID
    pub fn canonical_token_id(&self, token_id: &str) -> Result<String, DsmError> {
        let metadata = self.get_token(token_id).ok_or_else(|| {
            DsmError::validation(
                format!("Token {} not found", token_id),
                None::<std::convert::Infallible>,
            )
        })?;

        Ok(metadata.canonical_id())
    }

    pub fn create_token(
        &mut self,
        params: CreateTokenParams,
    ) -> Result<(TokenMetadata, TokenSupply), DsmError> {
        // Use the params to create token
        let metadata = TokenMetadata {
            name: params.name,
            symbol: params.token_id.clone(),
            description: params.description,
            icon_url: params.icon_url,
            decimals: params.decimals,
            fields: HashMap::new(),
            token_id: params.token_id.clone(),
            token_type: TokenType::Created,
            owner_id: "system".to_string(),
            creation_timestamp: chrono::Utc::now().timestamp() as u64,
            metadata_uri: params.metadata_uri,
            policy_anchor: params.policy_anchor,
        };

        let supply = TokenSupply {
            total_supply: params.initial_supply.unwrap_or(0),
            circulating_supply: params.initial_supply.unwrap_or(0),
            max_supply: params.max_supply,
            min_supply: Some(0),
        };

        self.tokens.insert(params.token_id, metadata.clone());
        self.supplies
            .insert(metadata.token_id.clone(), supply.clone());

        Ok((metadata, supply))
    }
}

pub struct CreateTokenParams {
    pub token_id: String,
    pub name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub metadata_uri: Option<String>,
    pub decimals: u8,
    pub initial_supply: Option<i64>,
    pub max_supply: Option<i64>,
    pub policy_anchor: Option<String>,
}

/// Token Factory for creating new tokens
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenFactory {
    /// Token registry
    pub registry: TokenRegistry,
    /// Fee in ROOT tokens for token creation
    pub creation_fee: i64,
    /// Genesis state hash
    pub genesis_hash: Vec<u8>,
}

impl TokenFactory {
    /// Create a new TokenFactory
    pub fn new(creation_fee: i64, genesis_hash: Vec<u8>) -> Self {
        Self {
            registry: TokenRegistry::new(),
            creation_fee,
            genesis_hash,
        }
    }

    /// Get creation fee
    pub fn get_creation_fee(&self) -> i64 {
        self.creation_fee
    }

    /// Update creation fee
    pub fn set_creation_fee(&mut self, fee: i64) {
        self.creation_fee = fee;
    }
}

/// Token operation for state transitions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TokenOperation {
    /// Create a new token
    Create {
        /// Token metadata
        metadata: Box<TokenMetadata>,
        /// Initial token supply
        supply: TokenSupply,
        /// Creation fee in ROOT tokens
        fee: i64,
    },
    /// Transfer tokens between accounts
    Transfer {
        /// Token ID to transfer
        token_id: String,
        /// Recipient identity
        recipient: String,
        /// Amount to transfer
        amount: i64,
        /// Optional memo
        memo: Option<String>,
    },
    /// Mint additional tokens (if allowed by supply)
    Mint {
        /// Token ID to mint
        token_id: String,
        /// Recipient of the newly minted tokens
        recipient: String,
        /// Amount to mint
        amount: i64,
    },
    /// Burn (destroy) tokens
    Burn {
        /// Token ID to burn
        token_id: String,
        /// Amount to burn
        amount: i64,
    },
    /// Lock tokens for a specific purpose
    Lock {
        /// Token ID to lock
        token_id: String,
        /// Amount to lock
        amount: i64,
        /// Lock reason/purpose
        purpose: String,
    },
    /// Unlock previously locked tokens
    Unlock {
        /// Token ID to unlock
        token_id: String,
        /// Amount to unlock
        amount: i64,
        /// Original lock purpose
        purpose: String,
    },
}

/// Token represents a complete token entity in the DSM system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Unique identifier for this token
    id: String,
    /// The owner's identity
    owner_id: String,
    /// Token data containing specification
    token_data: Vec<u8>,
    /// Metadata associated with this token
    metadata: Vec<u8>,
    /// Cryptographic hash of this token
    token_hash: Vec<u8>,
    /// Current token status
    status: TokenStatus,
    /// Token balance
    balance: Balance,
    /// Content-Addressed Token Policy Anchor (CTPA) hash
    policy_anchor: Option<[u8; 32]>,
}

impl Token {
    /// Create a new token
    pub fn new(owner_id: &str, token_data: Vec<u8>, metadata: Vec<u8>, balance: Balance) -> Self {
        let id = format!(
            "{}-{}",
            owner_id,
            blake3::hash(&token_data).to_hex().as_str()
        );
        let token_hash = blake3::hash(&[&token_data[..], &metadata[..]].concat())
            .as_bytes()
            .to_vec();

        Self {
            id,
            owner_id: owner_id.to_string(),
            token_data,
            metadata,
            token_hash,
            status: TokenStatus::Active,
            balance,
            policy_anchor: None,
        }
    }
    
    /// Create a new token with policy anchor
    pub fn new_with_policy(owner_id: &str, token_data: Vec<u8>, metadata: Vec<u8>, balance: Balance, policy_anchor: [u8; 32]) -> Self {
        let id = format!(
            "{}-{}",
            owner_id,
            blake3::hash(&token_data).to_hex().as_str()
        );
        let token_hash = blake3::hash(&[&token_data[..], &metadata[..]].concat())
            .as_bytes()
            .to_vec();

        Self {
            id,
            owner_id: owner_id.to_string(),
            token_data,
            metadata,
            token_hash,
            status: TokenStatus::Active,
            balance,
            policy_anchor: Some(policy_anchor),
        }
    }

    /// Get token ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get owner ID
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// Get token data
    pub fn token_data(&self) -> &[u8] {
        &self.token_data
    }

    /// Get metadata
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Get token hash
    pub fn token_hash(&self) -> &[u8] {
        &self.token_hash
    }

    /// Get token status
    pub fn status(&self) -> &TokenStatus {
        &self.status
    }

    /// Get balance
    pub fn balance(&self) -> &Balance {
        &self.balance
    }

    /// Set token status
    pub fn set_status(&mut self, status: TokenStatus) {
        self.status = status;
    }

    /// Set token owner
    pub fn set_owner(&mut self, owner_id: &str) {
        self.owner_id = owner_id.to_string();
    }

    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        self.status == TokenStatus::Active
    }
    
    /// Get policy anchor
    pub fn policy_anchor(&self) -> Option<&[u8; 32]> {
        self.policy_anchor.as_ref()
    }
    
    /// Set policy anchor
    pub fn set_policy_anchor(&mut self, anchor: [u8; 32]) {
        self.policy_anchor = Some(anchor);
    }

    /// Update token balance
    pub fn update_balance(&mut self, delta: i64) {
        self.balance.update(delta);
    }
}

/// Token status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenStatus {
    /// Token is active and can be transferred
    Active,
    /// Token has been revoked and is no longer valid
    Revoked,
    /// Token has expired (expiration enforced by state progression)
    Expired,
    /// Token is temporarily locked
    Locked,
}
