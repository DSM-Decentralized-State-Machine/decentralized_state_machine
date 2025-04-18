//! Token types for DSM
//!
//! This module defines the comprehensive token system for DSM, including:
//! - Native ROOT token and created tokens
//! - Token balance management with atomic state integration
//! - Token registry and supply tracking
//! - Advanced token operations (transfer, mint, burn, lock)
//! - Quantum-resistant token state evolution
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::error::DsmError;
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
    pub total_supply: u64,
    /// Current circulating supply
    pub circulating_supply: u64,
    /// Maximum allowed supply (can be None for unlimited)
    pub max_supply: Option<u64>,
    /// Minimum allowed supply (cannot go below this value)
    pub min_supply: Option<u64>,
}

impl TokenSupply {
    /// Create a new TokenSupply with fixed total supply
    pub fn new(total_supply: u64) -> Self {
        Self {
            total_supply,
            circulating_supply: total_supply,
            max_supply: Some(total_supply),
            min_supply: Some(0),
        }
    }

    /// Create a TokenSupply with flexible minting/burning parameters
    pub fn with_limits(
        total_supply: u64,
        max_supply: Option<u64>,
        min_supply: Option<u64>,
    ) -> Self {
        Self {
            total_supply,
            circulating_supply: total_supply,
            max_supply,
            min_supply,
        }
    }

    /// Check if a supply change is within allowed limits
    /// Returns true if applying the amount would keep supply within limits
    pub fn is_valid_supply_change(&self, amount: u64, is_addition: bool) -> bool {
        if is_addition {
            // For additions, ensure we don't exceed maximum
            let new_supply = self.circulating_supply.saturating_add(amount);
            if let Some(max) = self.max_supply {
                if new_supply > max {
                    return false;
                }
            }
            true
        } else {
            // For subtractions, ensure we don't go below minimum
            // If attempting to decrease by more than current supply, it's invalid
            if amount > self.circulating_supply {
                return false;
            }

            let new_supply = self.circulating_supply - amount;
            if let Some(min) = self.min_supply {
                if new_supply < min {
                    return false;
                }
            }
            true
        }
    }

    /// Check if a supply change using TokenAmount is within allowed limits
    pub fn validate_supply_change(&self, amount: TokenAmount, is_mint: bool) -> bool {
        if is_mint {
            // Adding tokens - check against max_supply
            let new_supply = self.circulating_supply.saturating_add(amount.value());
            if let Some(max) = self.max_supply {
                if new_supply > max {
                    return false;
                }
            }
            true
        } else {
            // Burning tokens - check against min_supply and circulating_supply
            if amount.value() > self.circulating_supply {
                return false;
            }

            let new_supply = self.circulating_supply - amount.value();
            if let Some(min) = self.min_supply {
                if new_supply < min {
                    return false;
                }
            }
            true
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

/// Specialized token amount with non-negative invariants
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TokenAmount {
    /// Non-negative token amount
    value: u64,
}

impl TokenAmount {
    /// Create a new TokenAmount with the given value
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    /// Checked addition that prevents overflow
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.value.checked_add(other.value).map(Self::new)
    }

    /// Checked subtraction that maintains non-negative invariant
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        if self.value < other.value {
            return None; // Prevents negative balance
        }
        Some(Self::new(self.value - other.value))
    }

    /// Saturating addition that never overflows
    pub fn saturating_add(self, other: Self) -> Self {
        Self::new(self.value.saturating_add(other.value))
    }

    /// Saturating subtraction that never goes below zero
    pub fn saturating_sub(self, other: Self) -> Self {
        Self::new(self.value.saturating_sub(other.value))
    }

    /// Get the underlying value
    pub fn value(&self) -> u64 {
        self.value
    }
}

impl Default for TokenAmount {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Core token balance type
///
/// This implementation uses unsigned integers to represent balances,
/// enforcing non-negative value invariants in accordance with the
/// conservation of value principle described in whitepaper Section 10.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Balance {
    /// Token value
    value: u64,
    /// Locked portion of balance that cannot be spent
    locked: u64,
    /// Last update timestamp
    last_updated: u64,
    /// Ledger state hash referencing the last update
    state_hash: Option<Vec<u8>>,
}

impl Balance {
    /// Create a new Balance
    /// 
    /// DEPRECATED: This method is maintained only for backward compatibility.
    /// New code should always use `from_state()` to ensure proper state hash linking
    /// as required by the DSM architecture (whitepaper Section 10).
    /// 
    /// As stated in whitepaper Section 18: "Token operations within the DSM framework
    /// evolve atomically in conjunction with identity state transitions."
    pub fn new(value: u64) -> Self {
        // Get current DSM state hash if available through thread-local context
        // or other global state management mechanism
        let state_hash = if let Some(current_hash) = Self::get_current_canonical_state_hash() {
            // Use the current canonical state hash if available
            Some(current_hash)
        } else {
            // Fallback to a deterministic timestamp-based hash only if no state hash is available
            // This should only happen in test environments or during system initialization
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
                
            // Create a deterministic hash based on time as a last resort
            let warning = format!("WARNING: Creating balance without canonical state hash at time {}", current_time);
            log::warn!("{}", warning);
            
            Some(blake3::hash(format!("balance_creation_{}", current_time).as_bytes()).as_bytes().to_vec())
        };
        
        Self {
            value,
            locked: 0,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            state_hash,
        }
    }
    
    /// Get the current canonical state hash from the DSM system context
    fn get_current_canonical_state_hash() -> Option<Vec<u8>> {
        // In a real implementation, this would access thread-local storage
        // or other context mechanism to get the current state hash from
        // the active DSM state machine
        
        // For now, this is a placeholder that will be expanded in future updates
        // We could consider exposing a global state context registry for this purpose
        None
    }

    /// Create a balance from a state
    pub fn from_state(value: u64, state_hash: Vec<u8>) -> Self {
        Self {
            value,
            locked: 0,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            state_hash: Some(state_hash),
        }
    }

    /// Get the available balance (total minus locked)
    pub fn available(&self) -> u64 {
        self.value.saturating_sub(self.locked)
    }

    /// Get the total balance value
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Get the locked balance
    pub fn locked(&self) -> u64 {
        self.locked
    }

    /// Lock a portion of the balance
    pub fn lock(&mut self, amount: u64) -> Result<(), DsmError> {
        if amount == 0 {
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
    pub fn unlock(&mut self, amount: u64) -> Result<(), DsmError> {
        if amount == 0 {
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

    /// Update the balance with an amount and operation type
    /// This provides a type-safe interface with explicit operation semantics
    pub fn update(&mut self, amount: u64, is_addition: bool) {
        if is_addition {
            self.value = self.value.saturating_add(amount);
        } else {
            self.value = self.value.saturating_sub(amount);
        }
        self.update_timestamp();
    }

    /// Update balance with TokenAmount and operation type
    /// This provides a safer and more semantically accurate way to update balances
    pub fn update_with_amount(
        &mut self,
        amount: TokenAmount,
        is_addition: bool,
    ) -> Result<(), DsmError> {
        if is_addition {
            self.value = self.value.saturating_add(amount.value());
        } else {
            if amount.value() > self.value {
                return Err(DsmError::validation(
                    "Insufficient balance for deduction",
                    None::<std::convert::Infallible>,
                ));
            }
            self.value -= amount.value();
        }
        self.update_timestamp();
        Ok(())
    }

    /// Update the balance with an unsigned delta (always an addition)
    pub fn update_add(&mut self, delta: u64) {
        self.value = self.value.saturating_add(delta);
        self.update_timestamp();
    }

    /// Update the balance with an unsigned delta (always a subtraction)
    pub fn update_sub(&mut self, delta: u64) -> Result<(), DsmError> {
        if delta > self.value {
            return Err(DsmError::validation(
                "Insufficient balance for deduction",
                None::<std::convert::Infallible>,
            ));
        }
        self.value -= delta;
        self.update_timestamp();
        Ok(())
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
        let factor = 10u64.pow(decimals as u32) as f64;
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
        let mut result = Vec::with_capacity(24); // 8 bytes for each u64, 8 for timestamp
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
        let root_supply = TokenSupply::new(100_000_000 * 10u64.pow(18));

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

    /// Update token supply with unsigned amount and explicit addition/subtraction flag
    pub fn update_supply(
        &mut self,
        token_id: &str,
        amount: u64,
        is_addition: bool,
    ) -> Result<(), DsmError> {
        let supply = self.supplies.get_mut(token_id).ok_or_else(|| {
            DsmError::validation(
                format!("Token {} not found", token_id),
                None::<std::convert::Infallible>,
            )
        })?;

        if !supply.is_valid_supply_change(amount, is_addition) {
            return Err(DsmError::validation(
                format!("Invalid supply change for token {}", token_id),
                None::<std::convert::Infallible>,
            ));
        }

        // Handle supply change with explicit operation semantics
        if is_addition {
            supply.circulating_supply = supply.circulating_supply.saturating_add(amount);
        } else {
            supply.circulating_supply = supply.circulating_supply.saturating_sub(amount);
        }

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
    pub initial_supply: Option<u64>,
    pub max_supply: Option<u64>,
    pub policy_anchor: Option<String>,
}

/// Token Factory for creating new tokens
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenFactory {
    /// Token registry
    pub registry: TokenRegistry,
    /// Fee in ROOT tokens for token creation
    pub creation_fee: u64,
    /// Genesis state hash
    pub genesis_hash: Vec<u8>,
}

impl TokenFactory {
    /// Create a new TokenFactory
    pub fn new(creation_fee: u64, genesis_hash: Vec<u8>) -> Self {
        Self {
            registry: TokenRegistry::new(),
            creation_fee,
            genesis_hash,
        }
    }

    /// Get creation fee
    pub fn get_creation_fee(&self) -> u64 {
        self.creation_fee
    }

    /// Update creation fee
    pub fn set_creation_fee(&mut self, fee: u64) {
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
        fee: u64,
    },
    /// Transfer tokens between accounts
    Transfer {
        /// Token ID to transfer
        token_id: String,
        /// Recipient identity
        recipient: String,
        /// Amount to transfer
        amount: u64,
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
        amount: u64,
    },
    /// Burn (destroy) tokens
    Burn {
        /// Token ID to burn
        token_id: String,
        /// Amount to burn
        amount: u64,
    },
    /// Lock tokens for a specific purpose
    Lock {
        /// Token ID to lock
        token_id: String,
        /// Amount to lock
        amount: u64,
        /// Lock reason/purpose
        purpose: String,
    },
    /// Unlock previously locked tokens
    Unlock {
        /// Token ID to unlock
        token_id: String,
        /// Amount to unlock
        amount: u64,
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
    pub fn new_with_policy(
        owner_id: &str,
        token_data: Vec<u8>,
        metadata: Vec<u8>,
        balance: Balance,
        policy_anchor: [u8; 32],
    ) -> Self {
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

    /// Update token balance with explicit operation semantics
    pub fn update_balance(&mut self, amount: u64, is_addition: bool) {
        self.balance.update(amount, is_addition);
    }

    /// Update token balance with TokenAmount
    pub fn update_balance_with_amount(
        &mut self,
        amount: TokenAmount,
        is_addition: bool,
    ) -> Result<(), DsmError> {
        self.balance.update_with_amount(amount, is_addition)
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
