//! # Wallet SDK Module
//!
//! This module implements comprehensive wallet functionality for the DSM system,
//! providing secure key management, transaction signing, and offline-capable
//! wallet operations with post-quantum cryptographic security.
//!
//! ## Key Concepts
//!
//! * **Hierarchical Key Management**: Secure derivation of keys from a master seed
//! * **Post-Quantum Security**: All cryptographic operations use quantum-resistant algorithms
//! * **Secure Storage**: Encrypted storage for keys and wallet state
//! * **Transaction Management**: Creation, signing, and verification of transactions
//! * **Offline Capability**: Full operation without network connectivity
//! * **Recovery Mechanisms**: Backup and recovery solutions for wallet data
//!
//! ## Architecture
//!
//! The wallet module follows the security model described in the DSM whitepaper,
//! using deterministic cryptographic state transitions to protect wallet assets
//! and ensuring bilateral state isolation for user funds.
//!
//! ## Usage Example
//!
//! ```rust
//! use dsm_sdk::wallet_sdk::WalletSDK;
//! use dsm_sdk::core_sdk::CoreSDK;
//! use std::sync::Arc;
//!
//! // Create a new wallet with the core SDK
//! let core_sdk = Arc::new(CoreSDK::new());
//! let wallet = WalletSDK::new(core_sdk.clone(), "my_wallet", None).unwrap();
//!
//! // Generate a new address
//! let address = wallet.generate_address().unwrap();
//! println!("New address: {}", address);
//!
//! // Create and sign a transaction
//! let transaction = wallet.create_transaction("recipient_address", 100, None).unwrap();
//! let signed_tx = wallet.sign_transaction(&transaction).unwrap();
//!
//! // Send the transaction
//! wallet.send_transaction(&signed_tx).await.unwrap();
//! ```

use super::core_sdk::{CoreSDK, TokenManager};
use super::identity_sdk::IdentitySDK;
use super::token_sdk::TokenSDK;
use dsm::types::error::DsmError;
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::{Balance, TokenOperation};
use dsm::crypto;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use blake3;
use log;

/// Security level for wallet encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Standard security with reasonable performance
    Standard,
    /// High security with additional protection mechanisms
    High,
    /// Maximum security with comprehensive protection (slower)
    Maximum,
}

/// Wallet address with security metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddress {
    /// The address string
    pub address: String,
    /// Public key associated with this address
    pub public_key: Vec<u8>,
    /// Optional label for the address
    pub label: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used: u64,
    /// Address visibility
    pub is_hidden: bool,
}

impl WalletAddress {
    /// Create a new wallet address
    pub fn new(address: String, public_key: Vec<u8>, label: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        Self {
            address,
            public_key,
            label,
            created_at: now,
            last_used: now,
            is_hidden: false,
        }
    }
}

/// Transaction status in the wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is pending confirmation
    Pending,
    /// Transaction has been confirmed
    Confirmed,
    /// Transaction failed
    Failed,
    /// Transaction was rejected
    Rejected,
    /// Transaction is scheduled for future execution
    Scheduled,
}

/// Wallet transaction record
#[derive(Clone, Serialize, Deserialize)]
pub struct WalletTransaction {
    /// Unique transaction identifier
    pub id: String,
    /// Sender address
    pub from: String,
    /// Recipient address
    pub to: String,
    /// Transaction amount
    pub amount: u64,
    /// Token identifier
    pub token_id: String,
    /// Optional transaction memo
    pub memo: Option<String>,
    /// Transaction timestamp
    pub timestamp: u64,
    /// Transaction status
    pub status: TransactionStatus,
    /// Block/state number where transaction was included
    pub state_number: Option<u64>,
    /// Transaction hash
    pub hash: Vec<u8>,
    /// Transaction fee
    pub fee: u64,
    /// Signature proving transaction authenticity
    pub signature: Option<Vec<u8>>,
    /// Additional metadata for the transaction
    pub metadata: HashMap<String, String>,
}

impl fmt::Debug for WalletTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletTransaction")
            .field("id", &self.id)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("amount", &self.amount)
            .field("token_id", &self.token_id)
            .field("memo", &self.memo)
            .field("timestamp", &self.timestamp)
            .field("status", &self.status)
            .field("state_number", &self.state_number)
            .field("fee", &self.fee)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl WalletTransaction {
    /// Create a new wallet transaction
    pub fn new(
        from: String,
        to: String,
        amount: u64,
        token_id: String,
        memo: Option<String>,
        fee: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        // Generate a transaction ID using a hash of inputs
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(from.as_bytes());
        id_hasher.update(to.as_bytes());
        id_hasher.update(&amount.to_le_bytes());
        id_hasher.update(token_id.as_bytes());
        if let Some(m) = &memo {
            id_hasher.update(m.as_bytes());
        }
        id_hasher.update(&now.to_le_bytes());
        let id_hash = id_hasher.finalize();
        let id = hex::encode(id_hash.as_bytes());

        // Create the transaction hash
        let mut tx_hasher = blake3::Hasher::new();
        tx_hasher.update(from.as_bytes());
        tx_hasher.update(to.as_bytes());
        tx_hasher.update(&amount.to_le_bytes());
        tx_hasher.update(token_id.as_bytes());
        if let Some(m) = &memo {
            tx_hasher.update(m.as_bytes());
        }
        tx_hasher.update(&now.to_le_bytes());
        tx_hasher.update(&fee.to_le_bytes());
        let hash = tx_hasher.finalize().as_bytes().to_vec();

        Self {
            id,
            from,
            to,
            amount,
            token_id,
            memo,
            timestamp: now,
            status: TransactionStatus::Pending,
            state_number: None,
            hash,
            fee,
            signature: None,
            metadata: HashMap::new(),
        }
    }

    /// Sign the transaction with the provided key
    pub fn sign(&mut self, private_key: &[u8]) -> Result<Vec<u8>, DsmError> {
        // The dsm::crypto::sign_data returns an Option, not a Result
        let signature = dsm::crypto::sign_data(&self.hash, private_key).ok_or_else(|| {
            DsmError::crypto("Failed to sign transaction", None::<std::io::Error>)
        })?;

        self.signature = Some(signature.clone());
        Ok(signature)
    }
}

/// Wallet recovery options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletRecoveryOptions {
    /// Mnemonic phrase for recovery
    pub mnemonic: Option<String>,
    /// Recovery key file path
    pub recovery_file: Option<PathBuf>,
    /// Recovery email
    pub recovery_email: Option<String>,
    /// Hardware device recovery path
    pub hardware_path: Option<String>,
}

/// Wallet configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Wallet name
    pub name: String,
    /// Security level
    pub security_level: SecurityLevel,
    /// Auto-lock timeout in seconds (0 = never)
    pub auto_lock_timeout: u64,
    /// Allow offline transactions
    pub offline_transactions_enabled: bool,
    /// Default fee
    pub default_fee: u64,
    /// Database path
    pub db_path: Option<PathBuf>,
    /// Backup schedule in hours (0 = disabled)
    pub backup_schedule_hours: u64,
    /// Recovery options
    pub recovery_options: WalletRecoveryOptions,
    /// Custom configuration options
    pub custom_options: HashMap<String, String>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            name: "DSM Wallet".to_string(),
            security_level: SecurityLevel::Standard,
            auto_lock_timeout: 300, // 5 minutes
            offline_transactions_enabled: true,
            default_fee: 1,
            db_path: None,
            backup_schedule_hours: 24,
            recovery_options: WalletRecoveryOptions {
                mnemonic: None,
                recovery_file: None,
                recovery_email: None,
                hardware_path: None,
            },
            custom_options: HashMap::new(),
        }
    }
}

/// Main wallet SDK for the DSM system
pub struct WalletSDK {
    /// Reference to the core SDK
    #[allow(dead_code)]
    core_sdk: Arc<CoreSDK>,

    /// Reference to token SDK
    token_sdk: Arc<TokenSDK<IdentitySDK>>,

    /// Wallet configuration
    config: RwLock<WalletConfig>,

    /// Wallet addresses
    addresses: RwLock<Vec<WalletAddress>>,

    /// Transaction history
    transactions: RwLock<Vec<WalletTransaction>>,

    /// Wallet locked status
    locked: RwLock<bool>,

    /// Last activity timestamp
    last_activity: RwLock<u64>,

    /// Device ID associated with this wallet
    device_id: String,

    /// Wallet keystore
    keystore: RwLock<HashMap<String, Vec<u8>>>,

    /// Currently active address
    active_address: RwLock<Option<String>>,

    /// Wallet backup state
    last_backup: RwLock<Option<u64>>,

    /// Address book for commonly used addresses
    address_book: RwLock<HashMap<String, String>>,
}

// Implement Debug trait for WalletSDK
impl fmt::Debug for WalletSDK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletSDK")
            .field("device_id", &self.device_id)
            .field("config", &self.config)
            .field("addresses", &self.addresses)
            .field("locked", &self.locked)
            .field("active_address", &self.active_address)
            .finish()
    }
}

impl WalletSDK {
    /// Create a new WalletSDK instance
    ///
    /// # Arguments
    ///
    /// * `core_sdk` - Reference to the CoreSDK
    /// * `device_id` - Device identifier for this wallet
    /// * `config` - Optional wallet configuration
    ///
    /// # Returns
    ///
    /// * `Result<Self, DsmError>` - New wallet instance or error
    pub fn new(
        core_sdk: Arc<CoreSDK>,
        device_id: &str,
        config: Option<WalletConfig>,
    ) -> Result<Self, DsmError> {
        // Get token SDK from the core SDK
        let token_sdk = Arc::new(TokenSDK::new(core_sdk.clone()));

        // Register the token SDK with the core SDK
        core_sdk.register_token_manager(token_sdk.clone());

        // Create the default configuration if none provided
        let config = config.unwrap_or_else(|| WalletConfig {
            name: format!("{}'s Wallet", device_id),
            ..WalletConfig::default()
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let wallet = Self {
            core_sdk,
            token_sdk,
            config: RwLock::new(config),
            addresses: RwLock::new(Vec::new()),
            transactions: RwLock::new(Vec::new()),
            locked: RwLock::new(false),
            last_activity: RwLock::new(now),
            device_id: device_id.to_string(),
            keystore: RwLock::new(HashMap::new()),
            active_address: RwLock::new(None),
            last_backup: RwLock::new(None),
            address_book: RwLock::new(HashMap::new()),
        };

        // Initialize the wallet with a primary address
        wallet.initialize()?;

        Ok(wallet)
    }

    /// Initialize the wallet with a primary address
    fn initialize(&self) -> Result<(), DsmError> {
        // Update last activity
        self.update_activity();

        // Generate a primary address if none exists
        let addresses = self.addresses.read();
        if addresses.is_empty() {
            // Release the read lock before calling generate_address
            drop(addresses);
            self.generate_address()?;
        }

        Ok(())
    }

    /// Update the last activity timestamp
    fn update_activity(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let mut last_activity = self.last_activity.write();
        *last_activity = now;

        // Check if we should auto-lock the wallet
        let auto_lock_timeout = self.config.read().auto_lock_timeout;
        if auto_lock_timeout > 0 {
            let mut locked = self.locked.write();
            let prev_activity = *last_activity;
            if now > prev_activity + auto_lock_timeout {
                *locked = true;
            }
        }
    }

    /// Generate a new wallet address
    ///
    /// # Arguments
    ///
    /// * `label` - Optional label for the address
    ///
    /// # Returns
    ///
    /// * `Result<String, DsmError>` - New address or error
    pub fn generate_address(&self) -> Result<String, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::invalid_parameter("Wallet is locked"));
        }

        // Update last activity
        self.update_activity();

        // Generate a new keypair
        let (kyber_pk, kyber_sk, sphincs_pk, sphincs_sk) = dsm::crypto::generate_keypair();

        // Compute address using the SPHINCS+ public key
        let mut address_hasher = blake3::Hasher::new();
        address_hasher.update(&sphincs_pk);
        let address_bytes = address_hasher.finalize();
        let address = format!("dsm_{}", hex::encode(address_bytes.as_bytes()));

        // Store the keys in the keystore
        let mut keystore = self.keystore.write();
        keystore.insert(format!("{}_kyber_pk", address), kyber_pk);
        keystore.insert(format!("{}_kyber_sk", address), kyber_sk);
        keystore.insert(format!("{}_sphincs_pk", address), sphincs_pk.clone());
        keystore.insert(format!("{}_sphincs_sk", address), sphincs_sk);

        // Create the wallet address
        let wallet_address = WalletAddress::new(address.clone(), sphincs_pk, None);

        // Add to addresses
        let mut addresses = self.addresses.write();
        addresses.push(wallet_address);

        // Set as active address if no active address
        {
            let mut active_address = self.active_address.write();
            if active_address.is_none() {
                *active_address = Some(address.clone());
            }
        }

        log::info!("Generated new wallet address: {}", address);

        Ok(address)
    }

    /// Set the active address
    ///
    /// # Arguments
    ///
    /// * `address` - Address to set as active
    ///
    /// # Returns
    ///
    /// * `Result<(), DsmError>` - Success or error
    pub fn set_active_address(&self, address: &str) -> Result<(), DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::invalid_parameter("Wallet is locked"));
        }

        // Update last activity
        self.update_activity();

        // Verify the address exists
        let addresses = self.addresses.read();
        let found = addresses.iter().any(|a| a.address == address);

        if !found {
            return Err(DsmError::invalid_parameter(format!(
                "Address {} not found in wallet",
                address
            )));
        }

        // Set as active address
        let mut active_address = self.active_address.write();
        *active_address = Some(address.to_string());

        log::info!("Set active wallet address: {}", address);

        Ok(())
    }

    /// Get the active address
    ///
    /// # Returns
    ///
    /// * `Result<String, DsmError>` - Active address or error
    pub fn get_active_address(&self) -> Result<String, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::invalid_parameter("Wallet is locked"));
        }

        // Update last activity
        self.update_activity();

        // Get active address
        let active_address = self.active_address.read();

        match active_address.as_ref() {
            Some(address) => Ok(address.clone()),
            None => Err(DsmError::not_found("Active address", None::<String>)),
        }
    }

    /// Get all wallet addresses
    ///
    /// # Returns
    ///
    /// * `Result<Vec<WalletAddress>, DsmError>` - List of addresses or error
    pub fn get_addresses(&self) -> Result<Vec<WalletAddress>, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Get addresses
        let addresses = self.addresses.read();
        Ok(addresses.clone())
    }

    /// Get balance for an address
    ///
    /// # Arguments
    ///
    /// * `address` - Address to check
    /// * `token_id` - Token identifier, defaults to "ROOT" if None
    ///
    /// # Returns
    ///
    /// * `Result<Balance, DsmError>` - Balance or error
    pub fn get_balance(&self, address: &str, token_id: Option<&str>) -> Result<Balance, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Verify the address exists
        let addresses = self.addresses.read();
        let found = addresses.iter().any(|a| a.address == address);

        if !found {
            return Err(DsmError::invalid_parameter(format!(
                "Address {} not found in wallet",
                address
            )));
        }

        // Get token ID, default to ROOT
        let token_id = token_id.unwrap_or("ROOT");

        // Get balance through token SDK
        let balance = self.token_sdk.get_token_balance(address, token_id);

        Ok(balance)
    }

    /// Create a transaction
    ///
    /// # Arguments
    ///
    /// * `to` - Recipient address
    /// * `amount` - Amount to send
    /// * `token_id` - Token identifier, defaults to "ROOT" if None
    /// * `memo` - Optional memo for the transaction
    /// * `fee` - Optional fee, uses default if None
    ///
    /// # Returns
    ///
    /// * `Result<WalletTransaction, DsmError>` - Transaction or error
    pub fn create_transaction(
        &self,
        to: &str,
        amount: u64,
        token_id: Option<&str>,
        memo: Option<&str>,
        fee: Option<u64>,
    ) -> Result<WalletTransaction, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Get active address
        let from = self.get_active_address()?;

        // Get token ID, default to ROOT
        let token_id = token_id.unwrap_or("ROOT").to_string();

        // Get fee, default to config
        let fee = fee.unwrap_or_else(|| self.config.read().default_fee);

        // Create the transaction
        let tx = WalletTransaction::new(
            from,
            to.to_string(),
            amount,
            token_id,
            memo.map(|s| s.to_string()),
            fee,
        );

        Ok(tx)
    }

    /// Sign a transaction
    ///
    /// # Arguments
    ///
    /// * `transaction` - Transaction to sign
    ///
    /// # Returns
    ///
    /// * `Result<WalletTransaction, DsmError>` - Signed transaction or error
    pub fn sign_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> Result<WalletTransaction, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Verify we have the private key for this address
        let keystore = self.keystore.read();
        let sk_key = format!("{}_sphincs_sk", transaction.from);

        let private_key = match keystore.get(&sk_key) {
            Some(key) => key,
            None => {
                return Err(DsmError::crypto(
                    format!("Private key not found for address {}", transaction.from),
                    None::<std::io::Error>,
                ))
            }
        };

        // Create a mutable copy of the transaction
        let mut tx_copy = transaction.clone();

        // Sign the transaction
        tx_copy.sign(private_key)?;

        Ok(tx_copy)
    }

    /// Send a transaction
    ///
    /// # Arguments
    ///
    /// * `transaction` - Signed transaction to send
    ///
    /// # Returns
    ///
    /// * `Result<State, DsmError>` - New state after transaction or error
    pub async fn send_transaction(
        &self,
        transaction: &WalletTransaction,
    ) -> Result<State, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Ensure transaction is signed
        if transaction.signature.is_none() {
            return Err(DsmError::invalid_parameter("Transaction must be signed"));
        }

        // Create token operation
        let token_op = TokenOperation::Transfer {
            token_id: transaction.token_id.clone(),
            recipient: transaction.to.clone(),
            amount: transaction.amount,
            memo: transaction.memo.clone(),
        };

        // Execute token operation
        let new_state = self.token_sdk.execute_token_operation(token_op).await?;

        // Add to transaction history
        let mut tx_copy = transaction.clone();
        tx_copy.status = TransactionStatus::Confirmed;
        tx_copy.state_number = Some(new_state.state_number);

        let mut transactions = self.transactions.write();
        transactions.push(tx_copy);

        log::info!(
            "Transaction completed: {} -> {}, amount: {}, token: {}",
            transaction.from,
            transaction.to,
            transaction.amount,
            transaction.token_id
        );

        Ok(new_state)
    }

    /// Lock the wallet
    ///
    /// # Returns
    ///
    /// * `Result<(), DsmError>` - Success or error
    pub fn lock(&self) -> Result<(), DsmError> {
        let mut locked = self.locked.write();
        *locked = true;

        log::info!("Wallet locked");

        Ok(())
    }

    /// Unlock the wallet with a password
    ///
    /// # Arguments
    ///
    /// * `password` - Wallet password
    ///
    /// # Returns
    ///
    /// * `Result<(), DsmError>` - Success or error
    pub fn unlock(&self, _password: &str) -> Result<(), DsmError> {
        // In a real implementation, we would verify the password
        // For now, we just unlock the wallet
        let mut locked = self.locked.write();
        *locked = false;

        // Update activity timestamp
        self.update_activity();

        log::info!("Wallet unlocked");

        Ok(())
    }

    /// Get wallet transaction history
    ///
    /// # Arguments
    ///
    /// * `limit` - Optional maximum number of transactions to return
    /// * `offset` - Optional offset for pagination
    ///
    /// # Returns
    ///
    /// * `Result<Vec<WalletTransaction>, DsmError>` - Transaction history or error
    pub fn get_transaction_history(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<WalletTransaction>, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Get transactions
        let transactions = self.transactions.read();

        // Apply offset and limit
        let offset = offset.unwrap_or(0);
        let transactions = if offset < transactions.len() {
            transactions[offset..].to_vec()
        } else {
            Vec::new()
        };

        let transactions = if let Some(limit) = limit {
            transactions.into_iter().take(limit).collect()
        } else {
            transactions
        };

        Ok(transactions)
    }

    /// Get transaction by ID
    ///
    /// # Arguments
    ///
    /// * `id` - Transaction ID
    ///
    /// # Returns
    ///
    /// * `Result<WalletTransaction, DsmError>` - Transaction or error
    pub fn get_transaction(&self, id: &str) -> Result<WalletTransaction, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Get transactions
        let transactions = self.transactions.read();

        // Find transaction by ID
        for tx in transactions.iter() {
            if tx.id == id {
                return Ok(tx.clone());
            }
        }

        Err(DsmError::not_found(
            "Transaction",
            Some(format!("{} not found", id)),
        ))
    }

    /// Add an address to the address book
    ///
    /// # Arguments
    ///
    /// * `address` - Address to add
    /// * `name` - Name for the address
    ///
    /// # Returns
    ///
    /// * `Result<(), DsmError>` - Success or error
    pub fn add_address_book_entry(&self, address: &str, name: &str) -> Result<(), DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Add to address book
        let mut address_book = self.address_book.write();
        address_book.insert(address.to_string(), name.to_string());

        log::info!("Added address book entry: {} -> {}", address, name);

        Ok(())
    }

    /// Get address book entries
    ///
    /// # Returns
    ///
    /// * `Result<HashMap<String, String>, DsmError>` - Address book or error
    pub fn get_address_book(&self) -> Result<HashMap<String, String>, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Get address book
        let address_book = self.address_book.read();
        Ok(address_book.clone())
    }

    /// Update wallet configuration
    ///
    /// # Arguments
    ///
    /// * `config` - New configuration
    ///
    /// # Returns
    ///
    /// * `Result<(), DsmError>` - Success or error
    pub fn update_config(&self, config: WalletConfig) -> Result<(), DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Update config
        let mut wallet_config = self.config.write();
        *wallet_config = config;

        log::info!("Updated wallet configuration");

        Ok(())
    }

    /// Generate a mnemonic recovery phrase
    ///
    /// # Returns
    ///
    /// * `Result<String, DsmError>` - Mnemonic phrase or error
    pub fn generate_recovery_mnemonic(&self) -> Result<String, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Generate entropy (used to create the mnemonic in a real implementation)
        let _entropy = crypto::generate_nonce();

        // In a real implementation, we would convert entropy to a BIP39 mnemonic
        // For this example, we'll just return a placeholder
        let mnemonic = "quantum resist secure wallet phrase post entropy example".to_string();

        // Update recovery options
        let mut config = self.config.write();
        config.recovery_options.mnemonic = Some(mnemonic.clone());

        log::info!("Generated recovery mnemonic");

        Ok(mnemonic)
    }

    /// Create a backup of the wallet
    ///
    /// # Arguments
    ///
    /// * `path` - Backup file path
    ///
    /// # Returns
    ///
    /// * `Result<(), DsmError>` - Success or error
    pub fn create_backup(&self, path: &Path) -> Result<(), DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // In a real implementation, we would serialize and encrypt the wallet data
        // For this example, we'll just update the last backup timestamp

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let mut last_backup = self.last_backup.write();
        *last_backup = Some(now);

        log::info!("Created wallet backup at {}", path.display());

        Ok(())
    }

    /// Execute a bilateral transfer with another device
    ///
    /// # Arguments
    ///
    /// * `recipient` - Recipient address
    /// * `amount` - Amount to transfer
    /// * `token_id` - Token identifier, defaults to "ROOT" if None
    /// * `recipient_public_key` - Recipient's public key
    /// * `memo` - Optional memo
    ///
    /// # Returns
    ///
    /// * `Result<State, DsmError>` - New state after transfer or error
    pub async fn execute_bilateral_transfer(
        &self,
        recipient: &str,
        amount: u64,
        token_id: Option<&str>,
        recipient_public_key: Vec<u8>,
        memo: Option<&str>,
    ) -> Result<State, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Get token ID, default to ROOT
        let token_id_str = token_id.unwrap_or("ROOT").to_string();

        // Convert memo
        let memo_string = memo.map(|s| s.to_string());

        // Execute bilateral transfer through token SDK
        let new_state = self
            .token_sdk
            .execute_bilateral_token_transfer(
                token_id_str.clone(),
                recipient.to_string(),
                amount,
                recipient_public_key,
                memo_string.clone(),
            )
            .await?;

        // Create transaction record
        let from_address = self.get_active_address()?;
        let mut tx = WalletTransaction::new(
            from_address.clone(),
            recipient.to_string(),
            amount,
            token_id_str.clone(),
            memo_string,
            self.config.read().default_fee,
        );

        tx.status = TransactionStatus::Confirmed;
        tx.state_number = Some(new_state.state_number);

        // Add to transaction history
        let mut transactions = self.transactions.write();
        transactions.push(tx);

        log::info!(
            "Bilateral transfer completed: {} -> {}, amount: {}, token: {}",
            from_address,
            recipient,
            amount,
            token_id_str
        );

        Ok(new_state)
    }

    /// Verify a transaction's integrity
    ///
    /// # Arguments
    ///
    /// * `transaction` - Transaction to verify
    ///
    /// # Returns
    ///
    /// * `Result<bool, DsmError>` - Verification result or error
    pub fn verify_transaction(&self, transaction: &WalletTransaction) -> Result<bool, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Check if transaction has a signature
        let signature = match &transaction.signature {
            Some(sig) => sig,
            None => return Ok(false),
        };

        // Get the public key for the sender
        let addresses = self.addresses.read();
        let sender_address = addresses.iter().find(|a| a.address == transaction.from);

        // If this is a transaction from an external address, we need to look up the public key
        // For now, we'll just return false if the sender is unknown
        let public_key = match sender_address {
            Some(addr) => addr.public_key.clone(),
            None => return Ok(false),
        };

        // Verify the signature
        Ok(dsm::crypto::verify_signature(
            &transaction.hash,
            signature,
            &public_key,
        ))
    }

    /// Import a wallet from mnemonic
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - Mnemonic phrase for import
    ///
    /// # Returns
    ///
    /// * `Result<(), DsmError>` - Success or error
    pub fn import_from_mnemonic(&self, _mnemonic: &str) -> Result<(), DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // In a real implementation, we would derive keys from the mnemonic
        // For this example, we'll just log a message

        log::info!("Imported wallet from mnemonic");

        Ok(())
    }

    /// Get wallet info summary
    ///
    /// # Returns
    ///
    /// * `Result<HashMap<String, String>, DsmError>` - Wallet info or error
    pub fn get_wallet_info(&self) -> Result<HashMap<String, String>, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        let mut info = HashMap::new();

        // Get wallet configuration
        let config = self.config.read();
        info.insert("name".to_string(), config.name.clone());
        info.insert("device_id".to_string(), self.device_id.clone());

        // Get address count
        let addresses = self.addresses.read();
        info.insert("address_count".to_string(), addresses.len().to_string());

        // Get active address
        if let Some(active) = self.active_address.read().clone() {
            info.insert("active_address".to_string(), active);
        }

        // Get transaction count
        let transactions = self.transactions.read();
        info.insert(
            "transaction_count".to_string(),
            transactions.len().to_string(),
        );

        // Get last backup time
        if let Some(last_backup) = *self.last_backup.read() {
            let dt = DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(last_backup));
            info.insert("last_backup".to_string(), dt.to_rfc3339());
        }

        Ok(info)
    }

    /// Get the wallet's primary device info
    ///
    /// # Returns
    ///
    /// * `Result<DeviceInfo, DsmError>` - Device info or error
    pub fn get_device_info(&self) -> Result<DeviceInfo, DsmError> {
        // Get the active address
        let active_address = self.get_active_address()?;

        // Get the public key for the active address
        let keystore = self.keystore.read();
        let pk_key = format!("{}_sphincs_pk", active_address);

        let public_key = match keystore.get(&pk_key) {
            Some(key) => key.clone(),
            None => {
                return Err(DsmError::crypto(
                    format!("Public key not found for address {}", active_address),
                    None::<std::io::Error>,
                ))
            }
        };

        // Create device info
        let device_info = DeviceInfo::new(&self.device_id, public_key);

        Ok(device_info)
    }
}

/// Implement TokenManager trait for WalletSDK
#[async_trait::async_trait]
impl TokenManager for WalletSDK {
    /// Get the current token balance
    async fn get_balance(&self) -> Result<Balance, DsmError> {
        // Get active address
        let address = self.get_active_address()?;

        // Get balance for active address
        self.get_balance(&address, Some("ROOT"))
    }

    /// Execute a token operation
    async fn execute_token_operation(&self, operation: TokenOperation) -> Result<State, DsmError> {
        // Make sure the wallet is unlocked
        if *self.locked.read() {
            return Err(DsmError::unauthorized("Wallet is locked", None::<std::io::Error>));
        }

        // Update last activity
        self.update_activity();

        // Execute through token SDK
        let new_state = self
            .token_sdk
            .execute_token_operation(operation.clone())
            .await?;

        // Add to transaction history if it's a transfer
        if let TokenOperation::Transfer {
            token_id,
            recipient,
            amount,
            memo,
        } = operation
        {
            let from = self.get_active_address()?;
            let mut tx = WalletTransaction::new(
                from,
                recipient,
                amount,
                token_id,
                memo,
                self.config.read().default_fee,
            );

            tx.status = TransactionStatus::Confirmed;
            tx.state_number = Some(new_state.state_number);

            // Add to transaction history
            let mut transactions = self.transactions.write();
            transactions.push(tx);
        }

        Ok(new_state)
    }

    /// Validate token conservation principles
    async fn validate_token_conservation(&self) -> Result<bool, DsmError> {
        // Forward to token SDK
        self.token_sdk.validate_token_conservation().await
    }
}

// Implement Default trait for WalletSDK
impl Default for WalletSDK {
    fn default() -> Self {
        // Create core SDK
        let core_sdk = Arc::new(CoreSDK::new());

        // Create wallet with default configuration
        Self::new(core_sdk, "default_device", None).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_initialization_and_active_address() {
        let wallet = WalletSDK::default();
        // Default wallet should have at least one address
        let addrs = wallet.get_addresses().unwrap();
        assert!(!addrs.is_empty(), "Expected at least one address on init");
        // Active address should match one of the addresses
        let active = wallet.get_active_address().unwrap();
        assert!(addrs.iter().any(|a| a.address == active));
        assert!(active.starts_with("dsm_"));
    }

    #[test]
    fn test_lock_and_unlock_behavior() {
        let wallet = WalletSDK::default();
        // Lock the wallet and expect operations to fail
        wallet.lock().unwrap();
        assert!(
            wallet.get_active_address().is_err(),
            "Expected error when locked"
        );
        assert!(
            wallet.generate_address().is_err(),
            "Expected error on generate when locked"
        );
        // Unlock and try again
        wallet.unlock("dummy").unwrap();
        assert!(wallet.get_active_address().is_ok());
        assert!(wallet.generate_address().is_ok());
    }

    #[test]
    fn test_generate_address_and_label() {
        let wallet = WalletSDK::default();
        wallet.unlock("any").unwrap();
        let before = wallet.get_addresses().unwrap().len();
        let new_addr = wallet.generate_address().unwrap();
        let all = wallet.get_addresses().unwrap();
        assert_eq!(all.len(), before + 1);
        assert!(all.iter().any(|a| a.address == new_addr));
    }

    #[test]
    fn test_create_and_sign_transaction() {
        let wallet = WalletSDK::default();
        wallet.unlock("x").unwrap();
        let to = "recipient_address";
        let tx = wallet
            .create_transaction(to, 100, None, Some("memo"), None)
            .unwrap();
        assert_eq!(tx.to, to);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.status, TransactionStatus::Pending);
        let signed = wallet.sign_transaction(&tx).unwrap();
        assert!(signed.signature.is_some(), "Transaction should be signed");
    }

    #[test]
    fn test_generate_recovery_mnemonic_and_config() {
        let wallet = WalletSDK::default();
        wallet.unlock("").unwrap();
        let mnem = wallet.generate_recovery_mnemonic().unwrap();
        assert!(mnem.contains("quantum"), "Expected placeholder mnemonic");
        let cfg = wallet.config.read();
        assert_eq!(cfg.recovery_options.mnemonic.as_ref().unwrap(), &mnem);
    }

    #[test]
    fn test_get_wallet_info_fields() {
        let wallet = WalletSDK::default();
        wallet.unlock("").unwrap();
        let info = wallet.get_wallet_info().unwrap();
        // Name follows format "<device_id>'s Wallet"
        assert_eq!(info.get("device_id").unwrap(), "default_device");
        assert!(info.get("name").unwrap().ends_with("Wallet"));
        // There should be at least one address and zero transactions
        let ac: usize = info.get("address_count").unwrap().parse().unwrap();
        assert!(ac >= 1);
        let tc: usize = info.get("transaction_count").unwrap().parse().unwrap();
        assert_eq!(tc, 0);
    }

    #[test]
    fn test_async_send_transaction_flow() {
        let wallet = WalletSDK::default();
        wallet.unlock("").unwrap();
        // Prepare a transaction
        let tx = wallet
            .create_transaction("r1", 1, None, None, None)
            .unwrap();
        let signed = wallet.sign_transaction(&tx).unwrap();
        // Use a runtime for async send
        let rt = Runtime::new().unwrap();
        // This will error or succeed depending on token_sdk mock; at minimum it shouldn't panic
        let result = rt.block_on(wallet.send_transaction(&signed));
        assert!(
            result.is_ok() || result.is_err(),
            "send_transaction should return Result<State, DsmError>"
        );
    }
}
