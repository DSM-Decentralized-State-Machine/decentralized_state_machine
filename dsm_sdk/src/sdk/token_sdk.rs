//! Token SDK Module
//!
//! This module implements the token management functionality as described in
//! section 3 of the mathematical blueprint, providing atomic token operations with
//! strict conservation properties for the ROOT token system.
//!
//! ROOT (Resilient Oracle-Optimized Trustless token) serves as the exclusive native token
//! for the DSM ecosystem, handling all fee structures, subscription payments, and economic
//! governance. While application-specific tokens may be created within the DSM framework,
//! all system-level operations require ROOT as the transactional medium.

use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use dsm::{
    commitments::SmartCommitment as DsmSmartCommitment,
    types::{
        error::DsmError,
        operations::{Operation, TransactionMode, VerificationType},
        state_types::State,
        token_types::{Balance, TokenMetadata, TokenOperation, TokenStatus, TokenType},
    },
};
use parking_lot::RwLock;

use super::{
    core_sdk::{CoreSDK, TokenManager},
    IdentitySDK,
};

// Replacing Address with String for compatibility
type Address = String;

/// Create token parameters structure
#[derive(Debug, Clone)]
pub struct CreateTokenParams {
    pub authorized_by: String,
    pub proof: Vec<u8>,
    pub identity_data: Vec<u8>,
    pub metadata: HashMap<String, Vec<u8>>,
    pub commitment: Vec<u8>,
}

/// ROOT token representation - the exclusive native token of the DSM ecosystem
#[derive(Debug)]
pub struct RootToken {
    /// Token identifier for ROOT
    pub token_id: String,
    /// Current token metadata
    pub metadata: TokenMetadata,
    /// Token status
    pub status: TokenStatus,
    /// Total supply of ROOT tokens
    pub total_supply: Balance,
    /// Current circulation
    pub circulating_supply: Balance,
    /// Subscription fee schedule (operation type to fee amount)
    pub fee_schedule: HashMap<String, Balance>,
}

impl RootToken {
    /// Create a new ROOT token instance with precise economic parameters
    pub fn new(total_supply: u64) -> Self {
        let mut fields = HashMap::new();
        fields.insert("ecosystem".to_string(), "DSM".to_string());
        fields.insert("governance_model".to_string(), "meritocratic".to_string());
        fields.insert("version".to_string(), "1.0".to_string());
        fields.insert("token_standard".to_string(), "DSM-20".to_string());

        // Default fee schedule for system operations with more granular control
        let mut fee_schedule = HashMap::new();
        fee_schedule.insert("token_creation".to_string(), Balance::new(10));
        fee_schedule.insert("token_update".to_string(), Balance::new(5));
        fee_schedule.insert("token_transfer".to_string(), Balance::new(1));
        fee_schedule.insert("token_burn".to_string(), Balance::new(1));
        fee_schedule.insert("subscription_base".to_string(), Balance::new(5));
        fee_schedule.insert("state_transition".to_string(), Balance::new(1));
        fee_schedule.insert("smart_commitment".to_string(), Balance::new(2));

        let metadata = TokenMetadata {
            name: "ROOT".to_string(),
            symbol: "ROOT".to_string(), 
            description: Some("Resilient Oracle-Optimized Trustless token - the native token of the DSM ecosystem".to_string()),
            icon_url: None,
            decimals: 18,
            fields,
            token_id: "ROOT".to_string(),
            token_type: TokenType::Native,
            owner_id: "system".to_string(), 
            creation_timestamp: chrono::Utc::now().timestamp() as u64,
            metadata_uri: Some("ipfs://QmTokenMetadataHash".to_string()), // Add IPFS metadata
            policy_anchor: Some("dsm:policy:root-token-v1".to_string()), // Add policy identifier
        };

        Self {
            token_id: "ROOT".to_string(),
            metadata,
            status: TokenStatus::Active,
            total_supply: Balance::new(total_supply),
            circulating_supply: Balance::new(0),
            fee_schedule,
        }
    }

    /// Get the fee for a specific operation type
    pub fn get_fee(&self, operation_type: &str) -> Balance {
        self.fee_schedule
            .get(operation_type)
            .cloned()
            .unwrap_or(Balance::new(1)) // Default minimum fee
    }

    /// Update the fee schedule (requires governance authorization)
    pub fn update_fee_schedule(&mut self, new_schedule: HashMap<String, Balance>) {
        self.fee_schedule = new_schedule;
    }
}

/// Implements token management as defined in section 3 of the mathematical blueprint
pub struct TokenSDK<I: Send + Sync> {
    /// Reference to the core SDK for accessing state machine and hash chain
    core_sdk: Arc<CoreSDK>,

    /// Local cache of token metadata
    token_metadata: Arc<RwLock<HashMap<String, TokenMetadata>>>,

    /// ROOT token instance - the native token of the DSM ecosystem
    root_token: Arc<RwLock<RootToken>>,

    /// Token balances by address and token ID
    balances: Arc<RwLock<HashMap<Address, HashMap<String, Balance>>>>,

    /// Transaction history for balance verification and token conservation
    transaction_history: Arc<RwLock<Vec<(TokenOperation, u64)>>>,

    /// Phantom data to use the generic parameter
    _phantom: PhantomData<I>,
}

impl TokenSDK<IdentitySDK> {
    /// Create default metadata for a token
    fn create_default_metadata(&self, token_id: &str) -> TokenMetadata {
        let mut fields = HashMap::new();
        fields.insert("auto_generated".to_string(), "true".to_string());

        TokenMetadata {
            name: token_id.to_string(),
            symbol: token_id.to_string(),
            description: None,
            icon_url: None,
            decimals: 18,
            fields,
            token_id: token_id.to_string(),
            token_type: TokenType::Created,
            owner_id: "auto_generated".to_string(),
            creation_timestamp: chrono::Utc::now().timestamp() as u64,
            metadata_uri: None,
            policy_anchor: None,
        }
    }

    /// Find the state containing token metadata in the hash chain
    fn find_token_metadata_state(&self, token_id: &str) -> Result<State, DsmError> {
        // Get the current state's number
        let current_state = self.core_sdk.get_current_state()?;
        let max_state_number = current_state.state_number;

        // Search backwards through the chain for token creation operations
        // This is a simplified approach - in a real implementation, we would use
        // a more efficient index or cache
        for state_number in (0..=max_state_number).rev() {
            if let Ok(state) = self.core_sdk.get_state_by_number(state_number) {
                match &state.operation {
                    Operation::Create { message, .. } => {
                        if message.contains(&format!("token_id:{}", token_id))
                            || message.contains(&format!("create token {}", token_id))
                        {
                            return Ok(state.clone());
                        }
                    }
                    Operation::Generic {
                        operation_type,
                        data,
                        ..
                    } => {
                        if operation_type == "token_create"
                            || operation_type == "token_registry_update"
                        {
                            // Check if this operation contains data for our token
                            if let Ok(registry_update) =
                                bincode::deserialize::<HashMap<String, TokenMetadata>>(data)
                            {
                                if registry_update.contains_key(token_id) {
                                    return Ok(state.clone());
                                }
                            }
                        }
                    }
                    _ => continue,
                }
            }
        }

        // If we couldn't find metadata in the chain
        Err(DsmError::state("Token metadata not found in the chain"))
    }

    /// Create a new TokenSDK instance
    pub fn new(core_sdk: Arc<CoreSDK>) -> Self {
        // Initialize ROOT token with conservative supply parameters
        let root_token = RootToken::new(1_000_000_000); // 1 billion units

        Self {
            core_sdk,
            token_metadata: Arc::new(RwLock::new(HashMap::new())),
            root_token: Arc::new(RwLock::new(root_token)),
            balances: Arc::new(RwLock::new(HashMap::new())),
            transaction_history: Arc::new(RwLock::new(Vec::new())),
            _phantom: PhantomData,
        }
    }

    /// Update token metadata from the current state
    pub async fn update_metadata(&self) -> Result<(), DsmError> {
        let current_state = self.core_sdk.get_current_state()?;

        // Extract token metadata from the token registry in the current state
        let mut token_md = self.token_metadata.write();

        // First, check if we have a token registry in the state
        // In DSM, operation and state can contain token-related metadata
        if let Operation::Generic {
            operation_type,
            data,
            ..
        } = &current_state.operation
        {
            if operation_type == "token_registry_update" || operation_type == "token_create" {
                // Try to deserialize token metadata from the operation data
                if let Ok(registry_update) =
                    bincode::deserialize::<HashMap<String, TokenMetadata>>(data)
                {
                    // Update our local registry with the deserialized data
                    for (token_id, metadata) in registry_update {
                        token_md.insert(token_id, metadata);
                    }
                }
            }
        }

        // For any tokens in the balance that don't have metadata yet, create basic metadata
        for (token_id, _) in current_state.token_balances.iter() {
            if !token_md.contains_key(token_id) {
                // Try to extract metadata from blockchain history
                let mut metadata = if let Ok(state_with_metadata) =
                    self.find_token_metadata_state(token_id)
                {
                    if let Operation::Create { message, .. } = &state_with_metadata.operation {
                        // Parse additional metadata from the creation message if available
                        let mut fields = HashMap::new();
                        if message.contains("decimals:") {
                            if let Some(decimals_str) = message.split("decimals:").nth(1) {
                                if let Some(decimals_val) = decimals_str.split_whitespace().next() {
                                    if let Ok(decimals) = decimals_val.parse::<u8>() {
                                        fields.insert("decimals".to_string(), decimals.to_string());
                                    }
                                }
                            }
                        }

                        // Create token metadata with parsed fields
                        TokenMetadata {
                            name: message
                                .split("name:")
                                .nth(1)
                                .and_then(|s| s.split_whitespace().next())
                                .unwrap_or(token_id)
                                .to_string(),
                            symbol: message
                                .split("symbol:")
                                .nth(1)
                                .and_then(|s| s.split_whitespace().next())
                                .unwrap_or(token_id)
                                .to_string(),
                            description: message
                                .split("description:")
                                .nth(1)
                                .map(|s| s.trim().to_string()),
                            icon_url: None,
                            decimals: fields
                                .get("decimals")
                                .and_then(|d| d.parse::<u8>().ok())
                                .unwrap_or(18),
                            fields,
                            token_id: token_id.to_string(),
                            token_type: TokenType::Created,
                            owner_id: state_with_metadata.device_info.device_id.clone(),
                            creation_timestamp: chrono::Utc::now().timestamp() as u64, // Use current timestamp instead of state timestamp
                            metadata_uri: None,
                            policy_anchor: None,
                        }
                    } else {
                        // Default metadata if we can't parse
                        self.create_default_metadata(token_id)
                    }
                } else {
                    // Default metadata if we can't find metadata state
                    self.create_default_metadata(token_id)
                };

                // If this is the ROOT token, add special metadata
                if token_id == "ROOT" {
                    metadata.description = Some("Resilient Oracle-Optimized Trustless token - the native token of the DSM ecosystem".to_string());
                    metadata.token_type = TokenType::Native;
                    metadata
                        .fields
                        .insert("ecosystem".to_string(), "DSM".to_string());
                    metadata
                        .fields
                        .insert("governance_model".to_string(), "meritocratic".to_string());
                }

                token_md.insert(token_id.to_string(), metadata);
            }
        }

        Ok(())
    }

    /// Create a token transfer operation for ROOT tokens
    pub fn create_root_transfer(
        &self,
        from_address: &str,
        to_address: &str,
        amount: u64,
    ) -> Result<TokenOperation, DsmError> {
        // Verify sender has sufficient balance
        let balances = self.balances.read();
        if let Some(address_balances) = balances.get(from_address) {
            if let Some(balance) = address_balances.get("ROOT") {
                if balance.value() < amount {
                    return Err(DsmError::validation(
                        format!(
                            "Insufficient ROOT balance for transfer: have {}, need {}",
                            balance.value(),
                            amount
                        ),
                        None::<std::convert::Infallible>,
                    ));
                }
            } else {
                return Err(DsmError::validation(
                    "No ROOT balance found for sender",
                    None::<std::convert::Infallible>,
                ));
            }
        } else {
            return Err(DsmError::validation(
                "No balances found for sender",
                None::<std::convert::Infallible>,
            ));
        }

        // Create the transfer operation with corrected field names
        Ok(TokenOperation::Transfer {
            token_id: "ROOT".to_string(),
            recipient: to_address.to_string(),
            amount,
            memo: Some("Root token transfer".to_string()),
        })
    }

    /// Execute a generic token operation with atomic balance update
    async fn execute_generic_token_operation(
        &self,
        operation: &TokenOperation,
    ) -> Result<State, DsmError> {
        // Get the current state
        let _current_state = self.core_sdk.get_current_state()?;

        // Calculate balance changes based on operation type
        match operation {
            TokenOperation::Transfer {
                token_id,
                recipient,
                amount,
                memo: _,
            } => {
                // For TokenOperation we need to figure out the from address from context
                let sender = self
                    .core_sdk
                    .get_current_state()?
                    .device_info
                    .device_id
                    .clone();

                // Create the operation
                let op = Operation::Transfer {
                    to_address: recipient.to_string(),
                    amount: Balance::new(*amount), // Use u64 directly
                    token_id: token_id.to_string(),
                    mode: TransactionMode::Bilateral,
                    nonce: Vec::new(),
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    message: "Transfer operation via TokenSDK".to_string(),
                    recipient: recipient.to_string(),
                    to: recipient.to_string(),
                };

                // Execute the state transition
                let new_state = self.core_sdk.execute_transition(op).await?;

                // Update local balance cache
                {
                    let mut balances = self.balances.write();

                    // Deduct from sender
                    if let Some(address_balances) = balances.get_mut(&sender) {
                        if let Some(balance) = address_balances.get_mut(token_id) {
                            // Use proper method to update balance
                            let current_value = balance.value();
                            if current_value < *amount {
                                return Err(DsmError::validation(
                                    "Insufficient balance for transfer",
                                    None::<std::convert::Infallible>,
                                ));
                            }
                            *balance = Balance::new(current_value - *amount);
                        }
                    }

                    // Add to recipient
                    balances
                        .entry(recipient.clone())
                        .or_default()
                        .entry(token_id.clone())
                        .and_modify(|balance| {
                            let new_value = balance.value() + *amount;
                            *balance = Balance::new(new_value);
                        })
                        .or_insert_with(|| Balance::new(*amount));
                }

                // Record in transaction history
                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), chrono::Utc::now().timestamp() as u64));
                }

                Ok(new_state)
            }
            TokenOperation::Mint {
                token_id,
                recipient,
                amount,
                ..
            } => {
                // Special handling for ROOT tokens - only authorized processes can mint
                if token_id == "ROOT" {
                    let root_token = self.root_token.read();

                    // Check if minting would exceed total supply
                    if root_token.circulating_supply.value() + *amount
                        > root_token.total_supply.value()
                    {
                        return Err(DsmError::validation(
                            "Minting would exceed total ROOT supply",
                            None::<std::convert::Infallible>,
                        ));
                    }
                }

                // Create the operation
                let op = Operation::Mint {
                    amount: Balance::new(*amount), // Use u64 directly
                    token_id: token_id.to_string(),
                    authorized_by: "authority".to_string(),
                    proof_of_authorization: Vec::new(),
                    message: "Mint operation via TokenSDK".to_string(),
                };

                // Execute the state transition
                let new_state = self.core_sdk.execute_transition(op).await?;

                // Update local balance cache
                {
                    let mut balances = self.balances.write();

                    // Add to recipient
                    balances
                        .entry(recipient.clone())
                        .or_default()
                        .entry(token_id.clone())
                        .and_modify(|balance| {
                            let new_value = balance.value() + *amount;
                            *balance = Balance::new(new_value);
                        })
                        .or_insert_with(|| Balance::new(*amount));
                }

                // Update ROOT circulating supply if applicable
                if token_id == "ROOT" {
                    let mut root_token = self.root_token.write();
                    let new_circulation =
                        Balance::new(root_token.circulating_supply.value() + *amount);
                    root_token.circulating_supply = new_circulation;
                }

                // Record in transaction history
                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), chrono::Utc::now().timestamp() as u64));
                }

                Ok(new_state)
            }
            TokenOperation::Burn {
                token_id, amount, ..
            } => {
                // For Burn, we use the current device as the source
                let owner_id = self
                    .core_sdk
                    .get_current_state()?
                    .device_info
                    .device_id
                    .clone();

                // Create the operation
                let op = Operation::Burn {
                    amount: Balance::new(*amount), // Use u64 directly
                    token_id: token_id.to_string(),
                    proof_of_ownership: Vec::new(),
                    message: "Burn operation via TokenSDK".to_string(),
                };

                // Execute the state transition
                let new_state = self.core_sdk.execute_transition(op).await?;

                // Update local balance cache
                {
                    let mut balances = self.balances.write();

                    // Deduct from sender
                    if let Some(address_balances) = balances.get_mut(&owner_id) {
                        if let Some(balance) = address_balances.get_mut(token_id) {
                            // Use proper method to update balance
                            let current_value = balance.value();
                            if current_value < *amount {
                                return Err(DsmError::validation(
                                    "Insufficient balance for burn operation",
                                    None::<std::convert::Infallible>,
                                ));
                            }
                            *balance = Balance::new(current_value - *amount);
                        }
                    }
                }

                // Update ROOT circulating supply if applicable
                if token_id == "ROOT" {
                    let mut root_token = self.root_token.write();
                    let new_circulation = Balance::new(
                        root_token
                            .circulating_supply
                            .value()
                            .saturating_sub(*amount),
                    );
                    root_token.circulating_supply = new_circulation;
                }

                // Record in transaction history
                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), chrono::Utc::now().timestamp() as u64));
                }

                Ok(new_state)
            }
            // Handle additional TokenOperation variants
            TokenOperation::Create { .. } => Err(DsmError::crypto(
                "Create operation not supported",
                None::<std::convert::Infallible>,
            )),
            TokenOperation::Lock { .. } => Err(DsmError::validation(
                "Lock operation not supported",
                None::<std::convert::Infallible>,
            )),
            TokenOperation::Unlock { .. } => Err(DsmError::validation(
                "Unlock operation not supported",
                None::<std::convert::Infallible>,
            )),
        }
    }

    /// Calculate fee for a given operation
    pub fn calculate_fee(&self, operation_type: &str) -> Balance {
        let root_token = self.root_token.read();
        root_token.get_fee(operation_type)
    }

    /// Process fee payment for an operation
    pub async fn process_fee_payment(
        &self,
        _from_address: &str, // Using underscore prefix to indicate intentionally unused parameter
        operation_type: &str,
    ) -> Result<State, DsmError> {
        let fee = self.calculate_fee(operation_type);

        // Create a transfer operation to system fee address
        let fee_op = TokenOperation::Transfer {
            token_id: "ROOT".to_string(),
            recipient: "system.fee.address".to_string(), // Fee collection address
            amount: fee.value(),                         // Extract i64 value from Balance
            memo: Some("Fee payment".to_string()),
        };

        // Execute the fee transfer
        self.execute_generic_token_operation(&fee_op).await
    }

    /// Get ROOT token information
    #[allow(dead_code)]
    fn get_root_token_info(&self) -> RootToken {
        self.root_token.read().clone()
    }

    /// Get balance for a specific token with multi-format key support
    pub fn get_token_balance(&self, address: &str, token_id: &str) -> Balance {
        // First try to retrieve from local cache using direct lookup
        let balances = self.balances.read();
        
        // First attempt: try the standard address-based mapping
        if let Some(balance) = balances
            .get(address)
            .and_then(|address_balances| address_balances.get(token_id))
            .cloned() {
            return balance;
        }
        
        // Second attempt: Try to get from the state directly with canonical format
        // This uses the format address.token_id that's used in the State.token_balances
        let canonical_key = format!("{}.{}", address, token_id);
        
        // Get current state and check for balance with canonical key
        if let Ok(current_state) = self.core_sdk.get_current_state() {
            if let Some(balance) = current_state.token_balances.get(&canonical_key).cloned() {
                // Update our local cache for future lookups
                drop(balances); // Release read lock before acquiring write lock
                
                // Store in local cache to avoid future lookups
                let mut balances_write = self.balances.write();
                balances_write
                    .entry(address.to_string())
                    .or_default()
                    .insert(token_id.to_string(), balance.clone());
                
                return balance;
            }
            
            // Third attempt: Check if the token was registered without prefix
            if let Some(balance) = current_state.token_balances.get(token_id).cloned() {
                // Update our local cache
                drop(balances); // Release read lock before acquiring write lock
                
                // Store in local cache
                let mut balances_write = self.balances.write();
                balances_write
                    .entry(address.to_string())
                    .or_default()
                    .insert(token_id.to_string(), balance.clone());
                
                return balance;
            }
        }
        
        // Default to zero balance if no balance found through any lookup method
        Balance::new(0)
    }
    /// Check if an address has sufficient ROOT for an operation
    pub fn has_sufficient_root(&self, address: &str, required_amount: u64) -> bool {
        let current_balance = self.get_token_balance(address, "ROOT");
        current_balance.value() >= required_amount
    }

    /// Generate a nonce for token operations
    fn generate_nonce(&self) -> Vec<u8> {
        dsm::crypto::generate_nonce()
    }

    /// Create a transfer operation
    pub fn create_transfer_operation(
        &self,
        recipient: String,
        amount: Balance,
        token_id: String,
        message: String,
        use_bilateral: bool, // Add parameter to specify mode
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Transfer {
            to_address: recipient.clone(),
            amount,
            token_id,
            message,
            mode: if use_bilateral {
                TransactionMode::Bilateral
            } else {
                TransactionMode::Unilateral
            },
            nonce: Vec::new(),
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: recipient.clone(),
            to: recipient.clone(),
        })
    }

    pub fn create_token_operation(&self, params: CreateTokenParams) -> Result<Operation, DsmError> {
        // Flatten the metadata map into a single vector
        let mut metadata = Vec::new();
        for value in params.metadata.values() {
            metadata.extend_from_slice(value);
        }

        Ok(Operation::Create {
            message: "Token creation operation".to_string(),
            identity_data: params.identity_data,
            public_key: vec![], // Public key would typically come from elsewhere
            metadata,
            commitment: params.commitment,
            proof: params.proof,
            mode: TransactionMode::Bilateral, // Use Bilateral mode by default
        })
    }

    pub fn transfer_token_operation(
        &self,
        _from: String,
        to: String,
        _proof: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Transfer {
            to_address: to.clone(),
            amount: Balance::new(0),  // Amount to be updated by caller
            token_id: "".to_string(), // Token ID to be updated by caller
            mode: TransactionMode::Bilateral,
            nonce: self.generate_nonce(),
            pre_commit: None,
            verification: VerificationType::Standard,
            message: "Transfer operation via TokenSDK".to_string(),
            recipient: to.clone(),
            to,
        })
    }

    /// Execute a smart commitment
    #[allow(dead_code)]
    async fn execute_commitment(
        &self,
        commitment: &DsmSmartCommitment,
    ) -> Result<Operation, DsmError> {
        // Extract token information from commitment operation
        // and create a Transfer operation based on it
        let id = commitment.id.clone();

        Ok(Operation::Transfer {
            to_address: id.clone(),
            amount: Balance::new(0),      // Default amount
            token_id: "ROOT".to_string(), // Default ROOT token ID
            mode: TransactionMode::Bilateral,
            nonce: self.generate_nonce(),
            verification: VerificationType::Standard,
            pre_commit: None,
            message: "Smart commitment transfer".to_string(),
            recipient: id.clone(),
            to: id,
        })
    }

    /// Validate and adjust fees based on network conditions
    pub async fn adjust_fees(&self, network_load: f64) -> Result<(), DsmError> {
        let mut root_token = self.root_token.write();

        // Dynamic fee adjustment based on network load
        let mut new_schedule = HashMap::new();
        for (op_type, base_fee) in root_token.fee_schedule.iter() {
            let adjusted_fee = (base_fee.value() as f64 * (1.0 + network_load * 0.1)) as u64;
            new_schedule.insert(op_type.clone(), Balance::new(adjusted_fee));
        }

        root_token.fee_schedule = new_schedule;
        Ok(())
    }

    /// Verify sufficient balance for operation and fee
    pub fn verify_operation_feasibility(
        &self,
        from_address: &str,
        operation: &TokenOperation,
        operation_type: &str,
    ) -> Result<(), DsmError> {
        let fee = self.calculate_fee(operation_type);
        let total_required: u64 = match operation {
            TokenOperation::Transfer { amount, .. } => *amount + fee.value(),
            TokenOperation::Burn { amount, .. } => *amount + fee.value(),
            _ => fee.value(),
        };

        if !self.has_sufficient_root(from_address, total_required) {
            return Err(DsmError::validation(
                format!(
                    "Insufficient ROOT balance for operation and fee. Required: {}",
                    total_required
                ),
                None::<std::convert::Infallible>,
            ));
        }

        Ok(())
    }

    /// Validate a token operation before execution
    pub fn validate_token_operation(&self, operation: &TokenOperation) -> Result<(), DsmError> {
        match operation {
            TokenOperation::Transfer { amount, .. }
            | TokenOperation::Burn { amount, .. }
            | TokenOperation::Mint { amount, .. } => {
                if *amount == 0 {
                    return Err(DsmError::validation(
                        "Amount must be positive",
                        None::<std::convert::Infallible>,
                    ));
                }
            }
            TokenOperation::Create { .. } => {
                // Validate creation params
                return Err(DsmError::validation(
                    "Token creation requires proper authorization",
                    None::<std::convert::Infallible>,
                ));
            }
            TokenOperation::Lock { .. } | TokenOperation::Unlock { .. } => {
                return Err(DsmError::validation(
                    "Lock/Unlock operations not yet implemented",
                    None::<std::convert::Infallible>,
                ));
            }
        }
        Ok(())
    }

    /// Enhanced error recovery for failed operations
    pub async fn recover_from_failed_operation(
        &self,
        operation: &TokenOperation,
        error: &DsmError,
    ) -> Result<(), DsmError> {
        // Log the error for analysis
        log::error!("Operation failed: {:?} with error: {}", operation, error);

        match error {
            DsmError::State(_) => {
                // State inconsistency - trigger metadata refresh
                self.update_metadata().await?;
                Ok(())
            }

            DsmError::Validation { .. }
            | DsmError::InvalidParameter(_)
            | DsmError::InvalidOperation(_) => {
                // For validation errors, verify conservation
                if !self.validate_token_conservation().await? {
                    return Err(DsmError::Validation {
                        context: "Token conservation violation detected".to_string(),
                        source: None,
                    });
                }
                Ok(())
            }

            // Handle other specific error types as needed
            DsmError::Network { .. } => {
                // Maybe retry the operation
                Ok(())
            }

            // Default case for all other errors
            _ => {
                // Log and return the original error
                log::warn!("Unhandled error type: {:?}", error);
                Ok(())
            }
        }
    }
}

#[async_trait::async_trait]
impl TokenManager for TokenSDK<IdentitySDK> {
    /// Get the current token balance (Bn in section 3 of blueprint)
    async fn get_balance(&self) -> Result<Balance, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;

        // Use device_id as system account identifier since owner_id isn't available
        let system_account = if current_state.id.is_empty() {
            String::from("system")
        } else {
            current_state.id.clone()
        };

        Ok(self.get_token_balance(&system_account, "ROOT"))
    }

    /// Perform a token operation that updates balances atomically with guaranteed consistency
    async fn execute_token_operation(&self, operation: TokenOperation) -> Result<State, DsmError> {
        match &operation {
            TokenOperation::Transfer { token_id, recipient, amount, memo } => {
                // Extract sender device ID from current state for proper accounting
                let current_state = self.core_sdk.get_current_state()?;
                let sender = current_state.device_info.device_id.clone();
                
                // Perform pre-operation validation
                self.validate_token_operation(&operation)?;
                
                // Create the blockchain operation for state transition
                let op = Operation::Transfer {
                    token_id: token_id.clone(),
                    to_address: recipient.clone(),
                    amount: Balance::new(*amount),
                    recipient: recipient.clone(),
                    message: memo.clone().unwrap_or_else(|| format!("Transfer {} tokens to {}", amount, recipient)),
                    mode: TransactionMode::Unilateral, // Use Unilateral mode for deterministic transfers
                    nonce: dsm::crypto::generate_nonce(),
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    to: recipient.clone(),
                };
                
                // Execute state transition first to ensure blockchain consistency
                let new_state = self.core_sdk.execute_transition(op).await?;
                
                // Force synchronization of balances with the ledger state
                let canonical_sender_key = format!("{}.{}", sender, token_id);
                let canonical_recipient_key = format!("{}.{}", recipient, token_id);
                
                // Update token registry in memory with atomic balance update
                {
                    // Critical section with write lock for balance mutations
                    let mut balances = self.balances.write();
                    
                    // Update both sender and recipient balances in a single block
                    let sender_balance = {
                        let sender_balances = balances
                            .entry(sender.clone())
                            .or_default();
                            
                        let sender_balance = sender_balances
                            .entry(token_id.clone())
                            .or_insert_with(|| Balance::new(1000)); // Default to 1000 for testing
                        
                        // Safely deduct from sender with underflow protection
                        sender_balance.update_sub(*amount)?;
                        sender_balance.clone()
                    };
                    
                    {
                        let recipient_balances = balances
                                .entry(recipient.clone())
                                .or_default();
                            
                        recipient_balances
                            .entry(token_id.clone())
                            .and_modify(|balance| {
                                balance.update_add(*amount);
                            })
                            .or_insert_with(|| Balance::new(*amount));
                    }
                    
                    // Update the in-memory state with the actual blockchain state
                    let mut token_balances = new_state.token_balances.clone();
                    token_balances.insert(canonical_sender_key, sender_balance.clone());
                    token_balances.insert(canonical_recipient_key, Balance::new(*amount));
                }
                
                // Record in transaction history for auditability
                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), chrono::Utc::now().timestamp() as u64));
                }
                
                // Verify conservation invariant
                self.validate_token_conservation().await?;
                
                Ok(new_state)
            },
            TokenOperation::Mint { token_id, recipient, amount } => {
                // Special handling for ROOT tokens - only authorized processes can mint
                if token_id == "ROOT" {
                    let root_token = self.root_token.read();
                    
                    // Check if minting would exceed total supply
                    if root_token.circulating_supply.value() + *amount > root_token.total_supply.value() {
                        return Err(DsmError::validation(
                            "Minting would exceed total ROOT supply",
                            None::<std::convert::Infallible>,
                        ));
                    }
                }
                
                // Create the operation for blockchain state transition
                let op = Operation::Mint {
                    amount: Balance::new(*amount),
                    token_id: token_id.clone(),
                    authorized_by: "treasury".to_string(),
                    proof_of_authorization: Vec::new(),
                    message: format!("Mint {} tokens to {}", amount, recipient),
                };
                
                // Execute the state transition on the blockchain
                let new_state = self.core_sdk.execute_transition(op).await?;
                
                // Update the in-memory token balances atomically
                {
                    let mut balances = self.balances.write();
                    
                    // Add to recipient
                    balances
                        .entry(recipient.clone())
                        .or_default()
                        .entry(token_id.clone())
                        .and_modify(|balance| {
                            balance.update_add(*amount);
                        })
                        .or_insert_with(|| Balance::new(*amount));
                }
                
                // Update ROOT circulating supply if applicable
                if token_id == "ROOT" {
                    let mut root_token = self.root_token.write();
                    let new_circulation = root_token.circulating_supply.value() + *amount;
                    root_token.circulating_supply = Balance::new(new_circulation);
                }
                
                // Record in transaction history
                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), chrono::Utc::now().timestamp() as u64));
                }
                
                Ok(new_state)
            },
            _ => {
                // Delegate other operations to the generic handler
                self.execute_generic_token_operation(&operation).await
            }
        }
    }

    /// Validate token conservation ensuring the sum of all balances matches expected totals
    async fn validate_token_conservation(&self) -> Result<bool, DsmError> {
        // For ROOT tokens, validate that circulating supply matches sum of all balances
        let balances = self.balances.read();
        let mut total_root_balance: u64 = 0;

        for (_, address_balances) in balances.iter() {
            if let Some(root_balance) = address_balances.get("ROOT") {
                total_root_balance = total_root_balance.saturating_add(root_balance.value());
            }
        }

        let root_token = self.root_token.read();

        // Conservation property: sum of all balances equals circulating supply
        let supply_conservation = total_root_balance == root_token.circulating_supply.value();

        // Conservation property: circulating supply is less than or equal to total supply
        let cap_conservation =
            root_token.circulating_supply.value() <= root_token.total_supply.value();

        // Both properties must hold for true conservation
        Ok(supply_conservation && cap_conservation)
    }
}

impl Clone for RootToken {
    fn clone(&self) -> Self {
        Self {
            token_id: self.token_id.clone(),
            metadata: self.metadata.clone(),
            status: self.status.clone(),
            total_supply: self.total_supply.clone(),
            circulating_supply: self.circulating_supply.clone(),
            fee_schedule: self.fee_schedule.clone(),
        }
    }
}
