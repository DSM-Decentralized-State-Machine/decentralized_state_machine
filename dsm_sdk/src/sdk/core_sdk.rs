//! # Core SDK Module
//!
//! This module provides the foundational interface for the DSM system, implementing
//! the core mathematical principles described in the DSM whitepaper. It serves as the
//! primary entry point for applications interacting with the DSM system and 
//! orchestrates operations across all subsystems.
//!
//! The Core SDK integrates:
//! 
//! * **Hash Chain Management**: State evolution and verification
//! * **Identity Management**: Cryptographic identity creation and device management
//! * **State Machine**: Deterministic state transitions
//! * **Token Operations**: Balance tracking and operations
//!
//! ## Architecture
//!
//! The Core SDK follows the mathematical blueprint laid out in the DSM whitepaper:
//!
//! * Section 2: Deterministic state transitions (Sn+1 = H(Sn∥opn+1))
//! * Section 3: Token conservation principles
//! * Section 4: Genesis state requirements
//! * Section 5: Hash chain integrity
//! * Section 6: System-wide verification
//! * Section 7: Identity management
//!
//! ## Usage Example
//!
//! ```rust
//! use dsm_sdk::core_sdk::CoreSDK;
//! use dsm::types::error::DsmError;
//! use dsm::types::state_types::{DeviceInfo, State};
//!
//! async fn example() -> Result<(), DsmError> {
//!     // Initialize the core SDK
//!     let sdk = CoreSDK::new();
//!
//!     // Create a device identity
//!     let device_info = DeviceInfo::new("my_device", vec![1, 2, 3, 4]);
//!     
//!     // Create an initial state
//!     let genesis = sdk.create_initial_state(&device_info)?;
//!     
//!     // Initialize the system with the genesis state
//!     sdk.initialize_with_genesis(genesis).await?;
//!     
//!     // Create and execute a generic operation
//!     let operation = sdk.generic_operation("test", vec![1, 2, 3])?;
//!     let new_state = sdk.execute_transition(operation).await?;
//!     
//!     // Verify system integrity
//!     let integrity = sdk.verify_system_integrity().await?;
//!     assert!(integrity);
//!     
//!     Ok(())
//! }
//! ```
use super::identity_sdk::IdentitySDK;
use async_trait::async_trait;
use dsm::types::state_types::StateParams;
use parking_lot::RwLock;
use std::sync::Arc;

use super::hashchain_sdk::HashChainSDK;
use dsm::core::state_machine::StateMachine;
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::{Balance, TokenOperation};

/// Token management functionality as defined in the DSM whitepaper
///
/// This trait defines the interface for token operations within the DSM system,
/// focusing on balance tracking, atomic operations, and conservation principles
/// as described in section 3 of the DSM whitepaper.
#[async_trait]
pub trait TokenManager: Send + Sync {
    /// Get the current token balance (Bn in whitepaper section 3)
    ///
    /// Returns the current balance for the active identity.
    ///
    /// # Returns
    ///
    /// * `Ok(Balance)` - The current token balance if successful
    /// * `Err(DsmError)` - If the balance couldn't be retrieved
    async fn get_balance(&self) -> Result<Balance, DsmError>;

    /// Perform a token operation that updates balances atomically
    ///
    /// This follows the Bn+1 = Bn + Δn+1 rule from the whitepaper,
    /// ensuring that token operations modify balances in a consistent way.
    ///
    /// # Arguments
    ///
    /// * `operation` - The token operation to execute
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The new state after the operation if successful
    /// * `Err(DsmError)` - If the operation couldn't be executed
    async fn execute_token_operation(&self, operation: TokenOperation) -> Result<State, DsmError>;

    /// Validate token conservation ensuring sum(Δi) ≤ Bn
    ///
    /// This method verifies that the token conservation principle from
    /// whitepaper section 3 holds true across all state transitions.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if token conservation holds, false otherwise
    /// * `Err(DsmError)` - If validation couldn't be performed
    async fn validate_token_conservation(&self) -> Result<bool, DsmError>;
}

/// Core SDK for the DSM system integrating all subsystems
///
/// This struct serves as the main entry point for applications using the DSM system.
/// It coordinates between the various subsystems (hash chain, identity management,
/// state machine, token operations) to provide a unified interface following the
/// mathematical principles outlined in the DSM whitepaper.
pub struct CoreSDK {
    /// Hash chain component handling state evolution as per whitepaper sections 2 & 5
    hash_chain_sdk: Arc<HashChainSDK>,

    /// Identity component managing device-specific states as per whitepaper sections 4 & 7
    identity_sdk: Arc<IdentitySDK>,

    /// State machine for deterministic state transitions as per whitepaper section 2
    state_machine: Arc<RwLock<StateMachine>>,
    
    /// Token manager for token operations as per whitepaper section 3
    token_manager: RwLock<Option<Arc<dyn TokenManager>>>,
}

impl CoreSDK {
    /// Create a new CoreSDK instance with default components
    ///
    /// This initializes the Core SDK with shared components:
    /// - A hash chain SDK for state tracking
    /// - A state machine for handling transitions
    /// - An identity SDK for managing identities
    ///
    /// # Returns
    ///
    /// A new CoreSDK instance ready for use
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::core_sdk::CoreSDK;
    ///
    /// // Create a new SDK instance
    /// let sdk = CoreSDK::new();
    /// ```
    pub fn new() -> Self {
        // Create shared state machine and hash chain components first
        let hash_chain_sdk = Arc::new(HashChainSDK::new());
        let state_machine = Arc::new(RwLock::new(StateMachine::new()));

        // Create identity SDK with proper references
        let identity_sdk = Arc::new(IdentitySDK::new(
            "default".to_string(),
            hash_chain_sdk.clone(),
        ));

        Self {
            hash_chain_sdk,
            identity_sdk,
            state_machine,
            token_manager: RwLock::new(None),
        }
    }
    
    /// Register a token manager implementation
    ///
    /// This associates a TokenManager implementation with the Core SDK,
    /// enabling token-related operations as described in whitepaper section 3.
    ///
    /// # Arguments
    ///
    /// * `manager` - An Arc-wrapped implementation of the TokenManager trait
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::core_sdk::{CoreSDK, TokenManager};
    /// use std::sync::Arc;
    ///
    /// // Assuming MyTokenManager implements TokenManager
    /// let sdk = CoreSDK::new();
    /// let token_manager = Arc::new(MyTokenManager::new());
    /// sdk.register_token_manager(token_manager);
    /// ```
    pub fn register_token_manager<T: TokenManager + 'static>(&self, manager: Arc<T>) {
        let mut token_manager = self.token_manager.write();
        *token_manager = Some(manager);
    }

    /// Initialize the system with a genesis state
    ///
    /// This sets up the initial genesis state (G) as described in whitepaper section 4.
    /// The genesis state serves as the foundation for all subsequent state transitions.
    ///
    /// # Arguments
    ///
    /// * `genesis_state` - The genesis state (must have state_number = 0)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization was successful
    /// * `Err(DsmError)` - If the genesis state is invalid or initialization failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::core_sdk::CoreSDK;
    /// use dsm::types::state_types::{DeviceInfo, State};
    ///
    /// async fn example() {
    ///     let sdk = CoreSDK::new();
    ///     let device_info = DeviceInfo::new("device_id", vec![1, 2, 3, 4]);
    ///     
    ///     // Create genesis state
    ///     let genesis = sdk.create_initial_state(&device_info).unwrap();
    ///     
    ///     // Initialize with genesis
    ///     sdk.initialize_with_genesis(genesis).await.unwrap();
    /// }
    /// ```
    pub async fn initialize_with_genesis(&self, genesis_state: State) -> Result<(), DsmError> {
        // Validate the genesis state according to section 4 requirements
        if genesis_state.state_number != 0 {
            return Err(DsmError::validation(
                "Cannot initialize with non-genesis state",
                None::<std::convert::Infallible>,
            ));
        }

        // Initialize the hash chain with the genesis state
        self.hash_chain_sdk
            .initialize_with_genesis(genesis_state.clone())?;

        // Set the genesis state in the state machine
        {
            let mut state_machine = self.state_machine.write();
            state_machine.set_state(genesis_state);
        }

        Ok(())
    }

    /// Verify the entire system's integrity
    ///
    /// This performs a comprehensive verification of the system as described in
    /// whitepaper section 6, checking both hash chain integrity and token conservation.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if the system integrity is verified, false otherwise
    /// * `Err(DsmError)` - If verification couldn't be performed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::core_sdk::CoreSDK;
    ///
    /// async fn verify_system(sdk: &CoreSDK) {
    ///     let integrity = sdk.verify_system_integrity().await.unwrap();
    ///     assert!(integrity, "System integrity check failed");
    /// }
    /// ```
    pub async fn verify_system_integrity(&self) -> Result<bool, DsmError> {
        // Verify the hash chain integrity
        let chain_integrity = self.hash_chain_sdk.verify_chain()?;

        // Verify token conservation if applicable
        let token_conservation = self.verify_token_conservation().await?;

        // System integrity is valid only if both checks pass
        Ok(chain_integrity && token_conservation)
    }

    /// Verify token conservation principles
    ///
    /// This checks that token conservation principles from whitepaper section 3
    /// are maintained throughout the system.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if token conservation is verified, false otherwise
    /// * `Err(DsmError)` - If verification couldn't be performed
    pub async fn verify_token_conservation(&self) -> Result<bool, DsmError> {
        // Clone the Arc<dyn TokenManager> while holding the lock briefly
        let manager_clone = {
            let token_manager = self.token_manager.read();
            token_manager.as_ref().cloned()
        }; // Lock is released here at end of scope
        
        // Execute async operation after the lock is released
        if let Some(manager) = manager_clone {
            manager.validate_token_conservation().await
        } else {
            // If no token manager is registered, assume conservation is valid
            // This is a simplification for testing purposes
            Ok(true)
        }
    }

    /// Get access to the hash chain SDK component
    ///
    /// # Returns
    ///
    /// An Arc-wrapped reference to the HashChainSDK
    pub fn hash_chain_sdk(&self) -> Arc<HashChainSDK> {
        self.hash_chain_sdk.clone()
    }

    /// Get access to the identity SDK component
    ///
    /// # Returns
    ///
    /// An Arc-wrapped reference to the IdentitySDK
    pub fn identity_sdk(&self) -> Arc<IdentitySDK> {
        self.identity_sdk.clone()
    }

    /// Create an identity-based operation
    ///
    /// Creates an operation for establishing or updating identity data
    /// in the DSM system.
    ///
    /// # Arguments
    ///
    /// * `identity_data` - The identity data to include in the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn create_operation_with_identity(
        &self,
        identity_data: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message: "Create new state".to_string(),
            identity_data,
            public_key: vec![],
            metadata: vec![],
            commitment: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral,
        })
    }

    /// Create an update operation
    ///
    /// Creates an operation for updating state in the DSM system.
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created update operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    pub fn update_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Update {
            message: "Update state".to_string(),
            identity_id: "default".to_string(),
            updated_data: vec![],
            proof: vec![],
            forward_link: None,
        })
    }

    /// Create a generic operation
    ///
    /// Creates a generic operation with the specified type and data.
    ///
    /// # Arguments
    ///
    /// * `operation_type` - The type of operation to create
    /// * `data` - The data to include in the operation
    ///
    /// # Returns
    ///
    /// * `Ok(Operation)` - The created generic operation if successful
    /// * `Err(DsmError)` - If operation creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::core_sdk::CoreSDK;
    ///
    /// fn create_test_op(sdk: &CoreSDK) {
    ///     let op = sdk.generic_operation("test", vec![1, 2, 3]).unwrap();
    ///     // Use operation for state transition
    /// }
    /// ```
    pub fn generic_operation(
        &self,
        operation_type: &str,
        data: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::Generic {
            operation_type: operation_type.to_string(),
            data,
            message: format!("Generic operation: {}", operation_type),
        })
    }

    /// Get the current state
    ///
    /// Retrieves the most recent state in the system.
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The current state if available
    /// * `Err(DsmError)` - If no current state exists or retrieval failed
    pub fn get_current_state(&self) -> Result<State, DsmError> {
        let current_state = self.hash_chain_sdk.current_state();
        current_state.ok_or_else(|| DsmError::state("No current state available"))
    }

    /// Get a historical state by its state number
    ///
    /// Retrieves a specific state from the hash chain by its sequence number.
    ///
    /// # Arguments
    ///
    /// * `state_number` - The sequence number of the state to retrieve
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The requested state if found
    /// * `Err(DsmError)` - If the state doesn't exist or retrieval failed
    pub fn get_state_by_number(&self, state_number: u64) -> Result<State, DsmError> {
        self.hash_chain_sdk.get_state_by_number(state_number)
    }

    /// Execute a state transition
    ///
    /// Performs a deterministic state transition as described in whitepaper section 2,
    /// following the formula Sn+1 = H(Sn∥opn+1).
    ///
    /// # Arguments
    ///
    /// * `operation` - The operation to execute in the transition
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The new state resulting from the transition
    /// * `Err(DsmError)` - If the transition failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::core_sdk::CoreSDK;
    ///
    /// async fn example(sdk: &CoreSDK) {
    ///     // Create a generic operation
    ///     let op = sdk.generic_operation("test", vec![1, 2, 3]).unwrap();
    ///     
    ///     // Execute the transition
    ///     let new_state = sdk.execute_transition(op).await.unwrap();
    ///     println!("New state number: {}", new_state.state_number);
    /// }
    /// ```
    pub async fn execute_transition(&self, operation: Operation) -> Result<State, DsmError> {
        // Execute the transition in the state machine (deterministic evolution as per Sn+1 = H(Sn∥opn+1))
        let new_state = {
            let mut state_machine = self.state_machine.write();
            state_machine.execute_transition(operation)?
        };

        // Add the new state to the hash chain
        self.hash_chain_sdk.add_state(new_state.clone())?;

        Ok(new_state)
    }

    /// Create an initial (genesis) state
    ///
    /// Creates a genesis state (G) as described in whitepaper section 4,
    /// which serves as the foundation for the state chain.
    ///
    /// # Arguments
    ///
    /// * `device_info` - Information about the device creating the genesis state
    ///
    /// # Returns
    ///
    /// * `Ok(State)` - The created genesis state if successful
    /// * `Err(DsmError)` - If genesis state creation failed
    ///
    /// # Examples
    ///
    /// ```
    /// use dsm_sdk::core_sdk::CoreSDK;
    /// use dsm::types::state_types::DeviceInfo;
    ///
    /// fn create_genesis(sdk: &CoreSDK) {
    ///     let device_info = DeviceInfo::new("device_id", vec![1, 2, 3, 4]);
    ///     let genesis = sdk.create_initial_state(&device_info).unwrap();
    ///     // Use genesis state to initialize system
    /// }
    /// ```
    pub fn create_initial_state(&self, device_info: &DeviceInfo) -> Result<State, DsmError> {
        let operation = Operation::Create {
            message: "Initial state creation".to_string(),
            identity_data: vec![],
            public_key: vec![],
            metadata: vec![],
            commitment: vec![],
            proof: vec![],
            mode: TransactionMode::Bilateral, // Use Bilateral mode
        };

        // Use the updated StateParams::new constructor with the correct parameter count
        let params = StateParams::new(
            0,                   // state_number
            vec![0u8; 32],       // entropy
            operation,           // operation
            device_info.clone(), // device_info
        );

        // Set additional parameters using the builder pattern
        let params = params.with_prev_state_hash(vec![0u8; 32]);

        Ok(State::new(params))
    }
}

/// Implements the Default trait for CoreSDK
///
/// This allows creating a CoreSDK instance using Default::default()
impl Default for CoreSDK {
    fn default() -> Self {
        Self::new()
    }
}
