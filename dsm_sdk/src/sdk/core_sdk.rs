use super::identity_sdk::IdentitySDK;
use async_trait::async_trait;
/// Core SDK Module
///
/// This module provides the foundational SDK interface for the DSM system,
/// implementing the core mathematical principles from the blueprint.
/// It serves as the primary entry point for applications interacting with the DSM
/// system and orchestrates operations across all subsystems.
use dsm::types::state_types::StateParams;
use parking_lot::RwLock;
use std::sync::Arc;

use super::hashchain_sdk::HashChainSDK;
use dsm::core::state_machine::StateMachine;
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::state_types::{DeviceInfo, State};
use dsm::types::token_types::{Balance, TokenOperation};

/// Token management functionality as defined in section 3 of the blueprint
#[async_trait]
pub trait TokenManager: Send + Sync {
    /// Get the current token balance (Bn in section 3 of blueprint)
    async fn get_balance(&self) -> Result<Balance, DsmError>;

    /// Perform a token operation that updates balances atomically (following Bn+1 = Bn + Δn+1 rule)
    async fn execute_token_operation(&self, operation: TokenOperation) -> Result<State, DsmError>;

    /// Validate token conservation ensuring sum(Δi) ≤ Bn as in section 3 of blueprint
    async fn validate_token_conservation(&self) -> Result<bool, DsmError>;
}

/// Core SDK that integrates all DSM subsystems according to the mathematical blueprint
pub struct CoreSDK {
    /// Hash chain component handling state evolution as per sections 2 & 5 of blueprint
    hash_chain_sdk: Arc<HashChainSDK>,

    /// Identity component managing device-specific states as per sections 4 & 7 of blueprint
    identity_sdk: Arc<IdentitySDK>,

    /// State machine for deterministic state transitions as per section 2 of blueprint
    state_machine: Arc<RwLock<StateMachine>>,
    
    /// Token manager for token operations
    token_manager: RwLock<Option<Arc<dyn TokenManager>>>,
}

impl CoreSDK {
    /// Create a new CoreSDK instance with shared components
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
    pub fn register_token_manager<T: TokenManager + 'static>(&self, manager: Arc<T>) {
        let mut token_manager = self.token_manager.write();
        *token_manager = Some(manager);
    }

    /// Initialize the system with a genesis state (G in section 4 of blueprint)
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

    /// Verify the entire state chain per section 6 of blueprint
    pub async fn verify_system_integrity(&self) -> Result<bool, DsmError> {
        // Verify the hash chain integrity
        let chain_integrity = self.hash_chain_sdk.verify_chain()?;

        // Verify token conservation if applicable
        let token_conservation = self.verify_token_conservation().await?;

        // System integrity is valid only if both checks pass
        Ok(chain_integrity && token_conservation)
    }

    /// Verify token conservation as per section 3 of blueprint
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
    pub fn hash_chain_sdk(&self) -> Arc<HashChainSDK> {
        self.hash_chain_sdk.clone()
    }

    /// Get access to the identity SDK component
    pub fn identity_sdk(&self) -> Arc<IdentitySDK> {
        self.identity_sdk.clone()
    }

    /// Create a identity-based operation
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
    pub fn get_current_state(&self) -> Result<State, DsmError> {
        let current_state = self.hash_chain_sdk.current_state();
        current_state.ok_or_else(|| DsmError::state("No current state available"))
    }

    /// Get a historical state by its state number
    pub fn get_state_by_number(&self, state_number: u64) -> Result<State, DsmError> {
        self.hash_chain_sdk.get_state_by_number(state_number)
    }

    /// Execute a state transition following deterministic rules in section 2 of blueprint
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
    /// Create initial state
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
impl Default for CoreSDK {
    fn default() -> Self {
        Self::new()
    }
}
