//! Core State Machine Module
//!
//! This module implements the core state machine functionality for DSM, including:
//! - Forward-only state transitions
//! - Deterministic state evolution
//! - Pre-commitment verification
//! - Hash-chain verification for efficient validation
//!
//! The state machine ensures that all transitions maintain the system's security properties
//! as described in the whitepaper.

pub mod batch;
pub mod batch_proof;
pub mod bilateral;
pub mod checkpoint;
pub mod hashchain;
pub mod random_walk;
pub mod relationship;
pub mod state;
pub mod state_projection;
pub mod sync_manager;
pub mod transition;
pub mod transition_fix;
pub mod transition_fix_test;
pub mod utils;
pub mod validation; // New centralized utility module

pub use crate::core::state_machine::checkpoint::Checkpoint;
use crate::core::state_machine::relationship::validate_relationship_state_transition;
use crate::core::state_machine::relationship::verify_relationship_entropy;
use crate::core::state_machine::relationship::KeyDerivationStrategy;
use crate::core::state_machine::transition::apply_transition;
use crate::core::state_machine::transition_fix::verify_transition_integrity_fixed;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;
pub use bilateral::BilateralStateManager;
use blake3::Hash;

pub use random_walk::algorithms::{
    generate_positions, generate_random_walk_coordinates, generate_seed, verify_positions,
    verify_random_walk_coordinates, verify_state_transition as verify_state_transition_random_walk,
    Position, RandomWalkConfig,
};

pub use batch::{BatchBuilder, BatchCommitment, BatchManager, StateBatch};
pub use relationship::{RelationshipManager, RelationshipStatePair};
pub use transition::{create_transition, generate_position_sequence, StateTransition};
pub use utils::{constant_time_eq, verify_state_hash}; // Export utility functions and remove hash_blake3 export

/// Type definition for precommitment generation function
type PrecommitmentGenFn = fn(&State, &Operation, &Hash) -> Result<(Hash, Vec<Position>), DsmError>;

/// Core state machine that handles transitions and verification
///
/// This state machine implementation uses the enhanced verification function
/// `verify_transition_integrity_fixed` from the transition_fix module which
/// supports both production and benchmark environments.
#[derive(Clone, Debug)]
pub struct StateMachine {
    /// Current state
    current_state: Option<State>,
    /// Relationship manager for bilateral state isolation
    #[allow(dead_code)]
    relationship_manager: RelationshipManager,
    /// Apply transition function type
    #[allow(dead_code)]
    apply_transition_fn: fn(&State, &Operation, &[u8]) -> Result<State, DsmError>,
    /// Verify transition function
    #[allow(dead_code)]
    verify_transition: fn(&State, &State, &Operation) -> Result<bool, DsmError>,
    /// Generate transition entropy function
    #[allow(dead_code)]
    generate_entropy: fn(&State, &Operation) -> Result<Vec<u8>, DsmError>,
    /// Verify state chain function
    #[allow(dead_code)]
    verify_chain: fn(&[State]) -> Result<bool, DsmError>,
    /// Hash function
    #[allow(dead_code)]
    hash_function: fn(&[u8]) -> blake3::Hash,
    /// Generate precommitment function
    #[allow(dead_code)]
    generate_precommitment: PrecommitmentGenFn,
    /// Verify precommitment function
    #[allow(dead_code)]
    verify_precommitment: fn(&State, &Operation, &[Position]) -> Result<bool, DsmError>,
}

impl StateMachine {
    /// Create a new state machine instance
    pub fn new() -> Self {
        Self::new_with_strategy(KeyDerivationStrategy::Canonical)
    }

    /// Create a new state machine with a specific key derivation strategy
    pub fn new_with_strategy(strategy: KeyDerivationStrategy) -> Self {
        StateMachine {
            current_state: None,
            relationship_manager: RelationshipManager::new(strategy),
            apply_transition_fn: apply_transition,
            verify_transition: verify_transition_integrity_fixed,
            generate_entropy: generate_transition_entropy,
            verify_chain: verify_state_chain,
            hash_function: internal_hash_blake3,
            generate_precommitment: |state, operation, hash| {
                // Generate entropy for operation
                let entropy = generate_transition_entropy(state, operation)?;

                // Generate seed for random walk
                let op_bytes = bincode::serialize(operation).map_err(|e| {
                    DsmError::serialization("Failed to serialize operation", Some(e))
                })?;

                let seed = random_walk::algorithms::generate_seed(hash, &op_bytes, Some(&entropy));

                // Generate positions from seed
                let positions = random_walk::algorithms::generate_positions(&seed, None)?;

                Ok((seed, positions))
            },
            verify_precommitment: |state, operation, positions| {
                // Create temporary state machine for verification
                let mut temp_machine = StateMachine::new();
                temp_machine.set_state(state.clone());

                // Re-generate positions
                let (_, generated_positions) = temp_machine.generate_precommitment(operation)?;

                // Verify positions match
                Ok(random_walk::algorithms::verify_positions(
                    &generated_positions,
                    positions,
                ))
            },
        }
    }

    /// Get the current state
    pub fn current_state(&self) -> Option<&State> {
        self.current_state.as_ref()
    }

    /// Set the current state
    pub fn set_state(&mut self, state: State) {
        self.current_state = Some(state);
    }

    /// Execute a state transition
    pub fn execute_transition(&mut self, operation: Operation) -> Result<State, DsmError> {
        if let Some(current_state) = &self.current_state {
            // Generate entropy for new state
            let new_entropy = generate_transition_entropy(current_state, &operation)?;

            // Create a transition
            let transition = create_transition(current_state, operation, &new_entropy)?;

            // Apply the transition to create a new state
            let new_state = transition::create_next_state(
                current_state,
                transition.operation,
                &new_entropy,
                &transition::VerificationType::Standard,
                false,
            )?;

            // Update the current state
            self.set_state(new_state.clone());

            Ok(new_state)
        } else {
            Err(crate::types::error::DsmError::state_machine(
                "No current state exists",
            ))
        }
    }
    
    /// Apply an operation to a state to create a new state directly
    /// 
    /// This method is useful when you want to apply an operation to a state without updating
    /// the current state of the state machine. It uses the transition module's apply_transition function
    /// to create a new state from the given state and operation.
    /// 
    /// # Arguments
    /// 
    /// * `state` - The state to apply the operation to
    /// * `operation` - The operation to apply
    /// * `new_entropy` - The entropy to use for the next state
    /// 
    /// # Returns
    /// 
    /// A result containing the new state or an error
    pub fn apply_operation(
        &self,
        state: State,
        operation: Operation,
        new_entropy: Vec<u8>,
    ) -> Result<State, DsmError> {
        // Apply the transition to create a new state
        transition::apply_transition(&state, &operation, &new_entropy)
    }

    /// Execute a state transition in the context of a relationship
    pub fn execute_relationship_transition(
        &mut self,
        entity_id: &str,
        counterparty_id: &str,
        operation: Operation,
    ) -> Result<RelationshipStatePair, DsmError> {
        // Generate entropy for new state
        let new_entropy = generate_transition_entropy(
            self.current_state.as_ref().ok_or_else(|| {
                DsmError::state_machine("No current state exists for relationship transition")
            })?,
            &operation,
        )?;

        // Execute the transition using the relationship manager
        self.relationship_manager.execute_relationship_transition(
            entity_id,
            counterparty_id,
            operation,
            new_entropy,
        )
    }

    /// Verify a state using hash-chain validation
    pub fn verify_state(&self, state: &State) -> Result<bool, DsmError> {
        if let Some(current_state) = &self.current_state {
            // First verify state number is sequential
            if state.state_number != current_state.state_number + 1 {
                return Ok(false);
            }

            // Then verify hash chain integrity
            let prev_hash = current_state.hash()?;
            if state.prev_state_hash != prev_hash {
                return Ok(false);
            }

            // Finally verify transition integrity using the operation from the state
            verify_transition_integrity(current_state, state, &state.operation)
        } else {
            Err(crate::types::error::DsmError::state_machine(
                "No current state exists for verification",
            ))
        }
    }

    /// Generate a pre-commitment for the next state transition
    pub fn generate_precommitment(
        &self,
        operation: &Operation,
    ) -> Result<(Hash, Vec<Position>), DsmError> {
        if let Some(current_state) = &self.current_state {
            let operation_bytes = bincode::serialize(operation)
                .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;

            let next_state_number = current_state.state_number + 1;
            let next_state_bytes = next_state_number.to_le_bytes();

            // Create entropy data according to whitepaper equation (20)
            let mut entropy_data = Vec::new();
            entropy_data.extend_from_slice(&current_state.entropy);
            entropy_data.extend_from_slice(&operation_bytes);
            entropy_data.extend_from_slice(&next_state_bytes);

            let next_entropy = blake3::hash(&entropy_data);

            // Generate seed for random walk according to whitepaper equation (21)
            let current_hash = blake3::hash(&current_state.hash);

            let seed = random_walk::algorithms::generate_seed(
                &current_hash,
                &operation_bytes,
                Some(next_entropy.as_bytes()),
            );

            // Generate positions for verification according to whitepaper equation (22)
            let positions = random_walk::algorithms::generate_positions(&seed, None)?;

            Ok((seed, positions))
        } else {
            Err(DsmError::state_machine(
                "No current state exists for pre-commitment",
            ))
        }
    }

    /// Verify a pre-commitment
    pub fn verify_precommitment(
        &self,
        operation: &Operation,
        expected_positions: &[Position],
    ) -> Result<bool, DsmError> {
        let (_, positions) = self.generate_precommitment(operation)?;
        Ok(random_walk::algorithms::verify_positions(
            &positions,
            expected_positions,
        ))
    }

    pub fn create_base_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message: "Create base state".to_string(),
            identity_data: Vec::new(),
            public_key: Vec::new(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Unilateral,
        })
    }

    pub fn update_base_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Update {
            message: "Update base state".to_string(),
            identity_id: String::new(),
            updated_data: Vec::new(),
            proof: Vec::new(),
            forward_link: None,
        })
    }

    pub fn add_relationship_operation(&self, counterparty_id: &str) -> Result<Operation, DsmError> {
        Ok(Operation::AddRelationship {
            message: format!("Add relationship with {}", counterparty_id),
            from_id: String::new(),
            to_id: String::new(),
            relationship_type: String::new(),
            metadata: Vec::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Unilateral,
        })
    }

    pub fn remove_relationship_operation(
        &self,
        counterparty_id: &str,
    ) -> Result<Operation, DsmError> {
        Ok(Operation::RemoveRelationship {
            message: format!("Remove relationship with {}", counterparty_id),
            from_id: String::new(),
            to_id: String::new(),
            relationship_type: String::new(),
            proof: Vec::new(),
            mode: crate::types::operations::TransactionMode::Unilateral,
        })
    }

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
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate deterministic entropy for a transition
///
/// This function implements the entropy evolution function from the whitepaper,
/// ensuring deterministic derivation of future state entropy from current state and operation.
pub fn generate_transition_entropy(
    current_state: &State,
    operation: &Operation,
) -> Result<Vec<u8>, DsmError> {
    let op_data = bincode::serialize(operation).map_err(|e| {
        DsmError::serialization(format!("Failed to serialize operation: {}", e), Some(e))
    })?;

    let next_state_number = current_state.state_number + 1;

    // Generate entropy according to en+1 = H(en || opn+1 || (n+1))
    let mut hasher = blake3::Hasher::new();
    hasher.update(&current_state.entropy);
    hasher.update(&op_data);
    hasher.update(&next_state_number.to_le_bytes());

    Ok(hasher.finalize().as_bytes().to_vec())
}

/// Verify a state transition meets all requirements
pub fn verify_transition_integrity(
    prev_state: &State,
    curr_state: &State,
    next_operation: &Operation,
) -> Result<bool, DsmError> {
    // Verify basic state transition properties
    if !verify_basic_transition(prev_state, curr_state)? {
        return Ok(false);
    }

    // For relationship states, verify relationship transition
    if curr_state.relationship_context.is_some() {
        // Create temporary next state for verification
        let mut next_state = curr_state.clone();
        next_state.operation = next_operation.clone();
        return validate_relationship_state_transition(curr_state, &next_state);
    }

    // For non-relationship states, verify standard transition
    verify_standard_transition(curr_state, next_operation)
}

/// Verify basic transition properties that apply to all state types
fn verify_basic_transition(state1: &State, state2: &State) -> Result<bool, DsmError> {
    // Verify state number increment
    if state2.state_number != state1.state_number + 1 {
        return Ok(false);
    }

    // Verify hash chain continuity
    if state2.prev_state_hash != state1.hash()? {
        return Ok(false);
    }

    // Verify entropy evolution
    if !verify_entropy_evolution(state1, state2)? {
        return Ok(false);
    }

    Ok(true)
}

/// Verify a standard (non-relationship) state transition
fn verify_standard_transition(
    curr_state: &State,
    next_operation: &Operation,
) -> Result<bool, DsmError> {
    // Verify state operation allowed
    if !is_operation_allowed(next_operation, curr_state)? {
        return Ok(false);
    }

    Ok(true)
}

/// Verify entropy evolution between states
fn verify_entropy_evolution(state1: &State, state2: &State) -> Result<bool, DsmError> {
    // For relationship states, use relationship entropy verification
    if state1.relationship_context.is_some() {
        return verify_relationship_entropy(state1, state2, &state2.entropy);
    }

    // For standard states, verify standard entropy evolution
    let expected_entropy = crate::crypto::blake3::generate_deterministic_entropy(
        &state1.entropy,
        &bincode::serialize(&state2.operation).unwrap_or_default(),
        state2.state_number,
    )
    .as_bytes()
    .to_vec();

    Ok(crate::core::state_machine::utils::constant_time_eq(
        &state2.entropy,
        &expected_entropy,
    ))
}

/// Check if an operation is allowed for the current state
fn is_operation_allowed(operation: &Operation, current_state: &State) -> Result<bool, DsmError> {
    match operation {
        Operation::Genesis => {
            // Genesis only allowed as first state
            Ok(current_state.state_number == 0)
        }
        Operation::Recovery { .. } => {
            // Recovery only allowed if state is marked as compromised
            Ok(current_state
                .flags
                .contains(&crate::types::state_types::StateFlag::Compromised))
        }
        _ => Ok(true), // Other operations always allowed
    }
}

/// Verify a state chain from genesis to current
fn verify_state_chain(states: &[State]) -> Result<bool, DsmError> {
    if states.is_empty() {
        return Ok(true);
    }

    // Verify continuity and transitions for each state
    for i in 1..states.len() {
        let prev_state = &states[i - 1];
        let curr_state = &states[i];

        // First verify hash chain continuity
        if curr_state.prev_state_hash != prev_state.hash()? {
            return Err(DsmError::validation(
                format!(
                    "Hash chain broken between states {} and {}",
                    prev_state.state_number, curr_state.state_number
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Then verify the transition integrity using the operation
        if !verify_transition_integrity(prev_state, curr_state, &curr_state.operation)? {
            return Err(DsmError::validation(
                format!(
                    "Invalid state transition between states {} and {}",
                    prev_state.state_number, curr_state.state_number
                ),
                None::<std::convert::Infallible>,
            ));
        }
    }

    Ok(true)
}

// Use the function from utils instead of defining it here again
// Integrate SIMD-optimized BLAKE3 hashing
#[allow(dead_code)]
fn internal_hash_blake3(data: &[u8]) -> blake3::Hash {
    utils::hash_blake3(data)
}

#[cfg(test)]
mod state_machine_tests {
    use super::*;
    use crate::types::state_types::DeviceInfo;

    // Helper function to create a test genesis state
    fn create_test_genesis_state() -> State {
        let device_info = DeviceInfo::new(
            "test_device",
            vec![5, 6, 7, 8], // Test public key
        );

        let mut state = State::new_genesis(
            vec![1, 2, 3, 4], // Initial entropy
            device_info,
        );

        // Compute and set hash for the initial state
        if let Ok(hash) = state.hash() {
            state.hash = hash;
        }

        state
    }

    #[test]
    fn test_state_chain_reconstruction() -> Result<(), DsmError> {
        // Create a genesis state for testing
        let initial_state = create_test_genesis_state();

        let mut states = vec![initial_state.clone()];
        let mut current_state = initial_state;

        // Create a chain of states through transitions
        for i in 0..3 {
            let op = Operation::Generic {
                operation_type: format!("test_{}", i),
                data: vec![],
                message: format!("Test operation {}", i),
            };

            // Generate entropy for transition
            let new_entropy = generate_transition_entropy(&current_state, &op)?;

            // Create a transition using the random walk
            let transition = create_transition(&current_state, op, &new_entropy)?;

            // Apply the transition to get a new state
            let new_state = apply_transition(&current_state, &transition.operation, &new_entropy)?;

            // Add to our chain and update current state
            states.push(new_state.clone());
            current_state = new_state;
        }

        // Verify the integrity of the entire chain
        assert!(verify_state_chain(&states)?);

        // Try breaking the chain by tampering with an intermediate state
        let mut broken_states = states.clone();
        broken_states[1].entropy = vec![99, 99, 99]; // Tamper with entropy

        // Compute new hash for the tampered state
        if let Ok(hash) = broken_states[1].hash() {
            broken_states[1].hash = hash;
        }

        // Verification should now fail
        assert!(verify_state_chain(&broken_states).is_err());

        Ok(())
    }

    #[test]
    fn test_state_machine_execute_transition() -> Result<(), DsmError> {
        // Create a state machine
        let mut machine = StateMachine::new();

        // Set initial state
        let initial_state = create_test_genesis_state();
        // Clone the state before consuming it
        let initial_state_clone = initial_state.clone();
        machine.set_state(initial_state);

        // Execute a transition
        let op = Operation::Generic {
            operation_type: "test_operation".to_string(),
            data: vec![1, 2, 3],
            message: "Test operation".to_string(),
        };

        let new_state = machine.execute_transition(op)?;

        // Verify the new state has been created correctly
        assert_eq!(new_state.state_number, 1);
        assert!(machine.current_state().unwrap().state_number == 1);

        // Verify it references the previous state
        assert_eq!(new_state.prev_state_hash, initial_state_clone.hash()?);

        Ok(())
    }

    #[test]
    fn test_precommitment_generation_and_verification() -> Result<(), DsmError> {
        // Create a state machine
        let mut machine = StateMachine::new();

        // Set initial state
        let initial_state = create_test_genesis_state();
        machine.set_state(initial_state);

        // Create an operation
        let op = Operation::Generic {
            operation_type: "test_operation".to_string(),
            data: vec![1, 2, 3],
            message: "Test operation".to_string(),
        };

        // Generate precommitment
        let (_, positions) = machine.generate_precommitment(&op)?;

        // Verify precommitment
        assert!(machine.verify_precommitment(&op, &positions)?);

        // Modify operation slightly
        let modified_op = Operation::Generic {
            operation_type: "test_operation".to_string(),
            data: vec![1, 2, 4], // Changed last byte
            message: "Test operation".to_string(),
        };

        // Verification should fail
        assert!(!machine.verify_precommitment(&modified_op, &positions)?);

        Ok(())
    }

    #[test]
    fn test_state_verification_chain() -> Result<(), DsmError> {
        // Create a state machine to test state transitions and verification
        let mut state_machine = StateMachine::new();

        // Initialize with genesis state
        let genesis = create_test_genesis_state();
        state_machine.set_state(genesis.clone());

        // Create first transition
        let op1 = Operation::Generic {
            operation_type: "first_operation".to_string(),
            data: vec![1, 2, 3, 4],
            message: "First operation".to_string(),
        };

        // Execute first transition
        let state1 = state_machine.execute_transition(op1)?;

        // Create a second operation
        let op2 = Operation::Generic {
            operation_type: "second_operation".to_string(),
            data: vec![5, 6, 7, 8],
            message: "Second operation".to_string(),
        };

        // Execute second transition
        let state2 = state_machine.execute_transition(op2)?;

        // Create a dummy next state for verification
        let mut next_state = state2.clone();
        next_state.state_number += 1;
        next_state.prev_state_hash = state2.hash()?;

        // Verify state2 from state1 using our refactored verification
        assert!(verify_transition_integrity(
            &state1,
            &state2,
            &next_state.operation
        )?);

        // Now also test the state machine's verify_state method
        // First reset to state1
        let mut test_machine = StateMachine::new();
        test_machine.set_state(state1.clone());

        // Verify state2 from state1 using the state machine
        assert!(test_machine.verify_state(&state2)?);

        // Create invalid state with wrong previous hash
        let mut invalid_state = state2.clone();
        invalid_state.prev_state_hash = vec![0, 1, 2, 3]; // Wrong hash

        // Verification should fail
        assert!(!test_machine.verify_state(&invalid_state)?);

        Ok(())
    }
}
