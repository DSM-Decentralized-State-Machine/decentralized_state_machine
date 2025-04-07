// deterministic_verification.rs
//
// Implementation of deterministic verification through straight hash chain
// and random walk verification as described in the DSM whitepaper.
// This replaces hardware-based verification with pure cryptographic guarantees.
use crate::crypto::hash::blake3;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::operations::TransactionMode;
use crate::types::state_types::State;
use blake3::Hash as HashOutput;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;

/// DeterministicVerifier implements verification mechanisms through cryptographic guarantees
/// rather than hardware-specific TEE/enclave features
#[derive(Debug)]
pub struct DeterministicVerifier {
    /// Number of verification steps to perform
    verification_steps: usize,

    /// Seed for deterministic random verification
    verification_seed: Vec<u8>,

    /// Set of already verified state hashes
    verified_states: HashSet<Vec<u8>>,
}

impl DeterministicVerifier {
    /// Create a new deterministic verifier
    ///
    /// # Arguments
    /// * `verification_steps` - Number of steps to verify
    /// * `verification_seed` - Seed for deterministic randomization
    ///
    /// # Returns
    /// * `Self` - New verifier
    pub fn new(verification_steps: usize, verification_seed: Vec<u8>) -> Self {
        Self {
            verification_steps,
            verification_seed,
            verified_states: HashSet::new(),
        }
    }

    /// Verify a state chain through random sampling
    ///
    /// This implements the random walk verification described in whitepaper Section 22.1.3,
    /// providing efficient verification without requiring hardware-specific features.
    ///
    /// # Arguments
    /// * `states` - States to verify
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether verification passed
    pub fn verify_chain(&mut self, states: &[State]) -> Result<bool, DsmError> {
        if states.is_empty() {
            return Ok(true); // Empty chain is valid
        }

        // Verify the genesis state
        let genesis_state = &states[0];
        if genesis_state.state_number != 0 {
            return Err(DsmError::verification("First state is not a genesis state"));
        }

        // Add genesis state to verified states
        self.verified_states
            .insert(blake3(&genesis_state.hash()?).as_bytes().to_vec());

        // If only genesis state, we're done
        if states.len() == 1 {
            return Ok(true);
        }

        // Create deterministic RNG from seed
        let seed_hash = blake3(&self.verification_seed);
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed_hash.as_bytes());

        let mut rng = ChaCha20Rng::from_seed(seed_array);

        // Determine how many steps to verify (min of steps or states-1)
        let actual_steps = std::cmp::min(self.verification_steps, states.len() - 1);

        // Select random indices to verify, always including the most recent state
        let mut indices = (1..states.len()).collect::<Vec<_>>();
        indices.shuffle(&mut rng);
        let mut selected_indices = indices
            .into_iter()
            .take(actual_steps - 1)
            .collect::<Vec<_>>();
        selected_indices.push(states.len() - 1); // Always verify the last state

        // Verify each selected state
        for &idx in &selected_indices {
            let state = &states[idx];
            let prev_state = &states[idx - 1];

            // Verify state number
            if state.state_number != prev_state.state_number + 1 {
                return Ok(false);
            }

            // Verify hash chain continuity
            if state.prev_state_hash != prev_state.hash()? {
                return Ok(false);
            }

            // Serialize the operation to get operation bytes
            let operation_bytes = bincode::serialize(&state.operation)
                .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;

            // Verify deterministic entropy evolution
            let expected_entropy = Self::calculate_next_entropy(
                &prev_state.entropy,
                &operation_bytes,
                state.state_number,
            );

            if state.entropy != expected_entropy.as_bytes() {
                return Ok(false);
            }

            // Add to verified states
            self.verified_states
                .insert(blake3(&state.hash()?).as_bytes().to_vec());
        }

        Ok(true)
    }

    /// Verify specific state transition
    ///
    /// # Arguments
    /// * `prev_state` - Previous state
    /// * `next_state` - Next state
    ///
    /// # Returns
    /// * `Result<bool, DsmError>` - Whether transition is valid
    pub fn verify_transition(
        &mut self,
        prev_state: &State,
        next_state: &State,
    ) -> Result<bool, DsmError> {
        // Verify state number continuity
        if next_state.state_number != prev_state.state_number + 1 {
            return Ok(false);
        }

        // Verify hash chain continuity
        if next_state.prev_state_hash != prev_state.hash()? {
            return Ok(false);
        }

        // Serialize the operation to get operation bytes
        let operation_bytes = bincode::serialize(&next_state.operation)
            .map_err(|e| DsmError::serialization("Failed to serialize operation", Some(e)))?;

        // Verify deterministic entropy evolution
        let expected_entropy = Self::calculate_next_entropy(
            &prev_state.entropy,
            &operation_bytes,
            next_state.state_number,
        );

        if next_state.entropy != expected_entropy.as_bytes() {
            return Ok(false);
        }

        // Add both states to verified states
        self.verified_states
            .insert(blake3(&prev_state.hash()?).as_bytes().to_vec());
        self.verified_states
            .insert(blake3(&next_state.hash()?).as_bytes().to_vec());

        Ok(true)
    }

    /// Calculate the next entropy value using deterministic algorithm
    ///
    /// This implements the deterministic entropy evolution described in whitepaper Section 6,
    /// ensuring consistent state transitions without hardware-specific features.
    ///
    /// # Arguments
    /// * `current_entropy` - Current entropy value
    /// * `operation` - Operation bytes
    /// * `state_number` - State number
    ///
    /// # Returns
    /// * `HashOutput` - Next entropy
    pub fn calculate_next_entropy(
        current_entropy: &[u8],
        operation: &[u8],
        state_number: u64,
    ) -> HashOutput {
        let mut data = Vec::new();
        data.extend_from_slice(current_entropy);
        data.extend_from_slice(operation);
        data.extend_from_slice(&state_number.to_be_bytes());

        blake3(&data)
    }

    /// Check if a specific state has been verified
    ///
    /// # Arguments
    /// * `state_hash` - Hash of the state
    ///
    /// # Returns
    /// * `bool` - Whether state is verified
    pub fn is_state_verified(&self, state_hash: &HashOutput) -> bool {
        self.verified_states
            .contains(&state_hash.as_bytes().to_vec())
    }

    /// Clear verified states cache
    pub fn clear_verified_states(&mut self) {
        self.verified_states.clear();
    }

    pub fn create_verification_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message: "Create verification state".to_string(),
            identity_data: Vec::new(),
            public_key: Vec::new(),
            metadata: Vec::new(),
            commitment: vec![],
            proof: Vec::new(),
            mode: TransactionMode::Unilateral,
        })
    }

    pub fn add_verification_relationship(&self, counterparty: &str) -> Result<Operation, DsmError> {
        Ok(Operation::AddRelationship {
            message: format!("Add verification relationship with {}", counterparty),
            from_id: String::new(),
            to_id: counterparty.to_string(),
            relationship_type: "verification".to_string(),
            metadata: Vec::new(),
            proof: Vec::new(),
            mode: TransactionMode::Bilateral,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::Operation;
    use crate::types::state_types::{DeviceInfo, State, StateParams};

    // Create a test State for testing purposes
    fn create_test_state(
        state_number: u64,
        prev_hash: Vec<u8>,
        entropy: Vec<u8>,
        operation_data: &[u8],
    ) -> State {
        let operation = Operation::Generic {
            operation_type: "test".to_string(),
            data: operation_data.to_vec(),
            message: "Test operation".to_string(),
        };

        let device_info = DeviceInfo {
            device_id: "test_device".to_string(),
            public_key: vec![0; 32],
        };

        let params = StateParams {
            state_number,
            entropy,
            encapsulated_entropy: None,
            prev_state_hash: prev_hash,
            sparse_index: crate::types::state_types::SparseIndex::new(Vec::new()),
            operation,
            device_info,
            forward_commitment: None,
            matches_parameters: false,
            state_type: "test".to_string(),
            value: vec![1, 2, 3],
            commitment: vec![13, 14, 15, 16],
            previous_hash: vec![17, 18, 19, 20],
            none_field: None,
            metadata: vec![],
            token_balance: None,
            signature: None,
            version: 0,
            forward_link: None,
            large_state: Box::new(State::default()),
        };

        State::new(params)
    }

    // Create a genesis state for testing
    fn create_genesis_state() -> State {
        let device_info = DeviceInfo {
            device_id: "test_device".to_string(),
            public_key: vec![0; 32],
        };

        State::new_genesis(vec![0; 32], device_info)
    }

    // Create a state derived from a previous state
    fn create_next_state(prev_state: &State, operation_data: &[u8]) -> State {
        let prev_hash = prev_state.hash().unwrap();

        // Calculate the next entropy
        let operation_bytes = bincode::serialize(&Operation::Generic {
            operation_type: "test".to_string(),
            data: operation_data.to_vec(),
            message: "Test operation".to_string(),
        })
        .unwrap();

        let next_entropy = DeterministicVerifier::calculate_next_entropy(
            &prev_state.entropy,
            &operation_bytes,
            prev_state.state_number + 1,
        );

        create_test_state(
            prev_state.state_number + 1,
            prev_hash,
            next_entropy.as_bytes().to_vec(),
            operation_data,
        )
    }

    #[test]
    fn test_deterministic_entropy() {
        let current_entropy = b"test_entropy";
        let operation = b"test_operation";
        let state_number = 42;

        let entropy1 =
            DeterministicVerifier::calculate_next_entropy(current_entropy, operation, state_number);
        let entropy2 =
            DeterministicVerifier::calculate_next_entropy(current_entropy, operation, state_number);

        // Same inputs should produce same entropy
        assert_eq!(entropy1.as_bytes(), entropy2.as_bytes());

        // Different inputs should produce different entropy
        let different_entropy = DeterministicVerifier::calculate_next_entropy(
            current_entropy,
            b"different_operation",
            state_number,
        );
        assert_ne!(entropy1.as_bytes(), different_entropy.as_bytes());
    }

    #[test]
    fn test_verify_chain() {
        // Create a chain of states
        let mut states = Vec::new();
        let genesis = create_genesis_state();
        states.push(genesis);

        // Add 10 more states to the chain
        for i in 1..11 {
            let prev_state = &states[i - 1];
            let next_state = create_next_state(prev_state, format!("op_{}", i).as_bytes());
            states.push(next_state);
        }

        // Create verifier
        let mut verifier = DeterministicVerifier::new(5, b"test_seed".to_vec());

        // Verify the chain
        let result = verifier.verify_chain(&states).unwrap();
        assert!(result);

        // Verify that some states are verified
        let genesis_hash = blake3(&states[0].hash().unwrap());
        let last_hash = blake3(&states[10].hash().unwrap());
        assert!(verifier.is_state_verified(&genesis_hash));
        assert!(verifier.is_state_verified(&last_hash)); // Last state should always be verified

        // Break the chain and test again
        let mut broken_states = states.clone();
        // Break the chain by modifying a state's entropy
        broken_states[5].entropy = blake3(b"wrong_entropy").as_bytes().to_vec();

        let mut verifier = DeterministicVerifier::new(10, b"test_seed".to_vec());
        let result = verifier.verify_chain(&broken_states).unwrap();

        // Should fail verification
        assert!(!result);
    }

    #[test]
    fn test_verify_transition() {
        // Create two consecutive states
        let state1 = create_genesis_state();
        let state2 = create_next_state(&state1, b"test_operation");

        // Create verifier
        let mut verifier = DeterministicVerifier::new(5, b"test_seed".to_vec());

        // Verify the transition
        let result = verifier.verify_transition(&state1, &state2).unwrap();
        assert!(result);

        // Both states should be verified
        let state1_hash = blake3(&state1.hash().unwrap());
        let state2_hash = blake3(&state2.hash().unwrap());
        assert!(verifier.is_state_verified(&state1_hash));
        assert!(verifier.is_state_verified(&state2_hash));

        // Break the transition and test again
        let mut broken_state2 = state2.clone();
        broken_state2.state_number = 2; // Wrong state number (should be 1)

        let mut verifier = DeterministicVerifier::new(5, b"test_seed".to_vec());
        let result = verifier.verify_transition(&state1, &broken_state2).unwrap();

        // Should fail verification
        assert!(!result);
    }
}
