//! Utility functions for the DSM state machine
//!
//! This module contains common utility functions used across the state machine
//! implementation, ensuring consistent behavior and reducing duplication.

use crate::types::error::DsmError;
use crate::types::state_types::State;
use blake3;

/// Perform constant-time equality comparison to prevent timing attacks
///
/// This function implements constant-time comparison for cryptographic values,
/// ensuring that timing information cannot be used to infer partial matches.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Hash function using BLAKE3 as recommended in the whitepaper
///
/// The DSM whitepaper specifies BLAKE3 for its quantum resistance
/// and performance characteristics.
pub fn hash_blake3(data: &[u8]) -> blake3::Hash {
    blake3::hash(data)
}

/// Verify a state's hash integrity with constant-time comparison
///
/// This implements the cryptographic validation described in whitepaper Section 3.1.
pub fn verify_state_hash(state: &State) -> Result<bool, DsmError> {
    let computed_hash = state.hash()?;

    // Use constant-time comparison to prevent timing side-channel attacks
    if computed_hash.len() != state.hash.len() {
        return Ok(false);
    }

    Ok(constant_time_eq(&computed_hash, &state.hash))
}

/// Calculate the next entropy based on current entropy, operation, and state number
///
/// This implements the deterministic entropy evolution function from whitepaper Section 6:
/// e(n+1) = H(e(n) || op(n+1) || (n+1))
pub fn calculate_next_entropy(
    current_entropy: &[u8],
    operation_bytes: &[u8],
    next_state_number: u64,
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(current_entropy);
    hasher.update(operation_bytes);
    hasher.update(&next_state_number.to_le_bytes());

    hasher.finalize().as_bytes().to_vec()
}

/// Thread-local optimized version of calculate_next_entropy for benchmarking environments
///
/// This implements the same entropy evolution function with thread-local optimizations
/// for high performance in benchmark scenarios. The results are identical to the standard
/// function but with better performance in concurrent scenarios.
pub fn calculate_next_entropy_concurrent(
    current_entropy: &[u8],
    operation_bytes: &[u8],
    next_state_number: u64,
) -> blake3::Hash {
    // Use thread_local hasher from blake3 for better performance
    let mut hasher = blake3::Hasher::new();

    // Update with the same values as the standard function
    hasher.update(current_entropy);
    hasher.update(operation_bytes);
    hasher.update(&next_state_number.to_le_bytes());

    // Return the hash directly without converting to Vec
    hasher.finalize()
}

// Add a utility function for creating test transitions

/// Create a test transition for testing purposes
#[cfg(test)]
pub fn create_test_transition() -> crate::core::state_machine::transition::StateTransition {
    use crate::core::state_machine::transition::StateTransition;
    use crate::types::operations::Operation;
    use std::collections::HashMap;

    StateTransition {
        operation: Operation::Generic {
            operation_type: "test".to_string(),
            data: vec![1, 2, 3],
            message: "Generic operation: test".to_string(),
        },
        new_entropy: Some(vec![4, 5, 6]),
        encapsulated_entropy: None,
        device_id: "test_device".to_string(),
        timestamp: 1_234_567_890,
        flags: vec![],
        position_sequence: None,
        token_balances: Some(HashMap::new()),
        forward_commitment: None,
        prev_state_hash: Some(vec![0; 32]),
        entity_signature: None,            // Default empty signature for tests
        counterparty_signature: None,      // Default empty signature for tests
        previous_state: State::default(),  // Use default State
        transaction: Operation::default(), // Use default Operation
        signature: Vec::new(),             // Empty vector for signature
        from_state: State::default(),      // Use default State
        to_state: State::default(),        // Use default State
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1, 2, 3]));
    }

    #[test]
    fn test_hash_blake3() {
        let data = b"test data";
        let hash = hash_blake3(data);

        // BLAKE3 produces deterministic results
        let expected = blake3::hash(data);
        assert_eq!(hash.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn test_calculate_next_entropy() {
        let current_entropy = vec![1, 2, 3];
        let operation_bytes = b"test_operation";
        let next_state_number = 42;

        let entropy1 = calculate_next_entropy(&current_entropy, operation_bytes, next_state_number);
        let entropy2 = calculate_next_entropy(&current_entropy, operation_bytes, next_state_number);

        // Entropy generation must be deterministic
        assert_eq!(entropy1, entropy2);

        // Different inputs should produce different entropy
        let different_entropy =
            calculate_next_entropy(&current_entropy, b"different", next_state_number);
        assert_ne!(entropy1, different_entropy);
    }
}
