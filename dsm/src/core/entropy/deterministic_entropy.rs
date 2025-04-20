// Deterministic Entropy Evolution
//
// This module implements deterministic entropy evolution as described in whitepaper
// Section 15.1. The entropy evolution is a critical security component that ensures
// each state has a unique, deterministic entropy value derived from the previous state's
// entropy, the operation being performed, and the state number.

use crate::crypto::hash::blake3;
use crate::types::error::DsmError;
use crate::types::operations::Operation;

/// Implementation of Deterministic Entropy derivation as defined in whitepaper
/// Section 15.1: Deterministic Entropy Evolution
pub struct DeterministicEntropy;

impl DeterministicEntropy {
    /// Derive new entropy from previous state entropy, operation and state number
    /// 
    /// Formula: en+1 = H(en || opn+1 || (n+1))
    /// 
    /// # Arguments
    /// * `previous_entropy` - Entropy from the previous state
    /// * `operation` - The operation to be executed
    /// * `state_number` - The state number (which should be previous state number + 1)
    /// 
    /// # Returns
    /// * `Result<Vec<u8>, DsmError>` - Derived entropy or error
    pub fn derive_entropy(
        previous_entropy: &[u8],
        operation: &Operation,
        state_number: u64,
    ) -> Result<Vec<u8>, DsmError> {
        // Serialize the operation to bytes
        let operation_bytes = operation.to_bytes();
        
        // Serialize the state number
        let state_number_bytes = state_number.to_le_bytes();
        
        // Combine all components for entropy derivation
        let mut combined = Vec::new();
        combined.extend_from_slice(previous_entropy);
        combined.extend_from_slice(&operation_bytes);
        combined.extend_from_slice(&state_number_bytes);
        
        // Hash the combined data using blake3 for quantum resistance
        let new_entropy = blake3(&combined).as_bytes().to_vec();
        
        Ok(new_entropy)
    }
    
    /// Verify that the provided entropy matches the expected derived value
    /// 
    /// # Arguments
    /// * `previous_entropy` - Entropy from the previous state
    /// * `operation` - The operation that was executed
    /// * `state_number` - The state number 
    /// * `provided_entropy` - The entropy to verify
    /// 
    /// # Returns
    /// * `Result<bool, DsmError>` - True if entropy is valid, false otherwise
    pub fn verify_entropy(
        previous_entropy: &[u8],
        operation: &Operation,
        state_number: u64,
        provided_entropy: &[u8],
    ) -> Result<bool, DsmError> {
        let expected_entropy = Self::derive_entropy(previous_entropy, operation, state_number)?;
        Ok(expected_entropy == provided_entropy)
    }
    
    /// Generate initial entropy from seed components
    /// 
    /// This is used for genesis state creation with multiple entropy sources
    /// 
    /// # Arguments
    /// * `components` - Vector of entropy components from different sources
    /// 
    /// # Returns
    /// * `Vec<u8>` - Combined initial entropy
    pub fn generate_initial_entropy(components: &[Vec<u8>]) -> Vec<u8> {
        let mut combined = Vec::new();
        
        // Combine all entropy components
        for component in components {
            combined.extend_from_slice(component);
        }
        
        // Hash the combined components
        blake3(&combined).as_bytes().to_vec()
    }
    
    /// Add additional entropy to an existing entropy value
    /// 
    /// # Arguments
    /// * `existing_entropy` - Existing entropy value
    /// * `additional_entropy` - Additional entropy to mix in
    /// 
    /// # Returns
    /// * `Vec<u8>` - Combined entropy
    pub fn add_entropy(existing_entropy: &[u8], additional_entropy: &[u8]) -> Vec<u8> {
        let mut combined = Vec::new();
        combined.extend_from_slice(existing_entropy);
        combined.extend_from_slice(additional_entropy);
        
        blake3(&combined).as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deterministic_entropy_derivation() {
        // Create simple test data
        let prev_entropy = vec![1, 2, 3, 4, 5];
        let operation = Operation::default(); // Genesis operation
        let state_number = 1;
        
        // Derive entropy
        let result = DeterministicEntropy::derive_entropy(&prev_entropy, &operation, state_number);
        assert!(result.is_ok());
        
        let derived_entropy = result.unwrap();
        
        // Verify the entropy
        let verify_result = DeterministicEntropy::verify_entropy(
            &prev_entropy,
            &operation,
            state_number,
            &derived_entropy
        );
        
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }
    
    #[test]
    fn test_different_inputs_produce_different_entropy() {
        // Test case 1
        let prev_entropy1 = vec![1, 2, 3, 4, 5];
        let operation1 = Operation::default();
        let state_number1 = 1;
        
        // Test case 2 - same operation, different entropy
        let prev_entropy2 = vec![5, 4, 3, 2, 1];
        let operation2 = Operation::default();
        let state_number2 = 1;
        
        // Test case 3 - same entropy, different state number
        let prev_entropy3 = vec![1, 2, 3, 4, 5];
        let operation3 = Operation::default();
        let state_number3 = 2;
        
        // Derive entropies
        let entropy1 = DeterministicEntropy::derive_entropy(&prev_entropy1, &operation1, state_number1).unwrap();
        let entropy2 = DeterministicEntropy::derive_entropy(&prev_entropy2, &operation2, state_number2).unwrap();
        let entropy3 = DeterministicEntropy::derive_entropy(&prev_entropy3, &operation3, state_number3).unwrap();
        
        // All values should be different
        assert_ne!(entropy1, entropy2);
        assert_ne!(entropy1, entropy3);
        assert_ne!(entropy2, entropy3);
    }
    
    #[test]
    fn test_initial_entropy_generation() {
        // Create multiple entropy sources
        let source1 = vec![1, 2, 3, 4, 5];
        let source2 = vec![10, 20, 30, 40, 50];
        let source3 = vec![100, 150, 200];
        
        let combined = DeterministicEntropy::generate_initial_entropy(&[source1.clone(), source2.clone(), source3.clone()]);
        
        // Ensure the output is not empty
        assert!(!combined.is_empty());
        
        // Ensure different inputs produce different outputs
        let combined2 = DeterministicEntropy::generate_initial_entropy(&[source2, source1, source3]);
        assert_ne!(combined, combined2);
    }
    
    #[test]
    fn test_add_entropy() {
        let base_entropy = vec![1, 2, 3, 4, 5];
        let additional_entropy = vec![10, 20, 30];
        
        let result = DeterministicEntropy::add_entropy(&base_entropy, &additional_entropy);
        
        // Ensure output is not empty
        assert!(!result.is_empty());
        
        // Ensure it's not just concatenating the values
        assert_ne!(result, {
            let mut concatenated = base_entropy.clone();
            concatenated.extend_from_slice(&additional_entropy);
            concatenated
        });
    }
}
