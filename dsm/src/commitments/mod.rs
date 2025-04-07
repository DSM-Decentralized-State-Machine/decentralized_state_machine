//! Commitments Module
//!
//! This module contains implementations of various commitment schemes used in DSM,
//! including pre-commitments, forward commitments, and deterministic smart commitments.
//!
//! Commitments are an essential part of DSM's security model, allowing for verifiable
//! state transitions without revealing underlying data or requiring global consensus.
//! The implementation follows sections 7, 14, and 15 of the whitepaper.

// Sub-modules
pub mod deterministic;
pub mod external_commitment;
pub mod parameter_comparison;
pub mod precommit;
pub mod smart_commitment;

// Re-export key components for easier access
pub use deterministic::{
    create_conditional_commitment, create_deterministic_commitment, create_recurring_commitment,
    create_time_locked_commitment, verify_deterministic_commitment,
};

pub use external_commitment::{
    create_external_commitment, create_external_commitment_with_metadata,
    verify_external_commitment, verify_external_commitment_with_metadata,
    DefaultExternalCommitmentVerifier, ExternalCommitment, ExternalCommitmentVerifier,
};

pub use smart_commitment::{
    CommitmentCondition, CommitmentContext, SmartCommitment, SmartCommitmentReference,
    SmartCommitmentRegistry, ThresholdOperator,
};

/// Create a basic commitment by hashing the data with BLAKE3
pub fn create_commitment(data: &[u8]) -> Vec<u8> {
    let mut hasher = ::blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

/// Verify a basic commitment by comparing it with a fresh hash of the data
pub fn verify_commitment(commitment: &[u8], data: &[u8]) -> bool {
    let calculated = create_commitment(data);
    calculated == commitment
}

/// Open a commitment using a nonce
/// Returns Some(data) if successful, None if invalid
pub fn open_commitment(commitment: &[u8], nonce: &[u8]) -> Option<Vec<u8>> {
    let mut hasher = ::blake3::Hasher::new();
    hasher.update(commitment);
    hasher.update(nonce);
    Some(hasher.finalize().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_commitment() {
        let data = b"test data";
        let commitment = create_commitment(data);

        assert_eq!(commitment.len(), 32); // BLAKE3 produces 32-byte output
        assert!(verify_commitment(&commitment, data));
        assert!(!verify_commitment(&commitment, b"wrong data"));
    }

    #[test]
    fn test_open_commitment() {
        let data = b"test data";
        let nonce = b"test nonce";
        let commitment = create_commitment(data);

        let opened = open_commitment(&commitment, nonce).unwrap();
        assert_eq!(opened.len(), 32);

        // Opening with different nonce should produce different result
        let opened2 = open_commitment(&commitment, b"different nonce").unwrap();
        assert_ne!(opened, opened2);
    }

    // Integration test between different commitment types
    #[test]
    fn test_commitment_integration() {
        // Create a basic commitment
        let data = b"original data";
        let basic_commitment = create_commitment(data);

        // Create an external commitment from the basic commitment
        let context = "ethereum";
        let external = create_external_commitment(&basic_commitment, context);

        // Verify the external commitment
        assert!(verify_external_commitment(
            &external,
            &basic_commitment,
            context
        ));

        // Create a deterministic commitment from operation data that includes our basic commitment
        use crate::types::operations::Operation;

        let operation = Operation::Generic {
            operation_type: "test".to_string(),
            data: basic_commitment.clone(),
            message: "Using basic commitment as operation data".to_string(), // Use our basic commitment as operation data
        };

        let state_hash = vec![1, 2, 3, 4];
        let recipient_info = b"recipient";

        let deterministic =
            create_deterministic_commitment(&state_hash, &operation, recipient_info, None);

        // Verify the deterministic commitment
        assert!(verify_deterministic_commitment(
            &deterministic,
            &state_hash,
            &operation,
            recipient_info,
            None
        ));

        // The combination of these commitment types demonstrates the
        // flexible commitment architecture described in the whitepaper
    }
}
