//! External commitment functionality
//!
//! This module provides functions to create and verify external commitments,
//! which are commitments that are published to external systems.

use blake3;

/// External commitment structure for cross-chain publication
#[derive(Debug, Clone)]
pub struct ExternalCommitment {
    /// Original internal commitment hash
    pub original_hash: Vec<u8>,

    /// External context where this commitment is published
    pub context: String,

    /// External commitment hash (derived from original + context)
    pub external_hash: Vec<u8>,
}

/// External commitment verification interface
pub trait ExternalCommitmentVerifier {
    /// Verify an external commitment against an original commitment and context
    fn verify_external_commitment(&self, external: &[u8], original: &[u8], context: &str) -> bool;

    /// Create a new external commitment from an internal commitment
    fn create_external_commitment(&self, original: &[u8], context: &str) -> Vec<u8>;
}

impl ExternalCommitment {
    /// Create a new external commitment
    pub fn new(original_hash: Vec<u8>, context: String) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&original_hash);
        hasher.update(context.as_bytes());
        let external_hash = hasher.finalize().as_bytes().to_vec();

        Self {
            original_hash,
            context,
            external_hash,
        }
    }

    /// Verify this external commitment
    pub fn verify(&self, original: &[u8]) -> bool {
        // Check that the stored original hash matches the provided original
        if self.original_hash != original {
            return false;
        }

        // Recalculate the external hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(original);
        hasher.update(self.context.as_bytes());
        let calculated_hash = hasher.finalize().as_bytes().to_vec();

        // Verify the calculated hash matches the stored external hash
        calculated_hash == self.external_hash
    }
}

/// Default implementation of external commitment verification
pub struct DefaultExternalCommitmentVerifier;

impl ExternalCommitmentVerifier for DefaultExternalCommitmentVerifier {
    fn verify_external_commitment(&self, external: &[u8], original: &[u8], context: &str) -> bool {
        let expected = self.create_external_commitment(original, context);
        expected == external
    }

    fn create_external_commitment(&self, original: &[u8], context: &str) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(original);
        hasher.update(context.as_bytes());
        hasher.finalize().as_bytes().to_vec()
    }
}

/// Create an external commitment by combining an internal commitment with context
///
/// # Parameters
/// - `commitment`: The internal commitment to externalize.
/// - `context`: The context string that identifies where this commitment is published.
///
/// # Returns
/// - A new commitment that includes both the original commitment and the context.
pub fn create_external_commitment(commitment: &[u8], context: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(commitment);
    hasher.update(context.as_bytes());
    hasher.finalize().as_bytes().to_vec()
}

/// Verify an external commitment against the original commitment and context
///
/// # Parameters
/// - `external`: The external commitment to verify.
/// - `original`: The original internal commitment.
/// - `context`: The context string that was used for publication.
///
/// # Returns
/// - `true` if the external commitment was derived from the original commitment
///   and context, `false` otherwise.
pub fn verify_external_commitment(external: &[u8], original: &[u8], context: &str) -> bool {
    let expected = create_external_commitment(original, context);
    expected == external
}

/// Create an external commitment from an internal commitment with metadata
///
/// # Parameters
/// - `commitment`: The internal commitment to externalize.
/// - `context`: The context string that identifies where this commitment is published.
/// - `metadata`: Additional metadata to include in the external commitment.
///
/// # Returns
/// - A new commitment that includes the original commitment, context, and metadata.
pub fn create_external_commitment_with_metadata(
    commitment: &[u8],
    context: &str,
    metadata: &[u8],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(commitment);
    hasher.update(context.as_bytes());
    hasher.update(metadata);
    hasher.finalize().as_bytes().to_vec()
}

/// Verify an external commitment with metadata
pub fn verify_external_commitment_with_metadata(
    external: &[u8],
    original: &[u8],
    context: &str,
    metadata: &[u8],
) -> bool {
    let expected = create_external_commitment_with_metadata(original, context, metadata);
    expected == external
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_external_commitment() {
        let internal = b"internal commitment";
        let context = "ethereum";

        let external = create_external_commitment(internal, context);

        // Output should be a BLAKE3 hash (32 bytes)
        assert_eq!(external.len(), 32);

        // The same input should produce the same output
        let external2 = create_external_commitment(internal, context);
        assert_eq!(external, external2);

        // Different context should produce different output
        let external3 = create_external_commitment(internal, "solana");
        assert_ne!(external, external3);
    }

    #[test]
    fn test_verify_external_commitment() {
        let internal = b"test commitment";
        let context = "ethereum";

        let external = create_external_commitment(internal, context);

        // Correct verification
        assert!(verify_external_commitment(&external, internal, context));

        // Incorrect context
        assert!(!verify_external_commitment(&external, internal, "wrong"));

        // Incorrect original commitment
        assert!(!verify_external_commitment(&external, b"wrong", context));

        // Both incorrect
        assert!(!verify_external_commitment(&external, b"wrong", "wrong"));
    }

    #[test]
    fn test_external_commitment_struct() {
        let internal = b"internal commitment".to_vec();
        let context = "ethereum".to_string();

        // Create external commitment
        let commitment = ExternalCommitment::new(internal.clone(), context);

        // Verify the commitment
        assert!(commitment.verify(&internal));

        // Verify with incorrect original
        let wrong_internal = b"wrong commitment".to_vec();
        assert!(!commitment.verify(&wrong_internal));
    }

    #[test]
    fn test_external_commitment_with_metadata() {
        let internal = b"internal commitment";
        let context = "ethereum";
        let metadata = b"timestamp=1234567890";

        let external = create_external_commitment_with_metadata(internal, context, metadata);

        // Correct verification
        assert!(verify_external_commitment_with_metadata(
            &external, internal, context, metadata
        ));

        // Incorrect metadata
        assert!(!verify_external_commitment_with_metadata(
            &external,
            internal,
            context,
            b"timestamp=0987654321"
        ));

        // Incorrect context and metadata
        assert!(!verify_external_commitment_with_metadata(
            &external,
            internal,
            "wrong",
            b"timestamp=0987654321"
        ));
    }

    #[test]
    fn test_default_verifier() {
        let verifier = DefaultExternalCommitmentVerifier;
        let internal = b"internal commitment";
        let context = "ethereum";

        let external = verifier.create_external_commitment(internal, context);

        // Correct verification
        assert!(verifier.verify_external_commitment(&external, internal, context));

        // Incorrect context
        assert!(!verifier.verify_external_commitment(&external, internal, "wrong"));
    }
}
