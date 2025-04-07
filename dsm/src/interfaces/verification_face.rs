// Verification interface trait definitions
use crate::types::error::DsmError;
use crate::types::general::VerificationResult;
use crate::types::state_types::State;
use async_trait::async_trait;

pub fn init() -> Result<(), &'static str> {
    println!("Verification service initialized");
    Ok(())
}

/// Verification interface trait
#[async_trait]
pub trait VerificationInterface {
    /// Verify a signature
    async fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> VerificationResult;

    /// Verify a hashchain
    async fn verify_hashchain(&self, hashchain_id: &str) -> VerificationResult;

    /// Verify a token
    async fn verify_token(&self, token_id: &str) -> VerificationResult;

    /// Verify an identity
    async fn verify_identity(&self, identity_id: &str) -> VerificationResult;

    /// Verify an identity's Genesis state
    fn verify_genesis(&self, genesis_hash: &[u8]) -> Result<bool, DsmError>;

    /// Verify a state transition is valid
    fn verify_state_transition(
        &self,
        from_state: &State,
        to_state: &State,
        signature: &[u8],
    ) -> Result<VerificationResult, DsmError>;

    /// Perform hash-chain verification of a state
    fn verify_hash_chain(
        &self,
        genesis_hash: &[u8],
        target_state: &State,
    ) -> Result<VerificationResult, DsmError>;

    /// Verify a pre-commitment against its claimed state
    fn verify_commitment(&self, commitment_hash: &[u8], state: &State) -> Result<bool, DsmError>;

    /// Perform TEE-secured random walk verification
    fn random_walk_verify(
        &self,
        genesis_hash: &[u8],
        target_state: &State,
    ) -> Result<VerificationResult, DsmError>;

    /// Verify an invalidation marker is legitimate
    fn verify_invalidation(
        &self,
        genesis_hash: &[u8],
        invalidation_marker: &[u8],
    ) -> Result<bool, DsmError>;
}
