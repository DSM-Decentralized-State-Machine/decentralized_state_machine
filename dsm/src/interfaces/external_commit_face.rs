use crate::types::error::DsmError;
use async_trait::async_trait;

#[async_trait]
pub trait ExternalCommitFace: Send + Sync {
    async fn submit_commitment(&self, data: Vec<u8>) -> Result<(), DsmError>;
    async fn verify_commitment(&self, commitment_id: &str) -> Result<bool, DsmError>;
}
