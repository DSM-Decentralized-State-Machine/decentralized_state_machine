use crate::types::error::DsmError;
use crate::types::state_types::State;
use async_trait::async_trait;

#[async_trait]
pub trait IdentityFace {
    async fn create_identity(&mut self) -> Result<State, DsmError>;
    async fn verify_identity(&self, state: &State) -> Result<bool, DsmError>;
    async fn get_current_state(&self) -> Result<Option<State>, DsmError>;
    async fn update_state(&mut self, new_state: State) -> Result<(), DsmError>;
}
