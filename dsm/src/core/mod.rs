//! Core Module: Responsible for initializing the DSM node, handling cryptographic verification, and starting/stopping services.

pub mod debug_helpers;
pub mod identity;
pub mod index;
pub mod state_machine;
pub mod token;
pub mod verification;

use crate::types::error::DsmError;
use crate::types::state_types::State;

pub trait CoreModule {
    fn init(&mut self) -> Result<(), DsmError>;
    fn validate(&self) -> Result<bool, DsmError>;
    fn get_current_state(&self) -> Option<&State>;
    fn shutdown(&mut self) -> Result<(), DsmError>;
    fn restart(&mut self) -> Result<(), DsmError>;
}
