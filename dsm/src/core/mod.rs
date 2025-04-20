//! # DSM Core Module
//! 
//! This module contains the core functionality of the Decentralized State Machine, including:
//!
//! * State machine initialization and lifecycle management
//! * Identity management and verification
//! * State transition validation
//! * Token management and tracking
//! * Cryptographic verification services
//! * State indexing for efficient lookups
//! * Entropy sources for randomness
//!
//! The Core Module serves as the central component responsible for initializing the DSM node,
//! handling cryptographic verification, and managing the lifecycle of the state machine services.
//! It coordinates the validation, state transitions, and persistence of the decentralized state.

pub mod debug_helpers;
pub mod identity;
pub mod index;
pub mod state_machine;
pub mod token;
pub mod verification;
pub mod entropy;

use crate::types::error::DsmError;
use crate::types::state_types::State;

/// Core functionality interface for DSM modules
///
/// This trait defines the lifecycle operations that all core DSM modules 
/// must implement, providing a consistent interface for initialization,
/// validation, state access, and shutdown procedures.
pub trait CoreModule {
    /// Initialize the module and its resources
    ///
    /// # Returns
    /// * `Ok(())` on successful initialization
    /// * `Err(DsmError)` if initialization fails
    fn init(&mut self) -> Result<(), DsmError>;
    
    /// Validate the current state of the module
    ///
    /// # Returns
    /// * `Ok(true)` if validation succeeds
    /// * `Ok(false)` if validation fails but without error
    /// * `Err(DsmError)` if validation process encounters an error
    fn validate(&self) -> Result<bool, DsmError>;
    
    /// Get the current state of the module
    ///
    /// # Returns
    /// * `Some(&State)` with a reference to the current state
    /// * `None` if no state is available
    fn get_current_state(&self) -> Option<&State>;
    
    /// Gracefully shut down the module
    ///
    /// # Returns
    /// * `Ok(())` on successful shutdown
    /// * `Err(DsmError)` if shutdown fails
    fn shutdown(&mut self) -> Result<(), DsmError>;
    
    /// Restart the module
    ///
    /// # Returns
    /// * `Ok(())` on successful restart
    /// * `Err(DsmError)` if restart fails
    fn restart(&mut self) -> Result<(), DsmError>;
}
