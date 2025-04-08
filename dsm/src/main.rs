//! DSM: Self-Evolving Cryptographic Identification with Tokens and Smart Commitments
//!
//! This is the main entry point for the DSM library. It re-exports public APIs
//! and provides functionality to initialize the system.

// Re-export key modules
pub mod api;
pub mod commitments;
pub mod common;
pub mod core;
pub mod cpta;
pub mod crypto;
pub mod crypto_verification;
pub mod identity;
pub mod interfaces;
pub mod merkle;
pub mod recovery;
pub mod types;
pub mod utils;

use crate::api::identity_api;
use std::sync::atomic::{AtomicBool, Ordering};

// Global initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the DSM system
///
/// This function initializes all required subsystems in the correct order.
/// It must be called before using any DSM functionality.
pub fn initialize() -> Result<(), types::error::DsmError> {
    // Check if already initialized
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    // Initialize crypto subsystem first
    crypto::init_crypto();

    // Initialize core APIs
    identity_api::init_identity();

    // Initialize interfaces
    interfaces::token_face::initialize()?;

    // Mark system as initialized
    INITIALIZED.store(true, Ordering::SeqCst);

    println!("DSM system initialized successfully");
    Ok(())
}

/// Check if the DSM system is initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Get version information
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// Add a main function to make it compile as a binary
fn main() {
    println!("This is the DSM library. Please use one of the provided binaries.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialization() {
        assert!(!is_initialized());
        let result = initialize();
        assert!(result.is_ok());
        assert!(is_initialized());
    }

    #[test]
    fn test_version_not_empty() {
        let v = version();
        assert!(!v.is_empty());
    }
}
