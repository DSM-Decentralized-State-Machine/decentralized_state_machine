//! # DSM: Decentralized State Machine
//!
//! DSM is a secure, distributed state machine implementation that ensures deterministic
//! state evolution with cryptographic guarantees. It enables resilient, trustless 
//! applications through a provable state transition system.
//!
//! ## Key Features
//!
//! * Forward-only state transitions with cryptographic verification
//! * Deterministic state evolution for predictable behavior
//! * Bilateral transaction support for offline & secure multi-party interactions
//! * Unilateral transactions for online operations
//! * Deterministic Limbo Vault (DLV) for secure asset management
//! * Pre-commitment verification and hash-chain validation
//!
//! ## Module Structure
//!
//! The DSM codebase is organized into several key modules:
//!
//! * `core`: Core state machine implementation and identity management
//! * `crypto`: Cryptographic primitives and operations
//! * `api`: Public API interfaces for interacting with DSM
//! * `vault`: Deterministic Limbo Vault (DLV) for asset management
//! * `unilateral`: Unilateral transaction support
//! * `interfaces`: Abstract interfaces for component interaction
//! * `types`: Data type definitions used throughout the system

// Module declarations - expose all modules through the library
pub mod api;
pub mod commitments;
pub mod common;
pub mod communication;
pub mod core;
pub mod cpta;
pub mod crypto;
pub mod interfaces;
pub mod merkle;
pub mod recovery;
pub mod types;
pub mod unilateral; // Module for unilateral transactions
pub mod utils;
pub mod vault; // Module for Deterministic Limbo Vault (DLV)

// Re-export key components for easier access
pub use crypto::{
    blake3 as hash, decrypt_from_sender, encrypt_for_recipient, generate_keypair, init_crypto,
    sign_data,
    sphincs::{generate_sphincs_keypair, sphincs_sign, sphincs_verify},
    verify_signature,
};
pub use types::{
    error::DsmError,
    policy_types::{PolicyAnchor, PolicyFile, TokenPolicy},
};

/// # DSM SDK: Decentralized State Machine Developer Library
/// 
/// This section re-exports the main modules and functions for easier access by library users.
/// These components provide the core functionality needed to build DSM applications.

/// Re-export primary modules from the core state machine implementation
pub use crate::core::state_machine;

/// Re-export identity management functionality
/// 
/// Provides key identity operations including:
/// * `Identity`: Core identity type for DSM
/// * `create_identity`: Function to create new identities
/// * `add_device`: Function to add devices to an existing identity
pub use crate::core::identity::{Identity, create_identity, add_device};

/// Re-export unilateral transaction functionality
/// 
/// Unilateral transactions allow single-party operations in a DSM system, including:
/// * `process_unilateral_transactions`: Function to handle pending unilateral transactions
/// * `send_unilateral_transaction`: Function to initiate a unilateral transaction
/// * `InboxEntry`: Type for incoming transaction data
/// * `InboxManager`: Managing incoming transaction messages
pub use crate::unilateral::{
    process_unilateral_transactions, send_unilateral_transaction, InboxEntry, InboxManager,
};

/// Re-export DLV (Deterministic Limbo Vault) functionality
/// 
/// DLV provides secure asset management with cryptographic guarantees, including:
/// * `DLVManager`: Core management interface for Deterministic Limbo Vaults
/// * `FulfillmentMechanism`: Types and functions for vault condition fulfillment
pub use crate::vault::dlv_manager::DLVManager;
pub use crate::vault::fulfillment::FulfillmentMechanism;

/// Initialize the DSM SDK
/// 
/// This function must be called before any DSM operations are performed.
/// It initializes critical subsystems including cryptography and recovery mechanisms.
/// 
/// # Example
/// ```
/// use dsm::initialize;
/// 
/// fn main() {
///     // Initialize DSM before any operations
///     initialize();
///     
///     // Now DSM operations can be performed safely
///     // ...
/// }
/// ```
pub fn initialize() {
    crypto::init_crypto();
    recovery::init_recovery();
}

/// Returns the version of the SDK
/// 
/// Retrieves the current version of the DSM SDK from cargo package metadata.
/// 
/// # Returns
/// 
/// A string containing the version number in semver format (e.g., "0.1.0")
/// 
/// # Example
/// ```
/// use dsm::version;
/// 
/// fn main() {
///     println!("DSM SDK Version: {}", version());
/// }
/// ```
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
