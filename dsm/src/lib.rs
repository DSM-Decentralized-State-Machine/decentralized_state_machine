// DSM Library Entry Point

// Module declarations - expose all modules through the library
pub mod api;
pub mod commitments;
pub mod common;
pub mod communication;
pub mod core;
pub mod cpta;
pub mod crypto;
pub mod crypto_verification;
pub mod identity;
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
};pub use types::{
    error::DsmError,
    policy_types::{PolicyAnchor, PolicyFile, TokenPolicy},
};

/// DSM SDK: Decentralized State Machine Developer Library
// Re-export main modules for easier access
pub use crate::core::state_machine;
pub use crate::crypto_verification::crypto_identity::{CryptoIdentity, CryptoIdentityFactory};
// Re-export unilateral transaction functionality
pub use crate::unilateral::{
    process_unilateral_transactions, send_unilateral_transaction, InboxEntry, InboxManager,
};
// Re-export DLV functionality
pub use crate::vault::dlv_manager::DLVManager;
pub use crate::vault::fulfillment::FulfillmentMechanism;

/// Initialize the DSM SDK
/// This must be called before any DSM operations are performed.
pub fn initialize() {
    crypto::init_crypto();
    recovery::init_recovery();
}

/// Returns the version of the SDK
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
