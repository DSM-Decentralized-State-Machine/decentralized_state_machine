// DSM Library Entry Point

// Module declarations - expose all modules through the library
pub mod api;
pub mod commitments;
pub mod common;
pub mod communication;
pub mod core;
pub mod crypto;
pub mod crypto_verification;
pub mod identity;
pub mod interfaces;
pub mod policy;
pub mod merkle;
pub mod recovery;
pub mod types;
pub mod unilateral; // Module for unilateral transactions
pub mod utils;
pub mod vault; // Module for Deterministic Limbo Vault (DLV)

// Re-export key components for easier access
pub use crypto::blake3 as hash;
pub use crypto::decrypt_from_sender;
pub use crypto::encrypt_for_recipient;
pub use crypto::generate_keypair;
pub use crypto::init_crypto;
pub use crypto::sign_data;
pub use crypto::sphincs::generate_sphincs_keypair;
pub use crypto::sphincs::sphincs_sign;
pub use crypto::sphincs::sphincs_sign_message;
pub use crypto::sphincs::sphincs_verify;
pub use crypto::verify_signature;
pub use types::error::DsmError;
pub use policy::policy_types::{TokenPolicy as Policy, PolicyFile, PolicyAnchor};

/// DSM SDK: Decentralized State Machine Developer Library
// Re-export main modules for easier access
pub use crate::core::state_machine;
pub use crate::crypto_verification::crypto_identity::{CryptoIdentity, CryptoIdentityFactory};

// Re-export unilateral transaction functionality
pub use crate::unilateral::{
    process_unilateral_transactions, send_unilateral_transaction, InboxEntry, InboxManager,
};

// Re-export DLV functionality
pub use crate::vault::{DLVManager, DeterministicLimboVault, VaultCondition, VaultStatus};

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
