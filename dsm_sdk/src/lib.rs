//! # DSM SDK: Distributed State Machine Software Development Kit
//!
//! This library provides a high-level interface for interacting with the DSM (Distributed 
//! State Machine) architecture. The SDK abstracts the complexity of cryptographic operations,
//! state transitions, and network communications into easy-to-use interfaces.
//!
//! ## Key Components
//!
//! * **Core SDK**: Foundation for all DSM operations
//! * **Identity SDK**: Management of cryptographic identities and devices
//! * **Hashchain SDK**: Creation and verification of state transitions
//! * **Token SDK**: Token operations and management
//! * **Smart Commitment SDK**: Creation and verification of cryptographic commitments
//! * **Wallet SDK**: Key management and secure storage
//! * **Bluetooth Transport**: Device-to-device communication
//!
//! ## Example Usage
//!
//! ```rust
//! use dsm_sdk::core_sdk::CoreSDK;
//! use dsm_sdk::identity_sdk::IdentitySDK;
//!
//! // Initialize core SDK components
//! let core_sdk = CoreSDK::new();
//! 
//! // Get identity SDK for managing identities
//! let identity_sdk = IdentitySDK::new(core_sdk.clone());
//! 
//! // Work with DSM functionality...
//! ```
//!
//! See the [README](https://github.com/dsm-project/decentralized-state-machine/blob/main/dsm_sdk/README.md)
//! for more detailed documentation and examples.

// Re-export all SDK modules for external consumption
pub mod sdk;

// Re-export commonly used components for convenience
pub use sdk::bluetooth_transport;
pub use sdk::core_sdk;
pub use sdk::hashchain_sdk;
pub use sdk::identity_sdk;
pub use sdk::pokemon_bluetooth_sdk;
pub use sdk::pokemon_sdk;
pub use sdk::smart_commitment_sdk;
pub use sdk::token_sdk;
pub use sdk::wallet_sdk;

/// Current version of the DSM SDK
///
/// This constant provides the semantic version of the SDK, which follows
/// the standard MAJOR.MINOR.PATCH format. It is automatically populated
/// from the version specified in Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
