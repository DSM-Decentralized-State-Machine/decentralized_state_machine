pub use protocol_metrics::ProtocolMetricsManager;
pub mod protocol_metrics;

// src/sdk/mod.rs
//
// SDK modules providing high-level interfaces to the DSM system
// as described in the mathematical blueprint.

// Core SDK modules - fundamental building blocks
pub mod core_sdk;
pub mod hashchain_sdk;
pub mod identity_sdk;
pub mod token_sdk;

// Smart contract and commitment functionality
pub mod smart_commitment_sdk;

// Transport and communication modules
pub mod bluetooth_transport;

// Application-specific SDK implementations
pub mod contact_sdk;
pub mod pokemon_bluetooth_sdk;
pub mod pokemon_sdk;
pub mod wallet_sdk;

// Re-export primary SDK components for easier access
pub use bluetooth_transport::{BluetoothMode, BluetoothTransport};
pub use core_sdk::CoreSDK;
pub use hashchain_sdk::HashChainSDK;
pub use identity_sdk::IdentitySDK;
pub use pokemon_bluetooth_sdk::PokemonBluetoothSDK;
pub use smart_commitment_sdk::SmartCommitmentSDK;
pub use token_sdk::TokenSDK;
