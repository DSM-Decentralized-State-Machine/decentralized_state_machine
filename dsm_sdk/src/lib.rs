// DSM SDK: Distributed State Machine Software Development Kit
//
// This library provides a high-level interface for interacting with DSM (Distributed State Machine)
// architecture. It includes components for identity management, state transitions, secure
// communications, and specialized modules for different application domains.

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

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
