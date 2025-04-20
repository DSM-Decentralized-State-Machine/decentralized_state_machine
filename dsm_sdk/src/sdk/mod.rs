//! # DSM SDK Core Module
//!
//! This module provides the foundation for the DSM Software Development Kit,
//! organizing functionality into logical components for building DSM applications.
//!
//! ## Module Organization
//!
//! The SDK is organized into several categories of modules:
//!
//! ### Core Foundational Modules
//!
//! * `core_sdk`: Central integration point for all DSM functionality
//! * `hashchain_sdk`: Manages state transitions and evolution in the DSM system
//! * `identity_sdk`: Handles cryptographic identity creation and management
//! * `token_sdk`: Provides token operations and policy enforcement
//!
//! ### Smart Contract Functionality
//!
//! * `smart_commitment_sdk`: Creates and verifies cryptographic commitments
//!
//! ### Transport and Communication
//!
//! * `bluetooth_transport`: Enables device-to-device communication via Bluetooth
//!
//! ### Application-Specific Implementations
//!
//! * `contact_sdk`: Manages peer relationships and communications
//! * `pokemon_sdk`: Example implementation for secure Pokemon trading
//! * `pokemon_bluetooth_sdk`: Bluetooth-enabled Pokemon trading implementation
//! * `wallet_sdk`: Key management and secure storage capabilities
//!
//! ### Utilities and Metrics
//!
//! * `protocol_metrics`: Performance monitoring and system diagnostics

pub use protocol_metrics::ProtocolMetricsManager;
pub mod protocol_metrics;

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
