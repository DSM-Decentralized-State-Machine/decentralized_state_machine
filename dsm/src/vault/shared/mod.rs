//! Shared types for the vault module
//!
//! This module provides shared type definitions used across the vault module
//! to ensure consistency and avoid duplication.

use serde::{Deserialize, Serialize};

/// Fulfillment mechanism that implements the logic for a vault condition
///
/// This is a unified type used across the vault module to represent
/// the mechanisms by which a vault can be unlocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FulfillmentMechanism {
    /// Time-based condition that unlocks after a specific state
    TimeRelease {
        /// Time after which to unlock
        unlock_time: u64,
        /// Reference states for verification
        reference_states: Vec<Vec<u8>>,
    },

    /// Payment-based condition requiring proof of payment
    Payment {
        /// Amount required
        amount: u64,
        /// Token identifier
        token_id: String,
        /// Payment recipient
        recipient: String,
        /// Verification state
        verification_state: Vec<u8>,
    },

    /// Multi-signature requirement
    MultiSignature {
        /// Public keys of required signers
        public_keys: Vec<Vec<u8>>,
        /// Number of signatures required
        threshold: usize,
    },

    /// Cryptographic condition
    CryptoCondition {
        /// Hash of the condition
        condition_hash: Vec<u8>,
        /// Public parameters
        public_params: Vec<u8>,
    },

    /// State reference verification
    StateReference {
        /// Hash of the referenced state
        state_hash: Vec<u8>,
    },

    /// Random walk verification with a key and statement
    RandomWalkVerification {
        /// Verification key
        verification_key: Vec<u8>,
        /// Statement to verify
        statement: String,
    },

    /// Logical AND of conditions
    And(Vec<FulfillmentMechanism>),

    /// Logical OR of conditions
    Or(Vec<FulfillmentMechanism>),
}

/// Status of a vault
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultStatus {
    /// Vault is in limbo state (locked)
    Limbo,

    /// Vault is unlocked but content not claimed
    Unlocked,

    /// Vault content has been claimed
    Claimed,

    /// Vault has been invalidated
    Invalidated,
}
