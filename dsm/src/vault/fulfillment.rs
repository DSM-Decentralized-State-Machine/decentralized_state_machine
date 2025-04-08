//! Vault Fulfillment Mechanisms
//!
//! This module defines the fulfillment mechanisms for Deterministic Limbo Vaults (DLVs).
//! Fulfillment mechanisms specify the conditions under which a vault can be unlocked.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Mechanism for fulfilling vault conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FulfillmentMechanism {
    /// Time-locked release mechanism
    TimeRelease {
        /// State number after which the vault can be unlocked
        unlock_time: u64,
        /// List of reference states that can be used to verify time
        reference_states: Vec<Vec<u8>>,
    },

    /// Payment-based fulfillment mechanism
    Payment {
        /// Required payment amount
        amount: u64,
        /// Token ID to be paid with
        token_id: String,
        /// Recipient of the payment
        recipient: String,
        /// State to be used for verification
        verification_state: Vec<u8>,
    },

    /// Cryptographic condition fulfillment
    CryptoCondition {
        /// Hash of the condition
        condition_hash: Vec<u8>,
        /// Public parameters for verification
        public_params: Vec<u8>,
    },

    /// Multi-signature fulfillment mechanism
    MultiSignature {
        /// Public keys of all potential signers
        public_keys: Vec<Vec<u8>>,
        /// Number of signatures required for fulfillment
        threshold: usize,
    },

    /// State reference verification
    StateReference {
        /// List of reference state hashes
        reference_states: Vec<Vec<u8>>,
        /// Parameters for verification
        parameters: Vec<u8>,
    },

    /// Random walk verification
    RandomWalkVerification {
        /// Public verification key
        verification_key: Vec<u8>,
        /// Statement to be verified
        statement: String,
    },

    /// Compound AND condition (all must be satisfied)
    And(Vec<FulfillmentMechanism>),

    /// Compound OR condition (any can be satisfied)
    Or(Vec<FulfillmentMechanism>),
}

impl fmt::Display for FulfillmentMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FulfillmentMechanism::TimeRelease { unlock_time, .. } => {
                write!(f, "TimeRelease at state {}", unlock_time)
            }
            FulfillmentMechanism::Payment {
                amount, token_id, ..
            } => write!(f, "Payment of {} {}", amount, token_id),
            FulfillmentMechanism::CryptoCondition { .. } => write!(f, "Cryptographic Condition"),
            FulfillmentMechanism::MultiSignature { threshold, .. } => {
                write!(f, "{}-of-n MultiSignature", threshold)
            }
            FulfillmentMechanism::StateReference { .. } => write!(f, "State Reference"),
            FulfillmentMechanism::RandomWalkVerification { statement, .. } => {
                write!(f, "RandomWalk: {}", statement)
            }
            FulfillmentMechanism::And(conditions) => {
                write!(f, "AND({} conditions)", conditions.len())
            }
            FulfillmentMechanism::Or(conditions) => {
                write!(f, "OR({} conditions)", conditions.len())
            }
        }
    }
}
