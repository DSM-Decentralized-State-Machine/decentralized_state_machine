//! Vault Condition Module
//!
//! This module defines the conditions under which a Deterministic Limbo Vault
//! can be unlocked, implementing the conditional logic described in the whitepaper
//! Section 20.2.

use crate::types::error::DsmError;
use crate::vault::shared::FulfillmentMechanism;
use serde::{Deserialize, Serialize};

/// High-level vault condition that can be converted to a FulfillmentMechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultCondition {
    /// Time-based condition that unlocks after a specific state number
    TimeRelease {
        /// State number after which the vault can be unlocked
        unlock_after_state: u64,
        /// Reference state hashes for verification
        reference_state_hashes: Vec<Vec<u8>>,
    },

    /// Payment-based condition requiring proof of payment
    Payment {
        /// Amount required for unlocking
        amount: u64,

        /// Token ID for the payment
        token_id: String,

        /// Recipient of the payment
        recipient: String,

        /// State hash for verification
        verification_state_hash: Vec<u8>,
    },

    /// Multiple signatures required to unlock
    MultiSignature {
        /// Public keys of required signers
        public_keys: Vec<Vec<u8>>,

        /// Number of signatures required (threshold)
        threshold: usize,
    },

    /// Cryptographic condition that requires a specific solution
    CryptoCondition {
        /// Hash of the condition
        condition_hash: Vec<u8>,

        /// Public parameters for verification
        public_params: Vec<u8>,
    },

    /// State reference verification
    StateReference {
        /// Hash of the referenced state
        state_hash: Vec<u8>,
    },

    /// Combination of conditions that all must be satisfied (AND)
    All(Vec<VaultCondition>),

    /// Combination of conditions where any can be satisfied (OR)
    Any(Vec<VaultCondition>),
}

impl VaultCondition {
    /// Convert this VaultCondition to a FulfillmentMechanism
    pub fn into_fulfillment_mechanism(&self) -> Result<FulfillmentMechanism, DsmError> {
        match self {
            VaultCondition::TimeRelease {
                unlock_after_state,
                reference_state_hashes,
            } => Ok(FulfillmentMechanism::TimeRelease {
                unlock_time: *unlock_after_state,
                reference_states: reference_state_hashes.clone(),
            }),

            VaultCondition::Payment {
                amount,
                token_id,
                recipient,
                verification_state_hash,
            } => Ok(FulfillmentMechanism::Payment {
                amount: *amount,
                token_id: token_id.clone(),
                recipient: recipient.clone(),
                verification_state: verification_state_hash.clone(),
            }),

            VaultCondition::MultiSignature {
                public_keys,
                threshold,
            } => Ok(FulfillmentMechanism::MultiSignature {
                public_keys: public_keys.clone(),
                threshold: *threshold,
            }),

            VaultCondition::CryptoCondition {
                condition_hash,
                public_params,
            } => Ok(FulfillmentMechanism::CryptoCondition {
                condition_hash: condition_hash.clone(),
                public_params: public_params.clone(),
            }),

            VaultCondition::StateReference { state_hash } => {
                Ok(FulfillmentMechanism::StateReference {
                    state_hash: state_hash.clone(),
                })
            }

            VaultCondition::All(conditions) => {
                let mut fulfillment_mechanisms = Vec::new();
                for condition in conditions {
                    fulfillment_mechanisms.push(condition.into_fulfillment_mechanism()?);
                }
                Ok(FulfillmentMechanism::And(fulfillment_mechanisms))
            }

            VaultCondition::Any(conditions) => {
                let mut fulfillment_mechanisms = Vec::new();
                for condition in conditions {
                    fulfillment_mechanisms.push(condition.into_fulfillment_mechanism()?);
                }
                Ok(FulfillmentMechanism::Or(fulfillment_mechanisms))
            }
        }
    }
}
