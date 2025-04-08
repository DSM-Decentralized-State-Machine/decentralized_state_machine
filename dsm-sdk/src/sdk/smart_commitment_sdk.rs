//! Smart Commitment SDK Module
//!
//! This module implements the non-Turing-complete deterministic smart commitments
//! as described in section 10 of the mathematical blueprint. It provides secure,
//! deterministic conditionals for time-locked, oracle-based, and recurring transfers
//! with quantum-resistant cryptographic guarantees.

use blake3;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::core_sdk::CoreSDK;
use dsm::crypto::{decrypt_from_sender, encrypt_for_recipient};
use dsm::types::error::DsmError;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
// Removed unused import
use dsm::types::state_types::State;
use dsm::types::token_types::Balance;
use pqcrypto_mlkem::mlkem512 as kyber;
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use std::string::String as Address; // Use String as Address type alias

/// Smart commitment conditions as specified in section 10
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CommitmentCondition {
    /// Time-locked commitment: Ctime = H(Sn ∥ recipient ∥ amount ∥ "after" ∥ T)
    TimeLocked { unlock_time: DateTime<Utc> },

    /// Conditional (oracle-based) commitment: Ccond = H(Sn ∥ recipient ∥ amount ∥ "if" ∥ condition ∥ O)
    ConditionalOracle {
        condition: String,
        oracle_id: String,
    },

    /// Recurring payment commitment: Crecur = H(Sn ∥ recipient ∥ amount ∥ "every" ∥ period ∥ end-date)
    Recurring {
        period_seconds: u64,
        end_date: Option<DateTime<Utc>>,
    },
}

/// Represents a smart commitment as defined in section 10
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartCommitment {
    /// Recipient of the commitment
    pub recipient: Address,

    /// Amount to transfer
    pub amount: u64,

    /// Token ID (typically ROOT for system operations)
    pub token_id: String,

    /// Condition for the commitment
    pub condition: CommitmentCondition,

    /// Commitment hash as per section 10 equations
    pub commitment_hash: Vec<u8>,

    /// Optional encrypted payload for secure transport
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<Vec<u8>>,

    /// Timestamp of commitment creation
    pub timestamp: u64,
}

/// SDK for creating and managing smart commitments as per section 10
pub struct SmartCommitmentSDK {
    /// Reference to the core SDK
    core_sdk: Arc<CoreSDK>,

    /// Executed commitments cache for verification
    executed_commitments: std::collections::HashMap<Vec<u8>, u64>,
}

impl SmartCommitmentSDK {
    /// Create a new SmartCommitmentSDK instance
    pub fn new(core_sdk: Arc<CoreSDK>) -> Self {
        Self {
            core_sdk,
            executed_commitments: std::collections::HashMap::new(),
        }
    }

    /// Create a time-locked commitment as defined in section 10
    pub fn create_time_locked_commitment(
        &self,
        recipient: &str,
        amount: u64,
        unlock_time: DateTime<Utc>,
    ) -> Result<SmartCommitment, DsmError> {
        // Get the current state
        let current_state = self.core_sdk.get_current_state()?;

        // Create the commitment hash: Ctime = H(Sn ∥ recipient ∥ amount ∥ "after" ∥ T)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bincode::serialize(&current_state)?);
        hasher.update(recipient.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"after");
        hasher.update(&bincode::serialize(&unlock_time)?);

        let commitment_hash = hasher.finalize().as_bytes().to_vec();

        Ok(SmartCommitment {
            recipient: recipient.to_string(),
            amount,
            token_id: "ROOT".to_string(),
            condition: CommitmentCondition::TimeLocked { unlock_time },
            commitment_hash,
            encrypted_payload: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Create a conditional (oracle-based) commitment as defined in section 10
    pub fn create_conditional_commitment(
        &self,
        recipient: &str,
        amount: u64,
        condition: &str,
        oracle_id: &str,
    ) -> Result<SmartCommitment, DsmError> {
        // Get the current state
        let current_state = self.core_sdk.get_current_state()?;

        // Create the commitment hash: Ccond = H(Sn ∥ recipient ∥ amount ∥ "if" ∥ condition ∥ O)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bincode::serialize(&current_state)?);
        hasher.update(recipient.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"if");
        hasher.update(condition.as_bytes());
        hasher.update(oracle_id.as_bytes());

        let commitment_hash = hasher.finalize().as_bytes().to_vec();

        Ok(SmartCommitment {
            recipient: recipient.to_string(),
            amount,
            token_id: "ROOT".to_string(),
            condition: CommitmentCondition::ConditionalOracle {
                condition: condition.to_string(),
                oracle_id: oracle_id.to_string(),
            },
            commitment_hash,
            encrypted_payload: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Create a recurring payment commitment as defined in section 10
    pub fn create_recurring_commitment(
        &self,
        recipient: &str,
        amount: u64,
        period_seconds: u64,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<SmartCommitment, DsmError> {
        // Get the current state
        let current_state = self.core_sdk.get_current_state()?;

        // Create the commitment hash: Crecur = H(Sn ∥ recipient ∥ amount ∥ "every" ∥ period ∥ end-date)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bincode::serialize(&current_state)?);
        hasher.update(recipient.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"every");
        hasher.update(&period_seconds.to_le_bytes());

        if let Some(end) = &end_date {
            hasher.update(&bincode::serialize(end)?);
        }

        let commitment_hash = hasher.finalize().as_bytes().to_vec();

        Ok(SmartCommitment {
            recipient: recipient.to_string(),
            amount,
            token_id: "ROOT".to_string(),
            condition: CommitmentCondition::Recurring {
                period_seconds,
                end_date,
            },
            commitment_hash,
            encrypted_payload: None,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Encrypt a commitment for secure transport as defined in section 10
    pub fn encrypt_commitment(
        &self,
        commitment: &SmartCommitment,
        recipient_public_key: &[u8],
    ) -> Result<SmartCommitment, DsmError> {
        println!(
            "Encrypting commitment: recipient public key size = {}",
            recipient_public_key.len()
        );

        let recipient_pk = kyber::PublicKey::from_bytes(recipient_public_key).map_err(|_| {
            DsmError::crypto(
                "Invalid recipient public key",
                None::<std::convert::Infallible>,
            )
        })?;

        let commitment_bytes = bincode::serialize(commitment).map_err(|e| {
            DsmError::serialization(format!("Failed to serialize commitment: {}", e), Some(e))
        })?;

        let (ct, ss) = kyber::encapsulate(&recipient_pk);

        println!("Shared secret size = {}", ss.as_bytes().len());
        println!("Ciphertext size = {}", ct.as_bytes().len());
        println!("Shared secret (bytes): {:?}", ss.as_bytes());
        println!("Ciphertext (bytes): {:?}", ct.as_bytes());

        let mut encryption_key = [0u8; 32];
        let ss_bytes = ss.as_bytes();
        let len = std::cmp::min(ss_bytes.len(), encryption_key.len());
        encryption_key[..len].copy_from_slice(&ss_bytes[..len]);

        let encrypted_payload = encrypt_for_recipient(&commitment_bytes, &encryption_key).ok_or(
            DsmError::crypto("Encryption failed", None::<std::convert::Infallible>),
        )?;

        println!("Encrypted payload (bytes): {:?}", encrypted_payload);
        println!("Encrypted payload size = {}", encrypted_payload.len());
        let mut encrypted_commitment = commitment.clone();
        let mut full_payload = Vec::new();
        full_payload.extend_from_slice(ct.as_bytes());
        full_payload.extend_from_slice(&encrypted_payload);
        encrypted_commitment.encrypted_payload = Some(full_payload);

        Ok(encrypted_commitment)
    }

    /// Decrypt a received encrypted commitment as defined in section 10
    pub fn decrypt_commitment(
        &self,
        encrypted_payload: &[u8],
        recipient_secret_key: &[u8],
    ) -> Result<SmartCommitment, DsmError> {
        println!(
            "Decrypting commitment: recipient secret key size = {}",
            recipient_secret_key.len()
        );
        println!("Encrypted payload size = {}", encrypted_payload.len());

        let ct_bytes_len = kyber::ciphertext_bytes();
        if encrypted_payload.len() <= ct_bytes_len {
            return Err(DsmError::crypto(
                "Invalid encrypted payload",
                None::<std::convert::Infallible>,
            ));
        }

        let (ciphertext, encrypted_data) = encrypted_payload.split_at(ct_bytes_len);

        let recipient_sk = kyber::SecretKey::from_bytes(recipient_secret_key).map_err(|_| {
            DsmError::crypto(
                "Invalid recipient secret key",
                None::<std::convert::Infallible>,
            )
        })?;

        let ct = kyber::Ciphertext::from_bytes(ciphertext).map_err(|_| {
            DsmError::crypto("Invalid ciphertext", None::<std::convert::Infallible>)
        })?;

        let ss = kyber::decapsulate(&ct, &recipient_sk);

        println!(
            "Shared secret size after decapsulation = {}",
            ss.as_bytes().len()
        );

        let mut decryption_key = [0u8; 32];
        let ss_bytes = ss.as_bytes();
        let len = std::cmp::min(ss_bytes.len(), decryption_key.len());
        decryption_key[..len].copy_from_slice(&ss_bytes[..len]);

        let decrypted_data =
            decrypt_from_sender(encrypted_data, &decryption_key).ok_or_else(|| {
                DsmError::crypto(
                    "Failed to decrypt commitment",
                    None::<std::convert::Infallible>,
                )
            })?;

        let commitment: SmartCommitment = bincode::deserialize(&decrypted_data).map_err(|e| {
            DsmError::serialization(format!("Failed to deserialize commitment: {}", e), Some(e))
        })?;

        Ok(commitment)
    }

    /// Execute a commitment when its condition is satisfied
    pub fn execute_commitment(&self, commitment: &SmartCommitment) -> Result<Operation, DsmError> {
        Ok(Operation::Transfer {
            token_id: commitment.token_id.clone(),
            amount: Balance::new(commitment.amount),
            recipient: commitment.recipient.clone(),
            to: commitment.recipient.clone(),
            message: "Smart commitment transfer".to_string(),
            to_address: commitment.recipient.clone(),
            mode: TransactionMode::Bilateral, // Use Bilateral mode
            nonce: Vec::new(),
            verification: VerificationType::Standard,
            pre_commit: None,
        })
    }

    /// Record a commitment execution in the cache
    pub fn record_execution(&mut self, commitment: &SmartCommitment) {
        let now = chrono::Utc::now().timestamp() as u64;
        self.executed_commitments
            .insert(commitment.commitment_hash.clone(), now);
    }

    /// Verify a commitment's integrity as per section 10
    pub fn verify_commitment(&self, commitment: &SmartCommitment) -> Result<bool, DsmError> {
        // Get the current state
        let current_state = self.core_sdk.get_current_state()?;

        // Recalculate the commitment hash based on its type
        let calculated_hash = match &commitment.condition {
            CommitmentCondition::TimeLocked { unlock_time } => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&bincode::serialize(&current_state)?);
                hasher.update(commitment.recipient.as_bytes());
                hasher.update(&commitment.amount.to_le_bytes());
                hasher.update(b"after");
                hasher.update(&bincode::serialize(unlock_time)?);
                hasher.finalize().as_bytes().to_vec()
            }
            CommitmentCondition::ConditionalOracle {
                condition,
                oracle_id,
            } => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&bincode::serialize(&current_state)?);
                hasher.update(commitment.recipient.as_bytes());
                hasher.update(&commitment.amount.to_le_bytes());
                hasher.update(b"if");
                hasher.update(condition.as_bytes());
                hasher.update(oracle_id.as_bytes());
                hasher.finalize().as_bytes().to_vec()
            }
            CommitmentCondition::Recurring {
                period_seconds,
                end_date,
            } => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&bincode::serialize(&current_state)?);
                hasher.update(commitment.recipient.as_bytes());
                hasher.update(&commitment.amount.to_le_bytes());
                hasher.update(b"every");
                hasher.update(&period_seconds.to_le_bytes());

                if let Some(end) = end_date {
                    hasher.update(&bincode::serialize(end)?);
                }

                hasher.finalize().as_bytes().to_vec()
            }
        };

        // Compare the calculated hash with the stored hash
        // Implementation follows the verification formula from section 10:
        // Verify(Ccommit) = (H(Sn∥P) == Ccommit)
        Ok(calculated_hash == commitment.commitment_hash)
    }

    /// Create a deterministic pre-commit forking structure as described in section 11
    pub fn create_conditional_execution_paths(
        &self,
        paths: Vec<Operation>,
    ) -> Result<Vec<u8>, DsmError> {
        // Get the current state
        let current_state = self.core_sdk.get_current_state()?;

        // Implement the cryptographic forking structure:
        // Cfork = H(Sn∥{path1, path2, ..., pathm})
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bincode::serialize(&current_state)?);

        // Add all potential execution paths
        for path in &paths {
            hasher.update(&bincode::serialize(path)?);
        }

        let fork_commitment = hasher.finalize();

        Ok(fork_commitment.as_bytes().to_vec())
    }

    /// Selects a deterministic execution path based on an external condition
    pub fn select_execution_path(
        &self,
        fork_commitment: &[u8],
        path_index: usize,
        paths: &[Operation],
    ) -> Result<Operation, DsmError> {
        // Ensure the path index is valid
        if path_index >= paths.len() {
            return Err(DsmError::validation(
                format!(
                    "Invalid path index {}, only {} paths available",
                    path_index,
                    paths.len()
                ),
                None::<std::convert::Infallible>,
            ));
        }

        // Verify the fork commitment
        let current_state = self.core_sdk.get_current_state()?;

        // Recalculate the fork commitment
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bincode::serialize(&current_state)?);

        for path in paths {
            hasher.update(&bincode::serialize(path)?);
        }

        let calculated_commitment = hasher.finalize();

        // Verify the commitment matches
        if calculated_commitment.as_bytes() != fork_commitment {
            return Err(DsmError::validation(
                "Fork commitment verification failed",
                None::<std::convert::Infallible>,
            ));
        }

        // Return the selected path
        Ok(paths[path_index].clone())
    }

    /// Create a ROOT token payment commitment
    pub fn create_root_payment_commitment(
        &self,
        sender: &str,
        recipient: &str,
        amount: u64,
    ) -> Result<SmartCommitment, DsmError> {
        // This is a simple immediate payment commitment (no time lock or conditions)
        // Get the current state
        let current_state = self.core_sdk.get_current_state()?;

        // Create a simple hash commitment
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bincode::serialize(&current_state)?);
        hasher.update(sender.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"payment");

        let commitment_hash = hasher.finalize().as_bytes().to_vec();

        // Create a commitment that's immediately executable
        let now = Utc::now();
        Ok(SmartCommitment {
            recipient: recipient.to_string(),
            amount,
            token_id: "ROOT".to_string(),
            condition: CommitmentCondition::TimeLocked {
                unlock_time: now, // Immediate execution
            },
            commitment_hash,
            encrypted_payload: None,
            timestamp: now.timestamp() as u64,
        })
    }

    /// (Optional) Example of how the operation might be executed in the system
    #[allow(dead_code)]
    fn execute_smart_commitment(&self, commitment: &SmartCommitment) -> Result<State, DsmError> {
        let operation = Operation::Transfer {
            to_address: commitment.recipient.clone(),
            amount: Balance::new(commitment.amount),
            recipient: commitment.recipient.clone(),
            token_id: commitment.token_id.clone(),
            to: commitment.recipient.clone(),
            message: "Smart commitment transfer".to_string(),
            mode: TransactionMode::Bilateral, // Use Bilateral mode for commitment transfers
            nonce: Vec::new(),
            verification: VerificationType::Standard,
            pre_commit: None,
        };

        // For demonstration, just return a default state here
        let _ = operation;
        Ok(State::default())
    }

    // Create the commitment operation
    pub fn create_commitment_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Create {
            message: "Create smart commitment".to_string(),
            identity_data: Vec::new(),
            public_key: Vec::new(),
            metadata: Vec::new(),
            commitment: Vec::new(),
            proof: Vec::new(),
            mode: TransactionMode::Bilateral, // Use Bilateral mode
        })
    }

    // Update commitment operation
    pub fn update_commitment_operation(&self) -> Result<Operation, DsmError> {
        Ok(Operation::Update {
            identity_id: "".to_string(),
            updated_data: vec![],
            proof: vec![],
            forward_link: None,
            message: "Update smart commitment".to_string(),
        })
    }
}
