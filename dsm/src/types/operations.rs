use crate::commitments::precommit::SecurityParameters;
use crate::types::error::DsmError;
use crate::types::token_types::Balance;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

/// Base Operations trait that all specific operation traits inherit from
pub trait Ops: Debug {
    fn validate(&self) -> Result<bool, DsmError>;
    fn execute(&self) -> Result<Vec<u8>, DsmError>;
    fn get_id(&self) -> &str;
    fn to_bytes(&self) -> Vec<u8>;
}

/// Identity management operations
pub trait IdOps: Ops {
    fn verify_identity(&self, public_key: &[u8]) -> Result<bool, DsmError>;
    fn update_identity(&mut self, new_data: &[u8]) -> Result<(), DsmError>;
    fn revoke_identity(&mut self) -> Result<(), DsmError>;
    fn get_identity_proof(&self) -> Result<Vec<u8>, DsmError>;
}

/// Token management operations  
pub trait TokenOps: Ops {
    fn is_valid(&self) -> bool;
    fn has_expired(&self) -> bool;
    fn verify_token(&self, public_key: &[u8]) -> Result<bool, DsmError>;
    fn extend_validity(&mut self, duration: u64) -> Result<(), DsmError>;
}

/// Generic operations for extensibility
pub trait GenericOps: Ops {
    fn get_operation_type(&self) -> &str;
    fn get_data(&self) -> &[u8];
    fn set_data(&mut self, data: Vec<u8>) -> Result<(), DsmError>;
    fn merge(&self, other: &dyn GenericOps) -> Result<Vec<u8>, DsmError>;
}

/// Smart commitment operations
pub trait SmartCommitOps: Ops {
    fn verify_commitment(&self, public_key: &[u8]) -> Result<bool, DsmError>;
    fn update_commitment(&mut self, new_data: &[u8]) -> Result<(), DsmError>;
    fn finalize_commitment(&mut self) -> Result<Vec<u8>, DsmError>;
    fn get_commitment_proof(&self) -> Result<Vec<u8>, DsmError>;
}

/// Transaction execution mode
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionMode {
    Bilateral,
    Unilateral,
}

/// How to verify the transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationType {
    Standard,
    Enhanced,
    Bilateral,
    Directory,
    Custom(Vec<u8>),
}

/// Main Operation enum that implements all operation traits
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum Operation {
    #[default]
    Genesis,
    Create {
        message: String,
        identity_data: Vec<u8>,
        public_key: Vec<u8>,
        metadata: Vec<u8>,
        commitment: Vec<u8>,
        proof: Vec<u8>,
        mode: TransactionMode,
    },
    Update {
        message: String,
        identity_id: String,
        updated_data: Vec<u8>,
        proof: Vec<u8>,
        forward_link: Option<Vec<u8>>,
    },
    Transfer {
        to_address: String,
        amount: Balance,
        token_id: String,
        mode: TransactionMode,
        nonce: Vec<u8>,
        verification: VerificationType,
        pre_commit: Option<PreCommitmentOp>,
        recipient: String,
        to: String,
        message: String,
    },
    Mint {
        amount: Balance,
        token_id: String,
        authorized_by: String,
        proof_of_authorization: Vec<u8>,
        message: String,
    },
    Burn {
        amount: Balance,
        token_id: String,
        proof_of_ownership: Vec<u8>,
        message: String,
    },
    LockToken {
        token_id: String,
        amount: i64,
        purpose: String,
        mode: TransactionMode,
    },
    UnlockToken {
        token_id: String,
        amount: i64,
        purpose: String,
        mode: TransactionMode,
    },
    AddRelationship {
        from_id: String,
        to_id: String,
        relationship_type: String,
        metadata: Vec<u8>,
        proof: Vec<u8>,
        mode: TransactionMode,
        message: String,
    },
    CreateRelationship {
        message: String,
        counterparty_id: String,
        commitment: Vec<u8>,
        proof: Vec<u8>,
        mode: TransactionMode,
    },
    RemoveRelationship {
        from_id: String,
        to_id: String,
        relationship_type: String,
        proof: Vec<u8>,
        mode: TransactionMode,
        message: String,
    },
    Recovery {
        message: String,
        state_number: u64,
        state_hash: Vec<u8>,
        state_entropy: Vec<u8>,
        invalidation_data: Vec<u8>,
        new_state_data: Vec<u8>,
        new_state_number: u64,
        new_state_hash: Vec<u8>,
        new_state_entropy: Vec<u8>,
        compromise_proof: Vec<u8>,
        authority_sigs: Vec<Vec<u8>>,
    },
    Delete {
        reason: String,
        proof: Vec<u8>,
        mode: TransactionMode,
        id: String,
    },
    Link {
        target_id: String,
        link_type: String,
        proof: Vec<u8>,
        mode: TransactionMode,
    },
    Unlink {
        target_id: String,
        proof: Vec<u8>,
        mode: TransactionMode,
    },
    Invalidate {
        reason: String,
        proof: Vec<u8>,
        mode: TransactionMode,
    },
    Generic {
        operation_type: String,
        data: Vec<u8>,
        message: String,
    },
}

impl Operation {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }

    pub fn get_state_number(&self) -> Option<u64> {
        None
    }
}

impl Ops for Operation {
    fn validate(&self) -> Result<bool, DsmError> {
        match self {
            Operation::Generic { .. } => Ok(true),
            Operation::Transfer {
                amount,
                token_id: _,
                ..
            } => Ok(amount.value() > 0),
            Operation::Mint {
                amount,
                token_id: _,
                ..
            } => Ok(amount.value() > 0),
            Operation::Burn {
                amount,
                token_id: _,
                ..
            } => Ok(amount.value() > 0),
            Operation::LockToken { .. } => Ok(true),
            Operation::UnlockToken { .. } => Ok(true),
            _ => Ok(true),
        }
    }

    fn execute(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.to_bytes())
    }

    fn get_id(&self) -> &str {
        match self {
            Operation::Genesis => "genesis",
            Operation::Generic { operation_type, .. } => operation_type,
            Operation::Transfer { .. } => "transfer",
            Operation::Mint { .. } => "mint",
            Operation::Burn { .. } => "burn",
            Operation::Create { .. } => "create",
            Operation::Update { .. } => "update",
            Operation::AddRelationship { .. } => "add_relationship",
            Operation::CreateRelationship { .. } => "create_relationship",
            Operation::RemoveRelationship { .. } => "remove_relationship",
            Operation::Recovery { .. } => "recovery",
            Operation::Delete { .. } => "delete",
            Operation::Link { .. } => "link",
            Operation::Unlink { .. } => "unlink",
            Operation::Invalidate { .. } => "invalidate",
            Operation::LockToken { .. } => "lock_token",
            Operation::UnlockToken { .. } => "unlock_token",
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl TokenOps for Operation {
    fn is_valid(&self) -> bool {
        match self {
            Operation::Transfer {
                amount,
                token_id: _,
                ..
            } => amount.value() > 0,
            Operation::Mint {
                amount,
                token_id: _,
                ..
            } => amount.value() > 0,
            Operation::Burn {
                amount,
                token_id: _,
                ..
            } => amount.value() > 0,
            _ => false,
        }
    }

    fn has_expired(&self) -> bool {
        false
    }

    fn verify_token(&self, _public_key: &[u8]) -> Result<bool, DsmError> {
        match self {
            Operation::Transfer { .. } | Operation::Mint { .. } | Operation::Burn { .. } => {
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn extend_validity(&mut self, _duration: u64) -> Result<(), DsmError> {
        Err(DsmError::generic(
            "Cannot extend validity of an operation",
            None::<std::io::Error>,
        ))
    }
}

impl GenericOps for Operation {
    fn get_operation_type(&self) -> &str {
        match self {
            Operation::Genesis => "genesis",
            Operation::Generic { operation_type, .. } => operation_type,
            _ => self.get_id(),
        }
    }

    fn get_data(&self) -> &[u8] {
        match self {
            Operation::Generic { data, .. } => data,
            _ => &[],
        }
    }

    fn set_data(&mut self, data: Vec<u8>) -> Result<(), DsmError> {
        match self {
            Operation::Generic {
                data: ref mut d, ..
            } => {
                *d = data;
                Ok(())
            }
            _ => Err(DsmError::generic(
                "Cannot set data on non-generic operation",
                None::<std::io::Error>,
            )),
        }
    }

    fn merge(&self, other: &dyn GenericOps) -> Result<Vec<u8>, DsmError> {
        let mut merged = Vec::new();
        merged.extend_from_slice(self.get_data());
        merged.extend_from_slice(other.get_data());
        Ok(merged)
    }
}

impl IdOps for Operation {
    fn verify_identity(&self, _public_key: &[u8]) -> Result<bool, DsmError> {
        match self {
            Operation::Create { .. } | Operation::Update { .. } => Ok(true),
            _ => Ok(false),
        }
    }

    fn update_identity(&mut self, _new_data: &[u8]) -> Result<(), DsmError> {
        match self {
            Operation::Update { .. } => Ok(()),
            _ => Err(DsmError::generic(
                "Cannot update identity with this operation",
                None::<std::io::Error>,
            )),
        }
    }

    fn revoke_identity(&mut self) -> Result<(), DsmError> {
        Err(DsmError::generic(
            "Identity revocation not implemented for operations",
            None::<std::io::Error>,
        ))
    }

    fn get_identity_proof(&self) -> Result<Vec<u8>, DsmError> {
        match self {
            Operation::Create { .. } | Operation::Update { .. } => Ok(Vec::new()),
            _ => Err(DsmError::generic(
                "No identity proof for this operation",
                None::<std::io::Error>,
            )),
        }
    }
}

impl SmartCommitOps for Operation {
    fn verify_commitment(&self, _public_key: &[u8]) -> Result<bool, DsmError> {
        Ok(true)
    }

    fn update_commitment(&mut self, _new_data: &[u8]) -> Result<(), DsmError> {
        Err(DsmError::generic(
            "Cannot update commitment for operation",
            None::<std::io::Error>,
        ))
    }

    fn finalize_commitment(&mut self) -> Result<Vec<u8>, DsmError> {
        Ok(self.to_bytes())
    }

    fn get_commitment_proof(&self) -> Result<Vec<u8>, DsmError> {
        Ok(self.to_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PreCommitmentOp {
    pub fixed_parameters: HashMap<String, Vec<u8>>,
    pub variable_parameters: Vec<String>,
    #[serde(skip)]
    pub security_params: SecurityParameters,
}

// Implement PartialEq, Eq, PartialOrd and Ord for consistent ordering
impl PartialEq for PreCommitmentOp {
    fn eq(&self, other: &Self) -> bool {
        self.fixed_parameters == other.fixed_parameters
            && self.variable_parameters == other.variable_parameters
    }
}

impl PartialOrd for PreCommitmentOp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PreCommitmentOp {}

impl Ord for PreCommitmentOp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let fixed_params_cmp = self
            .fixed_parameters
            .len()
            .cmp(&other.fixed_parameters.len());
        if fixed_params_cmp != std::cmp::Ordering::Equal {
            return fixed_params_cmp;
        }

        let var_params_cmp = self.variable_parameters.cmp(&other.variable_parameters);
        if var_params_cmp != std::cmp::Ordering::Equal {
            return var_params_cmp;
        }

        std::cmp::Ordering::Equal
    }
}

// Implement conversion from StateTransition to Operation
use crate::core::state_machine::transition::StateTransition;

impl From<StateTransition> for Operation {
    fn from(transition: StateTransition) -> Self {
        // Simply extract the operation from the transition
        transition.operation
    }
}
