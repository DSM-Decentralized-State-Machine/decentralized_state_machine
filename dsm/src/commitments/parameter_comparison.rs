use crate::types::error::DsmError;
use crate::types::operations::{Operation, TransactionMode, VerificationType};
use crate::types::token_types::Balance;
use std::collections::{HashMap, HashSet};

// Helper function to convert Balance to bytes
fn balance_to_bytes(balance: &Balance) -> Vec<u8> {
    bincode::serialize(balance).unwrap_or_default()
}

fn verify_bilateral_transfer_parameters(
    nonce: &[u8],
    verification: &VerificationType,
    pre_commit: &Option<impl serde::Serialize>,
) -> HashMap<String, Vec<u8>> {
    let mut params = HashMap::new();
    params.insert("operation_type".to_string(), b"transfer".to_vec());
    params.insert("nonce".to_string(), nonce.to_vec());
    params.insert(
        "verification".to_string(),
        bincode::serialize(verification).unwrap(),
    );
    if let Some(pc) = pre_commit {
        params.insert("pre_commit".to_string(), bincode::serialize(pc).unwrap());
    }
    params
}

fn verify_unilateral_transfer_parameters(
    nonce: &[u8],
    verification: &VerificationType,
) -> HashMap<String, Vec<u8>> {
    let mut params = HashMap::new();
    params.insert("operation_type".to_string(), b"transfer".to_vec());
    params.insert("nonce".to_string(), nonce.to_vec());
    params.insert(
        "verification".to_string(),
        bincode::serialize(verification).unwrap(),
    );
    params
}

/// Extracts parameters from an operation in a consistent format for comparison
pub fn extract_operation_parameters(
    operation: &Operation,
) -> Result<HashMap<String, Vec<u8>>, DsmError> {
    match operation {
        Operation::Genesis => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"genesis".to_vec());
            Ok(params)
        }
        Operation::Transfer {
            amount,
            token_id,
            mode,
            nonce,
            verification,
            pre_commit,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("token_id".to_string(), token_id.as_bytes().to_vec());
            params.insert("amount".to_string(), amount.value().to_le_bytes().to_vec());

            match mode {
                TransactionMode::Bilateral => {
                    // Add bilateral transfer parameters
                    let bilateral_params =
                        verify_bilateral_transfer_parameters(nonce, verification, pre_commit);
                    params.extend(bilateral_params);
                }
                TransactionMode::Unilateral => {
                    // Add unilateral transfer parameters
                    let unilateral_params =
                        verify_unilateral_transfer_parameters(nonce, verification);
                    params.extend(unilateral_params);
                }
            }
            Ok(params)
        }
        Operation::Mint {
            amount,
            token_id,
            authorized_by,
            proof_of_authorization,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"mint".to_vec());
            params.insert("amount".to_string(), balance_to_bytes(amount));
            params.insert("token_id".to_string(), token_id.as_bytes().to_vec());
            params.insert(
                "authorized_by".to_string(),
                authorized_by.as_bytes().to_vec(),
            );
            params.insert(
                "proof_of_authorization".to_string(),
                proof_of_authorization.clone(),
            );
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Burn {
            amount,
            token_id,
            proof_of_ownership,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"burn".to_vec());
            params.insert("amount".to_string(), balance_to_bytes(amount));
            params.insert("token_id".to_string(), token_id.as_bytes().to_vec());
            params.insert("proof_of_ownership".to_string(), proof_of_ownership.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Create {
            identity_data,
            public_key,
            metadata,
            commitment,
            message,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"create".to_vec());
            params.insert("identity_data".to_string(), identity_data.clone());
            params.insert("public_key".to_string(), public_key.clone());
            params.insert("metadata".to_string(), metadata.clone());
            params.insert("commitment".to_string(), commitment.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            Ok(params)
        }
        Operation::Update {
            identity_id,
            updated_data,
            proof,
            forward_link,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"update".to_vec());
            params.insert("identity_id".to_string(), identity_id.as_bytes().to_vec());
            params.insert("updated_data".to_string(), updated_data.clone());
            params.insert("proof".to_string(), proof.clone());
            if let Some(link) = forward_link {
                params.insert("forward_link".to_string(), link.clone());
            }
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::AddRelationship {
            from_id,
            to_id,
            relationship_type,
            metadata,
            proof,
            mode,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"add_relationship".to_vec());
            params.insert("from_id".to_string(), from_id.as_bytes().to_vec());
            params.insert("to_id".to_string(), to_id.as_bytes().to_vec());
            params.insert(
                "relationship_type".to_string(),
                relationship_type.as_bytes().to_vec(),
            );
            params.insert("metadata".to_string(), metadata.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::CreateRelationship {
            message,
            counterparty_id,
            commitment,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert(
                "operation_type".to_string(),
                b"create_relationship".to_vec(),
            );
            params.insert(
                "counterparty_id".to_string(),
                counterparty_id.as_bytes().to_vec(),
            );
            params.insert("commitment".to_string(), commitment.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::RemoveRelationship {
            from_id,
            to_id,
            relationship_type,
            proof,
            mode,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert(
                "operation_type".to_string(),
                b"remove_relationship".to_vec(),
            );
            params.insert("from_id".to_string(), from_id.as_bytes().to_vec());
            params.insert("to_id".to_string(), to_id.as_bytes().to_vec());
            params.insert(
                "relationship_type".to_string(),
                relationship_type.as_bytes().to_vec(),
            );
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Recovery {
            state_number,
            state_hash,
            message,
            invalidation_data,
            new_state_data,
            new_state_number,
            new_state_hash,
            new_state_entropy,
            compromise_proof,
            authority_sigs,
            state_entropy,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"recovery".to_vec());
            params.insert(
                "state_number".to_string(),
                state_number.to_string().as_bytes().to_vec(),
            );
            params.insert("state_hash".to_string(), state_hash.to_vec());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            params.insert("invalidation_data".to_string(), invalidation_data.clone());
            params.insert("new_state_data".to_string(), new_state_data.clone());
            params.insert(
                "new_state_number".to_string(),
                new_state_number.to_string().as_bytes().to_vec(),
            );
            params.insert("new_state_hash".to_string(), new_state_hash.to_vec());
            params.insert("new_state_entropy".to_string(), new_state_entropy.clone());
            params.insert("compromise_proof".to_string(), compromise_proof.clone());
            // Serialize authority_sigs to handle Vec<Vec<u8>>
            params.insert(
                "authority_sigs".to_string(),
                bincode::serialize(&authority_sigs).unwrap_or_default(),
            );
            params.insert("state_entropy".to_string(), state_entropy.clone());
            // Removed the mode parameter since it doesn't exist in the Recovery operation
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Invalidate { .. } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"invalidate".to_vec());
            Ok(params)
        }
        Operation::Delete {
            id,
            proof,
            reason,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"delete".to_vec());
            params.insert("id".to_string(), id.as_bytes().to_vec());
            params.insert("proof".to_string(), proof.clone());
            params.insert("reason".to_string(), reason.as_bytes().to_vec());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            Ok(params)
        }
        Operation::Link {
            target_id,
            link_type,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"link".to_vec());
            params.insert("target_id".to_string(), target_id.as_bytes().to_vec());
            params.insert("link_type".to_string(), link_type.as_bytes().to_vec());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            Ok(params)
        }
        Operation::Generic {
            operation_type,
            data,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert(
                "operation_type".to_string(),
                operation_type.as_bytes().to_vec(),
            );
            params.insert("data".to_string(), data.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Unlink {
            target_id,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"unlink".to_vec());
            params.insert("target_id".to_string(), target_id.as_bytes().to_vec());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            Ok(params)
        }
        Operation::LockToken {
            token_id,
            amount,
            purpose,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"lock_token".to_vec());
            params.insert("token_id".to_string(), token_id.as_bytes().to_vec());
            params.insert("amount".to_string(), amount.to_le_bytes().to_vec());
            params.insert("purpose".to_string(), purpose.as_bytes().to_vec());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            Ok(params)
        }
        Operation::UnlockToken {
            token_id,
            amount,
            purpose,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"unlock_token".to_vec());
            params.insert("token_id".to_string(), token_id.as_bytes().to_vec());
            params.insert("amount".to_string(), amount.to_le_bytes().to_vec());
            params.insert("purpose".to_string(), purpose.as_bytes().to_vec());
            params.insert("mode".to_string(), bincode::serialize(mode).unwrap());
            Ok(params)
        }
    }
}

pub fn verify_operation_parameters(
    operation: &Operation,
    fixed_parameters: &HashMap<String, Vec<u8>>,
    _variable_parameters: &HashSet<String>,
    _timeout: u64,
) -> Result<bool, DsmError> {
    // Extract parameters from the operation
    let operation_params = extract_operation_parameters(operation)?;

    // Check all fixed parameters match exactly
    for (key, value) in fixed_parameters {
        // Get the operation's value for this parameter
        let op_value = match operation_params.get(key) {
            Some(val) => val,
            None => return Ok(false),
        };

        // If the values don't match, return false
        if op_value != value {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_extract_operation_parameters() -> Result<(), DsmError> {
        // Test with a Transfer operation
        let transfer_op = Operation::Transfer {
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3],
            verification: VerificationType::Standard,
            pre_commit: None,
            to_address: "recipient".to_string(),
            amount: Balance::new(100),
            token_id: "token123".to_string(),
            message: "Test transfer".to_string(),
            recipient: "recipient".to_string(),
            to: "to".to_string(),
        };

        let params = extract_operation_parameters(&transfer_op)?;

        // Check parameters were extracted correctly
        assert_eq!(params.get("operation_type").unwrap(), b"transfer");

        // Test with a Generic operation
        let generic_op = Operation::Generic {
            operation_type: "custom_op".to_string(),
            data: vec![1, 2, 3],
            message: "Test generic".to_string(),
        };

        // Extract parameters from generic operation and check them
        let generic_params = extract_operation_parameters(&generic_op)?;
        assert_eq!(generic_params.get("operation_type").unwrap(), b"custom_op");

        Ok(())
    }

    #[test]
    fn test_verify_operation_parameters() -> Result<(), DsmError> {
        // Create fixed parameters for a transfer operation
        let mut fixed_params = HashMap::new();
        fixed_params.insert("operation_type".to_string(), b"transfer".to_vec());

        // Create variable parameters
        let var_params = HashSet::new();

        // Create a valid operation that matches fixed parameters
        let valid_op = Operation::Transfer {
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3],
            verification: VerificationType::Standard,
            pre_commit: None,
            to_address: "recipient".to_string(),
            amount: Balance::new(100),
            token_id: "token123".to_string(),
            message: "Test transfer".to_string(),
            recipient: "recipient".to_string(),
            to: "to".to_string(),
        };

        // Create an invalid operation
        let invalid_op = Operation::Generic {
            operation_type: "invalid".to_string(),
            data: vec![4, 5, 6],
            message: "Invalid operation".to_string(),
        };

        // Verify operations
        assert!(verify_operation_parameters(
            &valid_op,
            &fixed_params,
            &var_params,
            0
        )?);
        assert!(!verify_operation_parameters(
            &invalid_op,
            &fixed_params,
            &var_params,
            0
        )?);
        assert!(!verify_operation_parameters(
            &invalid_op,
            &fixed_params,
            &var_params,
            0
        )?);

        Ok(())
    }
}
