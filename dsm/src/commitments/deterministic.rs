use crate::types::operations::Operation;
use bincode;
use blake3;

/// Create a deterministic commitment for a token operation
pub fn create_deterministic_commitment(
    current_state_hash: &[u8],
    operation: &Operation,
    recipient_info: &[u8],
    conditions: Option<&str>,
) -> Vec<u8> {
    let mut commit_data = Vec::new();
    commit_data.extend_from_slice(current_state_hash);
    commit_data.extend_from_slice(&bincode::serialize(operation).unwrap_or_default());
    commit_data.extend_from_slice(recipient_info);

    if let Some(cond) = conditions {
        commit_data.extend_from_slice(cond.as_bytes());
    }

    blake3::hash(&commit_data).as_bytes().to_vec()
}

/// Create a time-locked deterministic commitment
pub fn create_time_locked_commitment(
    current_state_hash: &[u8],
    operation: &Operation,
    recipient_info: &[u8],
    unlock_time: u64,
) -> Vec<u8> {
    let mut commit_data = Vec::new();
    commit_data.extend_from_slice(current_state_hash);
    commit_data.extend_from_slice(&bincode::serialize(operation).unwrap_or_default());
    commit_data.extend_from_slice(recipient_info);
    commit_data.extend_from_slice(&unlock_time.to_be_bytes());
    commit_data.extend_from_slice(b"time_locked");

    blake3::hash(&commit_data).as_bytes().to_vec()
}

/// Create a conditional deterministic commitment
pub fn create_conditional_commitment(
    current_state_hash: &[u8],
    operation: &Operation,
    recipient_info: &[u8],
    condition: &str,
    oracle_id: &str,
) -> Vec<u8> {
    let mut commit_data = Vec::new();
    commit_data.extend_from_slice(current_state_hash);
    commit_data.extend_from_slice(&bincode::serialize(operation).unwrap_or_default());
    commit_data.extend_from_slice(recipient_info);
    commit_data.extend_from_slice(condition.as_bytes());
    commit_data.extend_from_slice(oracle_id.as_bytes());
    commit_data.extend_from_slice(b"conditional");

    blake3::hash(&commit_data).as_bytes().to_vec()
}

/// Create a recurring payment deterministic commitment
pub fn create_recurring_commitment(
    current_state_hash: &[u8],
    operation: &Operation,
    recipient_info: &[u8],
    period_seconds: u64,
    end_date: u64,
) -> Vec<u8> {
    let mut commit_data = Vec::new();
    commit_data.extend_from_slice(current_state_hash);
    commit_data.extend_from_slice(&bincode::serialize(operation).unwrap_or_default());
    commit_data.extend_from_slice(recipient_info);
    commit_data.extend_from_slice(&period_seconds.to_be_bytes());
    commit_data.extend_from_slice(&end_date.to_be_bytes());
    commit_data.extend_from_slice(b"recurring");

    blake3::hash(&commit_data).as_bytes().to_vec()
}

/// Verify a deterministic commitment
pub fn verify_deterministic_commitment(
    commitment: &[u8],
    current_state_hash: &[u8],
    operation: &Operation,
    recipient_info: &[u8],
    conditions: Option<&str>,
) -> bool {
    let calculated =
        create_deterministic_commitment(current_state_hash, operation, recipient_info, conditions);

    calculated == commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::operations::PreCommitmentOp;
    use crate::types::token_types::Balance;
    use serde::{Deserialize, Serialize};

    #[derive(Default, Clone, Serialize, Deserialize)]
    struct TestPreCommitment {}

    // Implement From trait for the test wrapper
    impl From<TestPreCommitment> for PreCommitmentOp {
        fn from(_: TestPreCommitment) -> Self {
            PreCommitmentOp::default()
        }
    }

    #[test]
    fn test_create_deterministic_commitment() {
        use crate::types::operations::TransactionMode;
        let current_state_hash = vec![1, 2, 3, 4];
        let recipient_info = b"recipient_public_key";
        let conditions = Some("payment for services");

        let operation = Operation::Transfer {
            to_address: "recipient123".to_string(),
            verification: crate::types::operations::VerificationType::Standard,
            token_id: "token123".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: Some(PreCommitmentOp::from(TestPreCommitment::default())),
            recipient: "recipient123".to_string(),
            to: "recipient123".to_string(),
            message: String::from("Test message"),
            amount: Balance::new(100),
        };

        let commitment = create_deterministic_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        );

        // Verify the commitment is non-empty and has correct length (32 bytes for Blake3)
        assert!(!commitment.is_empty());
        assert_eq!(commitment.len(), 32);

        // Verify the same inputs produce the same commitment (deterministic property)
        let commitment2 = create_deterministic_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        );
        assert_eq!(commitment, commitment2);

        let different_operation = Operation::Transfer {
            to_address: "recipient123".to_string(),
            amount: Balance::new(200), // Changed amount
            token_id: "token123".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: None,
            verification: crate::types::operations::VerificationType::Standard,
            recipient: "recipient123".to_string(),
            to: "recipient123".to_string(),
            message: String::from("Test message"),
        };

        let different_commitment = create_deterministic_commitment(
            &current_state_hash,
            &different_operation,
            recipient_info,
            conditions,
        );

        assert_ne!(commitment, different_commitment);
    }

    #[test]
    fn test_verify_deterministic_commitment() {
        use crate::types::operations::TransactionMode;
        let current_state_hash = vec![1, 2, 3, 4];
        let recipient_info = b"recipient_public_key";

        let operation = Operation::Transfer {
            to_address: "recipient123".to_string(),
            amount: Balance::new(100),
            token_id: "token123".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: Some(PreCommitmentOp::from(TestPreCommitment::default())),
            verification: crate::types::operations::VerificationType::Standard,
            recipient: "recipient123".to_string(),
            to: "recipient123".to_string(),
            message: String::from("Test message"),
        };
        let conditions = Some("payment for services");
        let commitment = create_deterministic_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        );

        // Verify the commitment with the same inputs
        assert!(verify_deterministic_commitment(
            &commitment,
            &current_state_hash,
            &operation,
            recipient_info,
            conditions,
        ));

        // Verify the commitment fails with different inputs
        let different_operation = Operation::Transfer {
            to_address: "recipient123".to_string(),
            amount: Balance::new(200), // Changed amount
            token_id: "token123".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: Some(PreCommitmentOp::from(TestPreCommitment::default())),
            verification: crate::types::operations::VerificationType::Standard,
            recipient: "recipient123".to_string(),
            to: "recipient123".to_string(),
            message: String::from("Test message"),
        };

        assert!(!verify_deterministic_commitment(
            &commitment,
            &current_state_hash,
            &different_operation,
            recipient_info,
            conditions,
        ));
    }

    #[test]
    fn test_time_locked_commitment() {
        use crate::types::operations::TransactionMode;
        let current_state_hash = vec![1, 2, 3, 4];
        let recipient_info = b"recipient_public_key";
        let unlock_time = 1_672_531_200; // January 1, 2023

        let operation = Operation::Transfer {
            to_address: "recipient123".to_string(),
            amount: Balance::new(100),
            token_id: "token123".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: Some(PreCommitmentOp::from(TestPreCommitment::default())),
            verification: crate::types::operations::VerificationType::Standard,
            recipient: "recipient123".to_string(),
            to: "recipient123".to_string(),
            message: String::from("Test message"),
        };

        let commitment = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_time,
        );

        // Verify same inputs produce same commitment
        let commitment2 = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_time,
        );
        assert_eq!(commitment, commitment2);

        // Verify different unlock time produces different commitment
        let different_commitment = create_time_locked_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            unlock_time + 3600, // Add one hour
        );
        assert_ne!(commitment, different_commitment);
    }
    #[test]
    fn test_conditional_commitment() {
        use crate::types::operations::TransactionMode;
        let current_state_hash = vec![1, 2, 3, 4];
        let recipient_info = b"recipient_public_key";
        let condition = "BTC price > $50,000";
        let oracle_id = "crypto_price_oracle";

        let operation = Operation::Transfer {
            to_address: "recipient123".to_string(),
            amount: Balance::new(100),
            token_id: "token123".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: Some(PreCommitmentOp::from(TestPreCommitment::default())),
            verification: crate::types::operations::VerificationType::Standard,
            recipient: "recipient123".to_string(),
            to: "recipient123".to_string(),
            message: String::from("Test message"),
        };

        let commitment = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            condition,
            oracle_id,
        );

        // Verify same inputs produce same commitment
        let commitment2 = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            condition,
            oracle_id,
        );
        assert_eq!(commitment, commitment2);

        // Verify different condition produces different commitment
        let different_commitment = create_conditional_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            "BTC price > $60,000", // Different condition
            oracle_id,
        );
        assert_ne!(commitment, different_commitment);
    }

    #[test]
    fn test_recurring_commitment() {
        use crate::types::operations::TransactionMode;
        let current_state_hash = vec![1, 2, 3, 4];
        let recipient_info = b"recipient_public_key";
        let period_seconds = 604_800; // 7 days
        let end_date = 1_704_067_200; // January 1, 2024

        let operation = Operation::Transfer {
            to_address: "recipient123".to_string(),
            amount: Balance::new(100),
            token_id: "token123".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4, 5],
            pre_commit: Some(PreCommitmentOp::from(TestPreCommitment::default())),
            verification: crate::types::operations::VerificationType::Standard,
            recipient: "recipient123".to_string(),
            to: "recipient123".to_string(),
            message: String::from("Test message"),
        };

        let commitment = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            period_seconds,
            end_date,
        );

        // Verify same inputs produce same commitment
        let commitment2 = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            period_seconds,
            end_date,
        );
        assert_eq!(commitment, commitment2);

        // Verify different period produces different commitment
        let different_commitment = create_recurring_commitment(
            &current_state_hash,
            &operation,
            recipient_info,
            2_592_000, // 30 days
            end_date,
        );
        assert_ne!(commitment, different_commitment);
    }
}
