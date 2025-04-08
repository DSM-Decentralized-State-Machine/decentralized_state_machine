#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use chrono::{Duration, Utc};
    
    use crate::policy::{
        generate_default_policy, generate_specialized_policy,
        policy_store::PolicyStore,
        policy_types::{PolicyAnchor, PolicyCondition, PolicyFile, PolicyRole},
        policy_verification::{verify_policy, PolicyVerificationResult},
    };
    use crate::types::error::DsmError;
    use crate::types::operations::{Operation, TransactionMode, VerificationType};
    use crate::types::token_types::Balance;
    
    #[tokio::test]
    async fn test_policy_anchor_creation_and_verification() {
        // Create a policy file
        let mut policy = PolicyFile::new("Test Policy", "1.0", "test_creator");
        policy.add_condition(PolicyCondition::TimeLock { unlock_time: 0 });
        
        // Generate anchor
        let anchor = policy.generate_anchor().expect("Failed to generate anchor");
        
        // Verify the anchor's properties
        assert_eq!(anchor.0.len(), 32, "CTPA anchor should be exactly 32 bytes");
        
        // Serialize and deserialize policy
        let serialized = serde_json::to_vec(&policy).expect("Failed to serialize policy");
        let deserialized: PolicyFile = serde_json::from_slice(&serialized).expect("Failed to deserialize policy");
        
        // Generate anchor from deserialized policy
        let deserialized_anchor = deserialized.generate_anchor().expect("Failed to generate anchor from deserialized policy");
        
        // Verify that anchors match
        assert_eq!(anchor, deserialized_anchor, "Anchors should be identical after serialization roundtrip");
        
        // Verify that anchor hex representation works
        let hex_str = anchor.to_hex();
        let from_hex = PolicyAnchor::from_hex(&hex_str).expect("Failed to parse hex");
        assert_eq!(anchor, from_hex, "Anchor should be identical after hex conversion roundtrip");
    }
    
    #[tokio::test]
    async fn test_policy_store_operations() {
        // Create a policy store
        let store = PolicyStore::new();
        
        // Create a policy
        let policy = generate_default_policy("TEST_TOKEN", "Test Token", "test_creator")
            .expect("Failed to generate default policy");
        
        // Store the policy
        let anchor = store.store_policy(&policy).await.expect("Failed to store policy");
        
        // Retrieve the policy
        let retrieved = store.get_policy(&anchor).await.expect("Failed to retrieve policy");
        
        // Verify retrieved policy matches original
        assert_eq!(retrieved.file.name, policy.name, "Retrieved policy name should match original");
        assert_eq!(retrieved.file.conditions.len(), policy.conditions.len(), 
            "Retrieved policy should have same number of conditions");
            
        // Test policy caching
        let cached = store.get_from_cache(&anchor);
        assert!(cached.is_some(), "Policy should be cached after retrieval");
        
        // Test clearing cache
        store.clear_cache();
        let cached_after_clear = store.get_from_cache(&anchor);
        assert!(cached_after_clear.is_none(), "Cache should be empty after clear");
        
        // Verify the policy can still be retrieved from storage
        let retrieved_again = store.get_policy(&anchor).await.expect("Failed to retrieve policy after cache clear");
        assert_eq!(retrieved_again.file.name, policy.name, "Policy should still be retrievable after cache clear");
    }
    
    #[tokio::test]
    async fn test_policy_verification() {
        let now = Utc::now();
        let one_hour_later = now + Duration::hours(1);
        let one_hour_later_ts = one_hour_later.timestamp() as u64;
        
        let mut policy = PolicyFile::new("Time-Locked Policy", "1.0", "test_creator");
        policy.add_condition(PolicyCondition::TimeLock { 
            unlock_time: one_hour_later_ts 
        });
        
        let anchor = policy.generate_anchor().expect("Failed to generate anchor");
        let token_policy = crate::policy::policy_types::TokenPolicy {
            file: policy,
            anchor,
            verified: true,
            last_verified: Utc::now().timestamp() as u64,
        };
        
        let transfer_op = Operation::Transfer { 
            to_address: "recipient".to_string(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1,2,3],
            verification: VerificationType::Standard,
            pre_commit: None,
            amount: Balance::new(100),
            token_id: "TEST_TOKEN".to_string(),
            message: "test transfer".to_string(),
            recipient: "recipient".to_string(),
            to: "to".to_string(),
        };
        
        let result = verify_policy(&token_policy, &transfer_op, None, None, None);
        
        match result {
            PolicyVerificationResult::Invalid { message, condition } => {
                assert!(message.contains("time-locked"), "Error message should mention time lock");
                assert!(matches!(condition, Some(PolicyCondition::TimeLock { .. })), 
                    "Failed condition should be TimeLock");
            },
            _ => panic!("Policy verification should fail due to time lock"),
        }
    }
    
    #[tokio::test]
    async fn test_default_policy_generation() {
        // Generate a default policy
        let policy = generate_default_policy("TEST_TOKEN", "Test Token", "test_creator")
            .expect("Failed to generate default policy");
        
        // Verify default policy properties
        assert!(policy.conditions.iter().any(|c| matches!(c, PolicyCondition::TimeLock { .. })),
            "Default policy should include a time lock condition");
            
        assert!(policy.conditions.iter().any(|c| 
            matches!(c, PolicyCondition::IdentityConstraint { allowed_identities, .. } 
                if allowed_identities.contains(&"test_creator".to_string()))),
            "Default policy should include creator in allowed identities");
            
        assert!(policy.conditions.iter().any(|c| 
            matches!(c, PolicyCondition::OperationRestriction { allowed_operations } 
                if allowed_operations.iter().any(|op| matches!(op, Operation::Transfer { .. })))),
            "Default policy should allow transfers");
    }
    
    #[tokio::test]
    async fn test_specialized_policy_generation() {
        // Create parameters for specialized policy
        let mut params = HashMap::new();
        params.insert("unlock_time".to_string(), "2099-01-01T00:00:00Z".to_string());
        
        // Generate a time-locked policy
        let policy = generate_specialized_policy(
            "TIME_LOCKED", "Time Locked Token", "test_creator", "TimeLocked", &params
        ).expect("Failed to generate specialized policy");
        
        // Verify specialized policy properties
        let has_time_lock = policy.conditions.iter().any(|c| 
            matches!(c, PolicyCondition::TimeLock { unlock_time } if *unlock_time > Utc::now().timestamp() as u64));
            
        assert!(has_time_lock, "Time-locked policy should have a future unlock time");
        
        // Test invalid policy type
        let result = generate_specialized_policy(
            "INVALID", "Invalid Policy", "test_creator", "NonexistentType", &params
        );
        
        assert!(result.is_err(), "Should fail with non-existent policy type");
        assert!(matches!(result, Err(DsmError::Validation { .. })), 
            "Should return validation error for invalid policy type");
    }
    
    #[tokio::test]
    async fn test_policy_idempotency() {
        // Create a policy file twice with the same parameters
        let policy1 = generate_default_policy("IDEMPOTENCY_TEST", "Idempotency Test", "test_creator")
            .expect("Failed to generate first policy");
            
        let policy2 = generate_default_policy("IDEMPOTENCY_TEST", "Idempotency Test", "test_creator")
            .expect("Failed to generate second policy");
        
        // Generate anchors (these will differ due to creation timestamps)
        let anchor1 = policy1.generate_anchor().expect("Failed to generate first anchor");
        let anchor2 = policy2.generate_anchor().expect("Failed to generate second anchor");
        
        // Anchors should differ despite similar content due to timestamps
        assert_ne!(anchor1, anchor2, "Different policy instances should have different anchors");
        
        // However, if we clone a policy, the anchor should be identical
        let policy3 = policy1.clone();
        let anchor3 = policy3.generate_anchor().expect("Failed to generate third anchor");
        
        assert_eq!(anchor1, anchor3, "Cloned policy should have identical anchor");
    }
    
    #[tokio::test]
    async fn test_policy_role_permissions() {
        let mut policy = PolicyFile::new("Role Test Policy", "1.0", "test_creator");
        
        // Add roles with different permissions
        policy.add_role(PolicyRole {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            permissions: vec![
                Operation::Transfer {
                    to_address: String::new(),
                    mode: TransactionMode::Bilateral,
                    nonce: vec![],
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    amount: Balance::new(0),
                    token_id: String::new(),
                    message: String::new(),
                    recipient: String::new(),
                    to: String::new(),
                }
            ],
        });
        
        policy.add_role(PolicyRole {
            id: "user".to_string(),
            name: "User".to_string(),
            permissions: vec![
                Operation::Transfer {
                    to_address: String::new(),
                    mode: TransactionMode::Bilateral,
                    nonce: vec![],
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    amount: Balance::new(0),
                    token_id: String::new(),
                    message: String::new(),
                    recipient: String::new(),
                    to: String::new(),
                }
            ],
        });
        
        // Verify roles were added correctly
        assert_eq!(policy.roles.len(), 2, "Policy should have 2 roles");
        
        let admin_role = policy.roles.iter().find(|r| r.id == "admin").expect("Admin role not found");
        let user_role = policy.roles.iter().find(|r| r.id == "user").expect("User role not found");
        
        assert!(admin_role.permissions.iter().any(|op| matches!(op, Operation::Transfer { .. })), 
            "Admin should have Transfer permission");
        assert!(user_role.permissions.iter().any(|op| matches!(op, Operation::Transfer { .. })), 
            "User should have Transfer permission");
        assert!(!user_role.permissions.iter().any(|op| matches!(op, Operation::Mint { .. })), 
            "User should not have Mint permission");
    }

    #[test]
    fn test_transfer_policy() {
        // Only declare variables we'll use
        let mut policy = PolicyFile::new("Test Policy", "1.0", "test_creator");
        policy.add_condition(PolicyCondition::OperationRestriction {
            allowed_operations: vec![
                Operation::Transfer {
                    to_address: "any".to_string(),
                    mode: TransactionMode::Bilateral,
                    nonce: vec![],
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    amount: Balance::new(0),
                    token_id: String::new(),
                    message: String::new(),
                    recipient: String::new(),
                    to: String::new()
                }
            ],
        });

        // Assert operations are allowed correctly
        assert!(policy.conditions.iter().any(|c| 
            matches!(c, PolicyCondition::OperationRestriction { allowed_operations } 
                if allowed_operations.iter().any(|op| matches!(op, Operation::Transfer { .. })))));
    }
}
