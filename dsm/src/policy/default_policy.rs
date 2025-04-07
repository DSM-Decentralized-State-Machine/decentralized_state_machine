//! Default Token Policy Generator
//!
//! This module provides a standardized default policy for tokens when no custom policy
//! is specified at creation time. Every token in the DSM system requires a Content-Addressed
//! Token Policy Anchor (CTPA), and this module ensures that tokens always have at least a
//! baseline policy.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

use crate::policy::policy_types::{PolicyCondition, PolicyFile, PolicyRole};
use crate::types::error::DsmError;
use crate::types::operations::{Operation, TransactionMode, VerificationType};
use crate::types::token_types::Balance;

pub struct PolicyParameters {
    pub mode: TransactionMode,
    pub verification: VerificationType,
    pub name: String,
    pub version: String,
    pub author: String,
}

/// Generate a default token policy file
///
/// Creates a reasonable default policy that allows basic token operations with
/// minimal restrictions. This is used when a token is created without a custom policy.
pub fn generate_default_policy(
    token_id: &str,
    token_name: &str,
    creator_id: &str,
) -> Result<PolicyFile, DsmError> {
    // Create a policy with a 1-year time lock by default
    let now = Utc::now();
    let one_year_later = now + Duration::days(365);
    
    // Convert to unix timestamp
    let now_ts = now.timestamp() as u64;

    // Create basic policy file
    let mut policy = PolicyFile::new(
        &format!("Default Policy for {}", token_name),
        "1.0",
        creator_id,
    );
    
    // Add description
    policy.description = Some(format!(
        "Default policy for token {} ({}). Created automatically at token genesis.",
        token_id, token_name
    ));
    
    // Add basic time lock condition
    policy.add_condition(PolicyCondition::TimeLock {
        unlock_time: now_ts, // Immediately available (not locked)
    });
    
    // Allow creator to control the token
    policy.add_condition(PolicyCondition::IdentityConstraint {
        allowed_identities: vec![creator_id.to_string()],
        allow_derived: true,  // Allow identities derived from the creator
    });
    
    // Add basic operation restrictions (allow all common operations)
    policy.add_condition(PolicyCondition::OperationRestriction {
        allowed_operations: vec![
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
                to: String::new()
            }
        ],
    });
    
    // Add metadata
    policy.add_metadata("token_id", token_id)
        .add_metadata("created_at", &now.to_rfc3339())
        .add_metadata("valid_until", &one_year_later.to_rfc3339())
        .add_metadata("is_default_policy", "true");
    
    // Add roles
    policy.add_role(PolicyRole {
        id: "owner".to_string(),
        name: "Token Owner".to_string(),
        permissions: vec![Operation::Transfer {
            to_address: String::new(),
            mode: TransactionMode::Bilateral,
            nonce: vec![],
            verification: VerificationType::Standard,
            pre_commit: None,
            amount: Balance::new(0),
            token_id: String::new(),
            message: String::new(),
            recipient: String::new(),
            to: String::new()
        }],
    });
    
    policy.add_role(PolicyRole {
        id: "user".to_string(),
        name: "Token User".to_string(),
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
                to: String::new()
            },
            Operation::LockToken {
                token_id: String::new(),
                amount: 0i64,
                purpose: "default".to_string(),
                mode: TransactionMode::Bilateral,
            },
            Operation::UnlockToken {
                token_id: String::new(),
                amount: 0i64,
                purpose: "default".to_string(),
                mode: TransactionMode::Bilateral,
            }
        ],
    });
    
    Ok(policy)
}

/// Generate a specialized token policy file
///
/// Creates a more restrictive policy for specialized token use cases,
/// such as time-locked tokens, identity-bound tokens, etc.
pub fn generate_specialized_policy(
    token_id: &str,
    token_name: &str,
    creator_id: &str,
    policy_type: &str,
    params: &HashMap<String, String>,
) -> Result<PolicyFile, DsmError> {
    // Start with default policy
    let mut policy = generate_default_policy(token_id, token_name, creator_id)?;
    
    // Override policy name and description
    policy.name = format!("{} Policy for {}", policy_type, token_name);
    policy.description = Some(format!(
        "Specialized {} policy for token {} ({}). Created with custom parameters.",
        policy_type, token_id, token_name
    ));
    
    // Add specialized conditions based on policy type
    match policy_type {
        "TimeLocked" => {
            // Parse unlock time parameter
            let unlock_time = if let Some(time_str) = params.get("unlock_time") {
                // Parse ISO date format
                match DateTime::parse_from_rfc3339(time_str) {
                    Ok(dt) => dt.timestamp() as u64,
                    Err(_) => {
                        // Try parsing as unix timestamp
                        time_str.parse::<u64>().map_err(|_| {
                            DsmError::validation(
                                format!("Invalid unlock_time format: {}", time_str),
                                None::<std::convert::Infallible>,
                            )
                        })?
                    }
                }
            } else {
                // Default to 30 days from now if not specified
                (Utc::now() + Duration::days(30)).timestamp() as u64
            };
            
            // Replace default time lock with specified one
            policy.conditions.retain(|c| !matches!(c, PolicyCondition::TimeLock { .. }));
            policy.add_condition(PolicyCondition::TimeLock { unlock_time });
            
            // Update metadata
            policy.add_metadata("policy_type", "time_locked")
                .add_metadata("unlock_time", &unlock_time.to_string());
        },
        "IdentityBound" => {
            // Get allowed identities
            let allowed_identities = if let Some(ids) = params.get("allowed_identities") {
                ids.split(',').map(|s| s.trim().to_string()).collect()
            } else {
                vec![creator_id.to_string()]
            };
            
            // Allow derived identities?
            let allow_derived = params.get("allow_derived")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false);
            
            // Replace default identity constraint
            policy.conditions.retain(|c| !matches!(c, PolicyCondition::IdentityConstraint { .. }));
            policy.add_condition(PolicyCondition::IdentityConstraint {
                allowed_identities,
                allow_derived,
            });
            
            // Update metadata
            policy.add_metadata("policy_type", "identity_bound")
                .add_metadata("allow_derived", &allow_derived.to_string());
        },
        "RestrictedOperations" => {
            // Get allowed operations
            let allowed_ops = if let Some(ops) = params.get("allowed_operations") {
                ops.split(',')
                    .map(|s| s.trim())
                    .filter_map(|op| match op {
                        "transfer" => Some(Operation::Transfer {
                            to_address: String::new(),
                            mode: TransactionMode::Bilateral,
                            nonce: vec![],
                            verification: VerificationType::Standard,
                            pre_commit: None,
                            amount: Balance::new(0),
                            token_id: String::new(),
                            message: String::new(),
                            recipient: String::new(),
                            to: String::new()
                        }),
                        "mint" => Some(Operation::Mint {
                            amount: Balance::new(0),
                            token_id: String::new(),
                            authorized_by: "default".to_string(),
                            proof_of_authorization: vec![],
                            message: String::new(),
                        }),
                        "burn" => Some(Operation::Burn {
                            amount: Balance::new(0),
                            token_id: String::new(),
                            proof_of_ownership: vec![],
                            message: String::new(),
                        }),
                        "lock" => Some(Operation::LockToken {
                            token_id: String::new(),
                            amount: 0i64,
                            purpose: "default".to_string(),
                            mode: TransactionMode::Bilateral,
                        }),
                        "unlock" => Some(Operation::UnlockToken {
                            token_id: String::new(),
                            amount: 0i64,
                            purpose: "default".to_string(),
                            mode: TransactionMode::Bilateral,
                        }),
                        _ => None,
                    })
                    .collect()
            } else {
                vec![Operation::Transfer {
                    to_address: String::new(),
                    mode: TransactionMode::Bilateral,
                    nonce: vec![],
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    amount: Balance::new(0),
                    token_id: String::new(),
                    message: String::new(),
                    recipient: String::new(),
                    to: String::new()
                }] // Default to transfer-only if not specified
            };
            
            // Replace default operation restrictions
            policy.conditions.retain(|c| !matches!(c, PolicyCondition::OperationRestriction { .. }));
            policy.add_condition(PolicyCondition::OperationRestriction {
                allowed_operations: allowed_ops,
            });
            
            // Update metadata
            policy.add_metadata("policy_type", "restricted_operations");
        },
        "GeographicRestriction" => {
            // Get allowed regions
            let allowed_regions = if let Some(regions) = params.get("allowed_regions") {
                regions.split(',').map(|s| s.trim().to_string()).collect()
            } else {
                return Err(DsmError::validation(
                    "Geographic restriction requires allowed_regions parameter",
                    None::<std::convert::Infallible>,
                ));
            };
            
            // Add geographic restriction
            policy.add_condition(PolicyCondition::GeographicRestriction {
                allowed_regions,
            });
            
            // Update metadata
            policy.add_metadata("policy_type", "geographic_restriction");
        },
        // Add more specialized policy types as needed
        _ => {
            return Err(DsmError::validation(
                format!("Unknown policy type: {}", policy_type),
                None::<std::convert::Infallible>,
            ));
        }
    }
    
    Ok(policy)
}

pub fn create_policy(params: PolicyParameters) -> Result<PolicyFile, DsmError> {   
    // Create basic policy file
    let mut policy = PolicyFile::new(&params.name, &params.version, &params.author);
    
    // Add verification mode condition
    policy.add_condition(PolicyCondition::OperationRestriction {
        allowed_operations: vec![
            Operation::Transfer {
                to_address: String::new(),
                mode: params.mode.clone(),
                nonce: vec![],
                verification: params.verification.clone(),
                pre_commit: None,
                amount: Balance::new(0),
                token_id: String::new(),
                message: String::new(),
                recipient: String::new(),
                to: String::new()
            }
        ],
    });

    Ok(policy)
}
