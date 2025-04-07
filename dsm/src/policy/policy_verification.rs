//! Token Policy Verification
//!
//! This module provides verification mechanisms for token policies, ensuring that
//! token operations adhere to the constraints defined in the policy.
//!
//! The implementation includes performance optimizations through selective verification
//! and early-exit patterns for both single-condition and composite-condition policies.

// Fix: Correct the Identity import path
use crate::api::identity_api::Identity;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::state_types::State;
use crate::vault::{DeterministicLimboVault, VaultStatus};
use crate::policy::policy_types::{PolicyAnchor, PolicyCondition, TokenPolicy};

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of policy verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyVerificationResult {
    /// Policy verification passed
    Valid,
    
    /// Policy verification failed
    Invalid {
        /// Error message
        message: String,
        /// Failed condition
        condition: Option<PolicyCondition>,
    },
    
    /// Policy could not be verified
    Unverifiable {
        /// Error message
        message: String,
    },
}

/// Verify if an operation complies with a token policy
pub fn verify_policy(
    policy: &TokenPolicy,
    operation: &Operation,
    state: Option<&State>,
    identity: Option<&Identity>,
    vault: Option<&DeterministicLimboVault>,
) -> PolicyVerificationResult {
    // Check if policy is verified
    if !policy.verified {
        return PolicyVerificationResult::Unverifiable {
            message: "Policy has not been verified".to_string(),
        };
    }

    // Performance optimization: Sort conditions by computational cost
    // Time locks are cheapest, identity constraints are more expensive, etc.
    let mut sorted_conditions = policy.file.conditions.clone();
    sorted_conditions.sort_by(|a, b| {
        let cost_a = condition_verification_cost(a);
        let cost_b = condition_verification_cost(b);
        cost_a.cmp(&cost_b)
    });

    // Verify each condition type with early exit on first failure
    for condition in &sorted_conditions {
        let result = verify_single_condition(condition, operation, state, identity, vault);
        match result {
            PolicyVerificationResult::Valid => {},  // Continue to next condition
            _ => return result,  // Exit early on failure or unverifiable condition
        }
    }
    
    // If we pass all conditions, validation is successful
    PolicyVerificationResult::Valid
}

/// Estimate the computational cost of verifying a condition
/// Returns a cost value (lower is cheaper)
fn condition_verification_cost(condition: &PolicyCondition) -> u8 {
    match condition {
        PolicyCondition::TimeLock { .. } => 1,  // Very cheap - just timestamp comparison
        PolicyCondition::OperationRestriction { .. } => 2,  // Simple enum matching
        PolicyCondition::GeographicRestriction { .. } => 3,  // String comparison
        PolicyCondition::IdentityConstraint { .. } => 4,  // More expensive identity checks
        PolicyCondition::VaultEnforcement { .. } => 5,  // Vault status verification
        PolicyCondition::Custom { .. } => 6,  // Most expensive - custom logic
    }
}

/// Verify a single policy condition
fn verify_single_condition(
    condition: &PolicyCondition,
    operation: &Operation,
    state: Option<&State>,
    identity: Option<&Identity>,
    vault: Option<&DeterministicLimboVault>,
) -> PolicyVerificationResult {
        match condition {
            PolicyCondition::TimeLock { unlock_time } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                    
                if now < *unlock_time {
                    return PolicyVerificationResult::Invalid {
                        message: format!("Token is time-locked until {}", unlock_time),
                        condition: Some(condition.clone()),
                    };
                }
                PolicyVerificationResult::Valid
            }
            
            PolicyCondition::IdentityConstraint { allowed_identities, allow_derived: _ } => {
                if let Some(identity) = identity {
                    let identity_id = identity.id();
                    
                    // Check if identity is directly allowed
                    let direct_match = allowed_identities.contains(&identity_id.to_string());
                    
                    // For now just check direct matches since derive checking isn't implemented
                    if !direct_match {
                        return PolicyVerificationResult::Invalid {
                            message: "Identity not authorized by policy".to_string(),
                            condition: Some(condition.clone()),
                        };
                    }
                    PolicyVerificationResult::Valid
                } else {
                    PolicyVerificationResult::Unverifiable {
                        message: "Identity context required but not provided".to_string(),
                    }
                }
            }
            
            PolicyCondition::VaultEnforcement { condition: vault_condition } => {
                if let Some(vault) = vault {
                    // Check if vault is active
                    if vault.status() != &VaultStatus::Active {
                        return PolicyVerificationResult::Invalid {
                            message: "Vault is not in active state".to_string(),
                            condition: Some(condition.clone()),
                        };
                    }
                    
                    // Validate vault condition
                    if vault.condition() != vault_condition {
                        return PolicyVerificationResult::Invalid {
                            message: "Vault condition does not match policy requirement".to_string(),
                            condition: Some(condition.clone()),
                        };
                    }
                    PolicyVerificationResult::Valid // Fix: Add this return value
                } else {
                    PolicyVerificationResult::Unverifiable {
                        message: "Vault context required but not provided".to_string(),
                    }
                }
            }
            
            PolicyCondition::OperationRestriction { allowed_operations } => {
                // First check if operation is allowed for any arbitrary operation type
                let is_operation_allowed = allowed_operations.iter().any(|op| 
                    match op {
                        Operation::Generic { operation_type, .. } => 
                            operation_type.to_lowercase() == "all",
                        _ => std::mem::discriminant(op) == std::mem::discriminant(operation)
                    }
                );
                
                if !is_operation_allowed {
                    return PolicyVerificationResult::Invalid {
                        message: "Operation type not allowed by policy".to_string(),
                        condition: Some(condition.clone()),
                    };
                }

                // If operation is allowed, determine its type string
                let operation_type = match operation {
                    Operation::Transfer { .. } => "Transfer",
                    Operation::Mint { .. } => "Mint", 
                    Operation::Burn { .. } => "Burn",
                    Operation::LockToken { .. } => "Lock",
                    Operation::UnlockToken { .. } => "Unlock",
                    Operation::Generic { operation_type, .. } => operation_type,
                    _ => "Unknown"
                };
                
                // Now check if the specific operation type is allowed
                let is_type_allowed = allowed_operations.iter().any(|op| {
                    match op {
                        Operation::Generic { operation_type: allowed_type, .. } => {
                            allowed_type.to_lowercase() == operation_type.to_lowercase() || 
                            allowed_type.to_lowercase() == "all"
                        },
                        _ => std::mem::discriminant(op) == std::mem::discriminant(operation)
                    }
                });
                
                if !is_type_allowed {
                    return PolicyVerificationResult::Invalid {
                        message: format!("Operation {} not allowed by policy", operation_type),
                        condition: Some(condition.clone()),
                    };
                }
                PolicyVerificationResult::Valid
            }
            
            PolicyCondition::GeographicRestriction { allowed_regions } => {
                if let Some(state) = state {
                    if let Some(region_bytes) = state.get_parameter("region") {
                        if let Ok(region_str) = std::str::from_utf8(region_bytes) {
                            if !allowed_regions.contains(&region_str.to_string()) {
                                return PolicyVerificationResult::Invalid {
                                    message: format!("Region {} not allowed by policy", region_str),
                                    condition: Some(condition.clone()),
                                };
                            }
                            PolicyVerificationResult::Valid
                        } else {
                            PolicyVerificationResult::Unverifiable {
                                message: "Region data is not valid UTF-8".to_string(),
                            }
                        }
                    } else {
                        PolicyVerificationResult::Unverifiable {
                            message: "Region information required but not available".to_string(),
                        }
                    }
                } else {
                    PolicyVerificationResult::Unverifiable {
                        message: "State context required but not provided".to_string(),
                    }
                }
            }
            
            PolicyCondition::Custom { constraint_type, parameters: _ } => {
                // Custom conditions require specific handlers
                // For now, treat as unverifiable
                PolicyVerificationResult::Unverifiable {
                    message: format!("Custom condition {} requires specific handler", constraint_type),
                }
            }
        }
    }
    
  

/// Verify if a policy anchor matches a policy file
pub fn verify_policy_anchor(policy_file: &[u8], anchor: &PolicyAnchor) -> Result<bool, DsmError> {
    let calculated_hash = blake3::hash(policy_file);
    let matches = calculated_hash.as_bytes() == &anchor.0;
    Ok(matches)
}
