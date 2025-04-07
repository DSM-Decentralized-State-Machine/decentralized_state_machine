// Added AllowedOperation enum
//! Token Policy Types
//!
//! This module defines the core types used for Content-Addressed Token Policy Anchors (CTPA).
//! The CTPA system ensures that every token in DSM is bound to an immutable policy
//! that defines its constraints and behaviors.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::blake3;
use crate::types::error::DsmError;
use crate::types::operations::Operation;
use crate::types::operations::VerificationType;
use crate::vault::VaultCondition;

/// Token Policy Anchor
///
/// A PolicyAnchor is a cryptographic hash that uniquely identifies a token policy.
/// This is the foundation of the Content-Addressed Token Policy Anchor (CTPA) system.
/// The anchor is a Blake3 hash of the serialized policy content, ensuring that
/// policy files cannot be altered without detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PolicyAnchor(pub [u8; 32]);

impl PolicyAnchor {
    /// Create a new policy anchor from a policy file
    pub fn from_policy(policy: &PolicyFile) -> Result<Self, DsmError> {
        let serialized = serde_json::to_vec(policy).map_err(|e| {
            DsmError::serialization(format!("Failed to serialize policy file: {}", e), Some(e))
        })?;
        
        let hash = blake3::hash(&serialized);
        Ok(PolicyAnchor(*hash.as_bytes()))
    }
    
    /// Convert to a hex string for identification
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Create from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, DsmError> {
        let bytes = hex::decode(hex_str).map_err(|e| {
            DsmError::validation(format!("Invalid policy anchor hex: {}", e), Some(e))
        })?;
        
        if bytes.len() != 32 {
            return Err(DsmError::validation(
                format!("Invalid policy anchor length: {}", bytes.len()),
                None::<std::convert::Infallible>,
            ));
        }
        
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&bytes);
        Ok(PolicyAnchor(anchor))
    }
}

/// Allowed operation in policy definitions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AllowedOperation {
    /// Allow all operations
    All,
    /// Allow a specific operation
    Specific(Box<Operation>),
}

/// Policy condition types that can constrain token behavior
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyCondition {
    /// Time-based restrictions (Unix timestamp)
    TimeLock {
        /// The timestamp after which the token can be transferred
        unlock_time: u64,
    },
    
    /// Identity-based restrictions
    IdentityConstraint {
        /// List of identity IDs allowed to interact with the token
        allowed_identities: Vec<String>,
        
        /// Whether to allow derived identities
        allow_derived: bool,
    },
    
    /// Vault-enforced conditions
    VaultEnforcement {
        /// The vault condition that must be satisfied
        condition: VaultCondition,
    },
    
    /// Operational restrictions
    OperationRestriction {
        /// Allowed operation types
        allowed_operations: Vec<Operation>,
    },
    
    /// Geographic restrictions using region codes
    GeographicRestriction {
        /// List of allowed region codes
        allowed_regions: Vec<String>,
    },
    
    /// Custom implementation-specific constraints
    Custom {
        /// Type identifier for the custom constraint
        constraint_type: String,
        
        /// Parameters for the constraint
        parameters: HashMap<String, String>,
    },
}

/// Role-based access control for token policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRole {
    /// Role identifier
    pub id: String,
    
    /// Role name
    pub name: String,
    
    /// Allowed operations for this role
    pub permissions: Vec<Operation>,
}

/// Token Policy File Structure
///
/// Represents the complete policy file that is hashed to create the CTPA.
/// This structure contains all the rules and constraints that govern a token's behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    /// Policy name for human readability
    pub name: String,
    
    /// Policy version
    pub version: String,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Policy author's identity
    pub author: String,
    
    /// Policy description
    pub description: Option<String>,
    
    /// Token policy conditions
    pub conditions: Vec<PolicyCondition>,
    
    /// Role-based access control
    pub roles: Vec<PolicyRole>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl PolicyFile {
    /// Create a new policy file
    pub fn new(name: &str, version: &str, author: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            author: author.to_string(),
            description: None,
            conditions: Vec::new(),
            roles: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add a condition to the policy
    pub fn add_condition(&mut self, condition: PolicyCondition) -> &mut Self {
        self.conditions.push(condition);
        self
    }
    
    /// Add a role to the policy
    pub fn add_role(&mut self, role: PolicyRole) -> &mut Self {
        self.roles.push(role);
        self
    }
    
    /// Add metadata to the policy
    pub fn add_metadata(&mut self, key: &str, value: &str) -> &mut Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
    
    /// Add a description to the policy
    pub fn with_description(&mut self, description: &str) -> &mut Self {
        self.description = Some(description.to_string());
        self
    }
    
    /// Generate a policy anchor (CTPA) for this policy file
    pub fn generate_anchor(&self) -> Result<PolicyAnchor, DsmError> {
        PolicyAnchor::from_policy(self)
    }
}

/// In-memory representation of an active token policy
///
/// TokenPolicy combines the policy file with its anchor for efficient
/// policy lookup and enforcement during runtime.
#[derive(Debug, Clone)]
pub struct TokenPolicy {
    /// The policy file content
    pub file: PolicyFile,
    
    /// The content-addressed policy anchor (CTPA)
    pub anchor: PolicyAnchor,
    
    /// Whether the policy has been verified
    pub verified: bool,
    
    /// Last verification time
    pub last_verified: u64,
}

impl TokenPolicy {
    /// Create a new token policy from a policy file
    pub fn new(file: PolicyFile) -> Result<Self, DsmError> {
        let anchor = file.generate_anchor()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Ok(Self {
            file,
            anchor,
            verified: false,
            last_verified: now,
        })
    }
    
    /// Mark the policy as verified
    pub fn mark_verified(&mut self) {
        self.verified = true;
        self.last_verified = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// Check if a condition is satisfied
    pub fn is_condition_satisfied(&self, condition: &PolicyCondition) -> bool {
        match condition {
            PolicyCondition::TimeLock { unlock_time } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now >= *unlock_time
            }
            // For other conditions, we need context from outside this method
            // Simply checking whether specific condition types exist in the policy
            // should be handled by the verification framework
            _ => true,
        }
    }
    
    /// Check if all time-based conditions are satisfied
    pub fn are_time_conditions_satisfied(&self) -> bool {
        self.file.conditions.iter().all(|condition| {
            match condition {
                PolicyCondition::TimeLock { .. } => self.is_condition_satisfied(condition),
                _ => true,
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerification {
    pub verification_type: VerificationType,
    pub parameters: HashMap<String, Vec<u8>>,
    // ...existing code...
}
