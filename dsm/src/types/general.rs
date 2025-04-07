use crate::crypto::sphincs::sphincs_verify; // Update import path
use crate::types::error::DsmError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a public/private key pair
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Public key
    pub public_key: Vec<u8>,

    /// Private key - should be stored securely or in a TEE
    pub private_key: Vec<u8>,
}
impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field(
                "public_key",
                &format!("{:?}...", &self.public_key.get(0..4).unwrap_or(&[])),
            )
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Internal node identifier for efficient tree operations

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    /// Level in the tree (0 = leaves)
    pub(crate) level: u32,

    /// Index within the level
    pub(crate) index: u64,
}
impl NodeId {
    /// Create a new node ID
    pub fn new(level: u32, index: u64) -> Self {
        NodeId { level, index }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericOps {
    operation_type: String,
    data: Vec<u8>,
}

impl GenericOps {
    pub fn new(operation_type: &str, data: Vec<u8>) -> Self {
        Self {
            operation_type: operation_type.to_string(),
            data,
        }
    }

    pub fn get_operation_type(&self) -> &str {
        &self.operation_type
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}
impl fmt::Display for GenericOps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Operation Type: {}, Data: {:?}",
            self.operation_type, self.data
        )
    }
}
impl Default for GenericOps {
    fn default() -> Self {
        Self {
            operation_type: "default".to_string(),
            data: vec![],
        }
    }
}

/// ID Token types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdToken {
    pub token_id: String,
    pub creation_time: u64,
    pub expiration_time: u64,
    pub issuer: String,
    pub subject: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Token operations trait
pub trait TokenOps {
    fn is_valid(&self) -> bool;
    fn has_expired(&self) -> bool;
    fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError>;
}

impl TokenOps for IdToken {
    fn is_valid(&self) -> bool {
        !self.has_expired() && !self.token_id.is_empty() && !self.issuer.is_empty()
    }

    fn has_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expiration_time
    }

    fn verify_signature(&self, public_key: &[u8]) -> Result<bool, DsmError> {
        // Construct message to verify
        let mut msg = Vec::new();
        msg.extend_from_slice(self.token_id.as_bytes());
        msg.extend_from_slice(&self.creation_time.to_be_bytes());
        msg.extend_from_slice(&self.expiration_time.to_be_bytes());
        msg.extend_from_slice(self.issuer.as_bytes());
        msg.extend_from_slice(self.subject.as_bytes());
        msg.extend_from_slice(&self.public_key);

        // Verify signature
        sphincs_verify(public_key, &msg, &self.signature)
    }
}

/// Directory entry for storing Genesis states and invalidation markers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// Unique identifier for the entry
    pub id: String,

    /// Genesis state hash
    pub genesis_hash: Vec<u8>,

    /// Timestamp of creation
    pub created_at: u64,

    /// Timestamp of last update
    pub updated_at: u64,

    /// Invalidation markers, if any
    pub invalidation_markers: Vec<Vec<u8>>,
}

/// A commitment to a future state update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    /// Hash of the commitment
    pub hash: Vec<u8>,

    /// Signature from the creator
    pub signature: Vec<u8>,

    /// Co-signature from counterparty, if available
    pub co_signature: Option<Vec<u8>>,

    /// Timestamp of creation
    pub timestamp: u64,

    /// Expiry timestamp, if any
    pub expires_at: Option<u64>,
}

/// Verification result with details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether verification was successful
    pub is_valid: bool,

    /// Reason for failure, if any
    pub reason: Option<String>,

    /// Additional details about verification
    pub details: Option<String>,

    /// Path of states verified (for hash-chain verification)
    pub verification_path: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Copy)]
pub enum SecurityLevel {
    Standard128,
    Medium192,
    High256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn test_keypair_debug_redacts_private_key() {
        let kp = KeyPair {
            public_key: vec![1, 2, 3, 4, 5],
            private_key: vec![6, 7, 8, 9, 10],
        };

        let mut debug_output = String::new();
        write!(debug_output, "{:?}", kp).expect("Debug formatting failed");

        assert!(debug_output.contains("[1, 2, 3, 4]..."));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("6, 7, 8, 9, 10"));
    }

    #[test]
    fn test_directory_entry() {
        let id = "entry123".to_string();
        let genesis_hash = vec![1, 2, 3];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = DirectoryEntry {
            id: id.clone(),
            genesis_hash: genesis_hash.clone(),
            created_at: now,
            updated_at: now,
            invalidation_markers: Vec::new(),
        };

        assert_eq!(entry.id, id);
        assert_eq!(entry.genesis_hash, genesis_hash);
        assert_eq!(entry.created_at, now);
        assert_eq!(entry.updated_at, now);
        assert!(entry.invalidation_markers.is_empty());
    }

    #[test]
    fn test_commitment_serialization() {
        let commitment = Commitment {
            hash: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            co_signature: Some(vec![7, 8, 9]),
            timestamp: 12345,
            expires_at: Some(67890),
        };

        let serialized = serde_json::to_string(&commitment).expect("Serialization failed");
        let deserialized: Commitment =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(deserialized.hash, commitment.hash);
        assert_eq!(deserialized.signature, commitment.signature);
        assert_eq!(deserialized.co_signature, commitment.co_signature);
        assert_eq!(deserialized.timestamp, commitment.timestamp);
        assert_eq!(deserialized.expires_at, commitment.expires_at);
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            is_valid: true,
            reason: None,
            details: Some("Test verification passed".to_string()),
            verification_path: vec![0, 1, 3, 7],
        };

        assert!(result.is_valid);
        assert!(result.reason.is_none());
        assert_eq!(result.details.unwrap(), "Test verification passed");
        assert_eq!(result.verification_path, vec![0, 1, 3, 7]);
    }
}
