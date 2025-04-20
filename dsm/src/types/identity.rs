use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IdentityClaim represents a request to validate or establish an identity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityClaim {
    /// Unique identifier for this identity
    pub identity_id: String,
    
    /// Timestamp when this claim was created
    pub timestamp: u64,
    
    /// Expiration timestamp for this claim
    pub expiration: u64,
    
    /// Public key associated with this claim
    pub public_key: Vec<u8>,
    
    /// Cryptographic signature over the claim data
    pub signature: Vec<u8>,
    
    /// Hash of the claim data
    pub claim_hash: Vec<u8>,
    
    /// Commitment to the identity anchor
    pub anchor_commitment: Vec<u8>,
    
    /// Device information
    pub device_info: crate::types::state_types::DeviceInfo,
    
    /// Additional metadata
    pub meta_data: HashMap<String, Vec<u8>>,
}

/// IdentityAnchor represents a verified cryptographic identity root
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityAnchor {
    /// Unique identifier for this identity
    pub identity_id: String,
    
    /// Public key associated with this identity
    pub public_key: Vec<u8>,
    
    /// Timestamp when this identity was created
    pub creation_time: u64,
    
    /// Optional timestamp when this identity was revoked
    pub revocation_time: Option<u64>,
    
    /// Additional metadata
    pub meta_data: HashMap<String, Vec<u8>>,
}
