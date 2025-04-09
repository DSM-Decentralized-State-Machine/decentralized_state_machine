// Types module for DSM Storage Node
//
// This module defines common types used throughout the DSM Storage Node.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod storage_types;

/// Blinded state entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedStateEntry {
    /// Blinded ID (deterministic hash of the entry content)
    pub blinded_id: String,

    /// Encrypted payload
    pub encrypted_payload: Vec<u8>,

    /// Timestamp (seconds since epoch)
    pub timestamp: u64,

    /// Time-to-live in seconds (0 = no expiration)
    pub ttl: u64,

    /// Geographic region
    pub region: String,

    /// Priority (higher = more important)
    pub priority: i32,

    /// Proof hash (cryptographic hash for verification)
    pub proof_hash: [u8; 32],

    /// Metadata (key-value pairs)
    pub metadata: HashMap<String, String>,
}

/// Storage node information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageNode {
    /// Node ID
    pub id: String,

    /// Node name
    pub name: String,

    /// Node region
    pub region: String,

    /// Node public key
    pub public_key: String,

    /// Node endpoint
    pub endpoint: String,
}

/// Distribution node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionNode {
    /// Node ID
    pub id: String,

    /// Node endpoint
    pub endpoint: String,

    /// Node public key
    pub public_key: String,

    /// Node region
    pub region: String,

    /// Connection status
    pub status: NodeStatus,

    /// Last seen timestamp
    pub last_seen: u64,

    /// Node capabilities
    pub capabilities: Vec<NodeCapability>,

    /// Stake amount
    pub stake: Option<u64>,
}

/// Node status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is online and responding
    Online,

    /// Node is offline or not responding
    Offline,

    /// Node status is unknown
    Unknown,

    /// Node is pending verification
    Pending,

    /// Node is suspended
    Suspended,
}

/// Node capability
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeCapability {
    /// Storage capability
    Storage,

    /// Distribution capability
    Distribution,

    /// Verification capability
    Verification,

    /// Staking capability
    Staking,

    /// Genesis capability
    Genesis,

    /// Checkpoint capability
    Checkpoint,

    /// Custom capability
    Custom(String),
}

/// Entry selector (for querying and filtering)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySelector {
    /// Blinded IDs to select
    pub blinded_ids: Option<Vec<String>>,

    /// Region to select from
    pub region: Option<String>,

    /// Minimum priority
    pub min_priority: Option<i32>,

    /// Maximum priority
    pub max_priority: Option<i32>,

    /// Minimum timestamp
    pub min_timestamp: Option<u64>,

    /// Maximum timestamp
    pub max_timestamp: Option<u64>,

    /// Include expired entries
    pub include_expired: bool,

    /// Metadata filters (key-value pairs that must match)
    pub metadata_filters: Option<HashMap<String, String>>,

    /// Limit results
    pub limit: Option<usize>,

    /// Offset results
    pub offset: Option<usize>,
}
