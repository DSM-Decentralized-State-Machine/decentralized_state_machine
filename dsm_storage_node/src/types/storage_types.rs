// Storage type definitions for DSM Storage Node
//
// This module defines types specific to the storage functionality.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Storage response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageResponse {
    /// Blinded ID
    pub blinded_id: String,

    /// Timestamp of the operation
    pub timestamp: u64,

    /// Status of the operation
    pub status: String,

    /// Optional message
    pub message: Option<String>,
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total number of entries
    pub total_entries: usize,

    /// Total storage size in bytes
    pub total_bytes: usize,

    /// Total number of expired entries
    pub total_expired: usize,

    /// Timestamp of oldest entry (if any)
    pub oldest_entry: Option<u64>,

    /// Timestamp of newest entry (if any)
    pub newest_entry: Option<u64>,
}

/// Data submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSubmissionRequest {
    /// Blinded ID
    pub blinded_id: String,

    /// Payload to store
    pub payload: Vec<u8>,

    /// Optional TTL in seconds (0 = no expiration)
    pub ttl: Option<u64>,

    /// Optional region
    pub region: Option<String>,

    /// Optional priority
    pub priority: Option<i32>,

    /// Optional proof hash
    pub proof_hash: Option<[u8; 32]>,

    /// Optional metadata
    pub metadata: Option<HashMap<String, String>>,
}

/// Data retrieval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRetrievalRequest {
    /// Blinded ID
    pub blinded_id: String,

    /// Optional requester ID
    pub requester_id: Option<String>,

    /// Optional signature for authenticated retrieval
    pub signature: Option<String>,
}

/// Storage assignment strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageAssignmentStrategy {
    /// Deterministic hashing for node assignment
    DeterministicHashing,

    /// Prioritize by region
    RegionPriority,

    /// Prioritize by reliability
    ReliabilityFirst,

    /// Pseudorandom selection
    PseudorandomSelection,
}

/// Replication strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationStrategy {
    /// Fixed number of replicas
    FixedReplicas(u8),

    /// Adaptive replicas based on network conditions
    AdaptiveReplicas,

    /// Geographic spread across regions
    GeographicSpread(u8),

    /// Hybrid approach combining multiple strategies
    Hybrid,
}

/// Distributed storage query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedStorageQuery {
    /// Target region
    pub region: Option<String>,

    /// Query blinded ID
    pub blinded_id: String,

    /// Query timestamp
    pub timestamp: u64,

    /// Query signature
    pub signature: Option<String>,

    /// Time-to-live for query
    pub ttl: u64,
}

/// Distributed storage response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedStorageResponse {
    /// Response ID
    pub response_id: String,

    /// Responding node ID
    pub node_id: String,

    /// Query blinded ID
    pub blinded_id: String,

    /// Data found status
    pub found: bool,

    /// Data payload (if found)
    pub payload: Option<Vec<u8>>,

    /// Timestamp of the response
    pub timestamp: u64,

    /// Signature of the response
    pub signature: Option<String>,
}

/// Storage pruning stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningStats {
    /// Number of entries pruned
    pub entries_pruned: usize,

    /// Bytes freed
    pub bytes_freed: usize,

    /// Duration of pruning in milliseconds
    pub duration_ms: u64,

    /// Timestamp of pruning
    pub timestamp: u64,
}

/// Storage event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageEventType {
    /// Data stored
    DataStored,

    /// Data retrieved
    DataRetrieved,

    /// Data deleted
    DataDeleted,

    /// Data expired
    DataExpired,

    /// Data pruned
    DataPruned,

    /// Data replicated
    DataReplicated,

    /// Data verified
    DataVerified,

    /// Data conflicted
    DataConflicted,
}

/// Storage event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEvent {
    /// Event ID
    pub event_id: String,

    /// Event type
    pub event_type: StorageEventType,

    /// Blinded ID
    pub blinded_id: String,

    /// Node ID
    pub node_id: String,

    /// Timestamp
    pub timestamp: u64,

    /// Additional data
    pub additional_data: Option<HashMap<String, String>>,
}
