// Multi-Party Computation API for DSM Storage Node
//
// This module handles the entropy generation endpoints for MPC-based
// genesis state creation, allowing storage nodes to participate as
// entropy contributors.

use crate::error::{Result, StorageNodeError};
use crate::storage::StorageEngine;
use crate::types::BlindedStateEntry;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use tracing::info;
use rand::{Rng, rngs::OsRng};
use blake3;
use std::time::{SystemTime, UNIX_EPOCH};

// Request body for entropy generation
#[derive(Debug, Serialize, Deserialize)]
pub struct EntropyRequest {
    /// ID of the MPC process
    pub process_id: String,
    /// Node ID requesting participation
    pub node_id: String,
    /// Request timestamp
    pub request_timestamp: u64,
}

// Response for entropy endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct EntropyResponse {
    /// Process ID this entropy is for
    pub process_id: String,
    /// Node ID that generated this entropy
    pub node_id: String,
    /// Status of the entropy generation
    pub status: String,
    /// Timestamp of generation
    pub timestamp: u64,
}

/// Entropy generation handler
pub async fn handle_entropy_request(
    process_id: String,
    request: EntropyRequest,
    storage_engine: Arc<dyn StorageEngine + Send + Sync>,
) -> Result<EntropyResponse> {
    // Validate process_id matches
    if process_id != request.process_id {
        return Err(StorageNodeError::InvalidInput(format!(
            "Process ID mismatch: {} vs {}",
            process_id, request.process_id
        )));
    }

    // Generate high-quality entropy (256 bits)
    let mut entropy = [0u8; 32];
    OsRng.fill(&mut entropy);

    // Add additional sources of entropy
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    
    // Create a Blake3 hasher and mix in all entropy sources
    let mut hasher = blake3::Hasher::new();
    hasher.update(&entropy);
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(process_id.as_bytes());
    
    // Get the final entropy value
    let final_entropy = hasher.finalize().as_bytes().to_vec();

    // Prepare data for storage
    let mpc_key = format!("mpc-entropy:{}:{}", process_id, request.node_id);
    let value = serde_json::json!({
        "process_id": process_id,
        "node_id": request.node_id,
        "entropy": final_entropy,
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });

    // Store the entropy contribution as a blinded state entry
    let serialized = serde_json::to_vec(&value).map_err(|e| {
        StorageNodeError::Serialization(format!("Failed to serialize entropy data: {}", e))
    })?;
    
    let entry = BlindedStateEntry {
        blinded_id: mpc_key.clone(),
        encrypted_payload: serialized,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        ttl: 0, // No expiration
        region: "global".to_string(),
        priority: 0,
        proof_hash: [0u8; 32], // No proof required for internal data
        metadata: HashMap::new(),
    };
    storage_engine.store(entry.clone()).await?;
    let process_key = format!("mpc-process:{}", process_id);
    if let Some(process_entry) = storage_engine.retrieve(&process_key).await? {
        // Parse the existing MPC process data
        let mut process_json: serde_json::Value = 
            serde_json::from_slice(&process_entry.encrypted_payload).map_err(|e| {
                StorageNodeError::Serialization(format!("Failed to deserialize MPC process: {}", e))
            })?;
        
        // Add the entropy contribution if there's a participants structure
        if let Some(participants) = process_json.get_mut("participants") {
            if let Some(participant) = participants.get_mut(request.node_id.as_str()) {
                // Update the participant's entropy contribution
                participant["entropy_contribution"] = serde_json::to_value(&final_entropy)
                    .map_err(|e| {
                        StorageNodeError::Serialization(format!("Failed to serialize entropy: {}", e))
                    })?;
                
                // Store the updated process
                let updated_process = serde_json::to_vec(&process_json).map_err(|e| {
                    StorageNodeError::Serialization(format!("Failed to serialize updated MPC process: {}", e))
                })?;
                
                let updated_entry = BlindedStateEntry {
                    blinded_id: process_key.clone(),
                    encrypted_payload: updated_process,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    ttl: process_entry.ttl,
                    region: process_entry.region,
                    priority: process_entry.priority,
                    proof_hash: process_entry.proof_hash,
                    metadata: HashMap::new(),
                };
                storage_engine.store(updated_entry).await?;
            }
        }
    }
    let response = EntropyResponse {
        process_id,
        node_id: request.node_id,
        status: "completed".to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    Ok(response)
}

/// Get the entropy contribution for a process and node
pub async fn get_entropy_contribution(
    process_id: String,
    node_id: String,
    storage_engine: Arc<dyn StorageEngine + Send + Sync>,
) -> Result<Option<Vec<u8>>> {
    let mpc_key = format!("mpc-entropy:{}:{}", process_id, node_id);
    
    if let Some(entry) = storage_engine.retrieve(&mpc_key).await? {
        let value: serde_json::Value = serde_json::from_slice(&entry.encrypted_payload).map_err(|e| {
            StorageNodeError::Serialization(format!("Failed to deserialize entropy data: {}", e))
        })?;
        
        if let Some(entropy_array) = value["entropy"].as_array() {
            let entropy = entropy_array
                .iter()
                .map(|v| v.as_u64().unwrap_or(0) as u8)
                .collect::<Vec<u8>>();
            
            return Ok(Some(entropy));
        }
    }
    
    Ok(None)
}
