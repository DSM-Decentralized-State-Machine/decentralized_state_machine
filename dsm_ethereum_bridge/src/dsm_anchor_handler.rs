use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::log::{error, info};

use crate::ethereum_anchor::{DsmState, EthereumAnchor};
use crate::state_management::PersistentStateManager;

#[derive(Deserialize)]
pub struct AnchorSubmission {
    pub block_number: u64,
    pub tx_hash: String,
    pub event_root: String,
    pub inclusion_proof: String,
    pub event_hash: String,
    pub data: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct AnchorResponse {
    pub success: bool,
    pub message: String,
    pub state_id: Option<String>,
}

/// HTTP endpoint for receiving Ethereum anchors from an off-chain relayer.
/// This stores the anchored state in both local storage and distributed storage nodes.
#[post("/submit-anchor")]
pub async fn submit_anchor(
    anchor: web::Json<AnchorSubmission>,
    state_manager: web::Data<Arc<PersistentStateManager>>,
) -> impl Responder {
    // Create a new DSM state with provided data or empty vector
    let data = anchor.data.clone().unwrap_or_default();
    let mut dsm_state = DsmState::new(data);

    info!(
        "Received anchor submission for block number: {}",
        anchor.block_number
    );

    // Convert hex-encoded strings into raw bytes
    let tx_hash_bytes = match hex::decode(&anchor.tx_hash) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Invalid tx_hash hex: {}", e);
            return HttpResponse::BadRequest().json(AnchorResponse {
                success: false,
                message: "Invalid tx_hash hex".to_string(),
                state_id: None,
            });
        }
    };
    let event_root_bytes = match hex::decode(&anchor.event_root) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Invalid event_root hex: {}", e);
            return HttpResponse::BadRequest().json(AnchorResponse {
                success: false,
                message: "Invalid event_root hex".to_string(),
                state_id: None,
            });
        }
    };
    let inclusion_proof_bytes = match hex::decode(&anchor.inclusion_proof) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Invalid inclusion_proof hex: {}", e);
            return HttpResponse::BadRequest().json(AnchorResponse {
                success: false,
                message: "Invalid inclusion_proof hex".to_string(),
                state_id: None,
            });
        }
    };
    let event_hash_bytes = match hex::decode(&anchor.event_hash) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Invalid event_hash hex: {}", e);
            return HttpResponse::BadRequest().json(AnchorResponse {
                success: false,
                message: "Invalid event_hash hex".to_string(),
                state_id: None,
            });
        }
    };

    // Convert 32-byte vectors into fixed-size arrays
    if tx_hash_bytes.len() != 32 || event_root_bytes.len() != 32 {
        return HttpResponse::BadRequest().json(AnchorResponse {
            success: false,
            message: "Incorrect tx_hash or event_root length".to_string(),
            state_id: None,
        });
    }

    let mut tx_hash_array = [0u8; 32];
    tx_hash_array.copy_from_slice(&tx_hash_bytes);

    let mut event_root_array = [0u8; 32];
    event_root_array.copy_from_slice(&event_root_bytes);

    let anchor_struct = EthereumAnchor {
        block_number: anchor.block_number,
        tx_hash: tx_hash_array,
        event_root: event_root_array,
    };

    // Incorporate the Ethereum anchor into the DSM state
    match dsm_state.incorporate_eth_anchor(anchor_struct, &inclusion_proof_bytes, &event_hash_bytes)
    {
        Ok(_) => {
            info!(
                "Successfully incorporated Ethereum anchor for block {}",
                anchor.block_number
            );

            // Generate a state ID before moving the state
            let state_id_suffix = state_manager.generate_state_id(&dsm_state);
            let state_id = format!("dsm_state:{}", state_id_suffix);

            // Store the state using the PersistentStateManager (both locally and in distributed storage)
            match state_manager.add_state(dsm_state).await {
                Ok(_) => {
                    info!("Successfully stored anchored state in distributed storage");

                    HttpResponse::Ok().json(AnchorResponse {
                        success: true,
                        message: "Ethereum anchor incorporated into DSM state and stored in distributed storage".to_string(),
                        state_id: Some(state_id),
                    })
                }
                Err(e) => {
                    error!("Failed to store anchored state: {:?}", e);
                    HttpResponse::InternalServerError().json(AnchorResponse {
                        success: false,
                        message: format!("Failed to store state: {}", e),
                        state_id: None,
                    })
                }
            }
        }
        Err(e) => {
            error!("Invalid Ethereum anchor proof: {:?}", e);
            HttpResponse::BadRequest().json(AnchorResponse {
                success: false,
                message: format!("Invalid Ethereum anchor proof: {:?}", e),
                state_id: None,
            })
        }
    }
}
