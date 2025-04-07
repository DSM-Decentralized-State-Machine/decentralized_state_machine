use crate::commitments::external_commitment;
use crate::interfaces::external_commit_face::ExternalCommitFace;
use crate::types::error::DsmError;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

// A simple in-memory store for commitments
lazy_static::lazy_static! {
    static ref COMMITMENT_STORE: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub struct ExternalCommitmentApi {
    commitment_interface: Box<dyn ExternalCommitFace>,
}

impl ExternalCommitmentApi {
    pub fn new(commitment_interface: Box<dyn ExternalCommitFace>) -> Self {
        Self {
            commitment_interface,
        }
    }

    pub async fn submit_commitment(&self, data: Vec<u8>) -> Result<(), DsmError> {
        self.commitment_interface.submit_commitment(data).await
    }

    pub async fn verify_commitment(&self, commitment_id: &str) -> Result<bool, DsmError> {
        self.commitment_interface
            .verify_commitment(commitment_id)
            .await
    }
}

/// Register an external commitment and return its ID
///
/// # Arguments
///
/// * `data` - The data to commit
/// * `provider` - The name of the external provider
///
/// # Returns
///
/// * `Result<String, DsmError>` - The commitment ID or an error
pub async fn register_external_commitment(data: &[u8], provider: &str) -> Result<String, DsmError> {
    // Create a commitment hash from the data
    let commitment_hash = external_commitment::create_external_commitment(data, provider);

    // Create a commitment ID
    let commitment_id = format!("{}-{}", provider, hex::encode(&commitment_hash[0..8]));

    // Store the commitment
    {
        let mut store = COMMITMENT_STORE.lock().map_err(|_| {
            DsmError::storage(
                "Failed to acquire lock on commitment store",
                None::<std::io::Error>,
            )
        })?;

        store.insert(commitment_id.clone(), commitment_hash);
    }

    Ok(commitment_id)
}

/// Verify an external commitment
///
/// # Arguments
///
/// * `commitment_id` - The ID of the commitment to verify
/// * `data` - The data to verify against the commitment
///
/// # Returns
///
/// * `Result<bool, DsmError>` - True if the commitment is valid, false otherwise
pub async fn verify_external_commitment(
    commitment_id: &str,
    data: &[u8],
) -> Result<bool, DsmError> {
    // Parse the commitment ID to get the provider
    let parts: Vec<&str> = commitment_id.split('-').collect();
    if parts.len() != 2 {
        return Err(DsmError::validation(
            format!("Invalid commitment ID format: {}", commitment_id),
            None::<std::io::Error>,
        ));
    }

    let provider = parts[0];

    // Get the stored commitment
    let stored_commitment = {
        let store = COMMITMENT_STORE.lock().map_err(|_| {
            DsmError::storage(
                "Failed to acquire lock on commitment store",
                None::<std::io::Error>,
            )
        })?;

        store.get(commitment_id).cloned()
    };

    // If we have the commitment, verify it
    if let Some(stored) = stored_commitment {
        // Create a new commitment from the provided data
        let new_commitment = external_commitment::create_external_commitment(data, provider);

        // Compare the commitments
        Ok(stored == new_commitment)
    } else {
        // Commitment not found
        Err(DsmError::not_found(
            "Commitment",
            Some(format!("No commitment found with ID {}", commitment_id)),
        ))
    }
}
