// storage_integration_test.rs
//
// Integration tests for cryptographic identity persistence in storage nodes

#[cfg(test)]
mod tests {
    use crate::{
        crypto_verification::crypto_identity::CryptoIdentityFactory,
        types::error::DsmError,
    };
    
    #[test]
    fn test_crypto_identity_creation() -> Result<(), DsmError> {
        // Create test identity
        let app_id = "com.dsm.testapp";
        let result = CryptoIdentityFactory::create_test_identity(app_id);
        assert!(result.is_ok());

        let (mut identity, _sphincs_keypair, _kyber_keypair) = result.unwrap();

        // Create genesis state
        let genesis_state = identity.create_state(None, b"genesis_operation")?;
        assert_eq!(genesis_state.state_number, 0);
        
        // Verify we can create subsequent states (local chain functionality)
        let next_state = identity.create_state(Some(&genesis_state), b"next_operation")?;
        assert_eq!(next_state.state_number, 1);
        assert_eq!(next_state.prev_state_hash, genesis_state.hash()?);
        
        println!("Successfully created crypto identity and verified state transitions");
        Ok(())
    }

    // This test requires the "reqwest" feature and a running storage node
    // To run this test: cargo test --features reqwest crypto_verification::storage_integration_test
    #[cfg(feature = "reqwest")]
    #[tokio::test]
    async fn test_identity_storage_integration() -> Result<(), DsmError> {
        use bincode;
        use reqwest;
        use serde_json::json;
        use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
        use base64::engine::Engine as Base64Engine;
        
        println!("Testing storage node integration with CryptoIdentity");
        
        // Create test identity
        let app_id = "com.dsm.testapp";
        let result = CryptoIdentityFactory::create_test_identity(app_id);
        assert!(result.is_ok());

        let (mut identity, sphincs_keypair, _kyber_keypair) = result.unwrap();

        // Create genesis state
        let genesis_state = identity.create_state(None, b"genesis_operation")?;
        assert_eq!(genesis_state.state_number, 0);
        
        // Serialize the identity's genesis state
        let identity_key = format!("identity_{}_{}",
            app_id,
            hex::encode(&identity.genesis_hash.as_bytes()[0..8]));
        
        let serialized_state = bincode::serialize(&genesis_state)
            .map_err(|e| DsmError::Storage {
                context: format!("Failed to serialize state: {}", e),
                source: Some(Box::new(e))
            })?;
        
        // Create HTTP client
        let client = reqwest::Client::new();
        
        // Check if storage node is healthy
        println!("Checking if storage node is healthy...");
        let health_url = "http://127.0.0.1:8080/api/v1/status";
        println!("Connecting to storage node at: {}", health_url);
        
        let health_response = client.get(health_url)
            .send()
            .await
            .map_err(|e: reqwest::Error| {
                println!("Error connecting to storage node: {}", e);
                DsmError::Network {
                    context: format!("Failed to connect to storage node: {}", e),
                    source: Some(Box::new(e)),
                    entity: "storage_node".to_string(),
                    details: Some("Error during health check".to_string())
                }
            })?;
            
        let status = health_response.status();
        println!("Storage node health check status: {}", status);
            
        if !status.is_success() {
            // Try a different approach - just check if the storage node is running
            // by checking any root endpoint
            println!("Health endpoint failed, trying root path...");
            let root_response = client.get("http://127.0.0.1:8080/")
                .send()
                .await
                .map_err(|e: reqwest::Error| {
                    println!("Error connecting to storage node root: {}", e);
                    DsmError::Network {
                        context: format!("Failed to connect to storage node: {}", e),
                        source: Some(Box::new(e)),
                        entity: "storage_node".to_string(),
                        details: Some("Error connecting to root endpoint".to_string())
                    }
                })?;
                
            println!("Storage node root path status: {}", root_response.status());
            
            // Even if root fails, continue anyway to check the key API endpoints
        }
        
        println!("Storage node is healthy");
        
        // Store the genesis state in the storage node
        println!("Storing identity genesis state in storage node...");
        
        // Encode the state as base64 to include in the JSON payload
        let encoded_state = BASE64_STANDARD.encode(&serialized_state);
                
        // Create payload for storage API according to the actual storage node implementation
        // The storage node expects a simple JSON value, not a complex DataSubmissionRequest
        let store_payload = json!({
            "state": encoded_state,
            "type": "identity_state",
            "state_number": genesis_state.state_number,
            "app_id": app_id,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        
        // The actual endpoint is /api/v1/data/:key
        let store_response = client.post(format!("http://127.0.0.1:8080/api/v1/data/{}", identity_key))
            .json(&store_payload)
            .send()
            .await
            .map_err(|e: reqwest::Error| DsmError::Network {
                context: format!("Failed to store data in storage node: {}", e),
                source: Some(Box::new(e)),
                entity: "storage_node".to_string(), 
                details: Some("Error storing initial state".to_string())
            })?;
            
        assert!(store_response.status().is_success(), "Failed to store data in storage node");
        println!("Successfully stored identity state in storage node");
        
        // Verify we can retrieve the state from storage
        println!("Retrieving identity state from storage node...");
        let retrieve_response = client.get(format!("http://127.0.0.1:8080/api/v1/data/{}", identity_key))
            .send()
            .await
            .map_err(|e: reqwest::Error| DsmError::Network {
                context: format!("Failed to retrieve data from storage node: {}", e),
                source: Some(Box::new(e)),
                entity: "storage_node".to_string(),
                details: Some("Error retrieving state".to_string())
            })?;
            
        if !retrieve_response.status().is_success() {
            println!("Failed to retrieve data: HTTP {}", retrieve_response.status());
            let error_text = retrieve_response.text().await.unwrap_or_default();
            println!("Error response: {}", error_text);
            return Err(DsmError::Storage {
                context: "Failed to retrieve data from storage node".to_string(),
                source: None
            });
        }
        
        println!("Successfully retrieved response from storage node");
            
        // Parse the response
        let response_json: serde_json::Value = retrieve_response.json()
            .await
            .map_err(|e: reqwest::Error| DsmError::Network {
                context: format!("Failed to parse response: {}", e),
                source: Some(Box::new(e)),
                entity: "storage_response".to_string(),
                details: Some("Error when parsing JSON response from storage node".to_string())
            })?;
            
        // Get the payload field from the response
        let retrieved_data_json = response_json.as_object().ok_or_else(|| DsmError::Storage {
            context: "Response is not a JSON object".to_string(),
            source: None
        })?;
            
        // In our revised format, look for the "state" field which contains the base64-encoded state
        let state_base64 = match retrieved_data_json.get("state") {
            Some(state) => state.as_str()
                .ok_or_else(|| DsmError::Storage {
                    context: "State field is not a string".to_string(),
                    source: None
                })?,
            None => {
                // Try various alternatives (for robustness)
                if let Some(data) = retrieved_data_json.get("data") {
                    if let Some(str_data) = data.as_str() {
                        str_data
                    } else {
                        return Err(DsmError::Storage {
                            context: "Data field is not a string".to_string(),
                            source: None
                        });
                    }
                } else if let Some(payload) = retrieved_data_json.get("payload") {
                    if let Some(str_payload) = payload.as_str() {
                        str_payload
                    } else {
                        return Err(DsmError::Storage {
                            context: "Payload field is not a string".to_string(),
                            source: None
                        });
                    }
                } else {
                    // Last resort: check if the entire response is the encoded data
                    // This handles cases where the storage node might just return the raw stored value
                    if let Some(str_val) = response_json.as_str() {
                        str_val
                    } else {
                        return Err(DsmError::Storage {
                            context: format!("Could not find state data in response: {}", response_json),
                            source: None
                        });
                    }
                }
            }
        };
            
        // Decode the base64 data
        let retrieved_data = BASE64_STANDARD.decode(state_base64)
            .map_err(|e: base64::DecodeError| DsmError::Storage {
                context: format!("Failed to decode base64 data: {}", e),
                source: Some(Box::new(e))
            })?;
            
        // Deserialize the state
        let retrieved_state = bincode::deserialize::<crate::types::state_types::State>(&retrieved_data)
            .map_err(|e: bincode::Error| DsmError::Storage {
                context: format!("Failed to deserialize state: {}", e),
                source: Some(Box::new(e))
            })?;
        
        // Verify state integrity
        assert_eq!(retrieved_state.state_number, genesis_state.state_number, "State number mismatch");
        assert_eq!(retrieved_state.hash, genesis_state.hash, "State hash mismatch");
        println!("Successfully retrieved and verified identity state from storage node");
        
        // Create next state (state 1)
        let next_state = identity.create_state(Some(&genesis_state), b"next_operation")?;
        assert_eq!(next_state.state_number, 1);
        assert_eq!(next_state.prev_state_hash, genesis_state.hash()?);
        
        // Serialize and store the next state
        let next_state_key = format!("identity_{}_state_{}", 
            app_id, 
            next_state.state_number);
            
        let serialized_next_state = bincode::serialize(&next_state)
            .map_err(|e: bincode::Error| DsmError::Storage {
                context: format!("Failed to serialize next state: {}", e),
                source: Some(Box::new(e))
            })?;
            
        // Store the next state in the storage node
        // Encode the state as base64 to include in the JSON payload
        let encoded_next_state = BASE64_STANDARD.encode(&serialized_next_state);
        
        let next_store_payload = json!({
            "state": encoded_next_state,
            "type": "identity_state",
            "state_number": next_state.state_number,
            "app_id": app_id,
            "prev_state_hash": hex::encode(&next_state.prev_state_hash),
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        
        println!("Storing next state in storage node...");
        let next_store_response = client.post(format!("http://127.0.0.1:8080/api/v1/data/{}", next_state_key))
            .json(&next_store_payload)
            .send()
            .await
            .map_err(|e: reqwest::Error| DsmError::Network {
                context: format!("Failed to store next state in storage node: {}", e),
                source: Some(Box::new(e)),
                entity: "storage_node".to_string(),
                details: Some("Error storing state 1".to_string())
            })?;
            
        assert!(next_store_response.status().is_success(), "Failed to store next state in storage node");
        println!("Successfully stored next state in storage node");
        
        // Create signature over next state hash for verification
        let signature = sphincs_keypair.sign(&next_state.hash)?;
        
        // Verify signature
        let verified = sphincs_keypair.verify(&next_state.hash, &signature)?;
        assert!(verified, "Signature verification failed");
        println!("Signature verification successful");
        
        // Cleanup - delete the states from storage
        println!("Cleaning up test data from storage node...");
        let delete_response = client.delete(format!("http://127.0.0.1:8080/api/v1/data/{}", identity_key))
            .send()
            .await
            .map_err(|e: reqwest::Error| DsmError::Network {
                context: format!("Failed to delete genesis state from storage node: {}", e),
                source: Some(Box::new(e)),
                entity: "storage_node".to_string(),
                details: Some("Error during cleanup".to_string())
            })?;
            
        if !delete_response.status().is_success() {
            println!("Warning: Failed to delete genesis state: HTTP {}", delete_response.status());
        } else {
            println!("Successfully deleted genesis state from storage node");
        }
        
        let next_delete_response = client.delete(format!("http://127.0.0.1:8080/api/v1/data/{}", next_state_key))
            .send()
            .await
            .map_err(|e: reqwest::Error| DsmError::Network {
                context: format!("Failed to delete next state from storage node: {}", e),
                source: Some(Box::new(e)),
                entity: "storage_node".to_string(),
                details: Some("Error during cleanup of state 1".to_string())
            })?;
            
        if !next_delete_response.status().is_success() {
            println!("Warning: Failed to delete next state: HTTP {}", next_delete_response.status());
        } else {
            println!("Successfully deleted next state from storage node");
        }
            
        println!("Storage integration test completed successfully");
        Ok(())
    }
}
