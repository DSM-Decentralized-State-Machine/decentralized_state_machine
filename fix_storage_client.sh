#!/bin/bash

# Restore the backup of the original file
cp /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/dsm/src/communication/storage_client.rs.bak /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/dsm/src/communication/storage_client.rs

# Edit the file to add the missing fields to DsmError::Network initializations
sed -i '' 's/DsmError::Network {/DsmError::Network {\n                entity: "storage_node".to_string(),\n                details: Some("Network operation failed".to_string()),/g' /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/dsm/src/communication/storage_client.rs

# Edit the file to add the missing fields to DsmError::Serialization initializations
sed -i '' 's/DsmError::Serialization {/DsmError::Serialization {\n                entity: "serialized_data".to_string(),\n                details: Some("Serialization operation failed".to_string()),/g' /Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/dsm/src/communication/storage_client.rs
