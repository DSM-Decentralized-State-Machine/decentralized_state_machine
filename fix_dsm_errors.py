#!/usr/bin/env python3

import re

# Open the file
with open('/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/dsm/src/communication/storage_client.rs', 'r') as file:
    content = file.read()

# Fix DsmError::Network instances
pattern_network = r'DsmError::Network\s*\{\s*context:\s*([^,]+),\s*source:\s*([^,}]+)(?:,)?\s*\}'
replacement_network = r'DsmError::Network {\n                context: \1,\n                source: \2,\n                entity: "storage_node".to_string(),\n                details: Some("Network operation failed".to_string())\n            }'

content = re.sub(pattern_network, replacement_network, content)

# Fix DsmError::Serialization instances
pattern_serialization = r'DsmError::Serialization\s*\{\s*context:\s*([^,]+),\s*source:\s*([^,}]+)(?:,)?\s*\}'
replacement_serialization = r'DsmError::Serialization {\n                context: \1,\n                source: \2,\n                entity: "serialized_data".to_string(),\n                details: Some("Serialization operation failed".to_string())\n            }'

content = re.sub(pattern_serialization, replacement_serialization, content)

# Fix DsmError::NotFound instance that's missing fields
pattern_not_found = r'DsmError::NotFound\s*\{\s*entity:\s*([^,]+),\s*context:\s*([^,}]+)(?:,)?\s*\}'
replacement_not_found = r'DsmError::NotFound {\n                entity: \1,\n                context: \2,\n                details: Some("Not found".to_string()),\n                source: None\n            }'

content = re.sub(pattern_not_found, replacement_not_found, content)

# Write the fixed content back to the file
with open('/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine/dsm/src/communication/storage_client.rs', 'w') as file:
    file.write(content)

print("Fixed the DsmError initializations in storage_client.rs")
