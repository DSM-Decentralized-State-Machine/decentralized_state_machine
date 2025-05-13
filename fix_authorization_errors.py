#!/usr/bin/env python3
"""
Script to fix DsmError::authorization calls in wallet_sdk.rs file
"""

import re

# Path to the wallet_sdk.rs file
file_path = '/Users/cryptskii/Desktop/claude_workspace/DSM_Project/DSM_Decentralized_State_Machine/dsm_sdk/src/sdk/wallet_sdk.rs'

# Read the file
with open(file_path, 'r') as f:
    content = f.read()

# Replace all instances of DsmError::authorization with DsmError::unauthorized
# with proper parameters
fixed_content = re.sub(
    r'DsmError::authorization\("([^"]*)"\)',
    r'DsmError::unauthorized("\1", None::<std::io::Error>)',
    content
)

# Write the fixed content back to the file
with open(file_path, 'w') as f:
    f.write(fixed_content)

print(f"Fixed all instances of DsmError::authorization in {file_path}")