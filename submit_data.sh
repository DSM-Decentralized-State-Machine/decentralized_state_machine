#!/bin/bash
# Script to submit data to the storage node using the DSM client

export DSM_STORAGE_URL="http://localhost:8080"
export DSM_LOG_LEVEL="info"

echo "Submitting test data to storage node at $DSM_STORAGE_URL"

# Generate a random state ID
STATE_ID=$(uuidgen)
echo "Using state ID: $STATE_ID"

# Create a simple state payload
STATE_PAYLOAD="{\"name\":\"Test State\",\"timestamp\":$(date +%s),\"data\":\"This is a test state submission\"}"

# Submit the state to the storage node
echo "Submitting state..."
./target/release/dsm storage submit --id "$STATE_ID" --data "$STATE_PAYLOAD"

echo "Verifying state was stored properly..."
./target/release/dsm storage retrieve --id "$STATE_ID"

echo "Test complete!"
