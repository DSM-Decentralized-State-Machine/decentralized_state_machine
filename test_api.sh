#!/bin/bash
# Script to test the storage node API

STORAGE_URL="http://127.0.0.1:8080"
echo "Testing storage node at $STORAGE_URL"

# Generate a random ID for our test
TEST_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
echo "Using test ID: $TEST_ID"

# Create test payload
TEST_PAYLOAD="{\"name\":\"Test Data\",\"timestamp\":$(date +%s),\"value\":42,\"message\":\"Hello from test script\"}"
echo "Test payload: $TEST_PAYLOAD"

# Step 1: Check if the storage node is running
echo -e "\n--- Step 1: Checking storage node status ---"
curl -s $STORAGE_URL/api/v1/status | jq .

# Step 2: Store data
echo -e "\n--- Step 2: Storing test data ---"
curl -v -X PUT -H "Content-Type: application/json" -d "$TEST_PAYLOAD" $STORAGE_URL/api/v1/data/$TEST_ID

# Step 3: Retrieve the data we just stored
echo -e "\n--- Step 3: Retrieving stored data ---"
curl -s $STORAGE_URL/api/v1/data/$TEST_ID | jq .

# Step 4: Delete the data
echo -e "\n--- Step 4: Deleting test data ---"
curl -v -X DELETE $STORAGE_URL/api/v1/data/$TEST_ID

# Step 5: Verify deletion
echo -e "\n--- Step 5: Verifying deletion (should return 404) ---"
curl -s -w "\nHTTP Status Code: %{http_code}\n" $STORAGE_URL/api/v1/data/$TEST_ID

echo -e "\nTest completed!"
