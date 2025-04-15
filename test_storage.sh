#!/bin/bash
# Test script for DSM Storage Node API

echo "Testing DSM Storage Node API..."

# Store data
echo "Storing test data with key 'test1'..."
curl -X POST -H "Content-Type: application/json" -d '{"name": "Test Item", "value": 42, "active": true}' http://127.0.0.1:8080/api/v1/data/test1

# Retrieve data
echo -e "\n\nRetrieving data with key 'test1'..."
curl -X GET http://127.0.0.1:8080/api/v1/data/test1

# Check node status
echo -e "\n\nChecking node status..."
curl -X GET http://127.0.0.1:8080/api/v1/status

# Delete data
echo -e "\n\nDeleting data with key 'test1'..."
curl -X DELETE http://127.0.0.1:8080/api/v1/data/test1

# Verify deletion
echo -e "\n\nVerifying deletion (should return 404 Not Found)..."
curl -X GET http://127.0.0.1:8080/api/v1/data/test1

echo -e "\n\nTest completed."
