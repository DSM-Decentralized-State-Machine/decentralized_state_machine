#!/bin/bash
# Test script for DSM Epidemic Storage

echo "Testing DSM Epidemic Storage..."

# Give the nodes time to discover each other and establish connections
echo "Waiting for nodes to establish connections..."
sleep 10

# Store data on node 1
echo "Storing test data with key 'epidemic1' on node1..."
curl -X POST -H "Content-Type: application/json" -d '{"name": "Epidemic Test", "value": 42, "active": true}' http://127.0.0.1:8080/api/v1/data/epidemic1

# Wait for epidemic propagation
echo -e "\n\nWaiting for epidemic propagation (15 seconds)..."
sleep 15

# Retrieve data from node 2 (should have propagated)
echo -e "\n\nRetrieving data with key 'epidemic1' from node2..."
curl -X GET http://127.0.0.1:8081/api/v1/data/epidemic1

# Retrieve data from node 3 (should have propagated)
echo -e "\n\nRetrieving data with key 'epidemic1' from node3..."
curl -X GET http://127.0.0.1:8082/api/v1/data/epidemic1

# Store data on node 3
echo -e "\n\nStoring test data with key 'epidemic2' on node3..."
curl -X POST -H "Content-Type: application/json" -d '{"name": "Epidemic Test 2", "value": 100, "region": "us-east"}' http://127.0.0.1:8082/api/v1/data/epidemic2

# Wait for epidemic propagation
echo -e "\n\nWaiting for epidemic propagation (15 seconds)..."
sleep 15

# Retrieve data from node 1 (should have propagated)
echo -e "\n\nRetrieving data with key 'epidemic2' from node1..."
curl -X GET http://127.0.0.1:8080/api/v1/data/epidemic2

# Check node status for all nodes
echo -e "\n\nChecking node1 status..."
curl -X GET http://127.0.0.1:8080/api/v1/status

echo -e "\n\nChecking node2 status..."
curl -X GET http://127.0.0.1:8081/api/v1/status

echo -e "\n\nChecking node3 status..."
curl -X GET http://127.0.0.1:8082/api/v1/status

echo -e "\n\nTest completed."
