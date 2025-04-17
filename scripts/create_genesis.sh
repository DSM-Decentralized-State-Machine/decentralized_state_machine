#!/bin/bash
# Script to build and run the DSM genesis creation examples

# Color codes for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}===========================================================${NC}"
echo -e "${BLUE}   DSM Genesis Creation Demo Script                         ${NC}"
echo -e "${BLUE}===========================================================${NC}"
echo

# Function to check if a command was successful
check_result() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: $1 failed${NC}"
        exit 1
    fi
}

# Build the examples
echo -e "${YELLOW}Building DSM examples...${NC}"
cd "$(dirname "$0")/.."
cargo build --examples
check_result "Building examples"
echo -e "${GREEN}Build completed successfully!${NC}"
echo

# Run the storage nodes example
echo -e "${YELLOW}Running storage nodes simulation...${NC}"
echo -e "${YELLOW}This demonstrates how multiple storage nodes participate in genesis creation${NC}"
echo
cargo run --example start_storage_nodes
check_result "Running storage nodes example"
echo
echo -e "${GREEN}Storage nodes simulation completed successfully!${NC}"
echo

# Short pause for readability
sleep 2

# Run the user-side genesis creation example
echo -e "${YELLOW}Running user genesis creation example...${NC}"
echo -e "${YELLOW}This demonstrates how a user device requests and processes a genesis state${NC}"
echo
cargo run --example user_genesis_creation
check_result "Running user genesis creation example"
echo
echo -e "${GREEN}User genesis creation example completed successfully!${NC}"
echo

echo -e "${BLUE}===========================================================${NC}"
echo -e "${GREEN}All examples ran successfully!${NC}"
echo -e "${BLUE}===========================================================${NC}"
echo
echo -e "For more information, see the documentation at:"
echo -e "  docs/genesis_creation_guide.md"
echo

# Check if the examples created any output files
EXAMPLE_OUTPUT="examples/output"
if [ -d "$EXAMPLE_OUTPUT" ]; then
    echo -e "${YELLOW}Example output files:${NC}"
    ls -l "$EXAMPLE_OUTPUT"
    echo
fi
