#!/bin/bash
set -euo pipefail

# DSM Docker-based Cross-Platform Build Script
# This script uses Docker to generate releases for multiple platforms from a single host

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== DSM Multi-Platform Release Builder ==="

# Create all necessary directories
mkdir -p "${HOST_REPO_ROOT}/target/release-package"

# Build Linux release using Docker with static RocksDB linking
echo "Building Linux release using Docker..."
docker run --rm \
    -v "${HOST_REPO_ROOT}:/workspace" \
    -w /workspace \
    rust:1.76 \
    bash -c "apt-get update && \
             apt-get install -y pkg-config libssl-dev cmake libclang-dev clang && \
             # Don't install librocksdb-dev from apt - we'll use bundled version instead \
             export ROCKSDB_STATIC=1 && \
             export CARGO_FEATURE_STATIC=1 && \
             ./scripts/release/linux.sh"

# Build macOS release natively
echo "Building macOS release natively..."
"${SCRIPT_DIR}/release/macos.sh"

# Generate Windows template
echo "Generating Windows release template..."
"${SCRIPT_DIR}/release/windows.sh"

# Generate checksums and platform matrix
source "${SCRIPT_DIR}/release/common.sh"
echo "Generating checksums and platform matrix..."
generate_checksums
create_platform_matrix

echo "=== Multi-platform build completed ==="
echo "Release packages are available in ${HOST_REPO_ROOT}/target/release-package"
echo ""
echo "Linux: Full build with binaries (via Docker)"
echo "macOS: Full build with binaries (native)"
echo "Windows: Template only (requires Windows to complete)"
echo ""
echo "For a complete Windows build, copy the template to a Windows machine and run:"
echo "  ./scripts/release/windows.sh"
