#!/bin/bash
set -euo pipefail

# DSM Release Script
# This script builds and packages the DSM project for release

VERSION="0.1.0-alpha.1"
RELEASE_DIR="./target/release-package"
ARTIFACTS_DIR="${RELEASE_DIR}/dsm-${VERSION}"

echo "Preparing DSM ${VERSION} release package..."

# Ensure clean state
cargo clean
mkdir -p "${ARTIFACTS_DIR}"

# Build in release mode with all security features
RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo build --release --all-features

# Copy binaries
echo "Copying binaries..."
mkdir -p "${ARTIFACTS_DIR}/bin"
cp ./target/release/server "${ARTIFACTS_DIR}/bin/dsm-server"
cp ./target/release/cli "${ARTIFACTS_DIR}/bin/dsm-cli"

# Copy documentation
echo "Copying documentation..."
mkdir -p "${ARTIFACTS_DIR}/docs"
cp README.md CHANGELOG.md LICENSE.md SECURITY.md "${ARTIFACTS_DIR}/"
cp -r ./docs/* "${ARTIFACTS_DIR}/docs/"

# Copy configuration templates
echo "Copying configuration templates..."
mkdir -p "${ARTIFACTS_DIR}/config"
cp ./.env.template "${ARTIFACTS_DIR}/config/dsm.env.template"
cp ./docker-compose.yml "${ARTIFACTS_DIR}/config/docker-compose.yml"

# Package examples
echo "Packaging examples..."
mkdir -p "${ARTIFACTS_DIR}/examples"
cp -r ./examples/* "${ARTIFACTS_DIR}/examples/"

# Create checksums
echo "Generating checksums..."
cd "${RELEASE_DIR}"
shasum -a 256 $(find "dsm-${VERSION}" -type f) > "dsm-${VERSION}.sha256"
cd -

# Create archive
echo "Creating archive..."
cd "${RELEASE_DIR}"
tar -czvf "dsm-${VERSION}.tar.gz" "dsm-${VERSION}"
cd -

echo "Release package created at ${RELEASE_DIR}/dsm-${VERSION}.tar.gz"
echo "Checksums available at ${RELEASE_DIR}/dsm-${VERSION}.sha256"
