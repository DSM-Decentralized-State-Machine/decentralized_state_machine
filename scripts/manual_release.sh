#!/bin/bash
set -euo pipefail

# DSM Manual Release Packager
# This script prepares a release package without requiring GitHub Actions

VERSION="0.1.0-alpha.1"
REPO_ROOT="/Users/cryptskii/Desktop/claude_workspace/DSM_Decentralized_State_Machine"
RELEASE_DIR="${REPO_ROOT}/target/release-package"
ARTIFACTS_DIR="${RELEASE_DIR}/dsm-${VERSION}"

echo "Preparing DSM ${VERSION} release package..."

# Ensure release directory exists
mkdir -p "${ARTIFACTS_DIR}"

# Copy documentation
echo "Copying documentation files..."
cp "${REPO_ROOT}/README.md" \
   "${REPO_ROOT}/CHANGELOG.md" \
   "${REPO_ROOT}/SECURITY.md" \
   "${REPO_ROOT}/INSTALL.md" \
   "${REPO_ROOT}/LICENSE.md" \
   "${ARTIFACTS_DIR}/"

# Copy configuration templates
echo "Copying configuration templates..."
mkdir -p "${ARTIFACTS_DIR}/config"
cp "${REPO_ROOT}/.env.template" "${ARTIFACTS_DIR}/config/dsm.env.template"
cp "${REPO_ROOT}/docker-compose.yml" "${ARTIFACTS_DIR}/config/docker-compose.yml"

# Copy source code (since we can't compile binaries in this environment)
echo "Packaging source code for build instructions..."
mkdir -p "${ARTIFACTS_DIR}/src"
find "${REPO_ROOT}/dsm" -name "*.rs" -exec cp --parents {} "${ARTIFACTS_DIR}" \;
find "${REPO_ROOT}/dsm-sdk" -name "*.rs" -exec cp --parents {} "${ARTIFACTS_DIR}" \;
find "${REPO_ROOT}/dsm-storage-node" -name "*.rs" -exec cp --parents {} "${ARTIFACTS_DIR}" \;

# Copy Cargo manifests
echo "Copying Cargo configuration..."
find "${REPO_ROOT}" -name "Cargo.toml" -exec cp --parents {} "${ARTIFACTS_DIR}" \;

# Package examples
echo "Packaging examples..."
mkdir -p "${ARTIFACTS_DIR}/examples"
cp -r "${REPO_ROOT}/examples"/* "${ARTIFACTS_DIR}/examples/"

# Create install script
echo "Creating installation script..."
cat > "${ARTIFACTS_DIR}/install.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

# DSM Installation Script
echo "Installing DSM v0.1.0-alpha.1..."

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Please install Rust first: https://rustup.rs/"
    exit 1
fi

# Check for required dependencies
echo "Checking dependencies..."
if ! command -v pkg-config &> /dev/null; then
    echo "Warning: pkg-config not found, which may be required for building dependencies"
fi

# Build from source
echo "Building DSM from source (this may take a few minutes)..."
cargo build --release

echo "Installation complete! You can find binaries in the target/release directory."
echo "For more information, see the documentation in docs/ directory."
EOF

chmod +x "${ARTIFACTS_DIR}/install.sh"

# Create archive
echo "Creating release archive..."
cd "${RELEASE_DIR}"
tar -czvf "dsm-${VERSION}.tar.gz" "dsm-${VERSION}"

# Generate checksums
echo "Generating checksums..."
shasum -a 256 "dsm-${VERSION}.tar.gz" > "dsm-${VERSION}.sha256"

echo "Manual release package created at ${RELEASE_DIR}/dsm-${VERSION}.tar.gz"
echo "Checksums available at ${RELEASE_DIR}/dsm-${VERSION}.sha256"
