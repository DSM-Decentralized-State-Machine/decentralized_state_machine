#!/bin/bash
set -euo pipefail

# DSM macOS-compatible Release Packager
# This script prepares a release package with macOS-compatible commands

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

# Package examples
echo "Packaging examples..."
mkdir -p "${ARTIFACTS_DIR}/examples"
cp -R "${REPO_ROOT}/examples"/* "${ARTIFACTS_DIR}/examples/"

# Add minimal core module files (no source, but essential Cargo.toml files)
echo "Copying Cargo configuration..."
mkdir -p "${ARTIFACTS_DIR}/dsm"
mkdir -p "${ARTIFACTS_DIR}/dsm-sdk"
mkdir -p "${ARTIFACTS_DIR}/dsm-storage-node"
cp "${REPO_ROOT}/Cargo.toml" "${ARTIFACTS_DIR}/"
cp "${REPO_ROOT}/dsm/Cargo.toml" "${ARTIFACTS_DIR}/dsm/"
cp "${REPO_ROOT}/dsm-sdk/Cargo.toml" "${ARTIFACTS_DIR}/dsm-sdk/"
cp "${REPO_ROOT}/dsm-storage-node/Cargo.toml" "${ARTIFACTS_DIR}/dsm-storage-node/"

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

# Check OS type and install required system dependencies
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS detected. Checking for Homebrew..."
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Please install Homebrew: https://brew.sh/"
        exit 1
    fi
    
    echo "Installing system dependencies..."
    brew install openssl rocksdb cmake
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Linux detected. Checking package manager..."
    if command -v apt-get &> /dev/null; then
        echo "Installing system dependencies with apt..."
        sudo apt-get update
        sudo apt-get install -y build-essential pkg-config libssl-dev librocksdb-dev clang cmake
    elif command -v yum &> /dev/null; then
        echo "Installing system dependencies with yum..."
        sudo yum install -y gcc gcc-c++ make openssl-devel clang cmake
        echo "Warning: You may need to install RocksDB manually on this platform"
    else
        echo "Unsupported Linux distribution. Please install build-essential, libssl-dev, and librocksdb-dev manually."
    fi
else
    echo "Unsupported operating system. Please refer to INSTALL.md for manual installation."
fi

# Clone the repository
echo "Cloning the DSM repository..."
git clone https://github.com/dsm-project/dsm.git
cd dsm
git checkout v0.1.0-alpha.1

# Build the project
echo "Building DSM from source (this may take a few minutes)..."
cargo build --release

echo "Installation complete!"
echo "You can find binaries in the target/release directory."
echo "For more information, see the documentation in docs/ directory."
EOF

chmod +x "${ARTIFACTS_DIR}/install.sh"

# Create documentation directory
echo "Creating documentation directory..."
mkdir -p "${ARTIFACTS_DIR}/docs"
echo "# DSM Documentation" > "${ARTIFACTS_DIR}/docs/index.md"
echo "See https://decentralizedstatemachine.com/devdocs/ for full documentation." >> "${ARTIFACTS_DIR}/docs/index.md"

# Create archive
echo "Creating release archive..."
cd "${RELEASE_DIR}"
tar -czvf "dsm-${VERSION}.tar.gz" "dsm-${VERSION}"

# Generate checksums
echo "Generating checksums..."
shasum -a 256 "dsm-${VERSION}.tar.gz" > "dsm-${VERSION}.sha256"

echo "Manual release package created at ${RELEASE_DIR}/dsm-${VERSION}.tar.gz"
echo "Checksums available at ${RELEASE_DIR}/dsm-${VERSION}.sha256"
