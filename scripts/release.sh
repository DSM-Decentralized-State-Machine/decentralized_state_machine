#!/bin/bash
set -euo pipefail

# DSM Master Release Script
# This script orchestrates the release process for all supported platforms

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/release/common.sh"

echo "=== DSM v${VERSION} Release Build ==="
echo "Target platforms: ${PLATFORMS[*]}"

# Ensure clean state
echo "Cleaning previous build artifacts..."
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

# Detect current platform
CURRENT_PLATFORM=$(detect_platform)
echo "Current platform: ${CURRENT_PLATFORM}"

# Build manifest.json with release metadata
cat > "${RELEASE_DIR}/manifest.json" << EOF
{
  "version": "${VERSION}",
  "releaseDate": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "platforms": $(printf '%s\n' "${PLATFORMS[@]}" | jq -R . | jq -s .),
  "minRustVersion": "1.76.0",
  "releaseNotes": "https://github.com/dsm-project/dsm/releases/tag/v${VERSION}"
}
EOF

# Build for current platform
echo "Building for ${CURRENT_PLATFORM}..."
case "${CURRENT_PLATFORM}" in
    "linux")
        bash "${SCRIPT_DIR}/release/linux.sh"
        ;;
    "macos")
        bash "${SCRIPT_DIR}/release/macos.sh"
        ;;
    "windows")
        bash "${SCRIPT_DIR}/release/windows.sh"
        ;;
    *)
        echo "Error: Unsupported platform: ${CURRENT_PLATFORM}"
        exit 1
        ;;
esac

# Generate checksums and platform matrix
echo "Generating checksums and platform matrix..."
generate_checksums
create_platform_matrix

# Create a unified README
cat > "${RELEASE_DIR}/README.md" << EOF
# DSM v${VERSION} Release

This is the initial alpha release of the Decentralized State Machine (DSM), a quantum-resistant decentralized state machine implementation with cryptographic verification and bilateral state isolation.

## Supported Platforms

See [platform-support.md](platform-support.md) for a detailed platform support matrix.

## Installation

1. Download the appropriate package for your platform
2. Extract the archive
3. Follow the platform-specific installation instructions:
   - Linux: Run \`./install.sh\` (or \`sudo ./install.sh system\` for system-wide installation)
   - macOS: Run \`./install.sh\` (or \`sudo ./install.sh system\` for system-wide installation)
   - Windows: Run \`install.bat\` (as Administrator for system-wide installation)

## Verification

Verify the integrity of your download with the provided SHA-256 checksums:

\`\`\`bash
# Example verification on Linux/macOS
shasum -a 256 -c dsm-${VERSION}.sha256

# Example verification on Windows (PowerShell)
Get-FileHash -Algorithm SHA256 dsm-${VERSION}-windows.zip | Format-List
\`\`\`

## Release Notes

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

## Security

See [SECURITY.md](SECURITY.md) for information about the security model and vulnerability reporting process.

## License

This project is licensed under either of:
- Apache License, Version 2.0
- MIT License

at your option.
EOF

echo "=== Release build completed ==="
echo "Release packages are available in ${RELEASE_DIR}"
echo "Upload these files to your GitHub release."
