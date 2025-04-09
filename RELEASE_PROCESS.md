# DSM Release Process

This document outlines the complete release process for DSM, including both automated and manual steps.

## Release Versioning

DSM follows Semantic Versioning (SemVer) with the format `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`.

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality
- **PATCH**: Backwards-compatible bug fixes
- **PRERELEASE**: alpha, beta, rc tags for pre-releases
- **BUILD**: Build metadata

Examples:
- `0.1.0-alpha.1`: Initial alpha release
- `0.1.0-beta.2`: Second beta release
- `0.1.0`: Stable release
- `0.1.1`: Patch release

## Prerequisites

- Access to the DSM repository
- Build environment for each target platform:
  - Linux: Ubuntu 20.04 or newer
  - macOS: 11.0 or newer
  - Windows: Windows 10/11 with MSYS2 or WSL

## Release Preparation

1. **Update Version Numbers**:
   ```bash
   # Find all Cargo.toml files and update versions
   find . -name "Cargo.toml" -type f -exec sed -i 's/version = "OLD_VERSION"/version = "NEW_VERSION"/g' {} \;
   ```

2. **Update CHANGELOG.md**:
   - Add new version section
   - Document all changes since the last release
   - Update "Unreleased" section for future changes

3. **Update Documentation**:
   - Ensure README.md reflects latest features
   - Update any version references in documentation
   - Verify installation instructions are current

4. **Run Pre-release Tests**:
   ```bash
   # Run all tests
   cargo test --all-features -- --nocapture
   ```

## Build Process

### Automated Build Process

The automated build process uses GitHub Actions to build packages for all platforms:

1. **Create and Push Git Tag**:
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

2. **Build Packages Via GitHub Actions**:
   - GitHub Actions workflow is triggered by the tag
   - Packages are built for all platforms
   - Release is created with all packages and checksums

### Manual Build Process

If GitHub Actions automation fails, follow these steps:

1. **Build Packages Locally**:
   ```bash
   # Using the master release script
   ./scripts/release.sh
   ```

2. **Create Release**:
   - Create a new release on GitHub manually
   - Upload all generated package files
   - Upload checksum files

## Platform-Specific Builds

### Linux Build

```bash
# Build Linux package
./scripts/release/linux.sh
```

### macOS Build

```bash
# Build macOS package
./scripts/release/macos.sh
```

### Windows Build

```bash
# Build Windows package
./scripts/release/windows.sh
```

## Release Verification

After creating the release, verify the following:

1. **Download URLs Work**: Test download links for all platforms
2. **Checksums Match**: Verify checksums against published values
3. **Installation Works**: Test installation process on each platform
4. **Basic Functionality**: Verify core functionality works as expected

## Post-Release Tasks

1. **Update Website**: Update website with latest version and documentation
2. **Announce Release**: Announce on community channels
3. **Create Release Branch**: For patch releases, create a branch if needed
4. **Update Development Version**: Increment version numbers for development
   ```bash
   # Find all Cargo.toml files and update to next development version
   find . -name "Cargo.toml" -type f -exec sed -i 's/version = "OLD_VERSION"/version = "NEW_VERSION-dev"/g' {} \;
   ```

## Hotfix Process

For urgent fixes to a release:

1. Create branch from the release tag
2. Apply hotfix
3. Increment patch version
4. Follow release process for the hotfix version

## Release Channels

DSM has the following release channels:

- **Alpha**: Early development releases for testing
- **Beta**: Feature-complete releases for wider testing
- **RC**: Release candidates for final testing
- **Stable**: Production-ready releases

## Cross-Platform Release Matrix

| Platform            | Architecture | Package Format | Installer |
|---------------------|--------------|----------------|-----------|
| Linux (Ubuntu/Debian) | x86_64     | .tar.gz        | install.sh |
| Linux (RHEL/CentOS)   | x86_64     | .tar.gz        | install.sh |
| macOS               | x86_64, arm64 | .tar.gz       | install.sh |
| Windows             | x86_64       | .zip, .tar.gz  | install.bat |
