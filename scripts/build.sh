#!/bin/bash

# DSM Project Build Script
# Usage: ./scripts/build.sh [target] [--release]

set -e

# Default values
TARGET="all"
BUILD_TYPE="debug"
VERBOSE=""

# Parse command line arguments
for arg in "$@"; do
  case $arg in
    --release)
      BUILD_TYPE="release"
      shift
      ;;
    --verbose)
      VERBOSE="--verbose"
      shift
      ;;
    all|dsm|storage-node|ethereum-bridge|sdk)
      TARGET="$arg"
      shift
      ;;
    *)
      echo "Unknown argument: $arg"
      echo "Usage: ./scripts/build.sh [all|dsm|storage-node|ethereum-bridge|sdk] [--release] [--verbose]"
      exit 1
      ;;
  esac
done

# Set cargo build flags based on build type
if [ "$BUILD_TYPE" = "release" ]; then
  CARGO_FLAGS="--release"
  BUILD_DIR="release"
else
  CARGO_FLAGS=""
  BUILD_DIR="debug"
fi

# Add verbose flag if specified
CARGO_FLAGS="$CARGO_FLAGS $VERBOSE"

# Display build configuration
echo "Building DSM Project:"
echo "  Target:     $TARGET"
echo "  Build type: $BUILD_TYPE"
echo ""

# Check for required dependencies
echo "Checking dependencies..."

# Check for Rust toolchain
if ! command -v cargo &> /dev/null; then
  echo "Error: Rust toolchain not found. Please install Rust from https://rustup.rs/"
  exit 1
fi

# Check for RocksDB on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
  if ! command -v brew &> /dev/null; then
    echo "Warning: Homebrew not found. You may need to install RocksDB manually."
  elif ! brew list | grep -q "rocksdb"; then
    echo "Warning: RocksDB not found. Installing via Homebrew..."
    brew install rocksdb
  fi
# Check for RocksDB on Linux
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  if ! ldconfig -p | grep -q "librocksdb"; then
    echo "Warning: RocksDB not found. For Ubuntu/Debian, install with:"
    echo "  sudo apt-get install librocksdb-dev"
    echo "For other distributions, please refer to your package manager."
    echo ""
    read -p "Do you want to continue without RocksDB? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  fi
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
  echo "Creating default .env file from template..."
  cp .env.template .env
fi

# Build function
build_component() {
  local component=$1
  local path=$2
  
  echo "Building $component..."
  
  # Check if component directory exists
  if [ ! -d "$path" ]; then
    echo "Error: Directory $path not found!"
    exit 1
  fi
  
  # Build the component
  (cd "$path" && cargo build $CARGO_FLAGS)
  
  if [ $? -eq 0 ]; then
    echo "✅ $component built successfully"
  else
    echo "❌ Failed to build $component"
    exit 1
  fi
}

# Build based on target
case $TARGET in
  all)
    build_component "dsm" "dsm"
    build_component "dsm-storage-node" "dsm-storage-node"
    build_component "dsm-ethereum-bridge" "dsm-ethereum-bridge"
    build_component "dsm-sdk" "dsm-sdk"
    echo ""
    echo "✅ All components built successfully!"
    echo "Binaries are available in the target/$BUILD_DIR directory of each component."
    ;;
  dsm)
    build_component "dsm" "dsm"
    ;;
  storage-node)
    build_component "dsm-storage-node" "dsm-storage-node"
    ;;
  ethereum-bridge)
    build_component "dsm-ethereum-bridge" "dsm-ethereum-bridge"
    ;;
  sdk)
    build_component "dsm-sdk" "dsm-sdk"
    ;;
esac

echo ""
echo "Build complete. Use ./scripts/run.sh to start the components."
