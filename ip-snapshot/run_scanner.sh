#!/bin/bash

# IP Scanner - Residential IP Address Collection Script
# This script runs the IP scanner to collect evenly distributed residential IPs worldwide

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Set default values
CONCURRENCY=250
OUTPUT_DIR="./data"
GEOIP_PATH="./GeoLite2-City.mmdb"

# Process command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--concurrency)
      CONCURRENCY="$2"
      shift 2
      ;;
    -o|--output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -g|--geoip)
      GEOIP_PATH="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo "Options:"
      echo "  -c, --concurrency NUM   Number of concurrent scans (default: 250)"
      echo "  -o, --output DIR        Output directory for collected data (default: ./data)"
      echo "  -g, --geoip PATH        Path to GeoIP database (default: ./GeoLite2-City.mmdb)"
      echo "  -h, --help              Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help to see available options"
      exit 1
      ;;
  esac
done

# Make sure output directory exists
mkdir -p "$OUTPUT_DIR"

# Check if GeoIP database exists
if [ ! -f "$GEOIP_PATH" ]; then
  echo "Error: GeoIP database not found at $GEOIP_PATH"
  echo "Download a GeoIP database or specify the path with --geoip option"
  exit 1
fi

echo "Starting IP scanner with the following settings:"
echo "  Concurrency: $CONCURRENCY"
echo "  Output directory: $OUTPUT_DIR"
echo "  GeoIP database: $GEOIP_PATH"
echo ""
echo "Press Ctrl+C to stop the scan and save results"
echo "-------------------------------------------"

# Run the scanner
cargo run --release -- scan \
  --concurrency "$CONCURRENCY" \
  --output "$OUTPUT_DIR" \
  --geoip "$GEOIP_PATH"
