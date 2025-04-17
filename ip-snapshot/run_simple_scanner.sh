#!/bin/bash

# Simple IP Scanner - Residential IP Address Collection Script
# This script runs a basic IP scanner to collect residential IPs worldwide

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Set default values
CONCURRENCY=500
OUTPUT_DIR="./data"
GEOIP_PATH="./GeoLite2-City.mmdb"

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
echo "Scanning for residential IPs globally... Press Ctrl+C to stop scan and save results."
echo "-------------------------------------------"

# Run the scanner
cargo run --release -- scan \
  --concurrency "$CONCURRENCY" \
  --output "$OUTPUT_DIR" \
  --geoip "$GEOIP_PATH"

# Export the data
echo "Exporting collected data to JSON..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cargo run --release -- export \
  --data "$OUTPUT_DIR" \
  --format json \
  --output "$OUTPUT_DIR/ip_snapshot_$TIMESTAMP.json"

echo "Snapshot saved to $OUTPUT_DIR/ip_snapshot_$TIMESTAMP.json"
